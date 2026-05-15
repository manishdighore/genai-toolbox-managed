# Security Configuration Guide

Three deployment tiers, each with a different credential security model.
Pick the one that matches your deployment. They are strictly additive —
enterprise includes everything in local, SaaS includes everything in enterprise.

---

## Tier 1 — Local / Self-Hosted

**Who uses this:** A single operator running db-mcp on their own machine or VM.
You are the server operator and you trust yourself.

**Threat model:** Protect against accidental credential exposure in logs or network traffic.

### What's enabled

- **HTTPS enforcement** — HTTP requests are redirected to HTTPS (loopback exempt)
- **Log redaction** — `password`, `encrypted_password`, `credential_token` fields are stripped from all logged request bodies before they reach any log sink
- **Credential staging token** — password is staged in a separate request and exchanged for a single-use 5-minute token; the token (not the password) travels in the connection creation request

### Configuration

```bash
./db-mcp serve \
  --config-mode=db \
  --db-url=file:./dbmcp.sqlite \
  --secrets-backend=sqlite \
  --secrets-file=./dbmcp-secrets.sqlite \
  --encryption-key=$(openssl rand -hex 32) \
  --security-tier=local \
  --enable-api \
  --port=5000
```

Or via environment variables:

```bash
export DBMCP_CONFIG_MODE=db
export DBMCP_DB_URL=file:./dbmcp.sqlite
export DBMCP_SECRETS_BACKEND=sqlite
export DBMCP_SECRETS_FILE=./dbmcp-secrets.sqlite
export DBMCP_ENCRYPTION_KEY=<32-byte-hex>
export DBMCP_SECURITY_TIER=local
export DBMCP_ENABLE_API=true
```

### Adding a connection (local tier flow)

```
Step 1 — Stage the credential
POST /api/credentials/stage
{ "password": "s3cr3t" }
← { "credential_token": "ctok_a1b2c3...", "expires_at": "..." }

Step 2 — Test with the token (optional but recommended)
POST /api/connections/test
{ "name": "prod-pg", "db_type": "postgres", ..., "credential_token": "ctok_a1b2c3..." }
← { "ok": true, "latency_ms": 42, "server_version": "PostgreSQL 15.2" }

Step 3 — Create (also accepts credential_token)
POST /api/connections
{ "name": "prod-pg", ..., "credential_token": "ctok_a1b2c3..." }
← 201 Created
```

The token is single-use. Step 2 consumes it — if you test first, stage again before creating.

---

## Tier 2 — Enterprise Self-Hosted

**Who uses this:** A company deploys db-mcp internally. The DevOps team runs the
server but should not see DB passwords. Logs ship to Splunk/Datadog.
Compliance frameworks (SOC 2, ISO 27001) require credential separation.

**Threat model:** Tier 1 threats + internal actors with log access + compliance auditors.

**What this adds over Tier 1:**

- **RSA-2048 key pair** generated on startup, private key stays in memory only, never written anywhere
- **Key rotation** every 24 hours, previous key valid for 5-minute overlap window
- **Client-side encryption** — frontend encrypts the password with the server's public key before staging; even the staging request body contains only a ciphertext

### Configuration

```bash
./db-mcp serve \
  --config-mode=db \
  --db-url=postgres://user:pass@host/dbmcp \
  --secrets-backend=gcp \
  --gcp-project=my-project \
  --security-tier=enterprise \
  --enable-api \
  --tls-cert=/etc/tls/cert.pem \
  --tls-key=/etc/tls/key.pem
```

### Fetching the public key (do this once per session, or when key_id changes)

```
GET /api/credentials/public-key
← {
    "key_id": "a1b2c3d4",
    "public_key": "MIIBIjANBgkq...",   ← base64 PKIX DER
    "algorithm": "RSA-OAEP-SHA256",
    "expires_at": "2026-04-06T10:00:00Z"
  }
```

### Encrypting on the frontend (Web Crypto API)

```javascript
async function encryptPassword(publicKeyB64, password) {
  const keyData = Uint8Array.from(atob(publicKeyB64), c => c.charCodeAt(0))
  const publicKey = await crypto.subtle.importKey(
    'spki',
    keyData,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  )
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    new TextEncoder().encode(password)
  )
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)))
}
```

### Adding a connection (enterprise tier flow)

```
Step 1 — Fetch public key
GET /api/credentials/public-key
← { key_id, public_key, algorithm, expires_at }

Step 2 — Encrypt on the client (browser / admin panel)
encrypted = RSA-OAEP-SHA256.encrypt(public_key, password)

Step 3 — Stage the encrypted credential
POST /api/credentials/stage
{ "encrypted_password": "<base64>", "key_id": "a1b2c3d4" }
← { "credential_token": "ctok_...", "expires_at": "..." }

Step 4 — Create connection with token
POST /api/connections
{ "name": "prod-pg", ..., "credential_token": "ctok_..." }
← 201 Created
```

The plaintext password exists only in:
1. The user's browser (typed in the form field)
2. Server memory during RSA decryption (microseconds)
3. The secrets backend

It never appears in any log, any request body captured by a proxy, or any
database row.

### Compliance checklist

| Requirement | How it's met |
|---|---|
| Credentials not in logs | Log redaction middleware strips all sensitive fields |
| Credentials not in transit as plaintext | RSA-OAEP encryption before staging |
| Private key not persisted | Generated in memory, never written to disk |
| Key rotation | Automatic every 24 hours |
| Credentials not in management DB | Only opaque secret reference stored |
| Access revocable | Delete connection → secret deleted from secrets manager |

---

## Tier 3 — SaaS (Option A: You own the secrets manager)

**Who uses this:** You host db-mcp as a service for multiple customers.
Your server must NEVER handle a customer's DB password — not even encrypted.

**Threat model:** All of the above + your own server being a threat to customer credentials.

**What this adds over Tier 2:**

- **Two-phase commit flow** — prepare (metadata only, no password) then confirm
- **Scoped upload token** — server issues a credential that only allows writing one specific secret, expiring in 5 minutes
- **Client writes directly to secrets manager** — browser/client calls GCP/AWS/Azure API directly; your server is never in the data path for the password
- **Server verifies write happened** — before confirming, server checks the secret was actually written

### Architecture

```
Customer's browser
    │
    │ Step 1: metadata only (no password)
    ▼
db-mcp server
    → validates metadata
    → pre-creates secret slot in GCP/AWS/Azure
    → issues scoped 5-min upload token
    ← returns { pending_id, upload_url, upload_token }
    │
    │ Step 2: browser calls cloud API directly
    ▼
GCP Secret Manager / AWS Secrets Manager / Azure Key Vault  (your account)
    ← browser writes password using scoped token
    ← token expires, can never be reused
    │
    │ Step 3: browser confirms with pending_id
    ▼
db-mcp server
    → verifies secret was written (no plaintext returned)
    → saves connection with secret reference
    → reloads Toolbox config
    ← 201 Created
```

### Configuration

```bash
./db-mcp serve \
  --config-mode=db \
  --db-url=postgres://user:pass@host/dbmcp \
  --secrets-backend=gcp \
  --gcp-project=my-project \
  --security-tier=saas \
  --saas-uploader-sa=uploader@my-project.iam.gserviceaccount.com \
  --enable-api
```

### GCP setup (one-time)

```bash
# 1. Create the uploader service account
gcloud iam service-accounts create dbmcp-uploader \
  --display-name="db-mcp Secret Uploader"

# 2. Allow your server's SA to impersonate the uploader SA
gcloud iam service-accounts add-iam-policy-binding \
  dbmcp-uploader@PROJECT.iam.gserviceaccount.com \
  --member="serviceAccount:SERVER_SA@PROJECT.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountTokenCreator"

# 3. When each secret is pre-created, bind the uploader SA to it:
#    (db-mcp does this automatically when handling prepare)
gcloud secrets add-iam-policy-binding SECRET_NAME \
  --member="serviceAccount:dbmcp-uploader@PROJECT.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretVersionAdder" \
  --condition="expression=resource.name=='projects/PROJECT/secrets/SECRET_NAME',title=single-secret"

# 4. Your server SA needs to read secrets (for Toolbox source init only)
gcloud projects add-iam-policy-binding PROJECT \
  --member="serviceAccount:SERVER_SA@PROJECT.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### AWS setup (one-time)

```bash
# 1. Create the uploader role
aws iam create-role --role-name dbmcp-uploader \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::ACCOUNT:role/SERVER_ROLE" },
      "Action": "sts:AssumeRole"
    }]
  }'

# No permissions on the role itself — they come from the session policy
# which db-mcp generates per-secret at issue time.
```

### Adding a connection (SaaS tier flow)

```
Step 1 — Prepare (no password sent)
POST /api/connections/prepare
{
  "name": "prod-pg",
  "db_type": "postgres",
  "host": "db.customer.com",
  "port": 5432,
  "database": "production",
  "username": "readonly"
}
← {
    "pending_id": "pnd_a1b2c3...",
    "secret_name": "dbmcp/prod-pg",
    "upload_url": "https://secretmanager.googleapis.com/v1/.../secrets/dbmcp-prod-pg:addVersion",
    "upload_token": { "access_token": "ya29.short-lived-token" },
    "expires_at": "2026-04-05T10:10:00Z"
  }

Step 2 — Browser writes password directly to GCP (server not involved)
POST https://secretmanager.googleapis.com/v1/.../secrets/dbmcp-prod-pg:addVersion
Authorization: Bearer ya29.short-lived-token
{ "payload": { "data": "<base64(password)>" } }
← { "name": "...versions/1" }

Step 3 — Confirm
POST /api/connections/confirm
{ "pending_id": "pnd_a1b2c3..." }
← 201 Created  { id, name, mcp_endpoint, ... }
```

### What your server sees

| Step | Sees password? |
|---|---|
| Prepare | No |
| Upload (browser → GCP) | No — not involved |
| Confirm | No — only verifies secret exists |
| Toolbox source init | Yes, briefly in memory — fetched from secrets manager |

The only time the password is in your server's memory is when Toolbox initialises
the DB connection pool. It is never in a request body, never in a log, and never
in a database row.

---

## Choosing a Secrets Backend per Tier

| Tier | Recommended backend |
|---|---|
| Local | `sqlite` — encrypted SQLite file |
| Enterprise self-hosted | `gcp` / `aws` / `azure` matching your cloud |
| SaaS | `gcp` / `aws` / `azure` — you own the secrets manager account |

---

## Security Flag Reference

| Flag | Env var | Values | Description |
|---|---|---|---|
| `--security-tier` | `DBMCP_SECURITY_TIER` | `local`, `enterprise`, `saas` | Activates the appropriate security features |
| `--tls-cert` | `DBMCP_TLS_CERT` | file path | TLS certificate for HTTPS |
| `--tls-key` | `DBMCP_TLS_KEY` | file path | TLS private key for HTTPS |
| `--tls-redirect` | `DBMCP_TLS_REDIRECT` | bool | Redirect HTTP → HTTPS |
| `--saas-uploader-sa` | `DBMCP_SAAS_UPLOADER_SA` | SA email / role ARN | Identity used to issue scoped upload tokens |

---

## What Is Never Stored

Regardless of tier, db-mcp guarantees:

- Plaintext passwords are **never written to the management database**
- Plaintext passwords are **never written to any log**
- Plaintext passwords are **never present in any API response**
- The RSA private key (enterprise+) is **never written to disk**
- Scoped upload tokens (SaaS) are **single-use and expire in 5 minutes**
