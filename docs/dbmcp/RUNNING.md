# Running DB-MCP

This document covers how to build, configure, and run the DB-MCP server in all three
security tiers (local, enterprise, SaaS). The server is a single binary that exposes:

- **MCP endpoints** at `/mcp/{connection-name}` — one per saved database connection
- **REST API** at `/api/connections/` — connection CRUD, test, reload
- **API docs** at `/docs` — interactive Scalar UI (always available)
- **OpenAPI spec** at `/openapi.yaml`

---

## 1. Build

```bash
cd fork/

# Install Go 1.26 via Homebrew if you haven't already
brew install go

# Build the binary
go build -o toolbox .

# Verify
./toolbox --help
```

---

## 2. Quick Reference — All Flags

### Core server flags (always available)

| Flag | Default | Description |
|------|---------|-------------|
| `--address` | `127.0.0.1` | Interface to listen on |
| `--port` | `5000` | Port to listen on |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--log-format` | `standard` | Log format: `standard`, `structured` |
| `--ui` | `false` | Enable the Toolbox web UI at `/ui` |
| `--allowed-origins` | `""` | Comma-separated CORS allowed origins |
| `--telemetry-gcp` | `false` | Enable GCP Cloud Trace/Metrics exporter |
| `--telemetry-otlp` | `""` | OTLP collector URL for traces/metrics |

### File mode flags (--config-mode=file, the default upstream behaviour)

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `tools.yaml` | Path to the YAML config file |
| `--disable-reload` | `false` | Disable hot-reload of `tools.yaml` |
| `--poll-interval` | `0` | Config poll interval in seconds (0 = watch) |

### DB mode flags (--config-mode=db)

| Flag | Default | Description |
|------|---------|-------------|
| `--config-mode` | `file` | Set to `db` to enable DB-backed connection management |
| `--security-tier` | `local` | `local`, `enterprise`, or `saas` |
| `--db-url` | `file:./dbmcp.sqlite?_journal_mode=WAL` | Management database DSN (SQLite or Postgres) |
| `--secrets-backend` | `sqlite` | Secrets provider: `sqlite`, `gcp`, `aws`, `azure` |
| `--secrets-file` | `./dbmcp-secrets.sqlite` | SQLite secrets DB path (`sqlite` backend only) |
| `--encryption-key` | `""` | 32-byte hex AES-256-GCM key (`sqlite` backend only) |
| `--gcp-project` | `""` | GCP project ID (`gcp` backend only) |
| `--aws-region` | `""` | AWS region (`aws` backend only) |
| `--azure-keyvault-url` | `""` | Azure Key Vault URL (`azure` backend only) |
| `--saas-uploader-sa` | `""` | Uploader service account email/ARN (`saas` tier only) |
| `--tls-cert` | `""` | Path to TLS certificate file |
| `--tls-key` | `""` | Path to TLS private key file |

---

## 3. Security Tiers

### Tier 1 — Local (default, for development / self-hosted)

Plaintext passwords are sent over HTTPS to a staging endpoint and exchanged for
a short-lived single-use token. The token is passed to the connection API.
**Always run behind HTTPS in production.**

```bash
# Generate a 32-byte encryption key for the SQLite secrets store
openssl rand -hex 32
# → e.g. a3f1c2d4e5b6a7f8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

./toolbox serve \
  --config-mode=db \
  --security-tier=local \
  --port=5000 \
  --db-url="file:./dbmcp.sqlite?_journal_mode=WAL" \
  --secrets-backend=sqlite \
  --secrets-file=./dbmcp-secrets.sqlite \
  --encryption-key=a3f1c2d4e5b6a7f8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

**Add a connection:**
```bash
# Step 1 — stage the password
TOKEN=$(curl -s -X POST http://localhost:5000/api/credentials/stage \
  -H "Content-Type: application/json" \
  -d '{"password":"myS3cureP@ss"}' | jq -r .credential_token)

# Step 2 — create the connection (test runs automatically)
curl -X POST http://localhost:5000/api/connections \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"prod-postgres\",
    \"db_type\": \"postgres\",
    \"host\": \"db.example.com\",
    \"port\": 5432,
    \"database\": \"myapp\",
    \"username\": \"app_user\",
    \"credential_token\": \"$TOKEN\",
    \"ssl_mode\": \"require\"
  }"

# Your MCP endpoint is now live:
# http://localhost:5000/mcp/prod-postgres
```

---

### Tier 2 — Enterprise (on-premise / private cloud)

Clients encrypt the password locally with the server's RSA-4096 public key
(OAEP+SHA256) before sending it. The server decrypts and stages it in memory.
Credentials never travel in plaintext over the network.

```bash
./toolbox serve \
  --config-mode=db \
  --security-tier=enterprise \
  --port=5000 \
  --db-url="postgres://dbmcp:secret@db-host/dbmcp_mgmt" \
  --secrets-backend=gcp \
  --gcp-project=my-gcp-project \
  --tls-cert=/etc/ssl/certs/server.crt \
  --tls-key=/etc/ssl/private/server.key
```

**Add a connection:**
```bash
# Step 1 — get the server's RSA public key
curl https://localhost:5000/api/credentials/public-key

# Step 2 — encrypt the password client-side (Python example)
python3 - <<'EOF'
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64, json

with open("pubkey.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read())

ciphertext = pub_key.encrypt(
    b"myS3cureP@ss",
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
print(json.dumps({"encrypted_password": base64.b64encode(ciphertext).decode(), "key_id": "kid-2026-01"}))
EOF

# Step 3 — stage the encrypted password
TOKEN=$(curl -s -X POST https://localhost:5000/api/credentials/stage \
  -H "Content-Type: application/json" \
  -d '{"encrypted_password":"<base64>","key_id":"kid-2026-01"}' | jq -r .credential_token)

# Step 4 — create the connection
curl -X POST https://localhost:5000/api/connections \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"prod-postgres\",\"db_type\":\"postgres\",\"host\":\"db.example.com\",\"port\":5432,\"database\":\"myapp\",\"username\":\"app_user\",\"credential_token\":\"$TOKEN\"}"
```

---

### Tier 3 — SaaS (you host, customers bring their own secrets manager)

The server **never sees the plaintext password**. The client writes the password
directly to their own secrets manager using a short-lived scoped token issued by the server.

> **Note:** The GCP scoped token issuer is functional but uses a placeholder access token.
> Wire in `google.golang.org/api/iamcredentials/v1` for production use.

```bash
./toolbox serve \
  --config-mode=db \
  --security-tier=saas \
  --port=5000 \
  --db-url="postgres://dbmcp:secret@db-host/dbmcp_mgmt" \
  --secrets-backend=gcp \
  --gcp-project=my-gcp-project \
  --saas-uploader-sa=uploader@my-project.iam.gserviceaccount.com \
  --tls-cert=/etc/ssl/certs/server.crt \
  --tls-key=/etc/ssl/private/server.key
```

**Add a connection (two-phase flow):**
```bash
# Phase 1 — prepare (server never sees the password)
PREPARE=$(curl -s -X POST https://localhost:5000/api/connections/prepare \
  -H "Content-Type: application/json" \
  -d '{"name":"prod-postgres","db_type":"postgres","host":"db.example.com","port":5432,"database":"myapp","username":"app_user"}')

PENDING_ID=$(echo $PREPARE | jq -r .pending_id)
UPLOAD_URL=$(echo $PREPARE | jq -r .upload_url)
ACCESS_TOKEN=$(echo $PREPARE | jq -r .upload_token.access_token)

# Phase 2a — write the password directly to GCP Secret Manager
curl -X POST "$UPLOAD_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"payload":{"data":"'$(echo -n "myS3cureP@ss" | base64)'"}}'

# Phase 2b — confirm
curl -X POST https://localhost:5000/api/connections/confirm \
  -H "Content-Type: application/json" \
  -d "{\"pending_id\":\"$PENDING_ID\"}"

# MCP endpoint is now live:
# https://localhost:5000/mcp/prod-postgres
```

---

## 4. Using GCP Secret Manager (--secrets-backend=gcp)

### Authentication

The server uses Application Default Credentials (ADC):

```bash
# Local development
gcloud auth application-default login

# On GCE / GKE / Cloud Run — the attached service account is used automatically
```

### Required IAM roles on the service account

| Role | Purpose |
|------|---------|
| `roles/secretmanager.secretAccessor` | Read secrets (used at startup and on each MCP request) |
| `roles/secretmanager.secretVersionAdder` | Create new secret versions (on connection create/update) |
| `roles/secretmanager.secretDeleter` | Delete secrets (on connection delete) |

```bash
# Grant all three roles
SA="my-service-account@my-project.iam.gserviceaccount.com"
PROJECT="my-gcp-project"

gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA" \
  --role="roles/secretmanager.secretAccessor"

gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA" \
  --role="roles/secretmanager.secretVersionAdder"

gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA" \
  --role="roles/secretmanager.secretDeleter"
```

---

## 5. Using Postgres as the Management Database

```bash
# Create the management database
createdb dbmcp_mgmt
psql dbmcp_mgmt -c "CREATE USER dbmcp WITH PASSWORD 'secret';"
psql dbmcp_mgmt -c "GRANT ALL ON DATABASE dbmcp_mgmt TO dbmcp;"

# Pass the DSN
./toolbox serve \
  --config-mode=db \
  --db-url="postgres://dbmcp:secret@localhost/dbmcp_mgmt?sslmode=require"
```

The server creates the `connections` table automatically on first run.

---

## 6. API Documentation

Once the server is running, open:

```
http://localhost:5000/docs
```

This is the interactive Scalar API reference UI. Every endpoint is documented with
request/response schemas and a live "Try it out" button.

The raw OpenAPI 3.1 spec is at:
```
http://localhost:5000/openapi.yaml
```

---

## 7. Connecting an MCP Client

Once you have created at least one connection, point your MCP client at:

```
http://localhost:5000/mcp/{connection-name}
```

### Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "prod-postgres": {
      "url": "http://localhost:5000/mcp/prod-postgres"
    }
  }
}
```

### Cursor (`.cursor/mcp.json` in project root)

```json
{
  "mcpServers": {
    "prod-postgres": {
      "url": "http://localhost:5000/mcp/prod-postgres"
    }
  }
}
```

---

## 8. Environment Variables

All flags can also be set via environment variables by uppercasing and replacing
hyphens with underscores, prefixed with `TOOLBOX_`:

| Flag | Environment variable |
|------|---------------------|
| `--config-mode` | `TOOLBOX_CONFIG_MODE` |
| `--security-tier` | `TOOLBOX_SECURITY_TIER` |
| `--db-url` | `TOOLBOX_DB_URL` |
| `--secrets-backend` | `TOOLBOX_SECRETS_BACKEND` |
| `--encryption-key` | `TOOLBOX_ENCRYPTION_KEY` |
| `--gcp-project` | `TOOLBOX_GCP_PROJECT` |
| `--port` | `TOOLBOX_PORT` |

---

## 9. Complete Docker Example

```dockerfile
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY fork/ .
RUN go build -o toolbox .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/toolbox .
EXPOSE 5000
ENTRYPOINT ["./toolbox", "serve"]
```

```bash
docker build -t dbmcp .
docker run -p 5000:5000 \
  -e TOOLBOX_CONFIG_MODE=db \
  -e TOOLBOX_SECURITY_TIER=local \
  -e TOOLBOX_SECRETS_BACKEND=gcp \
  -e TOOLBOX_GCP_PROJECT=my-project \
  dbmcp
```
