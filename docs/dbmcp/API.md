# DB-MCP API Reference

Complete reference for all REST endpoints exposed by the DB-MCP server.
The interactive version of this document is served at runtime at `http://localhost:5001/docs`.

---

## Table of Contents

1. [Overview](#overview)
2. [Base URL & Conventions](#base-url--conventions)
3. [Security Tiers](#security-tiers)
4. [Credential Staging](#credential-staging)
   - [POST /api/credentials/stage](#post-apicredentialsstage)
   - [GET /api/credentials/public-key](#get-apicredentialspublic-key)
5. [Connection Management](#connection-management)
   - [GET /api/connections](#get-apiconnections)
   - [POST /api/connections](#post-apiconnections)
   - [GET /api/connections/:id](#get-apiconnectionsid)
   - [PUT /api/connections/:id](#put-apiconnectionsid)
   - [DELETE /api/connections/:id](#delete-apiconnectionsid)
   - [POST /api/connections/test](#post-apiconnectionstest)
   - [POST /api/connections/:id/test](#post-apiconnectionsidtest)
   - [POST /api/connections/reload](#post-apiconnectionsreload)
6. [SaaS Two-Phase Flow](#saas-two-phase-flow)
   - [POST /api/connections/prepare](#post-apiconnectionsprepare)
   - [POST /api/connections/confirm](#post-apiconnectionsconfirm)
7. [MCP Endpoints](#mcp-endpoints)
8. [Error Responses](#error-responses)
9. [End-to-End Examples by Tier](#end-to-end-examples-by-tier)

---

## Overview

The DB-MCP server exposes a single port that serves three things simultaneously:

| Path prefix | Purpose |
|-------------|---------|
| `/api/credentials/` | Secure credential staging |
| `/api/connections/` | Connection lifecycle management |
| `/mcp/{name}` | Live MCP endpoint per connection |
| `/docs` | Scalar interactive API UI |
| `/openapi.yaml` | Raw OpenAPI 3.1 spec |

Connections are **not stored in config files**. They live in a SQLite or Postgres management database. Each connection you create immediately gets a live MCP endpoint — no restart required.

Passwords are **never stored in the management database**. Only an opaque reference to the secrets backend is stored.

---

## Base URL & Conventions

```
http://localhost:5001
```

- All request and response bodies are `application/json`
- All timestamps are RFC3339 UTC
- All IDs are UUID v4
- Test endpoints always return HTTP 200 — inspect the `ok` field for pass/fail
- Mutation endpoints (POST/PUT/DELETE) automatically reload the MCP config

---

## Security Tiers

The server runs in one of three security tiers set via `--security-tier`. The tier determines how credentials travel from the client to the secrets backend.

### Local (default — `--security-tier=local`)

Best for: development, self-hosted single-user deployments.

```
Client → POST /api/credentials/stage { password: "..." }
       ← { credential_token: "ctok_..." }          (5-min single-use)

Client → POST /api/connections { credential_token: "ctok_..." }
       ← Connection created, /mcp/{name} live
```

The password travels in plaintext over HTTPS once (to `/api/credentials/stage`).
It is stored in an AES-256-GCM encrypted SQLite file on disk — never in the management DB.

### Enterprise (`--security-tier=enterprise`)

Best for: on-premise / private cloud, multiple operators.

```
Client → GET /api/credentials/public-key
       ← { key_id, public_key_pem }               (RSA-4096)

Client  encrypts password locally with RSA-OAEP+SHA256
Client → POST /api/credentials/stage { encrypted_password, key_id }
       ← { credential_token: "ctok_..." }          (5-min single-use)

Client → POST /api/connections { credential_token: "ctok_..." }
       ← Connection created
```

The password never travels in plaintext over the network.
The server decrypts the RSA ciphertext in memory, stages it, then routes it to the secrets backend.

### SaaS (`--security-tier=saas`)

Best for: multi-tenant hosted service. The server **never sees the plaintext password**.

```
Client → POST /api/connections/prepare { name, db_type, host, ... }
       ← { pending_id, upload_url, upload_token, secret_name }

Client  writes password DIRECTLY to secrets manager using upload_token
        (e.g. GCP Secret Manager, AWS Secrets Manager, Azure Key Vault)

Client → POST /api/connections/confirm { pending_id }
       ← Connection created, /mcp/{name} live
```

The upload token is short-lived (5 min) and scoped to a single secret.

---

## Credential Staging

### POST /api/credentials/stage

Stage a database password and receive a short-lived single-use token.
Use the token in place of the raw password in any connection endpoint.

**Available in:** local, enterprise tiers (not needed in SaaS — use prepare/confirm instead).

#### Local tier request

```http
POST /api/credentials/stage
Content-Type: application/json

{
  "password": "myS3cureP@ss"
}
```

#### Enterprise tier request

```http
POST /api/credentials/stage
Content-Type: application/json

{
  "encrypted_password": "base64EncodedRSAOAEPCiphertext==",
  "key_id": "kid-2026-01"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `password` | string | local only | Plaintext password (over HTTPS) |
| `encrypted_password` | string | enterprise only | RSA-OAEP+SHA256 encrypted password, base64-encoded |
| `key_id` | string | enterprise only | Key ID from `GET /api/credentials/public-key` |

#### Response `200 OK`

```json
{
  "credential_token": "ctok_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "expires_at": "2026-04-07T06:35:00Z",
  "note": "single-use, expires in 5 minutes — use immediately in POST /api/connections or POST /api/connections/test"
}
```

| Field | Description |
|-------|-------------|
| `credential_token` | Pass this as `credential_token` in any connection call |
| `expires_at` | Token expires at this time — use it immediately |

**Errors**

| Code | Reason |
|------|--------|
| `400` | Missing or empty password / encrypted_password |
| `400` | `encrypted_password` sent but `--security-tier` is not enterprise |
| `500` | Token generation failed |

---

### GET /api/credentials/public-key

Get the server's RSA-4096 public key for encrypting passwords client-side.

**Available in:** enterprise tier only.

```http
GET /api/credentials/public-key
```

#### Response `200 OK`

```json
{
  "key_id": "kid-2026-01",
  "algorithm": "RSA-OAEP-SHA256",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
  "key_size_bits": 4096
}
```

**Encrypting with Python:**

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

with open("pubkey.pem", "wb") as f:
    f.write(public_key_pem.encode())

with open("pubkey.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read())

ciphertext = pub_key.encrypt(
    b"myS3cureP@ss",
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
encrypted_b64 = base64.b64encode(ciphertext).decode()
```

**Errors**

| Code | Reason |
|------|--------|
| `404` | Enterprise tier not enabled |

---

## Connection Management

### GET /api/connections

List all saved connections. Passwords and secret references are never returned.

```http
GET /api/connections
```

#### Response `200 OK`

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "prod-postgres",
    "db_type": "postgres",
    "host": "db.example.com",
    "port": 5432,
    "database": "myapp",
    "username": "app_user",
    "ssl_mode": "require",
    "description": "Production Postgres",
    "mcp_endpoint": "http://localhost:5001/mcp/prod-postgres",
    "last_tested_at": "2026-04-07T06:00:00Z",
    "last_test_ok": true,
    "created_at": "2026-04-07T05:00:00Z",
    "updated_at": "2026-04-07T05:00:00Z"
  }
]
```

Returns `[]` when no connections exist.

---

### POST /api/connections

Create a new connection. The server runs a connectivity test before saving anything.
On success, the MCP endpoint at `/mcp/{name}` goes live immediately.

**Credential resolution order:** `credential_token` → `password`

```http
POST /api/connections
Content-Type: application/json

{
  "name": "prod-postgres",
  "db_type": "postgres",
  "host": "db.example.com",
  "port": 5432,
  "database": "myapp",
  "username": "app_user",
  "credential_token": "ctok_a1b2c3d4e5f6...",
  "ssl_mode": "require",
  "description": "Production Postgres"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique name. Pattern: `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$` |
| `db_type` | string | yes | `postgres`, `mysql`, or `mssql` |
| `host` | string | yes | Hostname or IP |
| `port` | integer | yes | 1–65535 |
| `database` | string | yes | Database name |
| `username` | string | yes | Database username |
| `credential_token` | string | yes* | Single-use token from `/api/credentials/stage` (preferred) |
| `password` | string | yes* | Plaintext password (local tier only, avoid in production) |
| `ssl_mode` | string | no | `disable`, `require` (default), `verify-full` |
| `description` | string | no | Human-readable description |

*One of `credential_token` or `password` is required.

**Save flow:**
```
Validate input → Check name uniqueness → Resolve password →
Test connectivity → Store secret → Insert DB row → Reload MCP config → 201
```
If connectivity fails, nothing is saved and the token is consumed.

#### Response `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "prod-postgres",
  "db_type": "postgres",
  "host": "db.example.com",
  "port": 5432,
  "database": "myapp",
  "username": "app_user",
  "ssl_mode": "require",
  "description": "Production Postgres",
  "mcp_endpoint": "http://localhost:5001/mcp/prod-postgres",
  "last_tested_at": "2026-04-07T06:00:00Z",
  "last_test_ok": true,
  "created_at": "2026-04-07T06:00:00Z",
  "updated_at": "2026-04-07T06:00:00Z"
}
```

**Errors**

| Code | Reason |
|------|--------|
| `400` | Invalid JSON or missing required field |
| `409` | A connection named `{name}` already exists |
| `422` | Connectivity test failed — see `test_result` in response body |
| `500` | Secret storage or DB insert failed |

**422 body (connectivity failed):**

```json
{
  "error": "connection test failed — credentials not saved",
  "test_result": {
    "ok": false,
    "latency_ms": null,
    "message": "dial tcp db.example.com:5432: connection refused"
  }
}
```

---

### GET /api/connections/:id

Fetch a single connection by UUID.

```http
GET /api/connections/550e8400-e29b-41d4-a716-446655440000
```

#### Response `200 OK`

Same shape as a single item from `GET /api/connections`.

**Errors**

| Code | Reason |
|------|--------|
| `404` | Connection not found |

---

### PUT /api/connections/:id

Partially update a connection. Only provided fields are changed.
If a new password is supplied (via `credential_token` or `password`), it is rotated
in the secrets backend. The updated connection is tested before any changes are committed.

```http
PUT /api/connections/550e8400-e29b-41d4-a716-446655440000
Content-Type: application/json

{
  "host": "new-db.example.com",
  "credential_token": "ctok_newtoken..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `host` | string | New hostname |
| `port` | integer | New port |
| `database` | string | New database name |
| `username` | string | New username |
| `credential_token` | string | Rotate password via staged token |
| `password` | string | Rotate password directly (local tier only) |
| `ssl_mode` | string | New SSL mode |
| `description` | string | New description |

All fields are optional. Send only what you want to change.

**Update flow:**
```
Load existing → Apply changes → Resolve test password →
Test connectivity → Rotate secret (if new password) → Update DB row → Reload MCP → 200
```
If the test fails, nothing is changed.

#### Response `200 OK`

Updated connection (same shape as GET).

**Errors**

| Code | Reason |
|------|--------|
| `400` | Invalid JSON |
| `404` | Connection not found |
| `422` | Connectivity test failed — no changes saved |
| `500` | Secret rotation or DB update failed |

---

### DELETE /api/connections/:id

Delete a connection. Removes the secret from the secrets backend, removes the DB row,
and immediately removes the `/mcp/{name}` endpoint.

```http
DELETE /api/connections/550e8400-e29b-41d4-a716-446655440000
```

#### Response `200 OK`

```json
{
  "deleted": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Errors**

| Code | Reason |
|------|--------|
| `404` | Connection not found |

> Note: If secret deletion fails, the error is logged but the DB row is still removed.
> A failed secret delete leaves an orphaned secret in the backend but does not leave the
> connection appearing active.

---

### POST /api/connections/test

Pre-save connectivity test. Tests credentials without saving or persisting anything.
Use this for a "Test Connection" button before the user confirms saving.

Always returns HTTP 200 — inspect the `ok` field.

```http
POST /api/connections/test
Content-Type: application/json

{
  "name": "prod-postgres",
  "db_type": "postgres",
  "host": "db.example.com",
  "port": 5432,
  "database": "myapp",
  "username": "app_user",
  "credential_token": "ctok_a1b2c3d4e5f6..."
}
```

Same body as `POST /api/connections`.

#### Response `200 OK`

```json
{
  "ok": true,
  "latency_ms": 12,
  "server_version": "PostgreSQL 16.2 on aarch64-unknown-linux-gnu",
  "message": "connection successful"
}
```

| Field | Description |
|-------|-------------|
| `ok` | `true` = test passed |
| `latency_ms` | Round-trip time in milliseconds (null if connection failed before completing) |
| `server_version` | Database server version string (when available) |
| `message` | Human-readable result or error message |

**Failure example:**

```json
{
  "ok": false,
  "latency_ms": null,
  "server_version": "",
  "message": "pq: password authentication failed for user \"app_user\""
}
```

---

### POST /api/connections/:id/test

Re-test an existing saved connection using its stored credentials.
Updates `last_tested_at` and `last_test_ok` on the connection record.
Does NOT modify the connection config or trigger a reload.

Always returns HTTP 200 — inspect the `ok` field.

```http
POST /api/connections/550e8400-e29b-41d4-a716-446655440000/test
```

No request body required.

#### Response `200 OK`

Same shape as `POST /api/connections/test`.

**Errors**

| Code | Reason |
|------|--------|
| `404` | Connection not found |
| `500` | Failed to fetch credentials from secrets backend |

---

### POST /api/connections/reload

Force a full config reload from the management database.
Normally this happens automatically after every mutation.
Use this for manual recovery if an automatic reload fails.

```http
POST /api/connections/reload
```

No request body required.

#### Response `200 OK`

```json
{
  "ok": true,
  "connections_reloaded": 5
}
```

**Errors**

| Code | Reason |
|------|--------|
| `500` | DB read failed or Toolbox config rebuild failed |

---

## SaaS Two-Phase Flow

Available only when `--security-tier=saas`. The server never receives the plaintext password.

### POST /api/connections/prepare

Phase 1: validate metadata, pre-create the secret slot, issue a scoped upload token.

```http
POST /api/connections/prepare
Content-Type: application/json

{
  "name": "prod-postgres",
  "db_type": "postgres",
  "host": "db.example.com",
  "port": 5432,
  "database": "myapp",
  "username": "app_user",
  "ssl_mode": "require",
  "description": "Production Postgres"
}
```

Same fields as `POST /api/connections` except **no password or credential_token** — they will never be sent to this server.

#### Response `200 OK`

```json
{
  "pending_id": "pnd_a1b2c3d4e5f6a7b8",
  "secret_name": "projects/my-project/secrets/dbmcp-prod-postgres",
  "upload_url": "https://secretmanager.googleapis.com/v1/projects/my-project/secrets/dbmcp-prod-postgres:addVersion",
  "upload_token": {
    "access_token": "ya29.short-lived-gcp-token"
  },
  "expires_at": "2026-04-07T06:10:00Z",
  "instructions": "Write your database password to https://... using the upload_token credentials. Then call POST /api/connections/confirm with pending_id within 10m. Provider: gcp. The server will never see your plaintext password."
}
```

| Field | Description |
|-------|-------------|
| `pending_id` | Pass to `POST /api/connections/confirm` |
| `secret_name` | The secret resource name in the secrets manager |
| `upload_url` | The exact API URL to write the password to |
| `upload_token` | Provider-specific credentials for that one write operation |
| `expires_at` | Must confirm before this time (10 min window) |
| `instructions` | Human-readable steps |

**upload_token fields by provider:**

| Provider | Fields |
|----------|--------|
| GCP | `access_token` |
| AWS | `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`, `aws_region` |
| Azure | `azure_token`, `azure_vault_url` |

**Writing to GCP Secret Manager with the upload token:**

```bash
curl -X POST "$UPLOAD_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"payload\":{\"data\":\"$(echo -n 'myS3cureP@ss' | base64)\"}}"
```

**Errors**

| Code | Reason |
|------|--------|
| `404` | SaaS tier not enabled |
| `409` | Connection name already exists |
| `422` | Validation failed |
| `500` | Secret slot pre-creation failed |

---

### POST /api/connections/confirm

Phase 2: verify the secret was written, save the connection, make MCP endpoint live.

Must be called within 10 minutes of `POST /api/connections/prepare`.

```http
POST /api/connections/confirm
Content-Type: application/json

{
  "pending_id": "pnd_a1b2c3d4e5f6a7b8"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `pending_id` | yes | From the prepare response |

#### Response `201 Created`

Full connection object (same shape as `POST /api/connections` response).

**Errors**

| Code | Reason |
|------|--------|
| `400` | `pending_id` missing, not found, or expired |
| `422` | Secret not found in secrets manager — password was not written |
| `500` | DB insert or MCP reload failed |

---

## MCP Endpoints

Each saved connection automatically gets an MCP endpoint:

```
/mcp/{connection-name}
```

Supports both SSE (`text/event-stream`) and streamable HTTP transports.

**Available tools per `db_type`:**

| db_type | Tool |
|---------|------|
| `postgres` | `execute_sql` |
| `mysql` | `execute_sql` |
| `mssql` | `execute_sql` |

**Connecting Claude Desktop:**

```json
{
  "mcpServers": {
    "prod-postgres": {
      "url": "http://localhost:5001/mcp/prod-postgres"
    }
  }
}
```

**Connecting Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "prod-postgres": {
      "url": "http://localhost:5001/mcp/prod-postgres"
    }
  }
}
```

---

## Error Responses

All error responses use this shape:

```json
{
  "status": "Not Found",
  "error": "not found"
}
```

| Field | Description |
|-------|-------------|
| `status` | HTTP status text |
| `error` | Machine-readable error detail |

---

## End-to-End Examples by Tier

### Local tier — full flow

```bash
BASE="http://localhost:5001"

# 1. Stage the password
TOKEN=$(curl -s -X POST $BASE/api/credentials/stage \
  -H "Content-Type: application/json" \
  -d '{"password":"myS3cureP@ss"}' | jq -r .credential_token)

echo "Token: $TOKEN"

# 2. Test before saving (optional but recommended)
curl -s -X POST $BASE/api/connections/test \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":\"prod-postgres\",
    \"db_type\":\"postgres\",
    \"host\":\"db.example.com\",
    \"port\":5432,
    \"database\":\"myapp\",
    \"username\":\"app_user\",
    \"credential_token\":\"$TOKEN\"
  }" | jq .

# 3. Save (token is now consumed — stage again if test was called above)
TOKEN=$(curl -s -X POST $BASE/api/credentials/stage \
  -H "Content-Type: application/json" \
  -d '{"password":"myS3cureP@ss"}' | jq -r .credential_token)

curl -s -X POST $BASE/api/connections \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":\"prod-postgres\",
    \"db_type\":\"postgres\",
    \"host\":\"db.example.com\",
    \"port\":5432,
    \"database\":\"myapp\",
    \"username\":\"app_user\",
    \"credential_token\":\"$TOKEN\",
    \"ssl_mode\":\"require\",
    \"description\":\"Production Postgres\"
  }" | jq .

# 4. MCP endpoint is now live
curl -s $BASE/api/connections | jq '.[0].mcp_endpoint'
# → "http://localhost:5001/mcp/prod-postgres"

# 5. Re-test an existing connection
ID=$(curl -s $BASE/api/connections | jq -r '.[0].id')
curl -s -X POST $BASE/api/connections/$ID/test | jq .

# 6. Update host (password stays the same)
curl -s -X PUT $BASE/api/connections/$ID \
  -H "Content-Type: application/json" \
  -d '{"host":"new-db.example.com"}' | jq .

# 7. Delete
curl -s -X DELETE $BASE/api/connections/$ID | jq .
```

---

### Enterprise tier — full flow

```bash
BASE="https://localhost:5001"

# 1. Get public key
curl -s $BASE/api/credentials/public-key | jq .

# 2. Encrypt password client-side (Python)
python3 <<'EOF'
import requests, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

resp = requests.get("https://localhost:5001/api/credentials/public-key", verify=False).json()
pub_pem = resp["public_key_pem"].encode()
key_id  = resp["key_id"]

pub_key = serialization.load_pem_public_key(pub_pem)
ciphertext = pub_key.encrypt(
    b"myS3cureP@ss",
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
print(f'key_id={key_id}')
print(f'encrypted={base64.b64encode(ciphertext).decode()}')
EOF

# 3. Stage encrypted password
TOKEN=$(curl -s -X POST $BASE/api/credentials/stage \
  -H "Content-Type: application/json" \
  -d "{\"encrypted_password\":\"<base64>\",\"key_id\":\"kid-2026-01\"}" | jq -r .credential_token)

# 4. Create connection (identical to local tier from here)
curl -s -X POST $BASE/api/connections \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":\"prod-postgres\",
    \"db_type\":\"postgres\",
    \"host\":\"db.example.com\",
    \"port\":5432,
    \"database\":\"myapp\",
    \"username\":\"app_user\",
    \"credential_token\":\"$TOKEN\"
  }" | jq .
```

---

### SaaS tier — full flow (GCP)

```bash
BASE="https://localhost:5001"

# Phase 1 — prepare
PREP=$(curl -s -X POST $BASE/api/connections/prepare \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-postgres",
    "db_type": "postgres",
    "host": "db.example.com",
    "port": 5432,
    "database": "myapp",
    "username": "app_user"
  }')

PENDING_ID=$(echo $PREP | jq -r .pending_id)
UPLOAD_URL=$(echo $PREP | jq -r .upload_url)
ACCESS_TOKEN=$(echo $PREP | jq -r .upload_token.access_token)

echo "Pending: $PENDING_ID"
echo "Upload to: $UPLOAD_URL"

# Write password directly to GCP Secret Manager (server never sees this)
curl -s -X POST "$UPLOAD_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"payload\":{\"data\":\"$(echo -n 'myS3cureP@ss' | base64)\"}}"

# Phase 2 — confirm
curl -s -X POST $BASE/api/connections/confirm \
  -H "Content-Type: application/json" \
  -d "{\"pending_id\":\"$PENDING_ID\"}" | jq .

# MCP endpoint is now live — server never saw the password
```
