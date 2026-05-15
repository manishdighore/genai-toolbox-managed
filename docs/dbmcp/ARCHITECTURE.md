# Architecture

This document describes exactly what changes from upstream genai-toolbox, what stays the same, and why every decision was made.

---

## Guiding Principle

**Touch as little of upstream as possible.**

The upstream codebase already has the MCP server, 42+ DB drivers, connection pooling, routing, and observability. The goal is to slot a management layer into the existing structure — not replace it.

`InitializeConfigs()` in `internal/server/server.go` accepts a `ServerConfig` struct containing maps of source/tool/toolset configs. It does not care where those maps came from. Today they come from YAML. We make them come from a database instead. That is the core of the change.

---

## Repository Layout After Changes

```
fork/
├── main.go                              UNCHANGED
├── cmd/
│   ├── root.go                          UNCHANGED
│   └── internal/
│       ├── config.go                    MODIFIED — add LoadFromDB()
│       ├── flags.go                     MODIFIED — add new CLI flags
│       ├── options.go                   UNCHANGED
│       └── serve/
│           └── command.go              MODIFIED — wire DB mode + secrets provider
│
├── internal/
│   ├── server/
│   │   ├── server.go                   MODIFIED — accept SecretsProvider + ConnStore
│   │   ├── api.go                      MODIFIED — add /api/connections/* routes
│   │   └── config.go                   UNCHANGED
│   │
│   ├── connections/                    NEW PACKAGE
│   │   ├── store.go                    DB CRUD — add/get/list/update/delete connections
│   │   ├── models.go                   Connection struct + DB schema
│   │   ├── tester.go                   Direct connection test per DB type
│   │   └── migrations.go               Embedded SQL migrations
│   │
│   ├── secrets/                        NEW PACKAGE
│   │   ├── secrets.go                  SecretsProvider interface
│   │   ├── gcp.go                      Google Secret Manager
│   │   ├── aws.go                      AWS Secrets Manager
│   │   ├── azure.go                    Azure Key Vault
│   │   └── plaintext.go               AES-256 encrypted in management DB (dev only)
│   │
│   │   ... all other internal/ packages UNCHANGED
│   ├── sources/
│   ├── tools/
│   ├── auth/
│   └── ...
```

---

## New Package: `internal/secrets`

### Interface

```go
// internal/secrets/secrets.go

package secrets

import "context"

// Provider stores and retrieves secrets by reference key.
// Implementations must be safe for concurrent use.
type Provider interface {
    // Get retrieves a secret value by its reference key.
    Get(ctx context.Context, ref string) (string, error)

    // Set stores a secret and returns the reference key to store in the DB.
    // The ref format is backend-specific:
    //   GCP:   "projects/PROJECT/secrets/NAME/versions/latest"
    //   AWS:   "arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME"
    //   Azure: "https://VAULT.vault.azure.net/secrets/NAME"
    //   Plain: "enc:BASE64_ENCRYPTED_VALUE"
    Set(ctx context.Context, name string, value string) (ref string, err error)

    // Delete removes a secret by its reference key.
    Delete(ctx context.Context, ref string) error
}
```

### GCP Implementation (`internal/secrets/gcp.go`)

```go
type GCPProvider struct {
    client    *secretmanager.Client
    projectID string
    prefix    string // optional, e.g. "dbmcp/" — prefixed to all secret names
}

// Authenticates via Application Default Credentials.
// No key files. On GCE/GKE/Cloud Run, uses attached service account.
// Locally: `gcloud auth application-default login`
func NewGCPProvider(ctx context.Context, projectID string) (*GCPProvider, error)

// Set creates a new secret version in GCP Secret Manager.
// Secret name: "{prefix}{connectionName}-{fieldName}"
// Returns: "projects/{project}/secrets/{name}/versions/latest"
func (p *GCPProvider) Set(ctx context.Context, name, value string) (string, error)

// Get fetches the latest version of a secret.
func (p *GCPProvider) Get(ctx context.Context, ref string) (string, error)

// Delete destroys all versions and the secret resource.
func (p *GCPProvider) Delete(ctx context.Context, ref string) error
```

Required IAM roles:
- `roles/secretmanager.secretAccessor` — read secrets
- `roles/secretmanager.secretVersionAdder` — create new versions
- `roles/secretmanager.admin` — delete secrets (or `roles/secretmanager.secretDeleter`)

### AWS Implementation (`internal/secrets/aws.go`)

```go
type AWSProvider struct {
    client *secretsmanager.Client
    prefix string
}

// Authenticates via AWS SDK default chain:
//   1. Environment variables (AWS_ACCESS_KEY_ID etc.) — avoid in production
//   2. EC2 instance profile / ECS task role / Lambda execution role — use this
//   3. ~/.aws/credentials — for local dev
func NewAWSProvider(ctx context.Context, region string) (*AWSProvider, error)

// Set creates a new secret or puts a new version.
// Secret name: "{prefix}{name}"
// Returns the secret ARN.
func (p *AWSProvider) Set(ctx context.Context, name, value string) (string, error)

// Get fetches the current value of a secret by ARN or name.
func (p *AWSProvider) Get(ctx context.Context, ref string) (string, error)

// Delete schedules the secret for deletion (7-day recovery window).
func (p *AWSProvider) Delete(ctx context.Context, ref string) error
```

Required IAM permissions:
- `secretsmanager:GetSecretValue`
- `secretsmanager:CreateSecret`
- `secretsmanager:PutSecretValue`
- `secretsmanager:DeleteSecret`

### Azure Implementation (`internal/secrets/azure.go`)

```go
type AzureProvider struct {
    client      *azsecrets.Client
    vaultURL    string
    prefix      string
}

// Authenticates via Azure SDK default chain:
//   1. Managed Identity — use this on Azure VMs, AKS, App Service
//   2. Azure CLI credentials — for local dev (`az login`)
//   3. Environment variables (AZURE_CLIENT_ID etc.) — avoid in production
func NewAzureProvider(ctx context.Context, vaultURL string) (*AzureProvider, error)

// Set creates or updates a secret in Key Vault.
// Returns: "https://{vault}.vault.azure.net/secrets/{name}"
func (p *AzureProvider) Set(ctx context.Context, name, value string) (string, error)

func (p *AzureProvider) Get(ctx context.Context, ref string) (string, error)
func (p *AzureProvider) Delete(ctx context.Context, ref string) error
```

Required Key Vault access policy (or RBAC role `Key Vault Secrets Officer`):
- `Get`, `Set`, `Delete` on Secrets

### SQLite Implementation (`internal/secrets/sqlite.go`)

For local development and self-hosted deployments. Credentials are AES-256-GCM encrypted and stored in a **dedicated SQLite file** — separate from the connection management DB.

```go
type SQLiteProvider struct {
    db  *sql.DB  // dedicated secrets SQLite file
    key []byte   // 32 bytes, from --encryption-key or DBMCP_ENCRYPTION_KEY
}
```

Schema of the secrets file:
```sql
CREATE TABLE secrets (
    key        TEXT PRIMARY KEY,  -- secret name, e.g. "dbmcp/prod-pg"
    ciphertext TEXT NOT NULL,     -- hex(nonce || AES-256-GCM ciphertext)
    created_at DATETIME,
    updated_at DATETIME
);
```

- `Set()` upserts an encrypted row; returns the key name as the reference.
- `Get()` looks up by key name, decrypts, returns plaintext.
- `Delete()` removes the row.
- The reference stored in the management DB is just the key name — not the ciphertext.
- Each encryption uses a unique random nonce — identical passwords produce different ciphertexts.

Two files on disk, independent security boundaries:
```
dbmcp.sqlite          ← connection metadata  (chmod 640)
dbmcp-secrets.sqlite  ← encrypted secrets    (chmod 600)
```

---

## New Package: `internal/connections`

### Models (`internal/connections/models.go`)

```go
package connections

import "time"

// Connection is stored in the management DB.
// Credentials are NEVER stored here — only secret references.
type Connection struct {
    ID          string    `db:"id"`           // UUID
    Name        string    `db:"name"`         // unique, used as toolset name
    DBType      string    `db:"db_type"`      // postgres, mysql, mongodb, etc.
    Host        string    `db:"host"`
    Port        int       `db:"port"`
    Database    string    `db:"database"`
    Username    string    `db:"username"`
    SSLMode     string    `db:"ssl_mode"`     // disable, require, verify-full
    Description string    `db:"description"`
    // PasswordRef is the secrets backend reference for the password.
    // Format depends on backend:
    //   GCP:      "projects/x/secrets/y/versions/latest"
    //   AWS:      "arn:aws:secretsmanager:..."
    //   Azure:    "https://vault.azure.net/secrets/name"
    //   Plaintext: "enc:base64_encrypted_value"
    PasswordRef  string    `db:"password_ref"`
    LastTestedAt *time.Time `db:"last_tested_at"`
    LastTestOK   *bool      `db:"last_test_ok"`
    CreatedAt    time.Time  `db:"created_at"`
    UpdatedAt    time.Time  `db:"updated_at"`
}
```

### DB Schema (`internal/connections/migrations.go`)

```sql
CREATE TABLE IF NOT EXISTS connections (
    id           TEXT PRIMARY KEY,        -- UUID v4
    name         TEXT UNIQUE NOT NULL,    -- used as toolset name in MCP
    db_type      TEXT NOT NULL,           -- postgres | mysql | mongodb | redis | ...
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    database     TEXT NOT NULL,
    username     TEXT NOT NULL,
    ssl_mode     TEXT NOT NULL DEFAULT 'require',
    description  TEXT NOT NULL DEFAULT '',
    password_ref TEXT NOT NULL,           -- secrets backend reference, never plaintext
    last_tested_at DATETIME,
    last_test_ok   BOOLEAN,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

Migrations are embedded in the binary using `//go:embed` and run on startup.

### Store (`internal/connections/store.go`)

```go
package connections

type Store struct {
    db *sql.DB
}

func NewStore(driverName, dataSourceName string) (*Store, error)

func (s *Store) Create(ctx context.Context, conn *Connection) error
func (s *Store) Get(ctx context.Context, id string) (*Connection, error)
func (s *Store) GetByName(ctx context.Context, name string) (*Connection, error)
func (s *Store) List(ctx context.Context) ([]*Connection, error)
func (s *Store) Update(ctx context.Context, conn *Connection) error
func (s *Store) Delete(ctx context.Context, id string) error
func (s *Store) UpdateTestResult(ctx context.Context, id string, ok bool) error
```

### Connection Tester (`internal/connections/tester.go`)

Tests credentials directly using the appropriate Go driver — no Toolbox involved. This is what `POST /api/connections/:id/test` calls.

```go
type TestResult struct {
    OK            bool
    LatencyMs     *int64
    ServerVersion string
    Message       string
}

func TestConnection(ctx context.Context, conn *Connection, password string) TestResult
```

Driver mapping:
| DBType | Driver | Probe |
|---|---|---|
| postgres, cloud-sql-postgres, alloydb-postgres | `jackc/pgx` | `SELECT version()` |
| mysql, cloud-sql-mysql, mariadb, tidb | `go-sql-driver/mysql` | `SELECT version()` |
| mongodb | `mongo-driver` | `ping` |
| redis, valkey | `redis/go-redis` | `PING` |
| mssql, cloud-sql-mssql | `microsoft/go-mssqldb` | `SELECT @@VERSION` |
| elasticsearch | `elastic/go-elasticsearch` | `/_cluster/health` |
| sqlite | `mattn/go-sqlite3` | `SELECT sqlite_version()` |
| snowflake | `snowflakedb/gosnowflake` | `SELECT current_version()` |
| clickhouse | `ClickHouse/clickhouse-go` | `SELECT version()` |
| cassandra | `gocql/gocql` | `system.local` query |
| bigquery | `cloud.google.com/go/bigquery` | dataset list |

Timeout: 5 seconds. Non-blocking — runs in a goroutine, result channel passed back.

---

## Modified File: `cmd/internal/config.go`

Add `LoadFromDB()` alongside the existing `LoadAndMergeConfigs()`. The function signature mirrors the existing one — both return a `Config` struct.

```go
// LoadFromDB loads connection configs from the management DB and translates
// each Connection into SourceConfig + ToolConfigs + ToolsetConfig.
// Credentials are fetched from the secrets provider and resolved in-memory.
// Nothing is written to disk.
func LoadFromDB(
    ctx context.Context,
    store *connections.Store,
    secrets secrets.Provider,
) (Config, error) {
    conns, err := store.List(ctx)
    if err != nil {
        return Config{}, fmt.Errorf("loading connections from DB: %w", err)
    }

    cfg := Config{
        Sources:  make(server.SourceConfigs),
        Tools:    make(server.ToolConfigs),
        Toolsets: make(server.ToolsetConfigs),
    }

    for _, conn := range conns {
        // Fetch password from secrets backend — in memory only
        password, err := secrets.Get(ctx, conn.PasswordRef)
        if err != nil {
            return Config{}, fmt.Errorf("fetching secret for connection %q: %w", conn.Name, err)
        }

        // Build SourceConfig for this connection
        sourceConfig, err := buildSourceConfig(conn, password)
        if err != nil {
            return Config{}, fmt.Errorf("building source config for %q: %w", conn.Name, err)
        }
        cfg.Sources[conn.Name] = sourceConfig

        // Auto-generate list_tables and execute_sql tools
        listTool, execTool := buildDefaultTools(conn)
        cfg.Tools[conn.Name+"_list_tables"] = listTool
        cfg.Tools[conn.Name+"_execute_sql"] = execTool

        // One toolset per connection — maps to /mcp/{conn.Name}
        cfg.Toolsets[conn.Name] = tools.ToolsetConfig{
            Name:      conn.Name,
            ToolNames: []string{conn.Name + "_list_tables", conn.Name + "_execute_sql"},
        }
    }

    return cfg, nil
}

// buildSourceConfig translates a Connection + resolved password
// into a SourceConfig that InitializeConfigs() can consume.
// password is the plaintext value fetched from the secrets backend.
func buildSourceConfig(conn *connections.Connection, password string) (sources.SourceConfig, error) {
    // Uses sources.DecodeConfig() with an in-memory map — same path as YAML unmarshaling.
    raw := map[string]any{
        "type":     conn.DBType,
        "host":     conn.Host,
        "port":     conn.Port,
        "database": conn.Database,
        "user":     conn.Username,
        "password": password,        // plaintext in memory, never on disk
        "sslMode":  conn.SSLMode,
    }
    dec, err := util.NewStrictDecoder(raw)
    if err != nil {
        return nil, err
    }
    return sources.DecodeConfig(ctx, conn.DBType, conn.Name, dec)
}
```

`InitializeConfigs()` is called with the resulting `Config` — **zero changes to InitializeConfigs itself**.

---

## Modified File: `cmd/internal/flags.go`

New flags added to the `serve` command:

```go
// Config mode
cmd.Flags().StringVar(&opts.ConfigMode, "config-mode", "file",
    `Config source: "file" (default, uses --config) or "db" (uses --db-url)`)

// Management DB
cmd.Flags().StringVar(&opts.DBURL, "db-url", "",
    `Management DB URL. SQLite: "file:./dbmcp.sqlite"  Postgres: "postgres://..."`)

// Secrets backend
cmd.Flags().StringVar(&opts.SecretsBackend, "secrets-backend", "sqlite",
    `Secrets backend: "sqlite" (default), "gcp", "aws", or "azure"`)

cmd.Flags().StringVar(&opts.SecretsFile, "secrets-file", "",
    `Path to SQLite secrets file (required when --secrets-backend=sqlite). Env: DBMCP_SECRETS_FILE`)

cmd.Flags().StringVar(&opts.EncryptionKey, "encryption-key", "",
    `32-byte hex AES-256 key (required when --secrets-backend=sqlite). Env: DBMCP_ENCRYPTION_KEY`)

cmd.Flags().StringVar(&opts.GCPProject, "gcp-project", "",
    `GCP project ID (required when --secrets-backend=gcp). Env: DBMCP_GCP_PROJECT`)

cmd.Flags().StringVar(&opts.AWSRegion, "aws-region", "",
    `AWS region (required when --secrets-backend=aws). Env: DBMCP_AWS_REGION`)

cmd.Flags().StringVar(&opts.AzureKeyVaultURL, "azure-keyvault-url", "",
    `Azure Key Vault URL (required when --secrets-backend=azure). Env: DBMCP_AZURE_KEYVAULT_URL`)
```

Existing flags (`--config`, `--port`, `--address`, etc.) are **unchanged**.

---

## Modified File: `cmd/internal/serve/command.go`

The serve command gains a branch at startup:

```go
func runServe(ctx context.Context, opts *Options) error {
    var toolboxCfg server.ServerConfig
    var connStore *connections.Store
    var secretsProvider secrets.Provider

    switch opts.ConfigMode {
    case "file":
        // EXISTING PATH — zero changes
        parser := &internal.ConfigParser{}
        fileCfg, err := parser.LoadAndMergeConfigs(ctx, configPaths)
        if err != nil { return err }
        toolboxCfg = buildServerConfig(opts, fileCfg)

    case "db":
        // NEW PATH
        connStore, err = connections.NewStore(opts.DBURL)
        if err != nil { return fmt.Errorf("opening management DB: %w", err) }

        secretsProvider, err = secrets.NewProvider(ctx, opts)
        if err != nil { return fmt.Errorf("initializing secrets provider: %w", err) }

        dbCfg, err := internal.LoadFromDB(ctx, connStore, secretsProvider)
        if err != nil { return err }
        toolboxCfg = buildServerConfig(opts, dbCfg)
        // inject store + secrets into server for the management API
        toolboxCfg.ConnStore = connStore
        toolboxCfg.SecretsProvider = secretsProvider
    }

    srv, err := server.NewServer(ctx, toolboxCfg)
    // ... unchanged from here
}
```

Hot-reload in `db` mode: instead of watching files with `fsnotify`, we re-call `LoadFromDB()` and `srv.UpdateConfig()` after every connection add/update/delete via the API. No polling needed — changes are event-driven.

---

## Modified File: `internal/server/server.go`

Add two optional fields to `ServerConfig`:

```go
type ServerConfig struct {
    // ... all existing fields unchanged ...

    // ConnStore is set when --config-mode=db.
    // Nil in file mode — the management API routes are not registered.
    ConnStore *connections.Store

    // SecretsProvider is set when --config-mode=db.
    SecretsProvider secrets.Provider
}
```

In `NewServer()`, after the existing route mounts, add:

```go
// Management API — only in db mode
if cfg.ConnStore != nil {
    mgmtR, err := managementRouter(s)
    if err != nil { return nil, err }
    r.Mount("/api/connections", mgmtR)
}
```

The `Server` struct gets two new fields mirroring the config:

```go
type Server struct {
    // ... all existing fields unchanged ...
    connStore       *connections.Store  // nil in file mode
    secretsProvider secrets.Provider    // nil in file mode
}
```

---

## Modified File: `internal/server/api.go`

Add a new `managementRouter()` function. The existing `apiRouter()` is **untouched**.

```go
// managementRouter creates the /api/connections subrouter.
// Only mounted when --config-mode=db.
func managementRouter(s *Server) (chi.Router, error) {
    r := chi.NewRouter()
    r.Use(middleware.AllowContentType("application/json"))
    r.Use(render.SetContentType(render.ContentTypeJSON))

    r.Get("/",            func(w http.ResponseWriter, r *http.Request) { listConnections(s, w, r) })
    r.Post("/",           func(w http.ResponseWriter, r *http.Request) { createConnection(s, w, r) })
    r.Post("/reload",     func(w http.ResponseWriter, r *http.Request) { reloadConfig(s, w, r) })
    r.Get("/{id}",        func(w http.ResponseWriter, r *http.Request) { getConnection(s, w, r) })
    r.Put("/{id}",        func(w http.ResponseWriter, r *http.Request) { updateConnection(s, w, r) })
    r.Delete("/{id}",     func(w http.ResponseWriter, r *http.Request) { deleteConnection(s, w, r) })
    r.Post("/{id}/test",  func(w http.ResponseWriter, r *http.Request) { testConnection(s, w, r) })

    return r, nil
}
```

Each handler follows the same pattern as existing handlers in `api.go`:
- Extract path params with `chi.URLParam`
- Validate input
- Call `s.connStore` for DB operations
- Call `s.secretsProvider` for credential operations
- Call `s.reloadFromDB()` to hot-reload config after mutations
- Use existing `newErrResponse` / `render.JSON` helpers

### `reloadFromDB()` method on Server

```go
// reloadFromDB re-fetches all connections, rebuilds ServerConfig, and calls UpdateConfig.
// Called after every connection create/update/delete.
func (s *Server) reloadFromDB(ctx context.Context) error {
    cfg, err := internal.LoadFromDB(ctx, s.connStore, s.secretsProvider)
    if err != nil {
        return err
    }
    return s.UpdateConfig(ctx, buildServerConfigFromLoaded(cfg))
}
```

`UpdateConfig()` already exists in upstream and handles atomically swapping the resource manager.

---

## Connection Test & Persist Flow

There are two distinct test mechanisms.

### Pre-save test — `POST /api/connections/test`

Tests credentials **without touching the secrets backend or management DB**.
Used by the frontend "Test Connection" button before the user clicks Save.

```
POST /api/connections/test  { name, db_type, host, port, db, user, password, ssl }
        │
        ▼
1. Validate required fields
        │
        ▼
2. TCP dial (fast-fail — catches firewall / wrong host before driver overhead)
        │
        ▼
3. Driver probe (SELECT version() for SQL, PING for Redis, etc.)
        │
        ▼
4. Return TestResult { ok, latency_ms, server_version, message }
   Always HTTP 200 — caller checks ok field.
   Nothing is written anywhere.
```

### Create with test-before-persist — `POST /api/connections`

```
POST /api/connections  { name, db_type, host, port, db, user, password, ssl }
        │
        ▼
1. Validate input (name format, required fields, port range)
        │
        ▼
2. Check name uniqueness → 409 Conflict if duplicate
        │
        ▼
3. Test credentials (same TCP + driver probe as above)
   → FAIL: return 422 with TestResult embedded in body
            { "error": "connection test failed", "test_result": {...} }
            Nothing is saved. Password never left memory.
        │
        ▼ (only reached if test passes)
4. Store password in secrets backend
   secretsProvider.Set(ctx, "dbmcp/{name}", password)
   → Returns opaque ref (SQLite key / GCP path / AWS ARN / Azure URL)
   → Plaintext password goes out of scope here
        │
        ▼
5. Insert Connection row in management DB
   { id, name, db_type, host, port, db, user, ssl, description, password_ref }
   → password_ref = opaque ref from step 4
   → If DB insert fails: delete the secret from step 4 (no orphaned credentials)
        │
        ▼
6. Record test result (last_tested_at, last_test_ok = true)
        │
        ▼
7. reloadFromDB() → /mcp/{name} goes live immediately
        │
        ▼
8. Return 201 with Connection response (no password field)
```

### Update with credential rotation — `PUT /api/connections/:id`

```
PUT /api/connections/:id  { host?, port?, db?, user?, password?, ssl?, description? }
        │
        ▼
1. Load existing connection from DB
        │
        ▼
2. Apply partial update to working copy
        │
        ▼
3. Resolve test password:
   - If new password provided → use it
   - Otherwise → fetch current password from secrets backend
     (so we still test connectivity for host/port changes)
        │
        ▼
4. Test updated credentials
   → FAIL: return 422, nothing changed
        │
        ▼
5. If new password → rotate in secrets backend (Set overwrites)
        │
        ▼
6. Update DB row + record test result
        │
        ▼
7. reloadFromDB()
        │
        ▼
8. Return 200 with updated Connection response
```

### Post-save test — `POST /api/connections/:id/test`

Re-test an already-saved connection on demand.

```
POST /api/connections/:id/test
        │
        ▼
1. Load connection from DB
        │
        ▼
2. Fetch password from secrets backend
        │
        ▼
3. TCP dial + driver probe
        │
        ▼
4. Persist result → UpdateTestResult(id, ok)
        │
        ▼
5. Return TestResult (always HTTP 200)
```

---

## Data Flow: Server Startup (DB Mode)

```
Binary starts
        │
        ▼
1. Parse flags → detect --config-mode=db
        │
        ▼
2. Open management DB, run migrations if needed
        │
        ▼
3. Initialize secrets provider (GCP/AWS/Azure/plaintext)
   → Provider authenticates via keyless mechanism (ADC/IAM role/Managed Identity)
   → No credentials in flags or config files
        │
        ▼
4. LoadFromDB():
   → SELECT * FROM connections
   → For each connection: secrets.Get(password_ref) → plaintext password in memory
   → Build SourceConfig using sources.DecodeConfig() — same as YAML path
   → Build ToolConfigs and ToolsetConfigs
   → Password goes out of scope after SourceConfig is initialized
        │
        ▼
5. InitializeConfigs(serverConfig)
   → Sources: open DB connection pools
   → Tools: bind to sources
   → Toolsets: group tools
   → Same code path as file mode, zero changes
        │
        ▼
6. NewServer() starts HTTP server
   → /mcp/{name} live for each connection in DB
   → /api/connections/* registered (db mode only)
   → /api/toolset, /api/tool/:name/invoke registered (always, if --enable-api)
```

---

## What Is NOT Changed

The following upstream packages are **completely untouched**. No forks, no modifications:

- `internal/sources/` — all 42+ DB drivers and their configs
- `internal/tools/` — all tool implementations and the factory registry
- `internal/auth/` — authentication services
- `internal/server/mcp.go` — MCP protocol handling and per-toolset routing
- `internal/server/web.go` — web UI
- `internal/server/resources/` — resource manager
- `internal/telemetry/` — OpenTelemetry
- `internal/prompts/` — prompts and promptsets
- `internal/embeddingmodels/` — embedding models
- `main.go`
- `cmd/root.go`

This means all upstream bug fixes and new DB driver additions can be merged from upstream with minimal conflict risk — the changes are isolated to the loading layer and the API layer.

---

## Dependency Additions to `go.mod`

```
# Management DB
github.com/mattn/go-sqlite3            v1.x   — SQLite driver (file mode)
github.com/lib/pq                              — already present (used by postgres source)

# Secrets backends
cloud.google.com/go/secretmanager      v1.x   — GCP Secret Manager
github.com/aws/aws-sdk-go-v2/...       v1.x   — AWS SDK v2 (secretsmanager + config)
github.com/Azure/azure-sdk-for-go/...  v1.x   — Azure SDK (azsecrets)

# Already present in upstream go.mod — no new deps needed:
# github.com/jackc/pgx/v5
# github.com/go-sql-driver/mysql
# go.mongodb.org/mongo-driver
# github.com/redis/go-redis/v9
```

GCP, AWS, and Azure SDKs use **build tags** so that a deployment targeting only one cloud does not pull in the others:

```go
//go:build gcp
// +build gcp

package secrets
// GCP implementation
```

Default build includes all three. Cloud-specific slim builds:

```bash
go build -tags gcp   -o db-mcp-gcp   ./main.go
go build -tags aws   -o db-mcp-aws   ./main.go
go build -tags azure -o db-mcp-azure ./main.go
go build             -o db-mcp       ./main.go   # all three included
```

---

## Merging Upstream Updates

Because changes are isolated:

1. Changes to `internal/sources/`, `internal/tools/`, `internal/server/mcp.go` — merge cleanly, no conflicts
2. Changes to `internal/server/server.go` — minor conflicts possible around `ServerConfig` struct; resolve by keeping our two added fields
3. Changes to `internal/server/api.go` — minor conflicts possible around `apiRouter()`; resolve by keeping our `managementRouter()` addition
4. Changes to `cmd/internal/config.go` — no conflicts; we added `LoadFromDB()`, upstream changes `LoadAndMergeConfigs()`
5. New DB drivers in `internal/sources/` — automatically available via `buildSourceConfig()` since it uses `sources.DecodeConfig()`

Recommended cadence: merge upstream monthly, or when a new DB driver is added.
