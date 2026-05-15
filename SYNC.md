# Syncing with upstream `googleapis/mcp-toolbox`

This repository is a real Git fork of [googleapis/mcp-toolbox](https://github.com/googleapis/mcp-toolbox). Upstream history is part of this repo's history, so you can pull new upstream releases with a normal Git merge.

## One-time setup (already done; documented for new clones)

```bash
git clone https://github.com/manishdighore/genai-toolbox-managed.git
cd genai-toolbox-managed
git remote add upstream https://github.com/googleapis/mcp-toolbox.git
git fetch upstream
```

Verify both remotes:
```bash
git remote -v
# origin    https://github.com/manishdighore/genai-toolbox-managed.git
# upstream  https://github.com/googleapis/mcp-toolbox.git
```

---

## The recurring sync workflow

Run this whenever upstream releases something you want.

### 1. Fetch upstream

```bash
git fetch upstream
git log --oneline upstream/main ^main | head     # what's new upstream
```

### 2. Create a sync branch

```bash
git checkout -b sync/upstream-$(date +%Y%m%d)
```

### 3. Merge upstream

```bash
git merge upstream/main
```

Three outcomes:

| Outcome | Meaning | Action |
|---|---|---|
| `Already up to date.` | Nothing new upstream. | Delete branch, done. |
| Merge succeeds cleanly. | Upstream changed only files you don't touch. | Skip to step 5 (build + test). |
| Merge has conflicts. | Upstream changed lines you also changed. | See step 4. |

### 4. Resolve conflicts

The conflict-prone files are the **modified upstream files** — see the table at the bottom of this doc. Files we added (`internal/connections/`, `internal/secrets/`, `internal/server/managed.go`, etc.) are ours alone and will never conflict.

For each conflicted file:
```bash
# Open in your editor. Resolve the <<<<<<< / >>>>>>> markers manually.
# Tip: when in doubt, take upstream's logic and re-apply your additions on top.
git add <file>
```

Common patterns to watch for:
- **Upstream renames a struct field** → update our references in our code that imports it.
- **Upstream changes a method signature** → update our callers in `server.go`, `api.go`, or `managed.go`.
- **Upstream removes/renames a function we call** → find the new equivalent in upstream's release notes or grep upstream for the new name.

Once all conflicts are resolved:
```bash
git commit
```

### 5. Build, lint, test

```bash
go build -tags nooracle -o /tmp/toolbox-test ./
go test -tags nooracle ./...
golangci-lint run
```

If anything fails, the conflict resolution was incomplete. Diagnose, fix, commit, re-test.

### 6. Smoke test the managed layer

```bash
# Start a fresh sandbox instance
KEY=$(openssl rand -hex 32)
mkdir -p /tmp/dbmcp-sync-test
/tmp/toolbox-test serve \
  --port=15555 \
  --config-mode=db --security-tier=local \
  --db-url="file:/tmp/dbmcp-sync-test/db.sqlite?_journal_mode=WAL" \
  --secrets-backend=sqlite --secrets-file=/tmp/dbmcp-sync-test/secrets.sqlite \
  --encryption-key="$KEY" &

# Verify the API
curl -sf http://127.0.0.1:15555/api/connections   # → []
```

### 7. Merge into main

```bash
git checkout main
git merge --no-ff sync/upstream-YYYYMMDD
git push origin main
```

Or open a PR if you prefer reviewing the merge commit before pushing.

---

## What's ours vs. what's upstream

When resolving conflicts or planning a refactor, this map helps you tell which files to treat as "preserve our version" vs. "take upstream's version and re-apply our patch."

### Entirely ours (no upstream version exists — won't conflict, just keep)

```
Root:
  README.md                                ← our product README
  build-run.sh                             ← local Docker run script
  docker-compose.yml                       ← local Docker compose
  Dockerfile.dbmcp                         ← our managed-mode Dockerfile
  .dockerignore.dbmcp
  .env.example
  UPSTREAM-README.md                       ← preserved copy of upstream's README
  SYNC.md                                  ← this file

Go packages we added:
  internal/connections/                    ← DB-backed connection store
  internal/secrets/                        ← multi-backend secrets (sqlite/gcp/aws/azure)

Files we added inside upstream's internal/server/ package:
  internal/server/credentials.go           ← /api/credentials handlers
  internal/server/keystore.go              ← in-memory staged-credential store
  internal/server/managed.go               ← defaultToolDescription() + managed helpers
  internal/server/middleware.go            ← managed-layer middleware
  internal/server/mocks.go                 ← test mocks for our packages
  internal/server/saas.go                  ← SaaS-tier handlers

Docs:
  docs/dbmcp/                              ← managed-layer docs (API, RUNNING, SECURITY, etc.)

Oracle build-tag stubs (compile when `-tags nooracle` is used):
  internal/sources/oracle/oracle_stub.go
  internal/tools/oracle/oracleexecutesql/stub.go
  internal/tools/oracle/oraclesql/stub.go
```

### Modified upstream files (these may conflict on sync)

| File | Why we modified it |
|---|---|
| `cmd/root.go` | Wrap `LoadConfig` so it's skipped in `--config-mode=db`. |
| `cmd/internal/flags.go` | Add `--config-mode`, `--security-tier`, `--db-url`, `--secrets-*`, `--encryption-key`, `--gcp-project`, `--aws-region`, `--azure-keyvault-url`, `--saas-uploader-sa`, `--tls-cert`, `--tls-key`. |
| `internal/server/config.go` | Add `ServerConfig` fields: `ConfigMode`, `SecurityTier`, `DBURL`, `SecretsBackend`, `SecretsFile`, `EncryptionKey`, `GCPProject`, `AWSRegion`, `AzureKeyVaultURL`, `SaaSUploaderSA`. |
| `internal/server/server.go` | Add `Server` struct fields (`connStore`, `secretsProvider`, `stagingStore`, etc.), `reloadFromDB`, `dbTypeToToolboxTypes`, `buildSourceConfigMap`, plus a setup block inside `NewServer()` that wires the connection store + secrets provider when `cfg.ConfigMode == "db"`. |
| `internal/server/api.go` | Add `managementRouter` + all `/api/connections` handlers (createConnection, listConnections, getConnection, updateConnection, deleteConnection, testConnection, reload, friendlyTestError, validateCreateRequest, resolveBaseURL). |
| `internal/server/web.go` | Add `docsRouter()` that serves the Scalar API UI at `/docs` and the OpenAPI spec at `/openapi.yaml`. |
| `internal/server/static/openapi.yaml`, `docs.html` | Static assets for the API UI. |
| `internal/sources/oracle/oracle.go` | Add `//go:build !nooracle` build tag. |
| `internal/tools/oracle/oracleexecutesql/oracleexecutesql.go` | Same. |
| `internal/tools/oracle/oraclesql/oraclesql.go` | Same. |
| `internal/sources/oracle/oracle_test.go` and tool test files | Same build tag. |

---

## Future cleanup (optional)

The diff to upstream is currently larger than it needs to be — `server.go` and `api.go` carry several hundred lines of our code inline. A future refactor can:

1. Move `reloadFromDB`, `dbTypeToToolboxTypes`, `buildSourceConfigMap` from `server.go` into `internal/server/managed.go` (`managed.go` already exists for `defaultToolDescription`).
2. Move all `/api/connections` handlers from `api.go` into `internal/server/managed_api.go`.
3. Move the DB-mode setup block in `NewServer()` into a helper `setupManaged(s)` defined in `managed.go`, called from a 2-line hook in `NewServer`.

After that refactor, conflicts on upstream sync should be confined to ~10 lines across 5 files instead of hundreds across 2 files.

---

## When upstream changes break things

Common upstream change patterns and how to spot them:

- **A method signature changes** (e.g. `Listen(ctx)` → `Listen(ctx, certFile, keyFile)`) → `go build` fails with "too many/few arguments." Update our callers.
- **A struct gets new required fields** → JSON/YAML deserialization fails at runtime. Re-run integration tests against a real database to catch.
- **A function we use is renamed** → `go build` fails with "undefined: oldName". Search upstream's release notes for the new name.
- **A package is moved** → `go build` fails with "no such module." Update import paths in our files.

If a sync is too painful, you can always cherry-pick specific upstream commits instead of merging the whole branch:

```bash
git fetch upstream
git cherry-pick <upstream-commit-sha>
```

---

## Reporting back to upstream

If our managed layer reveals a bug in upstream — e.g. a tool's `Description` being `validate:"required"` blocking auto-registration — you can open an issue or PR at https://github.com/googleapis/mcp-toolbox/issues. We're not obligated to upstream every change, but bug reports help everyone.
