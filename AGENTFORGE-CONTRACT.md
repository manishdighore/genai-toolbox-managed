# Schema sharing with AgentForge — no action required

This document exists for the AgentForge backend team's awareness only. **It
asks for zero changes** on the AgentForge side.

## What db-mcp does with the shared `credentials` table

db-mcp uses your existing `credentials` table to persist DB-connection passwords.
It does this **without modifying your existing rows or your existing code**.

### The columns db-mcp shares (already exist, untouched)

```
id            TEXT        PRIMARY KEY
name          TEXT        NOT NULL
encrypted_dek BYTEA       NOT NULL
dek_nonce     BYTEA       NOT NULL
nonce         BYTEA       NOT NULL
ciphertext    BYTEA       NOT NULL
created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

db-mcp inserts using these columns with the exact same format AgentForge
already uses for `agentforge/providers/...` rows. AgentForge's existing
3 rows continue to work unchanged.

### One column db-mcp adds at startup

db-mcp's startup migration runs:

```sql
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS type TEXT;
```

This is **nullable, has no default, and has no CHECK constraint**. AgentForge's
existing rows get `type = NULL` and behave exactly as before. db-mcp's new rows
write `type = 'db_connection'` to discriminate themselves.

After this migration runs on first startup, your `credentials` table looks like:

```
id            TEXT        PRIMARY KEY
name          TEXT        NOT NULL
type          TEXT        ← NEW, nullable. db-mcp writes 'db_connection'; existing rows are NULL.
encrypted_dek BYTEA       NOT NULL
dek_nonce     BYTEA       NOT NULL
nonce         BYTEA       NOT NULL
ciphertext    BYTEA       NOT NULL
created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### What db-mcp's rows look like

| Field | Value |
|---|---|
| `id` | freshly generated UUID — stored as the suffix of `db_connections.password_ref = "cred:<uuid>"` |
| `name` | `"dbmcp/<connection-name>"` — human label, e.g. `"dbmcp/prod-pg"` |
| `type` | `'db_connection'` (the discriminator) |
| `encrypted_dek` | 48-byte BYTEA: `AES-256-GCM(DEK, DBMCP_APP_KEY, dek_nonce)` |
| `dek_nonce` | 12 random bytes |
| `nonce` | 12 random bytes |
| `ciphertext` | `AES-256-GCM(plaintext-password, DEK, nonce)` |
| `created_at` | now |

**db-mcp's `DBMCP_APP_KEY` is a different master key from AgentForge's.** Each service can only decrypt its own rows. This is by design — db-mcp is independent and not in any password-resolution path AgentForge depends on.

## Things to know (no action required, just awareness)

1. **Don't try to decrypt rows where `type = 'db_connection'`.** They use db-mcp's master key, not AgentForge's. Decryption will fail.
2. **Skip them in any AgentForge-side key-rotation job.** Scope your rotation to `WHERE type IS DISTINCT FROM 'db_connection'`. db-mcp manages its own rotation.
3. **Skip them in any AgentForge UI that lists credentials**, unless you want to display them informationally. Same `WHERE` filter works.
4. **Optional hardening (later):** if you want to enforce at the DB layer that AgentForge's role can't touch db-mcp's rows (and vice versa), add an RLS policy keyed on `type`. Not required to ship.

## How to verify everything is wired up correctly

After db-mcp starts and someone saves a connection in its UI:

```sql
-- db-mcp wrote a row of its own:
SELECT id, name, type, created_at
FROM credentials
WHERE type = 'db_connection';

-- AgentForge's existing rows are unchanged:
SELECT id, name, type, created_at
FROM credentials
WHERE type IS NULL;
```

Both should return what you expect: db-mcp rows tagged, AgentForge rows untagged.
