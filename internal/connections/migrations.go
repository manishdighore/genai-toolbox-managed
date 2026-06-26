// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package connections

// Postgres-only schema for the management database. The `db_connections`
// table is owned by db-mcp; the `credentials` table that holds passwords is
// expected to exist (managed by whichever service originally provisioned it)
// — db-mcp inserts rows into it from the credentials secrets backend but
// does not own its DDL.
//
// Per-connection tool enable/disable state is intentionally NOT modeled here.
// That responsibility was moved to a separate service which manages its own
// per-project table. db-mcp neither reads nor writes tool-flag state.

const schema = `
CREATE TABLE IF NOT EXISTS db_connections (
    id              TEXT        PRIMARY KEY,
    name            TEXT        UNIQUE NOT NULL,
    db_type         TEXT        NOT NULL,
    host            TEXT        NOT NULL,
    port            INTEGER     NOT NULL,
    database        TEXT        NOT NULL,
    username        TEXT        NOT NULL,
    ssl_mode        TEXT        NOT NULL DEFAULT 'require',
    description     TEXT        NOT NULL DEFAULT '',
    extra_params    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    metadata        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    password_ref    TEXT        NOT NULL,
    last_tested_at  TIMESTAMPTZ,
    last_test_ok    BOOLEAN,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_db_connections_name ON db_connections(name);
`

// alterations are best-effort, idempotent ALTER statements applied after the
// schema CREATE. Each runs in isolation; failures are silently ignored so
// re-running is a no-op on already-migrated databases.
var alterations = []string{
	// JSONB columns for installs created by an earlier db-mcp version.
	`ALTER TABLE db_connections ADD COLUMN IF NOT EXISTS extra_params JSONB NOT NULL DEFAULT '{}'::jsonb`,
	// metadata is consumer-owned (e.g. AgentForge). db-mcp never reads or writes it.
	`ALTER TABLE db_connections ADD COLUMN IF NOT EXISTS metadata     JSONB NOT NULL DEFAULT '{}'::jsonb`,

	// `credentials` table is shared with other services (db-mcp does NOT own
	// its DDL). We add a nullable `type` column so db-mcp can discriminate
	// its own rows ('db_connection') from rows written by others (NULL).
	// IF NOT EXISTS makes this safe on re-run and on installs where the
	// column already exists.
	`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS type TEXT`,
}
