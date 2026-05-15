// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package connections

// schema is the management DB schema — applied on every startup (idempotent).
const schema = `
CREATE TABLE IF NOT EXISTS connections (
    id              TEXT    PRIMARY KEY,
    name            TEXT    UNIQUE NOT NULL,
    db_type         TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    database        TEXT    NOT NULL,
    username        TEXT    NOT NULL,
    ssl_mode        TEXT    NOT NULL DEFAULT 'require',
    description     TEXT    NOT NULL DEFAULT '',
    extra_params    TEXT    NOT NULL DEFAULT '{}',
    -- secrets backend reference — never plaintext password
    password_ref    TEXT    NOT NULL,
    last_tested_at  DATETIME,
    last_test_ok    BOOLEAN,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast name lookups (used on every MCP request routing).
CREATE UNIQUE INDEX IF NOT EXISTS idx_connections_name ON connections(name);
`

// alterations are best-effort ALTER TABLE statements applied after schema creation.
// Each is run individually; errors (e.g. "duplicate column") are silently ignored
// so that existing databases are upgraded without issues on repeated startups.
var alterations = []string{
	// v2: extra_params column — silently ignored if already present (new DBs have it in CREATE TABLE).
	`ALTER TABLE connections ADD COLUMN extra_params TEXT NOT NULL DEFAULT '{}'`,
}
