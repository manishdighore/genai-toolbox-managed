// Copyright 2025 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License");

// Package server — managed-layer additions.
//
// This file contains helpers used by reloadFromDB() when registering tools
// from saved connections. It exists to keep our additions isolated from
// upstream's server.go so future upstream syncs touch the smallest possible
// surface area.

package server

import "fmt"

// defaultToolDescription returns the description used when synthesizing a
// tool config map for an auto-registered tool from a saved connection.
//
// Upstream tool configs declare Description with `validate:"required"` on a
// subset of tools (e.g. postgres-execute-sql, postgres-list-tables). Without
// a description these tools fail config validation and never register, so
// the per-connection toolset ends up empty.
//
// The returned string is also surfaced verbatim to the LLM, so it includes
// the connection name and database type — this lets an agent that has
// multiple connections registered pick the right tool by reading the
// description ("Execute SQL against the LocalPostgres database…" vs.
// "Execute SQL against the AnalyticsMySQL database…").
func defaultToolDescription(toolType, connName, dbType string) string {
	// Tool-type-specific descriptions.
	switch toolType {
	// ── Generic SQL execution ─────────────────────────────────────────
	case "postgres-execute-sql",
		"mysql-execute-sql",
		"mssql-execute-sql",
		"sqlite-execute-sql",
		"cockroachdb-execute-sql",
		"yugabytedb-sql",
		"clickhouse-execute-sql",
		"snowflake-execute-sql":
		return fmt.Sprintf("Execute a SQL statement against the %s database (connection: %s). Accepts any valid SQL: SELECT, INSERT, UPDATE, DELETE, DDL — bounded by the connected user's grants.", dbType, connName)

	// ── Listing tables / collections / equivalents ─────────────────────
	case "postgres-list-tables", "mysql-list-tables", "mssql-list-tables":
		return fmt.Sprintf("List all tables in the %s database (connection: %s), with schema and table names.", dbType, connName)

	// ── Postgres-specific operational tools ────────────────────────────
	case "postgres-list-active-queries":
		return fmt.Sprintf("List currently active (running) queries on the %s server (connection: %s), with PID, user, state, query text, and duration.", dbType, connName)
	case "postgres-list-available-extensions":
		return fmt.Sprintf("List all Postgres extensions available to install on the %s server (connection: %s).", dbType, connName)
	case "postgres-list-installed-extensions":
		return fmt.Sprintf("List Postgres extensions currently installed in the %s database (connection: %s).", dbType, connName)
	}

	// Fallback for any tool type not enumerated above. Upstream may add
	// new required-description tools; this keeps registration working
	// (with a non-empty description) instead of silently dropping them.
	return fmt.Sprintf("Run %s against the %s database (connection: %s).", toolType, dbType, connName)
}
