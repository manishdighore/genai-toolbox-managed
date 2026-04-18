// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package connections

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO required
)

// Store provides CRUD access to the connections management database.
// Thread-safe — the underlying *sql.DB manages a connection pool.
type Store struct {
	db *sql.DB
}

// NewStore opens (or creates) the management database and runs migrations.
// dsn examples:
//
//	SQLite:   "file:./dbmcp.sqlite?_journal_mode=WAL"
//	Postgres: "postgres://user:pass@host:5432/dbmcp?sslmode=require"
func NewStore(dsn string) (*Store, error) {
	// Detect driver from DSN prefix.
	driver := "sqlite"
	if len(dsn) > 8 && dsn[:8] == "postgres" {
		driver = "postgres"
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening management DB: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging management DB: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return s, nil
}

// migrate applies the schema and any additive alterations. Safe to run on every startup.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Apply best-effort alterations (e.g. ADD COLUMN for existing databases).
	// Errors are silently ignored — duplicate column errors are expected on re-runs.
	for _, alt := range alterations {
		s.db.Exec(alt) //nolint:errcheck
	}
	return nil
}

// Close closes the underlying database connection pool.
func (s *Store) Close() error {
	return s.db.Close()
}

// Create inserts a new connection. conn.ID is set if empty.
func (s *Store) Create(ctx context.Context, conn *Connection) error {
	if conn.ID == "" {
		conn.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	conn.CreatedAt = now
	conn.UpdatedAt = now

	if conn.ExtraParams == "" {
		conn.ExtraParams = "{}"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO connections
			(id, name, db_type, host, port, database, username, ssl_mode, description, password_ref, extra_params, created_at, updated_at)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		conn.ID, conn.Name, conn.DBType, conn.Host, conn.Port,
		conn.Database, conn.Username, conn.SSLMode, conn.Description,
		conn.PasswordRef, conn.ExtraParams, conn.CreatedAt, conn.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting connection %q: %w", conn.Name, err)
	}
	return nil
}

// Get retrieves a connection by ID.
func (s *Store) Get(ctx context.Context, id string) (*Connection, error) {
	return s.scanOne(ctx, `SELECT * FROM connections WHERE id = ?`, id)
}

// GetByName retrieves a connection by name.
func (s *Store) GetByName(ctx context.Context, name string) (*Connection, error) {
	return s.scanOne(ctx, `SELECT * FROM connections WHERE name = ?`, name)
}

// List returns all connections ordered by name.
func (s *Store) List(ctx context.Context) ([]*Connection, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, db_type, host, port, database, username,
		       ssl_mode, description, password_ref, extra_params,
		       last_tested_at, last_test_ok, created_at, updated_at
		FROM connections ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing connections: %w", err)
	}
	defer rows.Close()

	var conns []*Connection
	for rows.Next() {
		c := &Connection{}
		if err := scanConnection(rows, c); err != nil {
			return nil, err
		}
		conns = append(conns, c)
	}
	return conns, rows.Err()
}

// Update applies an UpdateRequest to a stored connection.
// Only non-nil fields are changed. UpdatedAt is always refreshed.
// PasswordRef must already be updated by the caller before calling Update
// (the caller rotates the secret in the secrets backend first).
func (s *Store) Update(ctx context.Context, conn *Connection) error {
	conn.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		UPDATE connections SET
			host         = ?,
			port         = ?,
			database     = ?,
			username     = ?,
			ssl_mode     = ?,
			description  = ?,
			password_ref = ?,
			extra_params = ?,
			updated_at   = ?
		WHERE id = ?`,
		conn.Host, conn.Port, conn.Database, conn.Username,
		conn.SSLMode, conn.Description, conn.PasswordRef,
		conn.ExtraParams, conn.UpdatedAt, conn.ID,
	)
	if err != nil {
		return fmt.Errorf("updating connection %q: %w", conn.ID, err)
	}
	return nil
}

// Delete removes a connection by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM connections WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting connection %q: %w", id, err)
	}
	return nil
}

// UpdateTestResult records the result of a connection test.
func (s *Store) UpdateTestResult(ctx context.Context, id string, ok bool) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE connections SET last_tested_at = ?, last_test_ok = ?, updated_at = ? WHERE id = ?`,
		now, ok, now, id,
	)
	return err
}

// NameExists returns true if a connection with the given name already exists.
func (s *Store) NameExists(ctx context.Context, name string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM connections WHERE name = ?`, name).Scan(&count)
	return count > 0, err
}

// scanOne runs a query and scans exactly one row into a Connection.
// scanOne runs a query and scans exactly one row. The query must SELECT all columns including extra_params.
func (s *Store) scanOne(ctx context.Context, query string, args ...any) (*Connection, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("not found")
	}
	c := &Connection{}
	if err := scanConnection(rows, c); err != nil {
		return nil, err
	}
	return c, nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanConnection(s scanner, c *Connection) error {
	return s.Scan(
		&c.ID, &c.Name, &c.DBType, &c.Host, &c.Port,
		&c.Database, &c.Username, &c.SSLMode, &c.Description,
		&c.PasswordRef, &c.ExtraParams, &c.LastTestedAt, &c.LastTestOK,
		&c.CreatedAt, &c.UpdatedAt,
	)
}
