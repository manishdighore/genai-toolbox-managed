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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx Postgres driver, registered as "pgx"
)

// Store provides CRUD access to the connections management database.
// Thread-safe — the underlying *sql.DB manages a connection pool.
type Store struct {
	db *sql.DB
}

// NewStore opens (or creates) the management database and runs migrations.
// dsn must be a Postgres DSN, e.g.:
//
//	postgres://user:pass@host:5432/dbname?sslmode=require
//	postgresql://user:pass@host:5432/dbname?sslmode=disable
func NewStore(dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("--db-url is required (Postgres DSN)")
	}
	if !(strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")) {
		return nil, fmt.Errorf("--db-url must be a Postgres DSN, got %q", dsn)
	}

	db, err := sql.Open("pgx", dsn)
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
		INSERT INTO db_connections
			(id, name, db_type, host, port, database, username, ssl_mode, description, password_ref, extra_params, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		conn.ID, conn.Name, conn.DBType, conn.Host, conn.Port,
		conn.Database, conn.Username, conn.SSLMode, conn.Description,
		conn.PasswordRef, conn.ExtraParams,
		conn.CreatedAt, conn.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting connection %q: %w", conn.Name, err)
	}
	return nil
}

// Get retrieves a connection by ID.
func (s *Store) Get(ctx context.Context, id string) (*Connection, error) {
	return s.scanOne(ctx, `
		SELECT id, name, db_type, host, port, database, username,
		       ssl_mode, description, password_ref, extra_params,
		       last_tested_at, last_test_ok, created_at, updated_at
		FROM db_connections WHERE id = $1`, id)
}

// GetByName retrieves a connection by name.
func (s *Store) GetByName(ctx context.Context, name string) (*Connection, error) {
	return s.scanOne(ctx, `
		SELECT id, name, db_type, host, port, database, username,
		       ssl_mode, description, password_ref, extra_params,
		       last_tested_at, last_test_ok, created_at, updated_at
		FROM db_connections WHERE name = $1`, name)
}

// List returns all connections ordered by name.
func (s *Store) List(ctx context.Context) ([]*Connection, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, db_type, host, port, database, username,
		       ssl_mode, description, password_ref, extra_params,
		       last_tested_at, last_test_ok, created_at, updated_at
		FROM db_connections ORDER BY name ASC`)
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
// PasswordRef must already be updated by the caller before calling Update
// (the caller rotates the secret in the secrets backend first).
func (s *Store) Update(ctx context.Context, conn *Connection) error {
	conn.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		UPDATE db_connections SET
			host          = $1,
			port          = $2,
			database      = $3,
			username      = $4,
			ssl_mode      = $5,
			description   = $6,
			password_ref  = $7,
			extra_params  = $8,
			updated_at    = $9
		WHERE id = $10`,
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
	_, err := s.db.ExecContext(ctx, `DELETE FROM db_connections WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting connection %q: %w", id, err)
	}
	return nil
}

// UpdateTestResult records the result of a connection test.
func (s *Store) UpdateTestResult(ctx context.Context, id string, ok bool) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE db_connections SET last_tested_at = $1, last_test_ok = $2, updated_at = $3 WHERE id = $4`,
		now, ok, now, id,
	)
	return err
}

// NameExists returns true if a connection with the given name already exists.
func (s *Store) NameExists(ctx context.Context, name string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM db_connections WHERE name = $1`,
		name,
	).Scan(&count)
	return count > 0, err
}

// scanOne runs a query that returns at most one row. The SELECT list must
// match the column order used by scanConnection.
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
		&c.PasswordRef, &c.ExtraParams,
		&c.LastTestedAt, &c.LastTestOK,
		&c.CreatedAt, &c.UpdatedAt,
	)
}
