// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx Postgres driver (registered as "pgx")
)

// CredentialsDirectProvider stores secrets as rows in the shared `credentials`
// Postgres table. Sharing with other services is an operational detail — db-mcp
// only ever reads/writes rows it created, identified by their `name` (we use
// the prefix "dbmcp/" — other services use their own prefixes like
// "agentforge/providers/...").
//
// Expected table schema. The `id, name, encrypted_dek, dek_nonce, nonce,
// ciphertext, created_at` columns are owned by whichever service originally
// provisioned the table (db-mcp does NOT alter them). db-mcp adds a nullable
// `type` column at startup via an idempotent ALTER (see migrations.go) and
// uses it to discriminate its own rows from other services' rows in the same
// table:
//
//	id            TEXT        PRIMARY KEY
//	name          TEXT        NOT NULL   -- human label, e.g. "dbmcp/prod-pg"
//	type          TEXT                   -- 'db_connection' for db-mcp rows; NULL for others
//	encrypted_dek BYTEA       NOT NULL   -- AES-256-GCM(DEK, masterKey, dek_nonce)
//	dek_nonce     BYTEA       NOT NULL   -- 12 bytes
//	nonce         BYTEA       NOT NULL   -- 12 bytes
//	ciphertext    BYTEA       NOT NULL   -- AES-256-GCM(plaintext, DEK, nonce)
//	created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
//
// Envelope format (db-mcp's own; does not need to match other services
// byte-for-byte because we only decrypt rows we wrote):
//
//	DEK            = 32 random bytes per row
//	encrypted_dek  = AES-256-GCM(DEK, masterKey, dek_nonce)  → 48 bytes
//	dek_nonce      = 12 random bytes per row
//	nonce          = 12 random bytes per row
//	ciphertext     = AES-256-GCM(plaintext, DEK, nonce)
//
// The reference string returned to callers is "cred:<uuid>" and stored in
// db_connections.password_ref.
type CredentialsDirectProvider struct {
	db     *sql.DB
	keyGCM cipher.AEAD // AES-256-GCM cipher constructed from the master key
	// ownerID is reserved for future use (e.g. per-tenant scoping). The current
	// schema has no owner column, so this is ignored.
	ownerID string
}

const (
	credRefPrefix     = "cred:"
	credTypeDBConn    = "db_connection"
	credOwnerDefault  = "db-mcp"
	masterKeyBytesLen = 32 // AES-256
	gcmNonceLen       = 12
	dekLen            = 32 // AES-256 DEK
)

func newCredentialsDirectProvider(dsn, masterKeyHex, ownerID string) (*CredentialsDirectProvider, error) {
	if dsn == "" {
		return nil, errors.New("credentials backend requires --db-url (or DBMCP_DB_URL) pointing at the Postgres holding the credentials table")
	}
	if !(strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")) {
		return nil, fmt.Errorf("credentials backend requires a Postgres DSN, got %q", maskedDSN(dsn))
	}
	if masterKeyHex == "" {
		return nil, errors.New("credentials backend requires --app-key (or DBMCP_APP_KEY): 32-byte hex string")
	}
	key, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("--app-key is not valid hex: %w", err)
	}
	if len(key) != masterKeyBytesLen {
		return nil, fmt.Errorf("--app-key must decode to %d bytes (got %d). Generate with: openssl rand -hex %d",
			masterKeyBytesLen, len(key), masterKeyBytesLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("constructing AES cipher: %w", err)
	}
	keyGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("constructing AES-GCM: %w", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening credentials DB: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging credentials DB: %w", err)
	}

	if ownerID == "" {
		ownerID = credOwnerDefault
	}
	return &CredentialsDirectProvider{db: db, keyGCM: keyGCM, ownerID: ownerID}, nil
}

// Set encrypts and inserts a new credentials row, returning "cred:<uuid>".
// name is recorded in the row's `name` column for human identification (e.g.
// "dbmcp/prod-pg"). Other services that share the table use their own
// naming conventions; db-mcp recognises its own rows by the "dbmcp/" prefix
// but does not enforce it on read — the UUID id is the authoritative key.
func (p *CredentialsDirectProvider) Set(ctx context.Context, name, value string) (string, error) {
	// 1. Generate a random per-row DEK and wrap it with the master key.
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return "", fmt.Errorf("generating DEK: %w", err)
	}
	dekNonce := make([]byte, gcmNonceLen)
	if _, err := rand.Read(dekNonce); err != nil {
		return "", fmt.Errorf("generating DEK nonce: %w", err)
	}
	encryptedDEK := p.keyGCM.Seal(nil, dekNonce, dek, nil)

	// 2. Encrypt the plaintext with the DEK.
	valNonce := make([]byte, gcmNonceLen)
	if _, err := rand.Read(valNonce); err != nil {
		return "", fmt.Errorf("generating value nonce: %w", err)
	}
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("constructing DEK cipher: %w", err)
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return "", fmt.Errorf("constructing DEK GCM: %w", err)
	}
	ciphertext := dekGCM.Seal(nil, valNonce, []byte(value), nil)

	id := uuid.NewString()
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO credentials
			(id, name, type, encrypted_dek, dek_nonce, nonce, ciphertext)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, name, credTypeDBConn, encryptedDEK, dekNonce, valNonce, ciphertext,
	)
	if err != nil {
		return "", fmt.Errorf("inserting credential row: %w", err)
	}
	return credRefPrefix + id, nil
}

// Get resolves the plaintext for a previously stored reference.
func (p *CredentialsDirectProvider) Get(ctx context.Context, ref string) (string, error) {
	id, err := credStripRefPrefix(ref)
	if err != nil {
		return "", err
	}
	var encryptedDEK, dekNonce, valNonce, ciphertext []byte
	err = p.db.QueryRowContext(ctx, `
		SELECT encrypted_dek, dek_nonce, nonce, ciphertext
		FROM credentials
		WHERE id = $1 AND type = $2`,
		id, credTypeDBConn,
	).Scan(&encryptedDEK, &dekNonce, &valNonce, &ciphertext)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("credential %s not found", id)
		}
		return "", fmt.Errorf("loading credential row: %w", err)
	}

	dek, err := p.keyGCM.Open(nil, dekNonce, encryptedDEK, nil)
	if err != nil {
		return "", fmt.Errorf("unwrapping DEK: %w (wrong --app-key, or row written by another service)", err)
	}
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("constructing DEK cipher: %w", err)
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return "", fmt.Errorf("constructing DEK GCM: %w", err)
	}
	plain, err := dekGCM.Open(nil, valNonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting credential: %w", err)
	}
	return string(plain), nil
}

// Delete removes a credentials row. Returns nil if the row is already gone.
func (p *CredentialsDirectProvider) Delete(ctx context.Context, ref string) error {
	id, err := credStripRefPrefix(ref)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `DELETE FROM credentials WHERE id = $1 AND type = $2`, id, credTypeDBConn)
	if err != nil {
		return fmt.Errorf("deleting credential row: %w", err)
	}
	return nil
}

func credStripRefPrefix(ref string) (string, error) {
	if !strings.HasPrefix(ref, credRefPrefix) {
		return "", fmt.Errorf("invalid credential ref %q (expected %s<uuid>)", ref, credRefPrefix)
	}
	id := strings.TrimPrefix(ref, credRefPrefix)
	if id == "" {
		return "", fmt.Errorf("invalid credential ref %q (empty id)", ref)
	}
	return id, nil
}

// maskedDSN strips the password from a Postgres DSN for safe logging.
func maskedDSN(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	if at < 0 {
		return dsn
	}
	scheme := strings.Index(dsn, "://")
	if scheme < 0 || scheme >= at {
		return dsn
	}
	return dsn[:scheme+3] + "***" + dsn[at:]
}
