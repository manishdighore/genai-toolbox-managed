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
	"fmt"
	"io"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO required
)

// SQLiteProvider stores AES-256-GCM encrypted secrets in a dedicated SQLite
// file, separate from the connection management database.
//
// Layout on disk:
//
//	dbmcp.sqlite          ← connection metadata (host, port, db name, refs)
//	dbmcp-secrets.sqlite  ← this file: encrypted secret values only
//
// The management DB stores only the secret key name as the reference.
// The actual encrypted value lives here.
//
// Security properties:
//   - AES-256-GCM: authenticated encryption — detects tampering.
//   - Each value gets a unique random nonce — identical passwords produce
//     different ciphertexts.
//   - The encryption key never touches disk — it comes from DBMCP_ENCRYPTION_KEY
//     or --encryption-key at runtime only.
//   - Set the file to chmod 600 and back it up separately from the management DB.
type SQLiteProvider struct {
	db  *sql.DB
	key []byte // 32 bytes, AES-256
}

const sqliteSecretsSchema = `
CREATE TABLE IF NOT EXISTS secrets (
    key        TEXT PRIMARY KEY,   -- secret name, e.g. "dbmcp/prod-pg"
    ciphertext TEXT NOT NULL,      -- hex(nonce || AES-256-GCM ciphertext)
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

func newSQLiteProvider(path, hexKey string) (*SQLiteProvider, error) {
	if path == "" {
		return nil, fmt.Errorf("--secrets-file is required when --secrets-backend=sqlite")
	}
	if hexKey == "" {
		return nil, fmt.Errorf("--encryption-key (or DBMCP_ENCRYPTION_KEY) is required when --secrets-backend=sqlite")
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decoding --encryption-key (must be 64 hex chars / 32 bytes): %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("--encryption-key must be exactly 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening secrets DB at %q: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging secrets DB at %q: %w", path, err)
	}
	if _, err := db.Exec(sqliteSecretsSchema); err != nil {
		return nil, fmt.Errorf("running secrets DB schema: %w", err)
	}

	return &SQLiteProvider{db: db, key: key}, nil
}

// Set encrypts value and upserts it under name.
// Returns the name itself as the reference — the reference stored in the
// management DB is just the key, not the ciphertext.
func (p *SQLiteProvider) Set(_ context.Context, name, value string) (string, error) {
	ct, err := p.encrypt(value)
	if err != nil {
		return "", fmt.Errorf("encrypting secret %q: %w", name, err)
	}
	_, err = p.db.Exec(`
		INSERT INTO secrets (key, ciphertext, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET
			ciphertext = excluded.ciphertext,
			updated_at = CURRENT_TIMESTAMP`,
		name, ct,
	)
	if err != nil {
		return "", fmt.Errorf("storing secret %q: %w", name, err)
	}
	return name, nil // reference = key name
}

// Get decrypts and returns the value for the given reference (key name).
func (p *SQLiteProvider) Get(_ context.Context, ref string) (string, error) {
	var ct string
	err := p.db.QueryRow(`SELECT ciphertext FROM secrets WHERE key = ?`, ref).Scan(&ct)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("secret %q not found in secrets DB", ref)
	}
	if err != nil {
		return "", fmt.Errorf("reading secret %q: %w", ref, err)
	}
	return p.decrypt(ct)
}

// Delete removes the secret row.
func (p *SQLiteProvider) Delete(_ context.Context, ref string) error {
	_, err := p.db.Exec(`DELETE FROM secrets WHERE key = ?`, ref)
	return err
}

// Close closes the underlying database.
func (p *SQLiteProvider) Close() error {
	return p.db.Close()
}

// encrypt returns hex(nonce || AES-256-GCM ciphertext).
func (p *SQLiteProvider) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(sealed), nil
}

// decrypt decodes hex(nonce || ciphertext) and returns the plaintext.
func (p *SQLiteProvider) decrypt(hexCT string) (string, error) {
	data, err := hex.DecodeString(hexCT)
	if err != nil {
		return "", fmt.Errorf("decoding ciphertext: %w", err)
	}
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", fmt.Errorf("ciphertext too short")
	}
	pt, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypting (wrong --encryption-key?): %w", err)
	}
	return string(pt), nil
}
