// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/render"
)

const (
	stagingTokenTTL    = 5 * time.Minute
	stagingTokenPrefix = "ctok_"
	// Sweep expired tokens every minute.
	stagingSweepInterval = time.Minute
)

// StagingEntry holds a credential staged for use in a single connection
// creation or test request. Single-use: consumed and deleted on first use.
type StagingEntry struct {
	Password  string
	ExpiresAt time.Time
}

// StagingStore is an in-memory, thread-safe store for short-lived credential
// tokens. Tokens expire after 5 minutes and are invalidated after first use.
//
// Used by all three deployment tiers as the final step before the password
// reaches the connection handler:
//
//   Local:      POST /api/credentials/stage { password } → token
//   Enterprise: POST /api/credentials/stage { encrypted_password, key_id } → token
//               (server decrypts RSA-OAEP before storing)
//   SaaS:       not used — SaaS uses the prepare/confirm flow instead
type StagingStore struct {
	mu      sync.Mutex
	entries map[string]*StagingEntry
}

// NewStagingStore creates a store and starts the background expiry sweeper.
func NewStagingStore() *StagingStore {
	s := &StagingStore{entries: make(map[string]*StagingEntry)}
	go s.sweepLoop()
	return s
}

// Stage stores a password and returns a single-use token.
func (s *StagingStore) Stage(password string) (string, time.Time, error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("generating token: %w", err)
	}
	token := stagingTokenPrefix + hex.EncodeToString(tokenBytes)
	exp := time.Now().Add(stagingTokenTTL)

	s.mu.Lock()
	s.entries[token] = &StagingEntry{Password: password, ExpiresAt: exp}
	s.mu.Unlock()

	return token, exp, nil
}

// Consume retrieves and deletes the password for a token.
// Returns an error if the token is unknown or expired.
// Single-use: calling Consume twice with the same token always fails the second time.
func (s *StagingStore) Consume(token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[token]
	if !ok {
		return "", fmt.Errorf("invalid or already-used credential token")
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(s.entries, token)
		return "", fmt.Errorf("credential token expired — stage credentials again")
	}

	password := entry.Password
	// Invalidate immediately — single use.
	delete(s.entries, token)
	// Zero out the stored copy.
	entry.Password = ""
	return password, nil
}

func (s *StagingStore) sweepLoop() {
	ticker := time.NewTicker(stagingSweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.sweep()
	}
}

func (s *StagingStore) sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, entry := range s.entries {
		if now.After(entry.ExpiresAt) {
			entry.Password = "" // zero before GC
			delete(s.entries, token)
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers for the credential staging endpoints
// Mounted under /api/credentials/
// ---------------------------------------------------------------------------

// stageCredentialHandler handles POST /api/credentials/stage.
//
// Accepts ONE of:
//   - { "password": "plaintext" }                        — local / self-hosted tier
//   - { "encrypted_password": "b64", "key_id": "kid" }  — enterprise tier (RSA-OAEP)
//
// Returns a short-lived single-use token the client passes to
// POST /api/connections or POST /api/connections/test instead of the password.
func stageCredentialHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	var req struct {
		// Local tier: plaintext password (only acceptable over HTTPS)
		Password string `json:"password"`
		// Enterprise tier: RSA-OAEP encrypted password
		EncryptedPassword string `json:"encrypted_password"`
		KeyID             string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("invalid JSON: %w", err), http.StatusBadRequest))
		return
	}

	var password string

	switch {
	case req.EncryptedPassword != "" && req.KeyID != "":
		// Enterprise tier — decrypt RSA-OAEP ciphertext.
		if s.keyStore == nil {
			_ = render.Render(w, r, newErrResponse(
				fmt.Errorf("encrypted_password requires --security-tier=enterprise (RSA key store not initialised)"),
				http.StatusBadRequest,
			))
			return
		}
		var err error
		password, err = s.keyStore.Decrypt(req.KeyID, req.EncryptedPassword)
		if err != nil {
			_ = render.Render(w, r, newErrResponse(err, http.StatusBadRequest))
			return
		}

	case req.Password != "":
		// Local / self-hosted tier — plaintext over HTTPS.
		password = req.Password

	default:
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("provide either 'password' (local tier) or 'encrypted_password'+'key_id' (enterprise tier)"),
			http.StatusBadRequest,
		))
		return
	}

	if len(password) == 0 {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("password must not be empty"), http.StatusBadRequest))
		return
	}
	if len(password) > 1024 {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("password exceeds maximum length"), http.StatusBadRequest))
		return
	}

	token, expiresAt, err := s.stagingStore.Stage(password)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
		return
	}

	render.JSON(w, r, map[string]string{
		"credential_token": token,
		"expires_at":       expiresAt.UTC().Format(time.RFC3339),
		"note":             "single-use, expires in 5 minutes — use immediately in POST /api/connections or POST /api/connections/test",
	})
}

// publicKeyHandler handles GET /api/credentials/public-key.
// Only available when --security-tier=enterprise.
func publicKeyHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	if s.keyStore == nil {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("RSA encryption not enabled — set --security-tier=enterprise"),
			http.StatusNotFound,
		))
		return
	}
	render.JSON(w, r, s.keyStore.CurrentPublicKey())
}

// resolvePassword extracts the plaintext password from a request that may
// supply it as one of:
//   - credential_token  (all tiers — preferred)
//   - password          (local/self-hosted only, accepted but discouraged in enterprise/SaaS)
//
// SaaS mode does not use this function — it uses the prepare/confirm flow.
func (s *Server) resolvePassword(credentialToken, rawPassword string) (string, error) {
	switch {
	case credentialToken != "":
		if s.stagingStore == nil {
			return "", fmt.Errorf("credential_token requires --config-mode=db")
		}
		return s.stagingStore.Consume(credentialToken)
	case rawPassword != "":
		return rawPassword, nil
	default:
		return "", fmt.Errorf("provide 'credential_token' (recommended) or 'password'")
	}
}
