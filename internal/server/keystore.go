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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

const (
	rsaKeyBits    = 2048
	keyRotateEvery = 24 * time.Hour
	// Keep the previous key alive for this long after rotation so in-flight
	// requests that fetched the old public key can still complete.
	keyOverlapWindow = 5 * time.Minute
)

// KeyEntry holds one RSA key pair with its ID and expiry.
type KeyEntry struct {
	ID          string
	PrivateKey  *rsa.PrivateKey
	PublicKeyDER []byte // PKIX DER — sent to clients
	GeneratedAt time.Time
	ExpiresAt   time.Time
}

// PublicKeyResponse is returned by GET /api/credentials/public-key.
type PublicKeyResponse struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // base64(PKIX DER)
	Algorithm string `json:"algorithm"`  // always "RSA-OAEP-SHA256"
	ExpiresAt string `json:"expires_at"` // RFC3339
}

// KeyStore manages RSA-2048 key pairs for enterprise self-hosted deployments.
//
// A new key pair is generated every 24 hours. The previous key is kept alive
// for 5 minutes after rotation so clients that fetched the old public key
// just before rotation can still complete their request.
//
// The private key NEVER leaves this process. It is never written to disk,
// never logged, and never sent over the network. Only the public key is exposed.
//
// Thread-safe.
type KeyStore struct {
	mu      sync.RWMutex
	current *KeyEntry
	previous *KeyEntry // retained briefly after rotation
}

// NewKeyStore generates the initial key pair and starts the background rotation ticker.
func NewKeyStore() (*KeyStore, error) {
	ks := &KeyStore{}
	if err := ks.rotate(); err != nil {
		return nil, fmt.Errorf("generating initial RSA key pair: %w", err)
	}
	go ks.rotationLoop()
	return ks, nil
}

// CurrentPublicKey returns the public key response for the active key pair.
func (ks *KeyStore) CurrentPublicKey() PublicKeyResponse {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return PublicKeyResponse{
		KeyID:     ks.current.ID,
		PublicKey: base64.StdEncoding.EncodeToString(ks.current.PublicKeyDER),
		Algorithm: "RSA-OAEP-SHA256",
		ExpiresAt: ks.current.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// Decrypt decrypts RSA-OAEP-SHA256 ciphertext using the key identified by keyID.
// Accepts both the current and previous key (overlap window).
// ciphertext must be base64-encoded.
func (ks *KeyStore) Decrypt(keyID, ciphertextB64 string) (string, error) {
	key := ks.findKey(keyID)
	if key == nil {
		return "", fmt.Errorf("unknown or expired key_id %q — fetch a fresh public key and re-encrypt", keyID)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decoding encrypted_password (must be base64): %w", err)
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key.PrivateKey, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting password (wrong key or corrupted ciphertext): %w", err)
	}
	return string(plaintext), nil
}

// IsEnabled returns true — once a KeyStore is created, RSA-OAEP is active.
func (ks *KeyStore) IsEnabled() bool {
	return ks != nil
}

func (ks *KeyStore) findKey(keyID string) *KeyEntry {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.current != nil && ks.current.ID == keyID {
		return ks.current
	}
	if ks.previous != nil && ks.previous.ID == keyID && time.Now().Before(ks.previous.ExpiresAt) {
		return ks.previous
	}
	return nil
}

func (ks *KeyStore) rotate() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	// Key ID: first 8 bytes of SHA-256 of the public key DER, hex-encoded.
	h := sha256.Sum256(pubDER)
	keyID := fmt.Sprintf("%x", h[:8])

	entry := &KeyEntry{
		ID:           keyID,
		PrivateKey:   privateKey,
		PublicKeyDER: pubDER,
		GeneratedAt:  time.Now(),
		ExpiresAt:    time.Now().Add(keyRotateEvery + keyOverlapWindow),
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// The current key becomes previous with a short expiry window.
	if ks.current != nil {
		prev := *ks.current
		prev.ExpiresAt = time.Now().Add(keyOverlapWindow)
		ks.previous = &prev
	}
	ks.current = entry
	return nil
}

func (ks *KeyStore) rotationLoop() {
	ticker := time.NewTicker(keyRotateEvery)
	defer ticker.Stop()
	for range ticker.C {
		if err := ks.rotate(); err != nil {
			// Log and continue — the old key remains valid.
			// In production, wire this to your structured logger.
			fmt.Printf("[keystore] WARNING: key rotation failed: %v\n", err)
		}
	}
}
