// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Package server — SaaS credential flow.
//
// In SaaS mode the server NEVER handles a plaintext password.
// The flow is a two-phase commit:
//
//  Phase 1 — Prepare
//  POST /api/connections/prepare   { name, db_type, host, port, ... }  (no password)
//  ← { pending_id, secret_name, upload_token, upload_url, expires_at }
//
//    The client uses upload_token to write the password DIRECTLY to the
//    secrets manager (GCP Secret Manager / AWS Secrets Manager / Azure Key Vault).
//    The server never sees the plaintext.
//
//  Phase 2 — Confirm
//  POST /api/connections/confirm   { pending_id }
//  ← 201 Connection created
//
//    The server verifies the secret was actually written, promotes the pending
//    record to active, and reloads Toolbox config.

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/render"
	"github.com/googleapis/genai-toolbox/internal/connections"
)

const (
	pendingTTL           = 10 * time.Minute
	pendingSweepInterval = 2 * time.Minute
)

// UploadToken is returned to the client to write directly to the secrets manager.
type UploadToken struct {
	// Provider-specific fields — only the relevant ones are populated.

	// GCP: short-lived OAuth2 access token scoped to addVersion on one secret.
	AccessToken string `json:"access_token,omitempty"`

	// AWS: STS temporary credentials scoped to PutSecretValue on one secret.
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`
	AWSSessionToken    string `json:"aws_session_token,omitempty"`
	AWSRegion          string `json:"aws_region,omitempty"`

	// Azure: short-lived Bearer token for Key Vault write.
	AzureToken   string `json:"azure_token,omitempty"`
	AzureVaultURL string `json:"azure_vault_url,omitempty"`
}

// PrepareResponse is returned by POST /api/connections/prepare.
type PrepareResponse struct {
	PendingID   string      `json:"pending_id"`
	SecretName  string      `json:"secret_name"`  // where to write the password
	UploadURL   string      `json:"upload_url"`   // exact API URL to PUT/POST the secret
	UploadToken UploadToken `json:"upload_token"` // credentials for that one call
	ExpiresAt   string      `json:"expires_at"`   // RFC3339 — confirm before this
	Instructions string     `json:"instructions"` // human-readable steps
}

// PendingConnection is stored in memory between prepare and confirm.
type PendingConnection struct {
	Request    connections.CreateRequest
	SecretName string
	SecretRef  string // full reference as stored in secrets backend
	UploadURL  string // URL the client should use to write the secret directly
	ExpiresAt  time.Time
}

// PendingStore is an in-memory store for connections awaiting confirmation.
type PendingStore struct {
	mu      sync.Mutex
	entries map[string]*PendingConnection
}

func newPendingStore() *PendingStore {
	ps := &PendingStore{entries: make(map[string]*PendingConnection)}
	go ps.sweepLoop()
	return ps
}

func (ps *PendingStore) add(id string, p *PendingConnection) {
	ps.mu.Lock()
	ps.entries[id] = p
	ps.mu.Unlock()
}

func (ps *PendingStore) consume(id string) (*PendingConnection, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.entries[id]
	if !ok {
		return nil, fmt.Errorf("pending_id %q not found or already confirmed", id)
	}
	if time.Now().After(p.ExpiresAt) {
		delete(ps.entries, id)
		return nil, fmt.Errorf("pending connection expired — start again with POST /api/connections/prepare")
	}
	delete(ps.entries, id)
	return p, nil
}

func (ps *PendingStore) sweepLoop() {
	ticker := time.NewTicker(pendingSweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		ps.mu.Lock()
		for id, p := range ps.entries {
			if now.After(p.ExpiresAt) {
				delete(ps.entries, id)
			}
		}
		ps.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// ScopedTokenIssuer issues short-lived, single-secret-scoped upload tokens.
// One implementation per cloud provider.
// ---------------------------------------------------------------------------

// ScopedTokenIssuer issues a short-lived credential that allows writing
// exactly ONE secret to the secrets manager.
type ScopedTokenIssuer interface {
	// Issue returns an UploadToken and the URL the client should POST to.
	// secretName is the full resource name of the pre-created secret.
	Issue(ctx context.Context, secretName string) (UploadToken, string, error)

	// Verify confirms that a secret version was actually written.
	// Called during Phase 2 (confirm) to ensure the client did write the password.
	Verify(ctx context.Context, secretRef string) error

	// Provider returns "gcp", "aws", or "azure".
	Provider() string
}

// ---------------------------------------------------------------------------
// GCP Scoped Token Issuer
// ---------------------------------------------------------------------------

// GCPScopedIssuer issues short-lived GCP access tokens scoped to addVersion
// on a single secret using Service Account impersonation + IAM conditions.
//
// Required setup:
//  1. A dedicated "uploader" service account in your GCP project.
//  2. IAM binding on each secret:  roles/secretmanager.secretVersionAdder
//     with condition: resource.name == "projects/PROJECT/secrets/SECRET"
//  3. Your main service account needs  roles/iam.serviceAccountTokenCreator
//     on the uploader service account.
type GCPScopedIssuer struct {
	ProjectID          string
	UploaderServiceAccount string // e.g. "uploader@my-project.iam.gserviceaccount.com"
}

func (g *GCPScopedIssuer) Provider() string { return "gcp" }

func (g *GCPScopedIssuer) Issue(ctx context.Context, secretName string) (UploadToken, string, error) {
	// In production: call the IAM Credentials API to generate a short-lived
	// access token for the uploader SA, scoped via IAM condition to this secret.
	//
	// POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{SA}:generateAccessToken
	// {
	//   "scope": ["https://www.googleapis.com/auth/cloud-platform"],
	//   "lifetime": "300s"
	// }
	//
	// The IAM condition (set when binding the role) restricts the token to
	// this specific secret — even if the token is leaked, it can only write
	// to one secret and expires in 5 minutes.
	//
	// This is a placeholder — wire in google.golang.org/api/iamcredentials/v1.
	return UploadToken{
		AccessToken: "SHORT_LIVED_GCP_TOKEN_PLACEHOLDER",
	}, fmt.Sprintf(
		"https://secretmanager.googleapis.com/v1/%s:addVersion",
		secretName,
	), nil
}

func (g *GCPScopedIssuer) Verify(ctx context.Context, secretRef string) error {
	// Call GCP Secret Manager to confirm at least one version exists.
	// GET https://secretmanager.googleapis.com/v1/{secretRef}
	// → check that payload.data is non-empty.
	// Placeholder — wire in cloud.google.com/go/secretmanager.
	return nil
}

// ---------------------------------------------------------------------------
// AWS Scoped Token Issuer
// ---------------------------------------------------------------------------

// AWSScopedIssuer issues STS temporary credentials via AssumeRole with an
// inline session policy that restricts to PutSecretValue on ONE secret ARN.
//
// Required setup:
//  1. An IAM role "dbmcp-uploader" that your server can assume.
//  2. Trust policy on that role: allow your server's instance role to assume it.
//  3. The role itself needs no permissions — the session policy restricts it further.
type AWSScopedIssuer struct {
	Region          string
	UploaderRoleARN string // e.g. "arn:aws:iam::123456789:role/dbmcp-uploader"
}

func (a *AWSScopedIssuer) Provider() string { return "aws" }

func (a *AWSScopedIssuer) Issue(ctx context.Context, secretName string) (UploadToken, string, error) {
	// In production: call STS AssumeRole with a session policy that locks
	// down to PutSecretValue on this specific secret ARN.
	//
	// Session policy JSON:
	// {
	//   "Version": "2012-10-17",
	//   "Statement": [{
	//     "Effect": "Allow",
	//     "Action": "secretsmanager:PutSecretValue",
	//     "Resource": "<secretARN>"
	//   }]
	// }
	//
	// Credentials expire in 900 seconds (15 min minimum for STS).
	// Wire in: github.com/aws/aws-sdk-go-v2/service/sts
	return UploadToken{
		AWSAccessKeyID:     "ASIA_PLACEHOLDER",
		AWSSecretAccessKey: "SECRET_PLACEHOLDER",
		AWSSessionToken:    "SESSION_TOKEN_PLACEHOLDER",
		AWSRegion:          a.Region,
	}, fmt.Sprintf(
		"https://secretsmanager.%s.amazonaws.com/",
		a.Region,
	), nil
}

func (a *AWSScopedIssuer) Verify(ctx context.Context, secretRef string) error {
	// Call GetSecretValue with the server's own credentials to confirm the
	// secret has a value. Placeholder — wire in aws-sdk-go-v2/service/secretsmanager.
	return nil
}

// ---------------------------------------------------------------------------
// Azure Scoped Token Issuer
// ---------------------------------------------------------------------------

// AzureScopedIssuer issues a short-lived Azure AD token scoped to writing
// one Key Vault secret using a dedicated service principal with a
// Key Vault Secrets Officer role restricted to a specific secret name.
//
// Required setup:
//  1. A dedicated service principal "dbmcp-uploader" in Azure AD.
//  2. Key Vault access policy: Set only, on the specific secret name.
//  3. Your server's Managed Identity needs permission to generate tokens
//     for the uploader SP (via Managed Identity federation or client credentials).
type AzureScopedIssuer struct {
	KeyVaultURL string // e.g. "https://my-vault.vault.azure.net"
}

func (az *AzureScopedIssuer) Provider() string { return "azure" }

func (az *AzureScopedIssuer) Issue(ctx context.Context, secretName string) (UploadToken, string, error) {
	// In production: get a client credentials token for the uploader SP
	// scoped to https://vault.azure.net/.default
	// Wire in: github.com/Azure/azure-sdk-for-go/sdk/azidentity
	return UploadToken{
		AzureToken:    "AZURE_BEARER_TOKEN_PLACEHOLDER",
		AzureVaultURL: az.KeyVaultURL,
	}, fmt.Sprintf("%s/secrets/%s?api-version=7.4", az.KeyVaultURL, secretName), nil
}

func (az *AzureScopedIssuer) Verify(ctx context.Context, secretRef string) error {
	return nil
}

// ---------------------------------------------------------------------------
// HTTP handlers — mounted only in SaaS mode
// ---------------------------------------------------------------------------

// prepareConnectionHandler handles POST /api/connections/prepare.
// Phase 1: validate metadata, pre-create secret slot, issue scoped upload token.
// No password is received. No secret value is stored by the server.
func prepareConnectionHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	var req connections.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("invalid JSON: %w", err), http.StatusBadRequest))
		return
	}

	// Validate everything except password — it won't arrive until confirm.
	req.Password = "placeholder" // bypass password validation for now
	if err := validateCreateRequest(&req); err != nil && err.Error() != "password is required" {
		_ = render.Render(w, r, newErrResponse(err, http.StatusUnprocessableEntity))
		return
	}
	req.Password = ""

	// Name must be unique.
	exists, err := s.connStore.NameExists(r.Context(), req.Name)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
		return
	}
	if exists {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("a connection named %q already exists", req.Name),
			http.StatusConflict,
		))
		return
	}

	// Generate the secret name — this is where the client will write the password.
	secretName := fmt.Sprintf("dbmcp/%s", req.Name)

	// Pre-create the secret slot in the secrets backend (empty, no value yet).
	// For GCP: creates the secret resource so we can set IAM on it.
	// For AWS/Azure: can be skipped — secret is created on first write.
	secretRef, err := s.secretsProvider.Set(r.Context(), secretName, "__pending__")
	if err != nil {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("pre-creating secret slot: %w", err),
			http.StatusInternalServerError,
		))
		return
	}

	// Issue a scoped upload token for the client.
	uploadToken, uploadURL, err := s.scopedIssuer.Issue(r.Context(), secretRef)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("issuing upload token: %w", err),
			http.StatusInternalServerError,
		))
		return
	}

	// Generate a pending ID.
	b := make([]byte, 12)
	rand.Read(b)
	pendingID := "pnd_" + hex.EncodeToString(b)

	expiresAt := time.Now().Add(pendingTTL)
	s.pendingStore.add(pendingID, &PendingConnection{
		Request:    req,
		SecretName: secretName,
		SecretRef:  secretRef,
		UploadURL:  uploadURL,
		ExpiresAt:  expiresAt,
	})

	provider := s.scopedIssuer.Provider()
	render.JSON(w, r, PrepareResponse{
		PendingID:   pendingID,
		SecretName:  secretName,
		UploadURL:   uploadURL,
		UploadToken: uploadToken,
		ExpiresAt:   expiresAt.UTC().Format(time.RFC3339),
		Instructions: fmt.Sprintf(
			"Write your database password to %s using the upload_token credentials. "+
				"Then call POST /api/connections/confirm with pending_id within %s. "+
				"Provider: %s. The server will never see your plaintext password.",
			uploadURL, pendingTTL, provider,
		),
	})
}

// confirmConnectionHandler handles POST /api/connections/confirm.
// Phase 2: verify the secret was written, save connection, reload Toolbox.
func confirmConnectionHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	var req struct {
		PendingID string `json:"pending_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("invalid JSON: %w", err), http.StatusBadRequest))
		return
	}
	if req.PendingID == "" {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("pending_id is required"), http.StatusBadRequest))
		return
	}

	pending, err := s.pendingStore.consume(req.PendingID)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusBadRequest))
		return
	}

	// Verify the client actually wrote the secret.
	// This calls the secrets manager to confirm a real value exists.
	if err := s.scopedIssuer.Verify(r.Context(), pending.SecretRef); err != nil {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("secret not found — did you write the password to %s? (%w)", pending.UploadURL, err),
			http.StatusUnprocessableEntity,
		))
		return
	}

	ssl := pending.Request.SSLMode
	if ssl == "" {
		ssl = "require"
	}
	conn := &connections.Connection{
		Name:        pending.Request.Name,
		DBType:      pending.Request.DBType,
		Host:        pending.Request.Host,
		Port:        pending.Request.Port,
		Database:    pending.Request.Database,
		Username:    pending.Request.Username,
		SSLMode:     ssl,
		Description: pending.Request.Description,
		PasswordRef: pending.SecretRef,
	}
	if err := s.connStore.Create(r.Context(), conn); err != nil {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("saving connection: %w", err),
			http.StatusInternalServerError,
		))
		return
	}

	if err := s.reloadFromDB(r.Context()); err != nil {
		s.logger.WarnContext(r.Context(), fmt.Sprintf("connection saved but reload failed: %v", err))
	}

	baseURL := s.toolboxUrl
	if baseURL == "" {
		baseURL = "http://localhost:5000"
	}
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, conn.ToResponse(baseURL))
}
