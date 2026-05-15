// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Package secrets provides a unified interface for storing and retrieving
// database credentials from a secrets backend.
//
// Available backends:
//
//   - SQLiteProvider  → AES-256-GCM encrypted, dedicated SQLite file on disk (local/self-hosted)
//   - GCPProvider     → Google Cloud Secret Manager
//   - AWSProvider     → AWS Secrets Manager
//   - AzureProvider   → Azure Key Vault
//
// All cloud backends authenticate via keyless mechanisms:
// ADC (GCP), IAM role (AWS), Managed Identity (Azure).
// No credentials are required in flags or config files.
//
// Configuration via environment variables (CLI flags take precedence):
//
//	DBMCP_SECRETS_BACKEND   sqlite | gcp | aws | azure
//	DBMCP_SECRETS_FILE      path to SQLite secrets file  (sqlite backend)
//	DBMCP_ENCRYPTION_KEY    32-byte hex key              (sqlite backend)
//	DBMCP_GCP_PROJECT       GCP project ID               (gcp backend)
//	DBMCP_AWS_REGION        AWS region                   (aws backend)
//	DBMCP_AZURE_KEYVAULT_URL Azure Key Vault URL         (azure backend)
package secrets

import (
	"context"
	"fmt"
	"os"
)

// Provider stores and retrieves secrets by opaque reference strings.
// Implementations must be safe for concurrent use.
type Provider interface {
	// Get retrieves a secret value by its reference string.
	Get(ctx context.Context, ref string) (string, error)

	// Set stores a secret value and returns an opaque reference string
	// to persist in the management DB. The reference format is backend-specific:
	//   sqlite: key name,  e.g. "dbmcp/prod-pg"
	//   GCP:    resource,  e.g. "projects/PROJECT/secrets/NAME/versions/latest"
	//   AWS:    ARN,       e.g. "arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME"
	//   Azure:  URL,       e.g. "https://VAULT.vault.azure.net/secrets/NAME"
	Set(ctx context.Context, name string, value string) (ref string, err error)

	// Delete removes the secret. Called when a connection is deleted.
	Delete(ctx context.Context, ref string) error
}

// Backend identifies which secrets implementation to use.
type Backend string

const (
	BackendSQLite Backend = "sqlite"
	BackendGCP    Backend = "gcp"
	BackendAWS    Backend = "aws"
	BackendAzure  Backend = "azure"
)

// Config holds all configuration for initialising a Provider.
// Fields are populated from CLI flags, with env var fallbacks applied by New().
type Config struct {
	Backend Backend

	// SQLite backend
	SecretsFile   string // path to the dedicated secrets SQLite file
	EncryptionKey string // 32-byte hex; set via --encryption-key or DBMCP_ENCRYPTION_KEY

	// GCP backend
	GCPProject string

	// AWS backend
	AWSRegion string

	// Azure backend
	AzureKeyVaultURL string

	// Prefix is prepended to secret names in the backend.
	// Default: "dbmcp/"
	Prefix string
}

// New initialises and returns a Provider.
// Env vars are applied as fallbacks for any empty Config fields before
// dispatching to the backend constructor.
func New(ctx context.Context, cfg Config) (Provider, error) {
	// Apply env var fallbacks.
	if cfg.Backend == "" {
		cfg.Backend = Backend(envOr("DBMCP_SECRETS_BACKEND", string(BackendSQLite)))
	}
	if cfg.SecretsFile == "" {
		cfg.SecretsFile = os.Getenv("DBMCP_SECRETS_FILE")
	}
	if cfg.EncryptionKey == "" {
		cfg.EncryptionKey = os.Getenv("DBMCP_ENCRYPTION_KEY")
	}
	if cfg.GCPProject == "" {
		cfg.GCPProject = os.Getenv("DBMCP_GCP_PROJECT")
	}
	if cfg.AWSRegion == "" {
		cfg.AWSRegion = os.Getenv("DBMCP_AWS_REGION")
	}
	if cfg.AzureKeyVaultURL == "" {
		cfg.AzureKeyVaultURL = os.Getenv("DBMCP_AZURE_KEYVAULT_URL")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = envOr("DBMCP_SECRETS_PREFIX", "dbmcp/")
	}

	switch cfg.Backend {
	case BackendSQLite:
		return newSQLiteProvider(cfg.SecretsFile, cfg.EncryptionKey)
	case BackendGCP:
		return newGCPProvider(ctx, cfg.GCPProject, cfg.Prefix)
	case BackendAWS:
		return newAWSProvider(ctx, cfg.AWSRegion, cfg.Prefix)
	case BackendAzure:
		return newAzureProvider(ctx, cfg.AzureKeyVaultURL, cfg.Prefix)
	default:
		return nil, fmt.Errorf("unknown secrets backend %q — must be one of: sqlite, gcp, aws, azure", cfg.Backend)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
