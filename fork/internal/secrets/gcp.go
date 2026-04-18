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
	"encoding/base64"
	"fmt"
	"strings"

	secretmanager "google.golang.org/api/secretmanager/v1"
)

// GCPProvider stores secrets in Google Cloud Secret Manager using the
// google.golang.org/api REST client (already a transitive dependency).
//
// Authentication uses Application Default Credentials (ADC):
//   - On GCE / GKE / Cloud Run: the attached service account is used automatically.
//   - Locally: run `gcloud auth application-default login`.
//
// Required IAM roles on the service account:
//   - roles/secretmanager.secretAccessor      (read secrets)
//   - roles/secretmanager.secretVersionAdder  (create versions)
//   - roles/secretmanager.secretDeleter       (delete secrets)
type GCPProvider struct {
	svc       *secretmanager.Service
	projectID string
	prefix    string
}

func newGCPProvider(ctx context.Context, projectID, prefix string) (*GCPProvider, error) {
	if projectID == "" {
		return nil, fmt.Errorf("--gcp-project is required when --secrets-backend=gcp")
	}
	svc, err := secretmanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating GCP Secret Manager client: %w", err)
	}
	return &GCPProvider{svc: svc, projectID: projectID, prefix: prefix}, nil
}

// Set creates a new secret (or adds a new version if it exists) in Secret Manager.
// Returns the full resource name of the latest version.
func (p *GCPProvider) Set(ctx context.Context, name, value string) (string, error) {
	secretID := p.secretID(name)
	parent := fmt.Sprintf("projects/%s", p.projectID)
	secretName := fmt.Sprintf("%s/secrets/%s", parent, secretID)

	// Create the secret resource if it doesn't exist yet.
	_, err := p.svc.Projects.Secrets.Create(parent, &secretmanager.Secret{
		Replication: &secretmanager.Replication{
			Automatic: &secretmanager.Automatic{},
		},
	}).SecretId(secretID).Context(ctx).Do()
	// Ignore AlreadyExists — we'll just add a new version.
	if err != nil && !isAlreadyExists(err) {
		return "", fmt.Errorf("creating GCP secret %q: %w", secretID, err)
	}

	// Add a new secret version (payload must be base64-encoded).
	_, err = p.svc.Projects.Secrets.AddVersion(secretName, &secretmanager.AddSecretVersionRequest{
		Payload: &secretmanager.SecretPayload{
			Data: base64.StdEncoding.EncodeToString([]byte(value)),
		},
	}).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("adding secret version for %q: %w", secretID, err)
	}

	// Always reference "latest" so rotation is automatic.
	return secretName + "/versions/latest", nil
}

// Get retrieves the latest version of a secret.
// ref must be a full resource name as returned by Set.
func (p *GCPProvider) Get(ctx context.Context, ref string) (string, error) {
	result, err := p.svc.Projects.Secrets.Versions.Access(ref).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("accessing GCP secret %q: %w", ref, err)
	}
	data, err := base64.StdEncoding.DecodeString(result.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("decoding GCP secret payload: %w", err)
	}
	return string(data), nil
}

// Delete destroys all versions of the secret and removes the secret resource.
func (p *GCPProvider) Delete(ctx context.Context, ref string) error {
	secretName := secretNameFromRef(ref)
	_, err := p.svc.Projects.Secrets.Delete(secretName).Context(ctx).Do()
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("deleting GCP secret %q: %w", secretName, err)
	}
	return nil
}

func (p *GCPProvider) secretID(name string) string {
	// Secret IDs can only contain letters, numbers, hyphens, underscores.
	safe := strings.NewReplacer("/", "-", ".", "-", " ", "-").Replace(p.prefix + name)
	return safe
}

func secretNameFromRef(ref string) string {
	// Strip "/versions/latest" suffix.
	if idx := strings.LastIndex(ref, "/versions/"); idx != -1 {
		return ref[:idx]
	}
	return ref
}

func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "409")
}

func isNotFound(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "NotFound"))
}
