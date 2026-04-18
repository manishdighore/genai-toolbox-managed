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
	"fmt"
)

// AzureProvider stores secrets in Azure Key Vault.
//
// To enable this backend, add the Azure Key Vault Secrets SDK module:
//
//	go get github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets
//	go get github.com/Azure/azure-sdk-for-go/sdk/azidentity
//
// Then replace this stub with the full implementation from the project docs.
//
// Authentication uses DefaultAzureCredential:
//  1. Managed Identity — preferred on Azure VMs, AKS, App Service, etc.
//  2. Azure CLI credentials — for local development (`az login`).
//  3. Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET).
//
// Required Key Vault access:
//   - RBAC role: "Key Vault Secrets Officer" on the vault
type AzureProvider struct {
	vaultURL string
	prefix   string
}

func newAzureProvider(_ context.Context, vaultURL, prefix string) (*AzureProvider, error) {
	if vaultURL == "" {
		return nil, fmt.Errorf("--azure-keyvault-url is required when --secrets-backend=azure")
	}
	return &AzureProvider{vaultURL: vaultURL, prefix: prefix}, nil
}

func (p *AzureProvider) Set(_ context.Context, name, _ string) (string, error) {
	return "", fmt.Errorf("Azure Key Vault backend not yet activated. " +
		"Run: go get github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets " +
		"then wire in the full implementation (see docs/ARCHITECTURE.md)")
}

func (p *AzureProvider) Get(_ context.Context, ref string) (string, error) {
	return "", fmt.Errorf("Azure Key Vault backend not yet activated. " +
		"Run: go get github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets " +
		"(secret ref: %s)", ref)
}

func (p *AzureProvider) Delete(_ context.Context, _ string) error {
	return nil // no-op stub
}
