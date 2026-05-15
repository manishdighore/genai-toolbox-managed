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

// AWSProvider stores secrets in AWS Secrets Manager.
//
// To enable this backend, add the AWS Secrets Manager SDK module:
//
//	go get github.com/aws/aws-sdk-go-v2/service/secretsmanager
//
// Then replace this stub with the full implementation from the project docs.
//
// Authentication uses the AWS SDK default credential chain:
//  1. EC2 instance profile / ECS task role / Lambda execution role — preferred in production.
//  2. Environment variables (AWS_ACCESS_KEY_ID, etc.) — avoid in production.
//  3. ~/.aws/credentials — for local development.
//
// Required IAM permissions:
//   - secretsmanager:CreateSecret
//   - secretsmanager:PutSecretValue
//   - secretsmanager:GetSecretValue
//   - secretsmanager:DeleteSecret
type AWSProvider struct {
	region string
	prefix string
}

func newAWSProvider(_ context.Context, region, prefix string) (*AWSProvider, error) {
	if region == "" {
		return nil, fmt.Errorf("--aws-region is required when --secrets-backend=aws")
	}
	return &AWSProvider{region: region, prefix: prefix}, nil
}

func (p *AWSProvider) Set(_ context.Context, name, _ string) (string, error) {
	return "", fmt.Errorf("AWS Secrets Manager backend not yet activated. " +
		"Run: go get github.com/aws/aws-sdk-go-v2/service/secretsmanager " +
		"then wire in the full implementation (see docs/ARCHITECTURE.md)")
}

func (p *AWSProvider) Get(_ context.Context, ref string) (string, error) {
	return "", fmt.Errorf("AWS Secrets Manager backend not yet activated. " +
		"Run: go get github.com/aws/aws-sdk-go-v2/service/secretsmanager " +
		"(secret ref: %s)", ref)
}

func (p *AWSProvider) Delete(_ context.Context, _ string) error {
	return nil // no-op stub
}
