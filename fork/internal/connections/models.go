// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Package connections manages the management database that stores DB connection
// metadata. Credentials are never stored here — only references to secrets
// stored in the configured secrets backend (GCP / AWS / Azure / plaintext).
package connections

import (
	"encoding/json"
	"time"
)

// Connection represents a user-configured database connection.
// Stored in the management DB. Passwords are NEVER stored here.
type Connection struct {
	ID          string `db:"id"`
	Name        string `db:"name"`        // unique; used as toolset name → /mcp/{name}
	DBType      string `db:"db_type"`     // postgres | mysql | mongodb | redis | ...
	Host        string `db:"host"`
	Port        int    `db:"port"`
	Database    string `db:"database"`
	Username    string `db:"username"`
	SSLMode     string `db:"ssl_mode"`    // disable | require | verify-full
	Description string `db:"description"`

	// PasswordRef is the opaque reference stored in the secrets backend.
	// Format depends on the backend in use:
	//   GCP:       "projects/PROJECT/secrets/NAME/versions/latest"
	//   AWS:       "arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME"
	//   Azure:     "https://VAULT.vault.azure.net/secrets/NAME"
	//   Plaintext: "enc:BASE64_AES_GCM_CIPHERTEXT"
	PasswordRef string `db:"password_ref"`

	// ExtraParams stores database-specific parameters as a JSON object.
	// Used for fields that don't fit the standard host/port/user/database model.
	//   Snowflake:     {"schema":"PUBLIC","warehouse":"COMPUTE_WH"}
	//   Neo4j:         {"uri_scheme":"bolt"}   (builds bolt://host:port)
	//   MongoDB:       {"uri":"mongodb+srv://..."}  (full URI, overrides host/port/user)
	ExtraParams string `db:"extra_params"` // JSON, default "{}"

	LastTestedAt *time.Time `db:"last_tested_at"`
	LastTestOK   *bool      `db:"last_test_ok"`
	CreatedAt    time.Time  `db:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"`
}

// CreateRequest is the API request body for adding a connection.
// Password is accepted here and immediately sent to the secrets backend —
// it is never persisted to the management DB.
type CreateRequest struct {
	Name            string            `json:"name"`
	DBType          string            `json:"db_type"`
	Host            string            `json:"host"`
	Port            int               `json:"port"`
	Database        string            `json:"database"`
	Username        string            `json:"username"`
	Password        string            `json:"password"`         // direct plaintext (local tier)
	CredentialToken string            `json:"credential_token"` // single-use staged token (all tiers, preferred)
	SSLMode         string            `json:"ssl_mode"`
	Description     string            `json:"description"`
	// ExtraParams holds database-specific parameters not covered by the standard fields.
	// See DATABASES.md for per-database keys.
	ExtraParams     map[string]string `json:"extra_params,omitempty"`
}

// UpdateRequest is the API request body for updating a connection.
// All fields are optional. If Password is non-empty, it is rotated in the
// secrets backend and the PasswordRef is updated.
type UpdateRequest struct {
	Host            *string           `json:"host,omitempty"`
	Port            *int              `json:"port,omitempty"`
	Database        *string           `json:"database,omitempty"`
	Username        *string           `json:"username,omitempty"`
	Password        *string           `json:"password,omitempty"`         // direct plaintext, rotated in secrets backend
	CredentialToken *string           `json:"credential_token,omitempty"` // single-use staged token
	SSLMode         *string           `json:"ssl_mode,omitempty"`
	Description     *string           `json:"description,omitempty"`
	ExtraParams     map[string]string `json:"extra_params,omitempty"`
}

// Response is the API response shape for a connection.
// Password and PasswordRef are never included.
type Response struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	DBType       string            `json:"db_type"`
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Database     string            `json:"database"`
	Username     string            `json:"username"`
	SSLMode      string            `json:"ssl_mode"`
	Description  string            `json:"description"`
	ExtraParams  map[string]string `json:"extra_params,omitempty"`
	MCPEndpoint  string            `json:"mcp_endpoint"`
	LastTestedAt *time.Time        `json:"last_tested_at,omitempty"`
	LastTestOK   *bool             `json:"last_test_ok,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// ExtraParamsMap parses the stored JSON extra_params into a map.
// Returns an empty map if the field is empty or invalid.
func (c *Connection) ExtraParamsMap() map[string]string {
	if c.ExtraParams == "" || c.ExtraParams == "{}" {
		return nil
	}
	m := make(map[string]string)
	_ = json.Unmarshal([]byte(c.ExtraParams), &m)
	return m
}

// ExtraParamsMarshal encodes a map to the JSON string stored in extra_params.
func ExtraParamsMarshal(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ToResponse converts a stored Connection to a safe API response.
// toolboxBaseURL is used to construct the mcp_endpoint field.
func (c *Connection) ToResponse(toolboxBaseURL string) Response {
	return Response{
		ID:           c.ID,
		Name:         c.Name,
		DBType:       c.DBType,
		Host:         c.Host,
		Port:         c.Port,
		Database:     c.Database,
		Username:     c.Username,
		SSLMode:      c.SSLMode,
		Description:  c.Description,
		ExtraParams:  c.ExtraParamsMap(),
		MCPEndpoint:  toolboxBaseURL + "/mcp/" + c.Name,
		LastTestedAt: c.LastTestedAt,
		LastTestOK:   c.LastTestOK,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}

// TestResult is returned by the connection test endpoint.
// Always HTTP 200 — inspect the OK field to determine pass/fail.
type TestResult struct {
	OK            bool   `json:"ok"`
	LatencyMs     *int64 `json:"latency_ms"`
	ServerVersion string `json:"server_version,omitempty"`
	Message       string `json:"message"`
}
