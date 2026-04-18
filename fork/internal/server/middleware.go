// Copyright 2026 db-mcp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
)

// sensitiveFields — values for these JSON keys are replaced with "[REDACTED]"
// in any logged representation of request bodies.
var sensitiveFields = []string{
	"password",
	"encrypted_password",
	"credential_token",
	"upload_token",
	"secret",
}

type ctxKeyRedactedBody struct{}

// HTTPSRedirectMiddleware redirects plain HTTP to HTTPS.
// Exempt: loopback addresses (127.0.0.1, ::1, localhost) for local dev.
// Behind a TLS-terminating proxy: checks X-Forwarded-Proto header.
func HTTPSRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if isLoopback(host) {
			next.ServeHTTP(w, r)
			return
		}
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto != "" {
			if proto != "https" {
				http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
				return
			}
		} else if r.TLS == nil {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LogRedactionMiddleware reads the JSON request body, replaces values of
// sensitive fields with "[REDACTED]", and stores the sanitised copy in the
// request context. The ORIGINAL body is fully restored for the handler.
//
// Purpose: any logging middleware running after this one (or any handler that
// logs the body) will find only the sanitised version — passwords never appear
// in logs regardless of how logging is configured downstream.
func LogRedactionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if r.Body == nil || !strings.Contains(ct, "application/json") {
			next.ServeHTTP(w, r)
			return
		}

		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()

		// Always restore the original body — handler must see the real data.
		r.Body = io.NopCloser(bytes.NewReader(raw))

		if err == nil && len(raw) > 0 {
			var body map[string]any
			if json.Unmarshal(raw, &body) == nil {
				redacted, _ := json.Marshal(redactFields(body))
				ctx := context.WithValue(r.Context(), ctxKeyRedactedBody{}, redacted)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RedactedBodyFromRequest returns the sanitised request body stored by
// LogRedactionMiddleware. Use this in structured logging instead of r.Body.
func RedactedBodyFromRequest(r *http.Request) []byte {
	if v, ok := r.Context().Value(ctxKeyRedactedBody{}).([]byte); ok {
		return v
	}
	return nil
}

// redactFields recursively replaces values of sensitive keys with "[REDACTED]".
func redactFields(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if isSensitiveField(k) {
			if v != nil && v != "" {
				out[k] = "[REDACTED]"
			} else {
				out[k] = v
			}
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = redactFields(nested)
		} else {
			out[k] = v
		}
	}
	return out
}

func isSensitiveField(name string) bool {
	lower := strings.ToLower(name)
	for _, f := range sensitiveFields {
		if lower == f || strings.HasSuffix(lower, "_"+f) {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
