// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/googleapis/genai-toolbox/internal/connections"
	"github.com/googleapis/genai-toolbox/internal/tools"
	"github.com/googleapis/genai-toolbox/internal/util"
	"github.com/googleapis/genai-toolbox/internal/util/parameters"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// apiRouter creates a router that represents the routes under /api
func apiRouter(s *Server) (chi.Router, error) {
	r := chi.NewRouter()

	r.Use(middleware.AllowContentType("application/json"))
	r.Use(middleware.StripSlashes)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	r.Get("/toolset", func(w http.ResponseWriter, r *http.Request) { toolsetHandler(s, w, r) })
	r.Get("/toolset/{toolsetName}", func(w http.ResponseWriter, r *http.Request) { toolsetHandler(s, w, r) })

	r.Route("/tool/{toolName}", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) { toolGetHandler(s, w, r) })
		r.Post("/invoke", func(w http.ResponseWriter, r *http.Request) { toolInvokeHandler(s, w, r) })
	})

	return r, nil
}

// toolsetHandler handles the request for information about a Toolset.
func toolsetHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	ctx, span := s.instrumentation.Tracer.Start(r.Context(), "toolbox/server/toolset/get")
	r = r.WithContext(ctx)

	toolsetName := chi.URLParam(r, "toolsetName")
	s.logger.DebugContext(ctx, fmt.Sprintf("toolset name: %s", toolsetName))
	span.SetAttributes(attribute.String("toolset.name", toolsetName))
	var err error
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	toolset, ok := s.ResourceMgr.GetToolset(toolsetName)
	if !ok {
		err = fmt.Errorf("toolset %q does not exist", toolsetName)
		s.logger.DebugContext(ctx, err.Error())
		_ = render.Render(w, r, newErrResponse(err, http.StatusNotFound))
		return
	}
	render.JSON(w, r, toolset.Manifest)
}

// toolGetHandler handles requests for a single Tool.
func toolGetHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	ctx, span := s.instrumentation.Tracer.Start(r.Context(), "toolbox/server/tool/get")
	r = r.WithContext(ctx)

	toolName := chi.URLParam(r, "toolName")
	s.logger.DebugContext(ctx, fmt.Sprintf("tool name: %s", toolName))
	span.SetAttributes(attribute.String("tool_name", toolName))
	var err error
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	tool, ok := s.ResourceMgr.GetTool(toolName)
	if !ok {
		err = fmt.Errorf("invalid tool name: tool with name %q does not exist", toolName)
		s.logger.DebugContext(ctx, err.Error())
		_ = render.Render(w, r, newErrResponse(err, http.StatusNotFound))
		return
	}
	// TODO: this can be optimized later with some caching
	m := tools.ToolsetManifest{
		ServerVersion: s.version,
		ToolsManifest: map[string]tools.Manifest{
			toolName: tool.Manifest(),
		},
	}

	render.JSON(w, r, m)
}

// toolInvokeHandler handles the API request to invoke a specific Tool.
func toolInvokeHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	ctx, span := s.instrumentation.Tracer.Start(r.Context(), "toolbox/server/tool/invoke")
	r = r.WithContext(ctx)
	ctx = util.WithLogger(r.Context(), s.logger)

	toolName := chi.URLParam(r, "toolName")
	s.logger.DebugContext(ctx, fmt.Sprintf("tool name: %s", toolName))
	span.SetAttributes(attribute.String("tool_name", toolName))
	var err error
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	tool, ok := s.ResourceMgr.GetTool(toolName)
	if !ok {
		err = fmt.Errorf("invalid tool name: tool with name %q does not exist", toolName)
		s.logger.DebugContext(ctx, err.Error())
		_ = render.Render(w, r, newErrResponse(err, http.StatusNotFound))
		return
	}

	// Extract OAuth access token from the "Authorization" header (currently for
	// BigQuery end-user credentials usage only)
	accessToken := tools.AccessToken(r.Header.Get("Authorization"))

	// Check if this specific tool requires the standard authorization header
	clientAuth, err := tool.RequiresClientAuthorization(s.ResourceMgr)
	if err != nil {
		errMsg := fmt.Errorf("error during invocation: %w", err)
		s.logger.DebugContext(ctx, errMsg.Error())
		_ = render.Render(w, r, newErrResponse(errMsg, http.StatusNotFound))
		return
	}
	if clientAuth {
		if accessToken == "" {
			err = fmt.Errorf("tool requires client authorization but access token is missing from the request header")
			s.logger.DebugContext(ctx, err.Error())
			_ = render.Render(w, r, newErrResponse(err, http.StatusUnauthorized))
			return
		}
	}

	// Tool authentication
	// claimsFromAuth maps the name of the authservice to the claims retrieved from it.
	claimsFromAuth := make(map[string]map[string]any)
	for _, aS := range s.ResourceMgr.GetAuthServiceMap() {
		claims, err := aS.GetClaimsFromHeader(ctx, r.Header)
		if err != nil {
			s.logger.DebugContext(ctx, err.Error())
			continue
		}
		if claims == nil {
			// authService not present in header
			continue
		}
		claimsFromAuth[aS.GetName()] = claims
	}

	// Tool authorization check
	verifiedAuthServices := make([]string, len(claimsFromAuth))
	i := 0
	for k := range claimsFromAuth {
		verifiedAuthServices[i] = k
		i++
	}

	// Check if any of the specified auth services is verified
	isAuthorized := tool.Authorized(verifiedAuthServices)
	if !isAuthorized {
		err = fmt.Errorf("tool invocation not authorized. Please make sure you specify correct auth headers")
		s.logger.DebugContext(ctx, err.Error())
		_ = render.Render(w, r, newErrResponse(err, http.StatusUnauthorized))
		return
	}
	s.logger.DebugContext(ctx, "tool invocation authorized")

	var data map[string]any
	if err = util.DecodeJSON(r.Body, &data); err != nil {
		render.Status(r, http.StatusBadRequest)
		err = fmt.Errorf("request body was invalid JSON: %w", err)
		s.logger.DebugContext(ctx, err.Error())
		_ = render.Render(w, r, newErrResponse(err, http.StatusBadRequest))
		return
	}

	params, err := parameters.ParseParams(tool.GetParameters(), data, claimsFromAuth)
	if err != nil {
		var clientServerErr *util.ClientServerError

		// Return 401 Authentication errors
		if errors.As(err, &clientServerErr) && clientServerErr.Code == http.StatusUnauthorized {
			s.logger.DebugContext(ctx, fmt.Sprintf("auth error: %v", err))
			_ = render.Render(w, r, newErrResponse(err, http.StatusUnauthorized))
			return
		}

		var agentErr *util.AgentError
		if errors.As(err, &agentErr) {
			s.logger.DebugContext(ctx, fmt.Sprintf("agent validation error: %v", err))
			errMap := map[string]string{"error": err.Error()}
			errMarshal, _ := json.Marshal(errMap)

			_ = render.Render(w, r, &resultResponse{Result: string(errMarshal)})
			return
		}

		// Return 500 if it's a specific ClientServerError that isn't a 401, or any other unexpected error
		s.logger.ErrorContext(ctx, fmt.Sprintf("internal server error: %v", err))
		_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
		return
	}
	s.logger.DebugContext(ctx, fmt.Sprintf("invocation params: %s", params))

	params, err = tool.EmbedParams(ctx, params, s.ResourceMgr.GetEmbeddingModelMap())
	if err != nil {
		err = fmt.Errorf("error embedding parameters: %w", err)
		s.logger.DebugContext(ctx, err.Error())
		_ = render.Render(w, r, newErrResponse(err, http.StatusBadRequest))
		return
	}

	res, err := tool.Invoke(ctx, s.ResourceMgr, params, accessToken)

	// Determine what error to return to the users.
	if err != nil {
		var tbErr util.ToolboxError

		if errors.As(err, &tbErr) {
			switch tbErr.Category() {
			case util.CategoryAgent:
				// Agent Errors -> 200 OK
				s.logger.DebugContext(ctx, fmt.Sprintf("Tool invocation agent error: %v", err))
				res = map[string]string{
					"error": err.Error(),
				}

			case util.CategoryServer:
				// Server Errors -> Check the specific code inside
				var clientServerErr *util.ClientServerError
				statusCode := http.StatusInternalServerError // Default to 500

				if errors.As(err, &clientServerErr) {
					if clientServerErr.Code != 0 {
						statusCode = clientServerErr.Code
					}
				}

				// Process auth error
				if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
					if clientAuth {
						// Token error, pass through 401/403
						s.logger.DebugContext(ctx, fmt.Sprintf("Client credentials lack authorization: %v", err))
						_ = render.Render(w, r, newErrResponse(err, statusCode))
						return
					}
					// ADC/Config error, return 500
					statusCode = http.StatusInternalServerError
				}

				s.logger.ErrorContext(ctx, fmt.Sprintf("Tool invocation server error: %v", err))
				_ = render.Render(w, r, newErrResponse(err, statusCode))
				return
			}
		} else {
			// Unknown error -> 500
			s.logger.ErrorContext(ctx, fmt.Sprintf("Tool invocation unknown error: %v", err))
			_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
			return
		}
	}

	resMarshal, err := json.Marshal(res)
	if err != nil {
		err = fmt.Errorf("unable to marshal result: %w", err)
		s.logger.DebugContext(ctx, err.Error())
		_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
		return
	}

	_ = render.Render(w, r, &resultResponse{Result: string(resMarshal)})
}

var _ render.Renderer = &resultResponse{} // Renderer interface for managing response payloads.

// resultResponse is the response sent back when the tool was invocated successfully.
type resultResponse struct {
	Result string `json:"result"` // result of tool invocation
}

// Render renders a single payload and respond to the client request.
func (rr resultResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, http.StatusOK)
	return nil
}

var _ render.Renderer = &errResponse{} // Renderer interface for managing response payloads.

// newErrResponse is a helper function initializing an ErrResponse
func newErrResponse(err error, code int) *errResponse {
	return &errResponse{
		Err:            err,
		HTTPStatusCode: code,

		StatusText: http.StatusText(code),
		ErrorText:  err.Error(),
	}
}

// errResponse is the response sent back when an error has been encountered.
type errResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status"`          // user-level status message
	ErrorText  string `json:"error,omitempty"` // application-level error message, for debugging
}

func (e *errResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

// ---------------------------------------------------------------------------
// Management router — only mounted when --config-mode=db
// Handles all connection lifecycle: pre-save test, CRUD, post-save test, reload.
// ---------------------------------------------------------------------------

// managementRouter creates the /api/connections subrouter.
func managementRouter(s *Server) (chi.Router, error) {
	r := chi.NewRouter()
	r.Use(middleware.AllowContentType("application/json"))
	r.Use(middleware.StripSlashes)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	// Pre-save test — test credentials without persisting anything.
	r.Post("/test", func(w http.ResponseWriter, r *http.Request) { preTestHandler(s, w, r) })

	// Force reload from DB (recovery / manual trigger).
	r.Post("/reload", func(w http.ResponseWriter, r *http.Request) { reloadHandler(s, w, r) })

	// SaaS two-phase flow — only mounted when pendingStore is active.
	if s.pendingStore != nil {
		r.Post("/prepare", func(w http.ResponseWriter, r *http.Request) { prepareConnectionHandler(s, w, r) })
		r.Post("/confirm", func(w http.ResponseWriter, r *http.Request) { confirmConnectionHandler(s, w, r) })
	}

	// Connection CRUD.
	r.Get("/", func(w http.ResponseWriter, r *http.Request) { listConnectionsHandler(s, w, r) })
	r.Post("/", func(w http.ResponseWriter, r *http.Request) { createConnectionHandler(s, w, r) })

	r.Route("/{id}", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) { getConnectionHandler(s, w, r) })
		r.Put("/", func(w http.ResponseWriter, r *http.Request) { updateConnectionHandler(s, w, r) })
		r.Delete("/", func(w http.ResponseWriter, r *http.Request) { deleteConnectionHandler(s, w, r) })
		// Post-save test — re-test an existing connection (fetches password from secrets).
		r.Post("/test", func(w http.ResponseWriter, r *http.Request) { postTestHandler(s, w, r) })
	})

	return r, nil
}

// ---------------------------------------------------------------------------
// POST /api/connections/test
// Test credentials without saving anything. Frontend uses this for the
// "Test Connection" button before the user confirms the save.
// ---------------------------------------------------------------------------
func preTestHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	var req connections.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("invalid JSON: %w", err), http.StatusBadRequest))
		return
	}
	if err := validateCreateRequest(&req); err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusUnprocessableEntity))
		return
	}

	password, err := s.resolvePassword(req.CredentialToken, req.Password)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusBadRequest))
		return
	}

	result := connections.TestFromParams(r.Context(), connections.TestParams{
		DBType:   req.DBType,
		Host:     req.Host,
		Port:     req.Port,
		Database: req.Database,
		Username: req.Username,
		Password: password,
		SSLMode:  req.SSLMode,
	})
	// Always 200 — caller checks result.OK.
	render.JSON(w, r, result)
}

// ---------------------------------------------------------------------------
// POST /api/connections
// Test → store secret → persist → reload. Only saves if the test passes.
// ---------------------------------------------------------------------------
func createConnectionHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	var req connections.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("invalid JSON: %w", err), http.StatusBadRequest))
		return
	}
	if err := validateCreateRequest(&req); err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusUnprocessableEntity))
		return
	}

	// Name must be unique.
	exists, err := s.connStore.NameExists(r.Context(), req.Name)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
		return
	}
	if exists {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("A connection named %q already exists. Choose a different name or delete the existing one first.", req.Name),
			http.StatusConflict,
		))
		return
	}

	// Resolve password from staged token or direct value.
	password, err := s.resolvePassword(req.CredentialToken, req.Password)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusBadRequest))
		return
	}

	// Test credentials before touching the secrets backend or the DB.
	result := connections.TestFromParams(r.Context(), connections.TestParams{
		DBType:   req.DBType,
		Host:     req.Host,
		Port:     req.Port,
		Database: req.Database,
		Username: req.Username,
		Password: password,
		SSLMode:  req.SSLMode,
	})
	if !result.OK {
		render.Status(r, http.StatusUnprocessableEntity)
		render.JSON(w, r, map[string]any{
			"error":       fmt.Sprintf("Could not connect to %s:%d — %s", req.Host, req.Port, friendlyTestError(result.Message)),
			"test_result": result,
		})
		return
	}

	// Store password in secrets backend. Nothing is saved to the management
	// DB until this succeeds.
	secretRef, err := s.secretsProvider.Set(r.Context(), "dbmcp/"+req.Name, password)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("storing credentials: %w", err),
			http.StatusInternalServerError,
		))
		return
	}

	ssl := req.SSLMode
	if ssl == "" {
		ssl = "require"
	}
	conn := &connections.Connection{
		Name:        req.Name,
		DBType:      req.DBType,
		Host:        req.Host,
		Port:        req.Port,
		Database:    req.Database,
		Username:    req.Username,
		SSLMode:     ssl,
		Description: req.Description,
		PasswordRef: secretRef,
		ExtraParams: connections.ExtraParamsMarshal(req.ExtraParams),
	}
	if err := s.connStore.Create(r.Context(), conn); err != nil {
		// Secret was stored but DB insert failed — clean up the secret so
		// there are no orphaned credentials.
		_ = s.secretsProvider.Delete(r.Context(), secretRef)
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("saving connection: %w", err),
			http.StatusInternalServerError,
		))
		return
	}

	// Record the successful test result.
	_ = s.connStore.UpdateTestResult(r.Context(), conn.ID, true)

	// Reload Toolbox config — new /mcp/{name} endpoint goes live immediately.
	if err := s.reloadFromDB(r.Context()); err != nil {
		s.logger.WarnContext(r.Context(), fmt.Sprintf("connection saved but reload failed: %v", err))
	}

	render.Status(r, http.StatusCreated)
	render.JSON(w, r, conn.ToResponse(resolveBaseURL(s, r)))
}

// ---------------------------------------------------------------------------
// GET /api/connections
// ---------------------------------------------------------------------------
func listConnectionsHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	conns, err := s.connStore.List(r.Context())
	if err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
		return
	}
	base := resolveBaseURL(s, r)
	resp := make([]connections.Response, 0, len(conns))
	for _, c := range conns {
		resp = append(resp, c.ToResponse(base))
	}
	render.JSON(w, r, resp)
}

// ---------------------------------------------------------------------------
// GET /api/connections/:id
// ---------------------------------------------------------------------------
func getConnectionHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	conn, err := s.connStore.Get(r.Context(), id)
	if err != nil {
		code := http.StatusInternalServerError
		if err.Error() == "not found" {
			code = http.StatusNotFound
		}
		_ = render.Render(w, r, newErrResponse(err, code))
		return
	}
	render.JSON(w, r, conn.ToResponse(resolveBaseURL(s, r)))
}

// ---------------------------------------------------------------------------
// PUT /api/connections/:id
// If password is provided, rotate it in the secrets backend before updating.
// Test new credentials before committing any changes.
// ---------------------------------------------------------------------------
func updateConnectionHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	existing, err := s.connStore.Get(r.Context(), id)
	if err != nil {
		code := http.StatusInternalServerError
		if err.Error() == "not found" {
			code = http.StatusNotFound
		}
		_ = render.Render(w, r, newErrResponse(err, code))
		return
	}

	var req connections.UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = render.Render(w, r, newErrResponse(fmt.Errorf("invalid JSON: %w", err), http.StatusBadRequest))
		return
	}

	// Apply partial updates to a working copy.
	updated := *existing
	if req.Host != nil {
		updated.Host = *req.Host
	}
	if req.Port != nil {
		updated.Port = *req.Port
	}
	if req.Database != nil {
		updated.Database = *req.Database
	}
	if req.Username != nil {
		updated.Username = *req.Username
	}
	if req.SSLMode != nil {
		updated.SSLMode = *req.SSLMode
	}
	if req.Description != nil {
		updated.Description = *req.Description
	}
	if req.ExtraParams != nil {
		updated.ExtraParams = connections.ExtraParamsMarshal(req.ExtraParams)
	}

	// Resolve the password to use for the connectivity test.
	// Prefer credential_token, then explicit password, then the current stored password.
	testPassword := ""
	credToken := ""
	if req.CredentialToken != nil {
		credToken = *req.CredentialToken
	}
	rawPwd := ""
	if req.Password != nil {
		rawPwd = *req.Password
	}
	if credToken != "" || rawPwd != "" {
		testPassword, err = s.resolvePassword(credToken, rawPwd)
		if err != nil {
			_ = render.Render(w, r, newErrResponse(err, http.StatusBadRequest))
			return
		}
	} else {
		testPassword, err = s.secretsProvider.Get(r.Context(), existing.PasswordRef)
		if err != nil {
			_ = render.Render(w, r, newErrResponse(
				fmt.Errorf("fetching current credentials for test: %w", err),
				http.StatusInternalServerError,
			))
			return
		}
	}

	// Test before committing any changes.
	result := connections.TestFromParams(r.Context(), connections.TestParams{
		DBType:   updated.DBType,
		Host:     updated.Host,
		Port:     updated.Port,
		Database: updated.Database,
		Username: updated.Username,
		Password: testPassword,
		SSLMode:  updated.SSLMode,
	})
	if !result.OK {
		render.Status(r, http.StatusUnprocessableEntity)
		render.JSON(w, r, map[string]any{
			"error":       "connection test failed — no changes saved",
			"test_result": result,
		})
		return
	}

	// Rotate the secret if a new password was provided (via token or direct).
	if credToken != "" || rawPwd != "" {
		newRef, err := s.secretsProvider.Set(r.Context(), "dbmcp/"+existing.Name, testPassword)
		if err != nil {
			_ = render.Render(w, r, newErrResponse(
				fmt.Errorf("rotating credentials: %w", err),
				http.StatusInternalServerError,
			))
			return
		}
		updated.PasswordRef = newRef
	}

	updated.UpdatedAt = time.Now().UTC()
	if err := s.connStore.Update(r.Context(), &updated); err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
		return
	}
	_ = s.connStore.UpdateTestResult(r.Context(), updated.ID, true)

	if err := s.reloadFromDB(r.Context()); err != nil {
		s.logger.WarnContext(r.Context(), fmt.Sprintf("connection updated but reload failed: %v", err))
	}

	render.JSON(w, r, updated.ToResponse(resolveBaseURL(s, r)))
}

// ---------------------------------------------------------------------------
// DELETE /api/connections/:id
// Removes the secret from the secrets backend, then the DB row, then reloads.
// ---------------------------------------------------------------------------
func deleteConnectionHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	conn, err := s.connStore.Get(r.Context(), id)
	if err != nil {
		code := http.StatusInternalServerError
		if err.Error() == "not found" {
			code = http.StatusNotFound
		}
		_ = render.Render(w, r, newErrResponse(err, code))
		return
	}

	// Delete from secrets backend first. If this fails, log and continue —
	// the DB row must still be removed to avoid a broken state where the
	// connection appears active but its secret is gone.
	if err := s.secretsProvider.Delete(r.Context(), conn.PasswordRef); err != nil {
		s.logger.WarnContext(r.Context(), fmt.Sprintf(
			"could not delete secret %q for connection %q: %v — DB row will still be removed",
			conn.PasswordRef, conn.Name, err,
		))
	}

	if err := s.connStore.Delete(r.Context(), id); err != nil {
		_ = render.Render(w, r, newErrResponse(err, http.StatusInternalServerError))
		return
	}

	if err := s.reloadFromDB(r.Context()); err != nil {
		s.logger.WarnContext(r.Context(), fmt.Sprintf("connection deleted but reload failed: %v", err))
	}

	render.JSON(w, r, map[string]string{"deleted": id})
}

// ---------------------------------------------------------------------------
// POST /api/connections/:id/test
// Test an existing saved connection. Fetches credentials from secrets backend.
// Does NOT modify the connection or trigger a reload.
// ---------------------------------------------------------------------------
func postTestHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	conn, err := s.connStore.Get(r.Context(), id)
	if err != nil {
		code := http.StatusInternalServerError
		if err.Error() == "not found" {
			code = http.StatusNotFound
		}
		_ = render.Render(w, r, newErrResponse(err, code))
		return
	}

	password, err := s.secretsProvider.Get(r.Context(), conn.PasswordRef)
	if err != nil {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("fetching credentials: %w", err),
			http.StatusInternalServerError,
		))
		return
	}

	result := connections.Test(r.Context(), conn, password)

	// Persist the test result (last_tested_at, last_test_ok) regardless of outcome.
	_ = s.connStore.UpdateTestResult(r.Context(), id, result.OK)

	render.JSON(w, r, result)
}

// ---------------------------------------------------------------------------
// POST /api/connections/reload
// Force a full config regeneration from DB. Normally triggered automatically.
// Use this for recovery after a failed automatic reload.
// ---------------------------------------------------------------------------
func reloadHandler(s *Server, w http.ResponseWriter, r *http.Request) {
	if err := s.reloadFromDB(r.Context()); err != nil {
		_ = render.Render(w, r, newErrResponse(
			fmt.Errorf("reload failed: %w", err),
			http.StatusInternalServerError,
		))
		return
	}
	count, _ := s.connStore.List(r.Context())
	render.JSON(w, r, map[string]any{
		"ok":                  true,
		"connections_reloaded": len(count),
	})
}

// resolveBaseURL returns the base URL for building mcp_endpoint values.
// Prefers the configured --toolbox-url, then falls back to the Host header
// from the incoming request so the URL is always correct regardless of port.
func resolveBaseURL(s *Server, r *http.Request) string {
	if s.toolboxUrl != "" {
		return s.toolboxUrl
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// ---------------------------------------------------------------------------
// friendlyTestError maps raw driver/network error strings to readable messages.
// ---------------------------------------------------------------------------
func friendlyTestError(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "connection refused"):
		return "Connection refused. Check that the host and port are correct and the database server is running."
	case strings.Contains(lower, "no such host"), strings.Contains(lower, "no route to host"):
		return "Host not found. Double-check the hostname or IP address."
	case strings.Contains(lower, "i/o timeout"), strings.Contains(lower, "timeout"):
		return "Connection timed out. The host may be unreachable or blocked by a firewall."
	case strings.Contains(lower, "password authentication failed"), strings.Contains(lower, "access denied"):
		return "Wrong username or password. Check your credentials and try again."
	case strings.Contains(lower, "ssl"), strings.Contains(lower, "tls"):
		return "SSL/TLS error. Try changing SSL mode to \"disable\" if your database does not have SSL configured."
	case strings.Contains(lower, "database") && strings.Contains(lower, "does not exist"):
		return "Database not found. Check the database name."
	case strings.Contains(lower, "tcp dial"):
		return "Could not reach the server. Check the host, port, and any firewall rules."
	default:
		return msg
	}
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

var validNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

func validateCreateRequest(req *connections.CreateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("Connection name is required.")
	}
	if !validNameRe.MatchString(req.Name) {
		return fmt.Errorf("Connection name %q is invalid. Use only letters, numbers, hyphens, and underscores (e.g. \"my-database\" or \"prod_postgres\"). Maximum 63 characters.", req.Name)
	}
	if req.DBType == "" {
		return fmt.Errorf("Database type is required. Choose from: postgres, mysql, mssql, sqlite, mongodb, redis, etc.")
	}
	if req.Host == "" {
		return fmt.Errorf("Host is required. Enter a hostname or IP address (e.g. \"db.example.com\" or \"127.0.0.1\").")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return fmt.Errorf("Port %d is invalid. Enter a valid port number between 1 and 65535.", req.Port)
	}
	if req.Database == "" {
		return fmt.Errorf("Database name is required.")
	}
	if req.Username == "" {
		return fmt.Errorf("Username is required.")
	}
	if req.Password == "" && req.CredentialToken == "" {
		return fmt.Errorf("A password is required. Provide either a \"password\" or a staged \"credential_token\".")
	}
	return nil
}
