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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httplog/v3"
	"github.com/go-chi/render"
	"github.com/googleapis/genai-toolbox/internal/auth"
	"github.com/googleapis/genai-toolbox/internal/auth/generic"
	"github.com/googleapis/genai-toolbox/internal/connections"
	"github.com/googleapis/genai-toolbox/internal/embeddingmodels"
	"github.com/googleapis/genai-toolbox/internal/log"
	"github.com/googleapis/genai-toolbox/internal/prompts"
	"github.com/googleapis/genai-toolbox/internal/secrets"
	"github.com/googleapis/genai-toolbox/internal/server/resources"
	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/googleapis/genai-toolbox/internal/telemetry"
	"github.com/googleapis/genai-toolbox/internal/tools"
	"github.com/googleapis/genai-toolbox/internal/util"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Server contains info for running an instance of Toolbox. Should be instantiated with NewServer().
type Server struct {
	version         string
	toolboxUrl      string
	srv             *http.Server
	listener        net.Listener
	root            chi.Router
	logger          log.Logger
	instrumentation *telemetry.Instrumentation
	sseManager      *sseManager
	ResourceMgr     *resources.ResourceManager
	mcpPrmFile      string

	// DB mode — only populated when cfg.ConfigMode == "db".
	connStore       *connections.Store
	secretsProvider secrets.Provider
	stagingStore    *StagingStore
	keyStore        *KeyStore
	pendingStore    *PendingStore
	scopedIssuer    ScopedTokenIssuer
}

func InitializeConfigs(ctx context.Context, cfg ServerConfig) (
	map[string]sources.Source,
	map[string]auth.AuthService,
	map[string]embeddingmodels.EmbeddingModel,
	map[string]tools.Tool,
	map[string]tools.Toolset,
	map[string]prompts.Prompt,
	map[string]prompts.Promptset,
	error,
) {
	metadataStr := cfg.Version
	if len(cfg.UserAgentMetadata) > 0 {
		metadataStr += "+" + strings.Join(cfg.UserAgentMetadata, "+")
	}
	ctx = util.WithUserAgent(ctx, metadataStr)
	instrumentation, err := util.InstrumentationFromContext(ctx)
	if err != nil {
		panic(err)
	}

	l, err := util.LoggerFromContext(ctx)
	if err != nil {
		panic(err)
	}

	// initialize and validate the sources from configs
	sourcesMap := make(map[string]sources.Source)
	for name, sc := range cfg.SourceConfigs {
		s, err := func() (sources.Source, error) {
			childCtx, span := instrumentation.Tracer.Start(
				ctx,
				"toolbox/server/source/init",
				trace.WithAttributes(attribute.String("source_type", sc.SourceConfigType())),
				trace.WithAttributes(attribute.String("source_name", name)),
			)
			defer span.End()
			s, err := sc.Initialize(childCtx, instrumentation.Tracer)
			if err != nil {
				return nil, fmt.Errorf("unable to initialize source %q: %w", name, err)
			}
			return s, nil
		}()
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		sourcesMap[name] = s
	}
	sourceNames := make([]string, 0, len(sourcesMap))
	for name := range sourcesMap {
		sourceNames = append(sourceNames, name)
	}
	l.InfoContext(ctx, fmt.Sprintf("Initialized %d sources: %s", len(sourcesMap), strings.Join(sourceNames, ", ")))

	// initialize and validate the auth services from configs
	authServicesMap := make(map[string]auth.AuthService)
	for name, sc := range cfg.AuthServiceConfigs {
		a, err := func() (auth.AuthService, error) {
			_, span := instrumentation.Tracer.Start(
				ctx,
				"toolbox/server/auth/init",
				trace.WithAttributes(attribute.String("auth_type", sc.AuthServiceConfigType())),
				trace.WithAttributes(attribute.String("auth_name", name)),
			)
			defer span.End()
			a, err := sc.Initialize()
			if err != nil {
				return nil, fmt.Errorf("unable to initialize auth service %q: %w", name, err)
			}
			return a, nil
		}()
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		authServicesMap[name] = a
	}
	authServiceNames := make([]string, 0, len(authServicesMap))
	for name := range authServicesMap {
		authServiceNames = append(authServiceNames, name)
	}
	l.InfoContext(ctx, fmt.Sprintf("Initialized %d authServices: %s", len(authServicesMap), strings.Join(authServiceNames, ", ")))

	// Initialize and validate embedding models from configs.
	embeddingModelsMap := make(map[string]embeddingmodels.EmbeddingModel)
	for name, ec := range cfg.EmbeddingModelConfigs {
		em, err := func() (embeddingmodels.EmbeddingModel, error) {
			_, span := instrumentation.Tracer.Start(
				ctx,
				"toolbox/server/embeddingmodel/init",
				trace.WithAttributes(attribute.String("model_type", ec.EmbeddingModelConfigType())),
				trace.WithAttributes(attribute.String("model_name", name)),
			)
			defer span.End()
			em, err := ec.Initialize(ctx)
			if err != nil {
				return nil, fmt.Errorf("unable to initialize embedding model %q: %w", name, err)
			}
			return em, nil
		}()
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		embeddingModelsMap[name] = em
	}
	embeddingModelNames := make([]string, 0, len(embeddingModelsMap))
	for name := range embeddingModelsMap {
		embeddingModelNames = append(embeddingModelNames, name)
	}
	l.InfoContext(ctx, fmt.Sprintf("Initialized %d embeddingModels: %s", len(embeddingModelsMap), strings.Join(embeddingModelNames, ", ")))

	// initialize and validate the tools from configs
	toolsMap := make(map[string]tools.Tool)
	for name, tc := range cfg.ToolConfigs {
		t, err := func() (tools.Tool, error) {
			_, span := instrumentation.Tracer.Start(
				ctx,
				"toolbox/server/tool/init",
				trace.WithAttributes(attribute.String("tool_type", tc.ToolConfigType())),
				trace.WithAttributes(attribute.String("tool_name", name)),
			)
			defer span.End()
			t, err := tc.Initialize(sourcesMap)
			if err != nil {
				return nil, fmt.Errorf("unable to initialize tool %q: %w", name, err)
			}
			return t, nil
		}()
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		toolsMap[name] = t
	}
	toolNames := make([]string, 0, len(toolsMap))
	for name := range toolsMap {
		toolNames = append(toolNames, name)
	}
	l.InfoContext(ctx, fmt.Sprintf("Initialized %d tools: %s", len(toolsMap), strings.Join(toolNames, ", ")))

	// create a default toolset that contains all tools
	allToolNames := make([]string, 0, len(toolsMap))
	for name := range toolsMap {
		allToolNames = append(allToolNames, name)
	}
	if cfg.ToolsetConfigs == nil {
		cfg.ToolsetConfigs = make(ToolsetConfigs)
	}
	cfg.ToolsetConfigs[""] = tools.ToolsetConfig{Name: "", ToolNames: allToolNames}

	// initialize and validate the toolsets from configs
	toolsetsMap := make(map[string]tools.Toolset)
	for name, tc := range cfg.ToolsetConfigs {
		t, err := func() (tools.Toolset, error) {
			_, span := instrumentation.Tracer.Start(
				ctx,
				"toolbox/server/toolset/init",
				trace.WithAttributes(attribute.String("toolset.name", name)),
			)
			defer span.End()
			t, err := tc.Initialize(cfg.Version, toolsMap)
			if err != nil {
				return tools.Toolset{}, fmt.Errorf("unable to initialize toolset %q: %w", name, err)
			}
			return t, err
		}()
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		toolsetsMap[name] = t
	}
	toolsetNames := make([]string, 0, len(toolsetsMap))
	for name := range toolsetsMap {
		if name == "" {
			toolsetNames = append(toolsetNames, "default")
		} else {
			toolsetNames = append(toolsetNames, name)
		}
	}
	l.InfoContext(ctx, fmt.Sprintf("Initialized %d toolsets: %s", len(toolsetsMap), strings.Join(toolsetNames, ", ")))

	// initialize and validate the prompts from configs
	promptsMap := make(map[string]prompts.Prompt)
	for name, pc := range cfg.PromptConfigs {
		p, err := func() (prompts.Prompt, error) {
			_, span := instrumentation.Tracer.Start(
				ctx,
				"toolbox/server/prompt/init",
				trace.WithAttributes(attribute.String("prompt_type", pc.PromptConfigType())),
				trace.WithAttributes(attribute.String("prompt_name", name)),
			)
			defer span.End()
			p, err := pc.Initialize()
			if err != nil {
				return nil, fmt.Errorf("unable to initialize prompt %q: %w", name, err)
			}
			return p, nil
		}()
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		promptsMap[name] = p
	}
	promptNames := make([]string, 0, len(promptsMap))
	for name := range promptsMap {
		promptNames = append(promptNames, name)
	}
	l.InfoContext(ctx, fmt.Sprintf("Initialized %d prompts: %s", len(promptsMap), strings.Join(promptNames, ", ")))

	// create a default promptset that contains all prompts
	allPromptNames := make([]string, 0, len(promptsMap))
	for name := range promptsMap {
		allPromptNames = append(allPromptNames, name)
	}
	if cfg.PromptsetConfigs == nil {
		cfg.PromptsetConfigs = make(PromptsetConfigs)
	}
	cfg.PromptsetConfigs[""] = prompts.PromptsetConfig{Name: "", PromptNames: allPromptNames}

	// initialize and validate the promptsets from configs
	promptsetsMap := make(map[string]prompts.Promptset)
	for name, pc := range cfg.PromptsetConfigs {
		p, err := func() (prompts.Promptset, error) {
			_, span := instrumentation.Tracer.Start(
				ctx,
				"toolbox/server/prompset/init",
				trace.WithAttributes(attribute.String("prompset_name", name)),
			)
			defer span.End()
			p, err := pc.Initialize(cfg.Version, promptsMap)
			if err != nil {
				return prompts.Promptset{}, fmt.Errorf("unable to initialize promptset %q: %w", name, err)
			}
			return p, err
		}()
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		promptsetsMap[name] = p
	}
	promptsetNames := make([]string, 0, len(promptsetsMap))
	for name := range promptsetsMap {
		if name == "" {
			promptsetNames = append(promptsetNames, "default")
		} else {
			promptsetNames = append(promptsetNames, name)
		}
	}
	l.InfoContext(ctx, fmt.Sprintf("Initialized %d promptsets: %s", len(promptsetsMap), strings.Join(promptsetNames, ", ")))

	return sourcesMap, authServicesMap, embeddingModelsMap, toolsMap, toolsetsMap, promptsMap, promptsetsMap, nil
}

func hostCheck(allowedHosts map[string]struct{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, hasWildcard := allowedHosts["*"]
			hostname := r.Host
			if host, _, err := net.SplitHostPort(r.Host); err == nil {
				hostname = host
			}
			_, hostIsAllowed := allowedHosts[hostname]
			if !hasWildcard && !hostIsAllowed {
				// Return 403 Forbidden to block the attack
				http.Error(w, "Invalid Host header", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NewServer returns a Server object based on provided Config.
func NewServer(ctx context.Context, cfg ServerConfig) (*Server, error) {
	instrumentation, err := util.InstrumentationFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ctx, span := instrumentation.Tracer.Start(ctx, "toolbox/server/init")
	defer span.End()

	l, err := util.LoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// set up http serving
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	// logging
	logLevel, err := log.SeverityToLevel(cfg.LogLevel.String())
	if err != nil {
		return nil, fmt.Errorf("unable to initialize http log: %w", err)
	}

	schema := *httplog.SchemaGCP
	schema.Level = cfg.LogLevel.String()
	schema.Concise(true)
	httpOpts := &httplog.Options{
		Level:  logLevel,
		Schema: &schema,
	}
	logger := l.SlogLogger()
	r.Use(httplog.RequestLogger(logger, httpOpts))

	// cors — must be registered before any routes (including DB-mode mounts below).
	if slices.Contains(cfg.AllowedOrigins, "*") {
		l.WarnContext(ctx, "wildcard (`*`) allows all origin to access the resource and is not secure. Use it with cautious for public, non-sensitive data, or during local development. Recommended to use `--allowed-origins` flag")
	}
	corsOpts := cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "Mcp-Session-Id", "MCP-Protocol-Version"},
		ExposedHeaders:   []string{"Mcp-Session-Id"},
		MaxAge:           300,
	}
	r.Use(cors.Handler(corsOpts))
	// validate hosts for DNS rebinding attacks
	if slices.Contains(cfg.AllowedHosts, "*") {
		l.WarnContext(ctx, "wildcard (`*`) allows all hosts to access the resource and is not secure. Use it with cautious for public, non-sensitive data, or during local development. Recommended to use `--allowed-hosts` flag to prevent DNS rebinding attacks")
	}
	allowedHostsMap := make(map[string]struct{}, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		hostname := h
		if host, _, err := net.SplitHostPort(h); err == nil {
			hostname = host
		}
		allowedHostsMap[hostname] = struct{}{}
	}
	r.Use(hostCheck(allowedHostsMap))

	sourcesMap, authServicesMap, embeddingModelsMap, toolsMap, toolsetsMap, promptsMap, promptsetsMap, err := InitializeConfigs(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize configs: %w", err)
	}

	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port))
	srv := &http.Server{Addr: addr, Handler: r}

	sseManager := newSseManager(ctx)

	resourceManager := resources.NewResourceManager(sourcesMap, authServicesMap, embeddingModelsMap, toolsMap, toolsetsMap, promptsMap, promptsetsMap)

	s := &Server{
		version:         cfg.Version,
		srv:             srv,
		root:            r,
		logger:          l,
		instrumentation: instrumentation,
		sseManager:      sseManager,
		ResourceMgr:     resourceManager,
		toolboxUrl:      cfg.ToolboxUrl,
		mcpPrmFile:      cfg.McpPrmFile,
	}

	// DB mode — initialize connection management infrastructure and mount extra routes.
	if cfg.ConfigMode == "db" {
		connStore, err := connections.NewStore(cfg.DBURL)
		if err != nil {
			return nil, fmt.Errorf("opening connection store: %w", err)
		}
		s.connStore = connStore

		secretsProvider, err := secrets.New(ctx, secrets.Config{
			Backend:          secrets.Backend(cfg.SecretsBackend),
			SecretsFile:      cfg.SecretsFile,
			EncryptionKey:    cfg.EncryptionKey,
			GCPProject:       cfg.GCPProject,
			AWSRegion:        cfg.AWSRegion,
			AzureKeyVaultURL: cfg.AzureKeyVaultURL,
		})
		if err != nil {
			return nil, fmt.Errorf("initializing secrets provider: %w", err)
		}
		s.secretsProvider = secretsProvider

		// Security middleware — log redaction runs before any handler.
		r.Use(LogRedactionMiddleware)
		r.Use(HTTPSRedirectMiddleware)

		// Staging store is used by all security tiers.
		s.stagingStore = NewStagingStore()

		// Enterprise and SaaS tiers add RSA-OAEP key rotation.
		if cfg.SecurityTier == "enterprise" || cfg.SecurityTier == "saas" {
			ks, err := NewKeyStore()
			if err != nil {
				return nil, fmt.Errorf("initializing RSA key store: %w", err)
			}
			s.keyStore = ks
		}

		// SaaS tier: two-phase prepare/confirm with client-side direct-write to secrets manager.
		if cfg.SecurityTier == "saas" {
			s.pendingStore = newPendingStore()
			switch cfg.SecretsBackend {
			case "gcp":
				s.scopedIssuer = &GCPScopedIssuer{
					ProjectID:              cfg.GCPProject,
					UploaderServiceAccount: cfg.SaaSUploaderSA,
				}
			case "aws":
				s.scopedIssuer = &AWSScopedIssuer{
					Region:          cfg.AWSRegion,
					UploaderRoleARN: cfg.SaaSUploaderSA,
				}
			case "azure":
				s.scopedIssuer = &AzureScopedIssuer{
					KeyVaultURL: cfg.AzureKeyVaultURL,
				}
			default:
				return nil, fmt.Errorf("SaaS tier requires a cloud secrets backend (gcp/aws/azure), got %q", cfg.SecretsBackend)
			}
		}

		// Mount credential staging endpoints under /api/credentials/.
		credR := chi.NewRouter()
		credR.Use(middleware.StripSlashes)
		credR.Use(render.SetContentType(render.ContentTypeJSON))
		credR.Post("/stage", func(w http.ResponseWriter, req *http.Request) { stageCredentialHandler(s, w, req) })
		credR.Get("/public-key", func(w http.ResponseWriter, req *http.Request) { publicKeyHandler(s, w, req) })
		r.Mount("/api/credentials", credR)

		// Mount connection management CRUD under /api/connections/.
		mgmtR, err := managementRouter(s)
		if err != nil {
			return nil, fmt.Errorf("building management router: %w", err)
		}
		r.Mount("/api/connections", mgmtR)

		// Load initial connection config from the management DB.
		if err := s.reloadFromDB(ctx); err != nil {
			// Log but don't fail — the DB may be empty on first run.
			l.WarnContext(ctx, fmt.Sprintf("initial DB config load: %v", err))
		}
	}

	// Host OAuth Protected Resource Metadata endpoint
	mcpAuthEnabled := false
	for _, authSvc := range s.ResourceMgr.GetAuthServiceMap() {
		if genCfg, ok := authSvc.ToConfig().(generic.Config); ok && genCfg.McpEnabled {
			mcpAuthEnabled = true
			break
		}
	}

	// Manual PRM override
	var cachedPrmBytes []byte
	var prmConfig ProtectedResourceMetadata
	if s.mcpPrmFile != "" {
		var err error
		cachedPrmBytes, err = os.ReadFile(s.mcpPrmFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read manual PRM file at startup: %w", err)
		}
		// Unmarshal into the struct to strictly validate the schema
		if err := json.Unmarshal(cachedPrmBytes, &prmConfig); err != nil {
			return nil, fmt.Errorf("manual PRM file does not match expected schema: %w", err)
		}
	}

	// Register route if auth is enabled or a manual file is provided
	if mcpAuthEnabled || s.mcpPrmFile != "" {
		r.Get("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, req *http.Request) {
			// Serve from memory if file was loaded
			if s.mcpPrmFile != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write(cachedPrmBytes); err != nil {
					s.logger.ErrorContext(req.Context(), "failed to write manual PRM file response", "error", err)
				}
				return
			}

			prmHandler(s, w, req)
		})
	}

	// control plane
	mcpR, err := mcpRouter(s)
	if err != nil {
		return nil, err
	}

	r.Mount("/mcp", mcpR)
	if cfg.EnableAPI {
		apiR, err := apiRouter(s)
		if err != nil {
			return nil, err
		}
		r.Mount("/api", apiR)
	} else {
		r.Handle("/api/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := errors.New("/api native endpoints are disabled by default. Please use the standard /mcp JSON-RPC endpoint")
			_ = render.Render(w, r, newErrResponse(err, http.StatusGone))
		}))
	}
	if cfg.UI {
		webR, err := webRouter()
		if err != nil {
			return nil, err
		}
		r.Mount("/ui", webR)
	}
	// API docs — always available, served from embedded static files.
	r.Mount("/docs", docsRouter())
	r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticContent.ReadFile("static/openapi.yaml")
		if err != nil {
			http.Error(w, "openapi.yaml not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(data)
	})
	// default endpoint for validating server is running
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("🧰 Hello, World! 🧰"))
	})

	return s, nil
}

func mcpAuthMiddleware(s *Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Find McpEnabled auth service
			var mcpSvc *generic.AuthService
			for _, authSvc := range s.ResourceMgr.GetAuthServiceMap() {
				if genSvc, ok := authSvc.(*generic.AuthService); ok && genSvc.McpEnabled {
					mcpSvc = genSvc
					break
				}
			}

			// MCP Auth not enabled
			if mcpSvc == nil {
				next.ServeHTTP(w, r)
				return
			}

			if err := mcpSvc.ValidateMCPAuth(r.Context(), r.Header); err != nil {
				var mcpErr *generic.MCPAuthError
				if errors.As(err, &mcpErr) {
					switch mcpErr.Code {
					case http.StatusUnauthorized:
						scopesArg := ""
						if len(mcpErr.ScopesRequired) > 0 {
							scopesArg = fmt.Sprintf(`, scope="%s"`, strings.Join(mcpErr.ScopesRequired, " "))
						}
						w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"%s`, s.toolboxUrl+"/.well-known/oauth-protected-resource", scopesArg))
						http.Error(w, mcpErr.Message, http.StatusUnauthorized)
						return
					case http.StatusForbidden:
						w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope="%s", resource_metadata="%s", error_description="%s"`, strings.Join(mcpErr.ScopesRequired, " "), s.toolboxUrl+"/.well-known/oauth-protected-resource", mcpErr.Message))
						http.Error(w, mcpErr.Message, http.StatusForbidden)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// reloadFromDB rebuilds Toolbox sources and tools from all connections in the
// management DB. Called at startup and after every connection mutation.
// Individual connection failures are logged as warnings and skipped — the rest
// of the connections remain operational.
func (s *Server) reloadFromDB(ctx context.Context) error {
	conns, err := s.connStore.List(ctx)
	if err != nil {
		return fmt.Errorf("listing connections: %w", err)
	}

	allSources := make(map[string]sources.Source)
	allTools := make(map[string]tools.Tool)

	for _, conn := range conns {
		password, err := s.secretsProvider.Get(ctx, conn.PasswordRef)
		if err != nil {
			s.logger.WarnContext(ctx, fmt.Sprintf("skipping connection %q: cannot fetch credentials: %v", conn.Name, err))
			continue
		}

		sourceType, toolTypes, ok := dbTypeToToolboxTypes(conn.DBType)
		if !ok {
			s.logger.WarnContext(ctx, fmt.Sprintf("skipping connection %q: unsupported db_type %q", conn.Name, conn.DBType))
			continue
		}

		// Build source config using the same factory machinery as YAML loading.
		extra := conn.ExtraParamsMap()
		srcMap := buildSourceConfigMap(sourceType, conn, password, extra)
		srcCfg, err := UnmarshalYAMLSourceConfig(ctx, conn.Name, srcMap)
		if err != nil {
			s.logger.WarnContext(ctx, fmt.Sprintf("skipping connection %q: source config error: %v", conn.Name, err))
			continue
		}

		// Initialize the source once — shared by all tools for this connection.
		src, err := srcCfg.Initialize(ctx, s.instrumentation.Tracer)
		if err != nil {
			s.logger.WarnContext(ctx, fmt.Sprintf("skipping connection %q: source init error: %v", conn.Name, err))
			continue
		}
		allSources[conn.Name] = src

		// Register one tool per tool type supported by this database.
		for _, toolType := range toolTypes {
			toolKey := conn.Name + "__" + toolType
			toolCfg, err := UnmarshalYAMLToolConfig(ctx, toolKey, map[string]any{
				"type":   toolType,
				"source": conn.Name,
			})
			if err != nil {
				s.logger.WarnContext(ctx, fmt.Sprintf("skipping tool %q for %q: %v", toolType, conn.Name, err))
				continue
			}
			tool, err := toolCfg.Initialize(map[string]sources.Source{conn.Name: src})
			if err != nil {
				s.logger.WarnContext(ctx, fmt.Sprintf("skipping tool %q for %q: init error: %v", toolType, conn.Name, err))
				continue
			}
			allTools[toolKey] = tool
		}
	}

	// Build toolsets: one default (all connections) + one per connection.
	allToolNames := make([]string, 0, len(allTools))
	for name := range allTools {
		allToolNames = append(allToolNames, name)
	}
	defaultToolset, err := tools.ToolsetConfig{Name: "", ToolNames: allToolNames}.Initialize(s.version, allTools)
	if err != nil {
		return fmt.Errorf("building default toolset: %w", err)
	}

	// Build per-connection tool key lists for toolset registration.
	connToolKeys := make(map[string][]string)
	for toolKey := range allTools {
		// toolKey format: "ConnName__tool-type"
		connName := strings.SplitN(toolKey, "__", 2)[0]
		connToolKeys[connName] = append(connToolKeys[connName], toolKey)
	}

	// Per-connection toolsets + matching empty promptsets so MCP lookup succeeds.
	emptyPrompts := make(map[string]prompts.Prompt)
	defaultPromptset, _ := prompts.PromptsetConfig{Name: ""}.Initialize(s.version, emptyPrompts)
	toolsetsMap := map[string]tools.Toolset{"": defaultToolset}
	promptsetsMap := map[string]prompts.Promptset{"": defaultPromptset}

	for connName, toolKeys := range connToolKeys {
		ts, err := tools.ToolsetConfig{Name: connName, ToolNames: toolKeys}.Initialize(s.version, allTools)
		if err != nil {
			s.logger.WarnContext(ctx, fmt.Sprintf("skipping per-connection toolset %q: %v", connName, err))
			continue
		}
		toolsetsMap[connName] = ts

		ps, err := prompts.PromptsetConfig{Name: connName}.Initialize(s.version, emptyPrompts)
		if err != nil {
			s.logger.WarnContext(ctx, fmt.Sprintf("skipping per-connection promptset %q: %v", connName, err))
			continue
		}
		promptsetsMap[connName] = ps
	}

	s.ResourceMgr.SetResources(
		allSources,
		make(map[string]auth.AuthService),
		make(map[string]embeddingmodels.EmbeddingModel),
		allTools,
		toolsetsMap,
		emptyPrompts,
		promptsetsMap,
	)

	s.logger.InfoContext(ctx, fmt.Sprintf("loaded %d connection(s) from DB", len(allSources)))
	return nil
}

// buildSourceConfigMap constructs the map passed to UnmarshalYAMLSourceConfig.
// Different databases use different field names — this centralises the mapping.
func buildSourceConfigMap(sourceType string, conn *connections.Connection, password string, extra map[string]string) map[string]any {
	ep := func(key, fallback string) string {
		if v, ok := extra[key]; ok && v != "" {
			return v
		}
		return fallback
	}

	base := map[string]any{"type": sourceType}

	switch sourceType {
	// ── MongoDB — takes a full URI ─────────────────────────────────────────
	case "mongodb":
		uri := ep("uri", "")
		if uri == "" {
			// Build from parts: mongodb://user:pass@host:port/database
			uri = fmt.Sprintf("mongodb://%s:%s@%s:%d/%s",
				conn.Username, password, conn.Host, conn.Port, conn.Database)
		}
		base["uri"] = uri

	// ── Neo4j — takes a URI + separate user/password/database ─────────────
	case "neo4j":
		scheme := ep("uri_scheme", "bolt")
		base["uri"] = fmt.Sprintf("%s://%s:%d", scheme, conn.Host, conn.Port)
		base["user"] = conn.Username
		base["password"] = password
		base["database"] = conn.Database

	// ── Snowflake — account replaces host; schema required ────────────────
	case "snowflake":
		base["account"] = ep("account", conn.Host)
		base["user"] = conn.Username
		base["password"] = password
		base["database"] = conn.Database
		base["schema"] = ep("schema", "PUBLIC")
		if wh := ep("warehouse", ""); wh != "" {
			base["warehouse"] = wh
		}
		if role := ep("role", ""); role != "" {
			base["role"] = role
		}

	// ── Cassandra — keyspace instead of database ───────────────────────────
	case "cassandra":
		base["host"] = conn.Host
		base["port"] = strconv.Itoa(conn.Port)
		base["username"] = conn.Username
		base["password"] = password
		base["keyspace"] = conn.Database // database field holds keyspace

	// ── Redis / Valkey — no database or user fields required ──────────────
	case "redis", "valkey":
		base["host"] = conn.Host
		base["port"] = strconv.Itoa(conn.Port)
		base["password"] = password
		if conn.Database != "" && conn.Database != "0" {
			base["database"] = conn.Database
		}

	// ── Elasticsearch — host/port, optional user/password ─────────────────
	case "elasticsearch":
		base["host"] = conn.Host
		base["port"] = strconv.Itoa(conn.Port)
		if conn.Username != "" {
			base["username"] = conn.Username
		}
		if password != "" {
			base["password"] = password
		}

	// ── ClickHouse — standard fields + optional secure flag ───────────────
	case "clickhouse":
		base["host"] = conn.Host
		base["port"] = strconv.Itoa(conn.Port)
		base["user"] = conn.Username
		base["password"] = password
		base["database"] = conn.Database
		base["secure"] = conn.SSLMode != "disable"

	// ── Standard: postgres, mysql, mssql, sqlite, cockroachdb, yugabytedb,
	//             tidb, cloud-sql-*, alloydb-postgres ─────────────────────
	default:
		base["host"] = conn.Host
		base["port"] = strconv.Itoa(conn.Port)
		base["user"] = conn.Username
		base["password"] = password
		base["database"] = conn.Database
	}

	return base
}

// dbTypeToToolboxTypes maps a connection's db_type to the Toolbox source and tool type strings.
func dbTypeToToolboxTypes(dbType string) (sourceType string, toolTypes []string, ok bool) {
	switch strings.ToLower(dbType) {
	// ── Standard SQL ──────────────────────────────────────────────────────────
	case "postgres", "postgresql":
		return "postgres", []string{
			"postgres-execute-sql",
			"postgres-list-tables",
			"postgres-list-schemas",
			"postgres-list-views",
			"postgres-list-indexes",
			"postgres-list-triggers",
			"postgres-list-roles",
			"postgres-list-sequences",
			"postgres-list-stored-procedure",
			"postgres-database-overview",
			"postgres-list-active-queries",
			"postgres-list-locks",
			"postgres-list-query-stats",
			"postgres-list-table-stats",
			"postgres-list-database-stats",
			"postgres-list-tablespaces",
			"postgres-list-pg-settings",
			"postgres-list-available-extensions",
			"postgres-list-installed-extensions",
			"postgres-get-column-cardinality",
			"postgres-long-running-transactions",
		}, true
	case "mysql", "mariadb":
		return "mysql", []string{
			"mysql-execute-sql",
			"mysql-list-tables",
			"mysql-list-active-queries",
			"mysql-get-query-plan",
			"mysql-list-table-fragmentation",
			"mysql-list-tables-missing-unique-indexes",
		}, true
	case "mssql", "sqlserver", "sql_server":
		return "mssql", []string{
			"mssql-execute-sql",
			"mssql-list-tables",
		}, true
	case "sqlite":
		return "sqlite", []string{"sqlite-execute-sql"}, true
	case "cockroachdb":
		return "cockroachdb", []string{"cockroachdb-execute-sql"}, true
	case "yugabytedb":
		return "yugabytedb", []string{"yugabytedb-sql"}, true
	case "tidb":
		return "tidb", []string{
			"mysql-execute-sql",
			"mysql-list-tables",
		}, true
	// ── Analytical / columnar ──────────────────────────────────────────────
	case "clickhouse":
		return "clickhouse", []string{"clickhouse-execute-sql"}, true
	case "snowflake":
		return "snowflake", []string{"snowflake-execute-sql"}, true
	// ── Google Cloud managed SQL ───────────────────────────────────────────
	case "cloud-sql-postgres", "cloudsqlpostgres":
		return "cloud-sql-postgres", []string{
			"postgres-execute-sql",
			"postgres-list-tables",
			"postgres-list-schemas",
		}, true
	case "cloud-sql-mysql", "cloudsqlmysql":
		return "cloud-sql-mysql", []string{
			"mysql-execute-sql",
			"mysql-list-tables",
		}, true
	case "cloud-sql-mssql", "cloudsqlmssql":
		return "cloud-sql-mssql", []string{
			"mssql-execute-sql",
			"mssql-list-tables",
		}, true
	case "alloydb-postgres", "alloydb":
		return "alloydb-postgres", []string{
			"postgres-execute-sql",
			"postgres-list-tables",
			"postgres-list-schemas",
		}, true
	// ── NoSQL / graph / search ─────────────────────────────────────────────
	case "mongodb":
		return "mongodb", []string{"mongodb-find"}, true
	case "redis":
		return "redis", []string{"redis"}, true
	case "valkey":
		return "valkey", []string{"valkey"}, true
	case "neo4j":
		return "neo4j", []string{"neo4j-execute-cypher"}, true
	case "cassandra":
		return "cassandra", []string{"cassandra-cql"}, true
	case "elasticsearch":
		return "elasticsearch", []string{"elasticsearch-esql"}, true
	default:
		return "", nil, false
	}
}

// Listen starts a listener for the given Server instance.
func (s *Server) Listen(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if s.listener != nil {
		return fmt.Errorf("server is already listening: %s", s.listener.Addr().String())
	}
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	var err error
	if s.listener, err = lc.Listen(ctx, "tcp", s.srv.Addr); err != nil {
		return fmt.Errorf("failed to open listener for %q: %w", s.srv.Addr, err)
	}
	s.logger.DebugContext(ctx, fmt.Sprintf("server listening on %s", s.srv.Addr))
	return nil
}

// Serve starts an HTTP server for the given Server instance.
func (s *Server) Serve(ctx context.Context) error {
	s.logger.DebugContext(ctx, "Starting a HTTP server.")
	return s.srv.Serve(s.listener)
}

// ServeStdio starts a new stdio session for mcp.
func (s *Server) ServeStdio(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	stdioServer := NewStdioSession(s, stdin, stdout)
	return stdioServer.Start(ctx)
}

// Shutdown gracefully shuts down the server without interrupting any active
// connections. It uses http.Server.Shutdown() and has the same functionality.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.DebugContext(ctx, "shutting down the server.")
	return s.srv.Shutdown(ctx)
}
