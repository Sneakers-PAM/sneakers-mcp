// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command mcp is the Sneakers MCP server: a thin, stateless bridge that
// speaks MCP (Streamable HTTP) to AI agents, authenticates each caller's
// bearer (an Ory Hydra JWT, or a service-account API token confirmed by the
// gateway), and forwards every tool call to the gateway's /machine/graphql
// carrying that same caller's token. It holds no credentials of its own, no
// state, and no authorization logic; the gateway and vault RACI decide.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/rs/zerolog"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/authn"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/hydra"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/tools"
)

const (
	serviceName = "mcp"
	// maxRequestBodyBytes caps one MCP POST. The largest legitimate call is a
	// create/generate with maxFields x maxFieldValueLen (512 KiB).
	maxRequestBodyBytes = 1 << 20
	metadataPath        = "/.well-known/oauth-protected-resource"
)

// version and commit are stamped at image build with
// -ldflags "-X main.version=<tag> -X main.commit=<sha>".
var (
	version = "dev"
	commit  = ""
)

// buildCommit is the stamped commit, else the VCS revision Go records when it
// builds from a git checkout, else "unknown".
func buildCommit() string {
	if commit != "" {
		return commit
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return s.Value
			}
		}
	}
	return "unknown"
}

// env returns the environment value for k, or def when unset/empty.
func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type config struct {
	HTTPPort      string
	OTLPEndpoint  string
	HydraIssuer   string
	HydraJWKSURL  string
	HydraAudience string
	ResourceURL   string
	GatewayURL    string
	Version       string
	// AcceptAPITokens enables the service-account API-token path.
	AcceptAPITokens bool
	// AuthorizationServer is the Sneakers sign-in issuer (the gateway's OAuth
	// server on the UI host) that OAuth-capable MCP clients are sent to.
	AuthorizationServer string
}

// hydraEnabled reports whether the Hydra JWT path is on: exactly when an
// issuer is configured.
func (c config) hydraEnabled() bool { return c.HydraIssuer != "" }

// loadConfig reads the environment. Two independent bearer modes exist:
// Hydra JWTs (on when HYDRA_ISSUER is set) and service-account API tokens
// (MCP_ACCEPT_API_TOKENS, default true; the gateway already accepts these on
// /machine/graphql and remains the authority for them). With neither mode on
// the service refuses to start rather than serve nothing or run unverified.
func loadConfig() (config, error) {
	cfg := config{
		HTTPPort:      env("HTTP_PORT", "9101"),
		OTLPEndpoint:  env("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
		HydraIssuer:   env("HYDRA_ISSUER", ""),
		HydraJWKSURL:  env("HYDRA_JWKS_URL", "http://sneakers-hydra:4444/.well-known/jwks.json"),
		HydraAudience: env("HYDRA_AUDIENCE", "sneakers-mcp"),
		ResourceURL:   env("MCP_RESOURCE_URL", ""),
		GatewayURL:    env("GATEWAY_MACHINE_GRAPHQL_URL", "http://sneakers-gateway:9100/machine/graphql"),
		Version:       env("SERVICE_VERSION", version),

		AuthorizationServer: env("MCP_AUTHORIZATION_SERVER", ""),
	}
	accept, err := strconv.ParseBool(env("MCP_ACCEPT_API_TOKENS", "true"))
	if err != nil {
		return cfg, fmt.Errorf("MCP_ACCEPT_API_TOKENS %q is not a boolean", os.Getenv("MCP_ACCEPT_API_TOKENS"))
	}
	cfg.AcceptAPITokens = accept
	if !cfg.hydraEnabled() && !cfg.AcceptAPITokens {
		return cfg, errors.New("no bearer mode configured: set HYDRA_ISSUER and/or MCP_ACCEPT_API_TOKENS=true; refusing to start")
	}
	// The resource URL is the audience OAuth clients are told to request, so
	// the Hydra mode must not run on a guessed host. API-token-only mode has
	// no OAuth flow and may omit it (no metadata is then served).
	if cfg.hydraEnabled() && cfg.ResourceURL == "" {
		return cfg, errors.New("MCP_RESOURCE_URL is required when HYDRA_ISSUER is set; refusing to start")
	}
	return cfg, nil
}

// resourceMetadataURL derives the RFC 9728 metadata location for resource:
// https://host/mcp -> https://host/.well-known/oauth-protected-resource/mcp.
func resourceMetadataURL(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("MCP_RESOURCE_URL %q is not an absolute URL", resource)
	}
	return u.Scheme + "://" + u.Host + metadataPath + strings.TrimSuffix(u.Path, "/"), nil
}

// opaqueVerifier wraps the bearer verifier so a rejected token gets a bare
// "invalid token" 401 (no validation detail for the caller to probe), while
// the reason goes to the operator log. The token itself is never logged.
func opaqueVerifier(v auth.TokenVerifier, logger zerolog.Logger) auth.TokenVerifier {
	return func(ctx context.Context, token string, r *http.Request) (*auth.TokenInfo, error) {
		info, err := v(ctx, token, r)
		if err != nil {
			logger.Warn().Str("reason", err.Error()).Str("path", r.URL.Path).Msg("mcp bearer rejected")
			return nil, auth.ErrInvalidToken
		}
		return info, nil
	}
}

// buildVerifier assembles the enabled bearer modes. It fails closed: with
// neither mode configured there is no verifier, never an open door.
func buildVerifier(cfg config) (*authn.Verifier, error) {
	v := &authn.Verifier{}
	if cfg.hydraEnabled() {
		hv, err := hydra.New(hydra.Config{
			Issuer:   cfg.HydraIssuer,
			JWKSURL:  cfg.HydraJWKSURL,
			Audience: cfg.HydraAudience,
		})
		if err != nil {
			return nil, err
		}
		v.JWT = hv.Verify
	}
	if cfg.AcceptAPITokens {
		av, err := authn.NewAPITokenVerifier(authn.APITokenConfig{GatewayURL: cfg.GatewayURL})
		if err != nil {
			return nil, err
		}
		v.APIToken = av
	}
	if !v.Enabled() {
		return nil, errors.New("no bearer mode configured")
	}
	return v, nil
}

// buildHandler wires the verifier, gateway client and MCP server into the
// service's routes.
func buildHandler(cfg config, logger zerolog.Logger) (http.Handler, error) {
	verifier, err := buildVerifier(cfg)
	if err != nil {
		return nil, err
	}
	var (
		mdURL    string
		metadata *oauthex.ProtectedResourceMetadata
	)
	if cfg.ResourceURL != "" {
		if mdURL, err = resourceMetadataURL(cfg.ResourceURL); err != nil {
			return nil, err
		}
		metadata = &oauthex.ProtectedResourceMetadata{
			Resource:               cfg.ResourceURL,
			BearerMethodsSupported: []string{"header"},
			ResourceName:           "Sneakers secret vault (MCP)",
		}
		switch {
		case cfg.AuthorizationServer != "":
			metadata.AuthorizationServers = []string{cfg.AuthorizationServer}
		case cfg.hydraEnabled():
			metadata.AuthorizationServers = []string{cfg.HydraIssuer}
		}
	}
	// No RequireBearerTokenOptions.Scopes: authorization is the gateway's and
	// vault's job via RACI. This layer only proves the token is genuine.
	authMW := auth.RequireBearerToken(opaqueVerifier(verifier.TokenVerifier(), logger), &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: mdURL,
	})

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "sneakers",
		Title:   "Sneakers secret vault",
		Version: cfg.Version,
	}, nil)
	tools.Register(mcpServer, gwclient.New(cfg.GatewayURL, nil), logger)

	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: maxRequestBodyBytes},
	)
	mux := newMux(streamable, authMW, metadata)
	mountHealth(mux, newHealthChecker(cfg, logger))
	return withLogging(mux, logger), nil
}

// newMux builds the service's routes. /health is unauthenticated (the
// gateway's diagnostics read it; /livez and /readyz are added beside it); /mcp is always behind the bearer middleware. The RFC 9728
// metadata routes exist only when metadata is non-nil.
func newMux(streamable http.Handler, authMW func(http.Handler) http.Handler, metadata *oauthex.ProtectedResourceMetadata) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": version, "commit": buildCommit()})
	})
	if metadata != nil {
		md := auth.ProtectedResourceMetadataHandler(metadata)
		mux.Handle(metadataPath, md)
		mux.Handle(metadataPath+"/mcp", md)
	}
	mux.Handle("/mcp", http.NewCrossOriginProtection().Handler(authMW(streamable)))
	return mux
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush keeps SSE responses streaming through the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// withLogging logs method, path, status and duration. Never headers or
// bodies: the Authorization header and tool payloads stay out of logs.
func withLogging(next http.Handler, logger zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		if isProbe(r.URL.Path) {
			return
		}
		logger.Info().Str("method", r.Method).Str("path", r.URL.Path).
			Int("status", rec.code).Dur("dur", time.Since(start)).Msg("http")
	})
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}

	otelShutdown, err := otel.Init(ctx, serviceName, cfg.OTLPEndpoint)
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	handler, err := buildHandler(cfg, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("wiring")
	}

	srv := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           otel.Metrics(handler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	logger.Info().Str("http", cfg.HTTPPort).Bool("hydra", cfg.hydraEnabled()).
		Bool("api_tokens", cfg.AcceptAPITokens).Str("issuer", cfg.HydraIssuer).
		Str("audience", cfg.HydraAudience).Str("resource", cfg.ResourceURL).
		Str("gateway", cfg.GatewayURL).Msg("mcp starting")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal().Err(err).Msg("http server exited")
	}
}
