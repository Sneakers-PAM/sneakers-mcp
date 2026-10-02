// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package hydra verifies Ory Hydra client-credentials JWTs for the MCP
// server's OAuth2 resource-server role. It deliberately knows nothing about
// MCP tools or GraphQL.
//
// The MCP SDK supplies the bearer middleware and the protected-resource
// metadata handler but no JWT or JWKS support, and the gateway's equivalent
// lives under the gateway module's internal/ tree, which Go forbids importing
// across modules. So this is a small independent implementation, and that
// independence is the design: the MCP server rejects bad tokens at the edge,
// then the gateway validates the same token again on its own.
package hydra

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	// cacheTTL bounds how long a fetched JWKS is trusted before it is
	// refetched. Hydra key rotation is rare; this only affects how quickly a
	// rotated or revoked key is noticed.
	cacheTTL = 10 * time.Minute
	// minRefreshInterval stops a flood of tokens carrying random kids from
	// turning every request into a JWKS fetch against Hydra.
	minRefreshInterval = 30 * time.Second
	// maxJWKSBytes caps the JWKS document we are willing to read.
	maxJWKSBytes  = 1 << 20
	defaultLeeway = 30 * time.Second
)

// Config is the Hydra-facing configuration. Issuer, JWKSURL and Audience are
// required; New refuses to build a verifier without them. Leeway defaults to
// 30s when zero; HTTPClient defaults to a client with a 10s timeout.
type Config struct {
	Issuer     string
	JWKSURL    string
	Audience   string
	Leeway     time.Duration
	HTTPClient *http.Client
}

// Verifier validates RS256 JWTs against Hydra's JWKS, caching keys by kid.
// It is safe for concurrent use. It caches public keys only, never tokens
// or verification results.
type Verifier struct {
	cfg Config
	hc  *http.Client

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	fetched     time.Time
	lastAttempt time.Time
	refreshMu   sync.Mutex
}

// New builds a Verifier. It fails closed: an empty issuer, JWKS URL or
// audience is a configuration error, never "skip that check".
func New(cfg Config) (*Verifier, error) {
	switch {
	case strings.TrimSpace(cfg.Issuer) == "":
		return nil, errors.New("hydra: issuer is required")
	case strings.TrimSpace(cfg.JWKSURL) == "":
		return nil, errors.New("hydra: JWKS URL is required")
	case strings.TrimSpace(cfg.Audience) == "":
		return nil, errors.New("hydra: audience is required")
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = defaultLeeway
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{cfg: cfg, hc: hc, keys: map[string]*rsa.PublicKey{}}, nil
}

// Verify implements auth.TokenVerifier. The *http.Request argument is unused
// (the token alone decides) but is part of the SDK's signature. Every failure
// wraps auth.ErrInvalidToken so the SDK's middleware answers 401. The error
// text names the reason for operator logs but never contains the token.
func (v *Verifier) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("%w: empty token", auth.ErrInvalidToken)
	}

	parsed, err := jwt.Parse(token, v.keyFunc(ctx),
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.cfg.Leeway),
	)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected claims type", auth.ErrInvalidToken)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing sub", auth.ErrInvalidToken)
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, fmt.Errorf("%w: missing exp", auth.ErrInvalidToken)
	}

	return &auth.TokenInfo{
		UserID:     sub,
		Scopes:     scopesOf(claims),
		Expiration: exp.Time,
	}, nil
}

// scopesOf reads granted scopes tolerantly. Hydra's JWT strategy emits "scp"
// as a JSON array by default, while the OAuth2 convention is a
// space-delimited "scope" string; accept either. Scopes are informational
// here (the gateway derives groups itself); malformed input yields none.
func scopesOf(claims jwt.MapClaims) []string {
	if s, ok := claims["scope"].(string); ok && s != "" {
		return strings.Fields(s)
	}
	if arr, ok := claims["scp"].([]any); ok {
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (v *Verifier) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no kid")
		}
		if k := v.cachedKey(kid); k != nil {
			return k, nil
		}
		if err := v.refresh(ctx); err != nil {
			return nil, err
		}
		if k := v.cachedKey(kid); k != nil {
			return k, nil
		}
		return nil, errors.New("signing key not found in JWKS")
	}
}

func (v *Verifier) cachedKey(kid string) *rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if time.Since(v.fetched) > cacheTTL {
		return nil
	}
	return v.keys[kid]
}

// refresh fetches and replaces the cached JWKS, at most once per
// minRefreshInterval unless the cache has expired outright.
func (v *Verifier) refresh(ctx context.Context) error {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	v.mu.RLock()
	expired := time.Since(v.fetched) > cacheTTL
	recent := time.Since(v.lastAttempt) < minRefreshInterval
	v.mu.RUnlock()
	if recent && !expired {
		return nil // throttled; caller re-checks the (unchanged) cache
	}
	v.mu.Lock()
	v.lastAttempt = time.Now()
	v.mu.Unlock()

	keys, err := v.fetch(ctx)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keys, v.fetched = keys, time.Now()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if pub := k.rsaPublicKey(); pub != nil {
			keys[k.Kid] = pub
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks contained no usable RSA signing keys")
	}
	return keys, nil
}

// jwk is the subset of an RFC 7517 JSON Web Key we consume. golang-jwt/v5
// has no JWK parser, so RSA keys are decoded by hand.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k jwk) rsaPublicKey() *rsa.PublicKey {
	if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") {
		return nil
	}
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil || len(nb) < 256 { // < 2048-bit modulus is refused
		return nil
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil
	}
	e := new(big.Int).SetBytes(eb).Int64()
	if e < 3 || e%2 == 0 {
		return nil
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e)}
}
