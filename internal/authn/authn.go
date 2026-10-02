// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package authn is the MCP server's bearer gate. It classifies each bearer
// strictly by shape and routes it to exactly one verifier:
//
//   - a well-formed RS256 JWT goes to the Hydra JWT verifier (when Hydra is
//     configured);
//   - a string in the exact identity service-account API token format
//     (base64url, no padding, of 32 random bytes: 43 chars) goes to the
//     API-token verifier (when MCP_ACCEPT_API_TOKENS is on);
//   - anything else, or a shape whose mode is disabled, is rejected.
//
// The MCP cannot verify an opaque API token locally, so the API-token
// verifier asks the gateway (the authority) with a machineHealth query
// carrying the caller's own bearer. A positive answer may be cached briefly,
// keyed only by the token's SHA-256. The token itself is never stored or
// logged, and no error produced here contains it.
package authn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Kind is a bearer's syntactic class.
type Kind int

const (
	KindInvalid Kind = iota
	KindJWT
	KindAPIToken
)

func (k Kind) String() string {
	switch k {
	case KindJWT:
		return "jwt"
	case KindAPIToken:
		return "api-token"
	default:
		return "invalid"
	}
}

const (
	// apiTokenLen and apiTokenBytes mirror identity's randomToken:
	// base64.RawURLEncoding of 32 crypto/rand bytes.
	apiTokenLen   = 43
	apiTokenBytes = 32
	// maxJWTLen bounds the header we are willing to decode while classifying.
	maxJWTLen = 16 << 10
)

// strictB64 rejects non-canonical encodings (non-zero trailing bits), so
// exactly one string represents each 32-byte token.
var strictB64 = base64.RawURLEncoding.Strict()

// Classify reports the bearer's class. It never touches the network.
func Classify(token string) Kind {
	if isAPIToken(token) {
		return KindAPIToken
	}
	if isRS256JWT(token) {
		return KindJWT
	}
	return KindInvalid
}

// userTokenPrefix marks a personal token; its body has the same shape as a
// service-account token and the gateway verifies either kind.
const userTokenPrefix = "snk_u_"

func isAPIToken(s string) bool {
	s = strings.TrimPrefix(s, userTokenPrefix)
	if len(s) != apiTokenLen {
		return false
	}
	b, err := strictB64.DecodeString(s)
	return err == nil && len(b) == apiTokenBytes
}

// isRS256JWT: three base64url segments, a JSON header whose alg is RS256.
// Signature and claims are the Hydra verifier's job; this only routes.
func isRS256JWT(s string) bool {
	if len(s) > maxJWTLen {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	for _, p := range parts[1:] {
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			return false
		}
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	return json.Unmarshal(hdr, &h) == nil && h.Alg == "RS256"
}

// Verifier dispatches a bearer to the verifier for its class. A nil field
// disables that mode: its bearers are rejected without being inspected.
type Verifier struct {
	JWT      auth.TokenVerifier
	APIToken *APITokenVerifier
}

// Enabled reports whether at least one mode is configured.
func (v *Verifier) Enabled() bool { return v.JWT != nil || v.APIToken != nil }

// TokenVerifier adapts v to the SDK's bearer middleware.
func (v *Verifier) TokenVerifier() auth.TokenVerifier {
	return func(ctx context.Context, token string, r *http.Request) (*auth.TokenInfo, error) {
		switch Classify(token) {
		case KindJWT:
			if v.JWT == nil {
				return nil, fmt.Errorf("%w: JWT bearer but Hydra is not configured", auth.ErrInvalidToken)
			}
			return v.JWT(ctx, token, r)
		case KindAPIToken:
			if v.APIToken == nil {
				return nil, fmt.Errorf("%w: API token bearer but API tokens are disabled", auth.ErrInvalidToken)
			}
			return v.APIToken.Verify(ctx, token)
		default:
			return nil, fmt.Errorf("%w: malformed bearer", auth.ErrInvalidToken)
		}
	}
}

// --- API-token verifier ---------------------------------------------------

const (
	// DefaultTTL is how long a gateway-confirmed token is trusted at this
	// edge without re-asking. Revocation still takes effect immediately for
	// data: every tool call is re-authenticated by the gateway.
	DefaultTTL = 30 * time.Second
	// MaxTTL is the hard ceiling on the positive-result cache.
	MaxTTL            = 60 * time.Second
	defaultMaxEntries = 4096
	defaultTimeout    = 10 * time.Second
	maxHealthBytes    = 64 << 10
	healthQuery       = `{"query":"query{machineHealth}"}`
	whoamiQuery       = `{"query":"query{machineHealth machineWhoami{kind userId principalId}}"}`
)

// APITokenConfig configures an APITokenVerifier. GatewayURL (the gateway's
// /machine/graphql) is required. TTL defaults to DefaultTTL and may not
// exceed MaxTTL. MaxEntries caps the cache (default 4096).
type APITokenConfig struct {
	GatewayURL string
	HTTPClient *http.Client
	TTL        time.Duration
	MaxEntries int

	now func() time.Time // test hook
}

// APITokenVerifier confirms opaque service-account API tokens with the
// gateway. It is safe for concurrent use.
type APITokenVerifier struct {
	endpoint   string
	hc         *http.Client
	ttl        time.Duration
	maxEntries int
	now        func() time.Time

	mu    sync.Mutex
	cache map[[sha256.Size]byte]cached // sha256(token) -> expiry and label
}

type cached struct {
	exp   time.Time
	label string
}

// whoami is the gateway's answer to machineWhoami, when it has one.
type whoami struct {
	Kind        string `json:"kind"`
	UserID      string `json:"userId"`
	PrincipalID string `json:"principalId"`
}

// NewAPITokenVerifier builds a verifier. Redirects are never followed, so
// the caller's bearer can never be replayed to another URL.
func NewAPITokenVerifier(cfg APITokenConfig) (*APITokenVerifier, error) {
	if strings.TrimSpace(cfg.GatewayURL) == "" {
		return nil, errors.New("authn: gateway URL is required for API-token verification")
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.TTL < 0 || cfg.TTL > MaxTTL {
		return nil, fmt.Errorf("authn: API-token cache TTL must be in (0, %s]", MaxTTL)
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = defaultMaxEntries
	}
	var hc http.Client
	if cfg.HTTPClient != nil {
		hc = *cfg.HTTPClient
	} else {
		hc.Timeout = defaultTimeout
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	return &APITokenVerifier{
		endpoint: cfg.GatewayURL, hc: &hc, ttl: cfg.TTL, maxEntries: cfg.MaxEntries, now: now,
		cache: map[[sha256.Size]byte]cached{},
	}, nil
}

// Verify accepts token only if it is well-formed and the gateway (or a
// fresh cached gateway answer) confirms it. Every failure, including a
// gateway outage, wraps auth.ErrInvalidToken: fail closed, generic 401.
func (v *APITokenVerifier) Verify(ctx context.Context, token string) (*auth.TokenInfo, error) {
	if !isAPIToken(token) {
		return nil, fmt.Errorf("%w: malformed API token", auth.ErrInvalidToken)
	}
	key := sha256.Sum256([]byte(token))
	now := v.now()
	if c, ok := v.lookup(key, now); ok {
		return &auth.TokenInfo{UserID: c.label, Expiration: c.exp}, nil
	}
	who, err := v.check(ctx, token, whoamiQuery)
	if errors.Is(err, errNoWhoami) {
		who, err = v.check(ctx, token, healthQuery)
	}
	if err != nil {
		v.evict(key)
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	c := cached{exp: now.Add(v.ttl), label: tokenLabel(token, key, who)}
	v.store(key, c, now)
	return &auth.TokenInfo{UserID: c.label, Expiration: c.exp}, nil
}

// tokenLabel names the caller for logs: its kind, the owner or account id
// when the gateway says, and a short fingerprint that can't be reversed to
// the 256-bit token.
func tokenLabel(token string, key [sha256.Size]byte, who whoami) string {
	kind, id := "sa-token", who.PrincipalID
	if strings.HasPrefix(token, userTokenPrefix) {
		kind, id = "user-token", who.UserID
	}
	fp := hex.EncodeToString(key[:6])
	if id == "" {
		return kind + ":" + fp
	}
	return kind + ":" + id + ":" + fp
}

func (v *APITokenVerifier) lookup(key [sha256.Size]byte, now time.Time) (cached, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.cache[key]
	if !ok {
		return cached{}, false
	}
	if !now.Before(c.exp) {
		delete(v.cache, key)
		return cached{}, false
	}
	return c, true
}

func (v *APITokenVerifier) evict(key [sha256.Size]byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.cache, key)
}

// store caches a positive result. When full it sweeps expired entries; if
// still full the result is simply not cached (correctness never depends on
// the cache).
func (v *APITokenVerifier) store(key [sha256.Size]byte, c cached, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= v.maxEntries {
		for k, e := range v.cache {
			if !now.Before(e.exp) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= v.maxEntries {
			return
		}
	}
	v.cache[key] = c
}

// errNoWhoami means the gateway refused the query that asks machineWhoami, as
// a gateway without that field does; the caller retries health only.
var errNoWhoami = errors.New("gateway pre-check: machineWhoami not supported")

// check asks the gateway whether token authenticates, and who it is when the
// query asks machineWhoami. Only a 200 with data.machineHealth == true counts.
// Returned errors never contain the token, the endpoint URL or gateway text.
func (v *APITokenVerifier) check(ctx context.Context, token, query string) (whoami, error) {
	asksWhoami := query == whoamiQuery
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader([]byte(query)))
	if err != nil {
		return whoami{}, errors.New("gateway pre-check: bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := v.hc.Do(req)
	if err != nil {
		return whoami{}, errors.New("gateway pre-check: gateway unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHealthBytes))
		return whoami{}, errors.New("gateway rejected the API token")
	case asksWhoami && (resp.StatusCode == http.StatusUnprocessableEntity || resp.StatusCode == http.StatusBadRequest):
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHealthBytes))
		return whoami{}, errNoWhoami
	case resp.StatusCode != http.StatusOK:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHealthBytes))
		return whoami{}, fmt.Errorf("gateway pre-check: gateway unavailable (HTTP %d)", resp.StatusCode)
	}
	var body struct {
		Data struct {
			MachineHealth *bool  `json:"machineHealth"`
			MachineWhoami whoami `json:"machineWhoami"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHealthBytes)).Decode(&body); err != nil {
		return whoami{}, errors.New("gateway pre-check: unreadable response")
	}
	if asksWhoami && len(body.Errors) > 0 {
		return whoami{}, errNoWhoami
	}
	if len(body.Errors) > 0 || body.Data.MachineHealth == nil || !*body.Data.MachineHealth {
		return whoami{}, errors.New("gateway pre-check: unhealthy response")
	}
	return body.Data.MachineWhoami, nil
}
