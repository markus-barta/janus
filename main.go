package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie     = "janus_session"
	hostSessionCookie = "__Host-janus_session"
	stateCookie       = "janus_oidc_state"
	hostStateCookie   = "__Host-janus_oidc_state"
	nonceCookie       = "janus_oidc_nonce"
	hostNonceCookie   = "__Host-janus_oidc_nonce"
	pkceCookie        = "janus_oidc_pkce"
	hostPKCECookie    = "__Host-janus_oidc_pkce"
	attemptCookie     = "janus_oidc_attempt"
	hostAttemptCookie = "__Host-janus_oidc_attempt"
	defaultSessionTTL = 12 * time.Hour
	loginAttemptTTL   = 10 * time.Minute
	maxLoginAttempts  = 3
	maxRequestBody    = int64(4096)
)

type Config struct {
	Listen       string
	PublicURL    string
	ProductMode  string
	DataDir      string
	CatalogFile  string
	RequireAuth  bool
	OIDCIssuer   string
	OIDCClientID string
	OIDCSecret   string
	CookieKey    []byte
	RolePolicy   RolePolicy
	ScopePolicy  ScopePolicy
}

func (c Config) OIDCConfigured() bool {
	return c.OIDCIssuer != "" && c.OIDCClientID != "" && c.OIDCSecret != "" && len(c.CookieKey) >= 32
}

func (c Config) SecureCookies() bool {
	u, err := url.Parse(c.PublicURL)
	return err == nil && u.Scheme == "https"
}

func (c Config) SessionCookieName() string {
	if c.SecureCookies() {
		return hostSessionCookie
	}
	return sessionCookie
}

func (c Config) StateCookieName() string {
	if c.SecureCookies() {
		return hostStateCookie
	}
	return stateCookie
}

func (c Config) NonceCookieName() string {
	if c.SecureCookies() {
		return hostNonceCookie
	}
	return nonceCookie
}

func (c Config) PKCECookieName() string {
	if c.SecureCookies() {
		return hostPKCECookie
	}
	return pkceCookie
}

func (c Config) AttemptCookieName() string {
	if c.SecureCookies() {
		return hostAttemptCookie
	}
	return attemptCookie
}

type SecretDescriptor struct {
	ID             string    `json:"id"`
	DisplayName    string    `json:"display_name"`
	Provider       string    `json:"provider"`
	Classification string    `json:"classification"`
	Owner          string    `json:"owner"`
	Scope          string    `json:"scope,omitempty"`
	Source         string    `json:"source,omitempty"`
	RotationDays   int       `json:"rotation_days"`
	LastCheckedAt  time.Time `json:"last_checked_at"`
	Lifecycle      string    `json:"lifecycle"`
	Status         string    `json:"status"`
	RevealAllowed  bool      `json:"reveal_allowed"`
	UseEnabled     bool      `json:"use_enabled"`
	ConsumerCount  int       `json:"consumer_count"`
	EgressMode     string    `json:"egress_mode,omitempty"`
	Tags           []string  `json:"tags"`
}

func (d SecretDescriptor) MarshalJSON() ([]byte, error) {
	type publicDescriptor struct {
		ID             string    `json:"id"`
		DisplayName    string    `json:"display_name"`
		Provider       string    `json:"provider"`
		Classification string    `json:"classification"`
		Owner          string    `json:"owner"`
		Scope          string    `json:"scope,omitempty"`
		RotationDays   int       `json:"rotation_days"`
		LastCheckedAt  time.Time `json:"last_checked_at"`
		Lifecycle      string    `json:"lifecycle"`
		Status         string    `json:"status"`
		RevealAllowed  bool      `json:"reveal_allowed"`
		UseEnabled     bool      `json:"use_enabled"`
		ConsumerCount  int       `json:"consumer_count"`
		EgressMode     string    `json:"egress_mode,omitempty"`
		Tags           []string  `json:"tags"`
	}
	return json.Marshal(publicDescriptor{
		ID:             d.ID,
		DisplayName:    d.DisplayName,
		Provider:       d.Provider,
		Classification: d.Classification,
		Owner:          d.Owner,
		Scope:          d.Scope,
		RotationDays:   d.RotationDays,
		LastCheckedAt:  d.LastCheckedAt,
		Lifecycle:      d.Lifecycle,
		Status:         d.Status,
		RevealAllowed:  d.RevealAllowed,
		UseEnabled:     d.UseEnabled,
		ConsumerCount:  d.ConsumerCount,
		EgressMode:     d.EgressMode,
		Tags:           d.Tags,
	})
}

type Store struct {
	mu                  sync.RWMutex
	catalogFile         string
	externalCatalogFile string
	auditFile           string
	items               []SecretDescriptor
}

func NewStore(dataDir, externalCatalogFile string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}

	s := &Store{
		catalogFile:         filepath.Join(dataDir, "catalog.json"),
		externalCatalogFile: externalCatalogFile,
		auditFile:           filepath.Join(dataDir, "audit.jsonl"),
	}
	if err := s.loadOrSeed(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadOrSeed() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.externalCatalogFile != "" {
		raw, err := os.ReadFile(s.externalCatalogFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &s.items); err != nil {
			return err
		}
		s.normalizeLocked()
		return s.persistLocked()
	}

	raw, err := os.ReadFile(s.catalogFile)
	if errors.Is(err, os.ErrNotExist) {
		s.items = seedCatalog()
		s.normalizeLocked()
		return s.persistLocked()
	}
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		s.items = nil
		return nil
	}
	if err := json.Unmarshal(raw, &s.items); err != nil {
		return err
	}
	s.normalizeLocked()
	return nil
}

func (s *Store) normalizeLocked() {
	now := time.Now().UTC()
	for i := range s.items {
		item := &s.items[i]
		item.ID = strings.TrimSpace(item.ID)
		item.DisplayName = strings.TrimSpace(item.DisplayName)
		if item.DisplayName == "" {
			item.DisplayName = item.ID
		}
		if item.Provider == "" {
			item.Provider = "agenix"
		}
		if item.Classification == "" {
			item.Classification = "internal"
		}
		if item.Owner == "" {
			item.Owner = "platform"
		}
		if item.Scope == "" {
			item.Scope = "csb1"
		}
		if item.RotationDays == 0 {
			item.RotationDays = 180
		}
		if item.LastCheckedAt.IsZero() {
			item.LastCheckedAt = now
		}
		item.Lifecycle = DescriptorLifecycle(*item)
		if item.Status == "" {
			item.Status = "managed"
		}
		if item.EgressMode == "" {
			item.EgressMode = "none"
		}
		item.RevealAllowed = false
	}
}

func (s *Store) persistLocked() error {
	raw, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(s.catalogFile, raw, 0o600)
}

func (s *Store) Descriptors() []SecretDescriptor {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]SecretDescriptor, len(s.items))
	copy(out, s.items)
	for i := range out {
		out[i].RevealAllowed = false
	}
	return out
}

func (s *Store) FindDescriptor(ref string) (SecretDescriptor, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ref = strings.TrimSpace(ref)
	for _, item := range s.items {
		if item.ID == ref {
			item.RevealAllowed = false
			return item, true
		}
	}
	return SecretDescriptor{}, false
}

type AuditEntry struct {
	Time      time.Time `json:"time"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
	Severity  string    `json:"severity,omitempty"`
	ActorHash string    `json:"actor_hash,omitempty"`
	RequestID string    `json:"request_id"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	SecretRef string    `json:"secret_ref,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	PrevHash  string    `json:"prev_hash,omitempty"`
	EventHash string    `json:"event_hash,omitempty"`
}

type App struct {
	cfg       Config
	store     *Store
	broker    *Broker
	permits   *PermitStore
	evidence  *EvidenceAttachmentStore
	limiter   *RateLimiter
	oauth     *oauth2.Config
	verifier  *oidc.IDTokenVerifier
	templates *template.Template
}

type Session struct {
	Subject string    `json:"sub"`
	Email   string    `json:"email,omitempty"`
	Name    string    `json:"name,omitempty"`
	Roles   []string  `json:"roles,omitempty"`
	Expiry  time.Time `json:"exp"`
}

type OIDCLoginAttempt struct {
	Count     int   `json:"count"`
	StartedAt int64 `json:"started_at"`
}

type SessionPosture struct {
	AbsoluteTTLSeconds int    `json:"absolute_ttl_seconds"`
	TTLLabel           string `json:"ttl_label"`
	ExpiresAt          string `json:"expires_at,omitempty"`
	ExpiresLabel       string `json:"expires_label,omitempty"`
	SecondsRemaining   int    `json:"seconds_remaining,omitempty"`
	CookieSameSite     string `json:"cookie_same_site"`
	CookieHostPrefixed bool   `json:"cookie_host_prefixed"`
	CSRFBound          bool   `json:"csrf_bound"`
	CookieSigned       bool   `json:"cookie_signed"`
	ValueReturned      bool   `json:"value_returned"`
}

type ProductModePosture struct {
	Mode          string               `json:"mode"`
	Current       string               `json:"current"`
	Baseline      string               `json:"baseline"`
	Enterprise    string               `json:"enterprise"`
	Summary       string               `json:"summary"`
	Controls      []ProductModeControl `json:"controls"`
	ValueReturned bool                 `json:"value_returned"`
}

type ProductModeControl struct {
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Tone   string `json:"tone"`
}

type UIActionResult struct {
	Title          string         `json:"title"`
	Outcome        string         `json:"outcome"`
	Message        string         `json:"message"`
	Receipt        *ActionReceipt `json:"receipt,omitempty"`
	HandleID       string         `json:"handle_id,omitempty"`
	PermitID       string         `json:"permit_id,omitempty"`
	ControlKey     string         `json:"control_key,omitempty"`
	SecretRef      string         `json:"secret_ref,omitempty"`
	Action         string         `json:"action,omitempty"`
	Status         string         `json:"status,omitempty"`
	EvidenceState  string         `json:"evidence_state,omitempty"`
	ExpiresAt      string         `json:"expires_at,omitempty"`
	RunReason      string         `json:"run_reason,omitempty"`
	RequestID      string         `json:"request_id,omitempty"`
	OutputScrubbed bool           `json:"output_scrubbed,omitempty"`
	ValueReturned  bool           `json:"value_returned"`
}

type AuthErrorView struct {
	Title         string
	CSPNonce      string
	Mode          string
	Session       Session
	CSRF          string
	StatusCode    int
	ReasonCode    string
	Headline      string
	Message       string
	NextAction    string
	PrimaryHref   string
	PrimaryLabel  string
	SecondaryHref string
	SecondaryText string
	Posture       AuthFailurePosture
	RequestID     string
	ValueReturned bool
}

type SafeFailureView struct {
	Title          string
	CSPNonce       string
	Mode           string
	Session        Session
	CSRF           string
	StatusCode     int
	ReasonCode     string
	Message        string
	RequestID      string
	AllowedMethods []string
	ValueReturned  bool
}

type DescriptorFocus struct {
	Descriptor       SecretDescriptor `json:"descriptor"`
	Gates            []CatalogGate    `json:"gates"`
	GateCount        int              `json:"gate_count"`
	Lifecycle        string           `json:"lifecycle"`
	LifecycleBlocked bool             `json:"lifecycle_blocked"`
	LifecycleReason  string           `json:"lifecycle_reason,omitempty"`
	NormalUseBlocked bool             `json:"normal_use_blocked"`
	NormalUseReason  string           `json:"normal_use_reason,omitempty"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	store, err := NewStore(cfg.DataDir, cfg.CatalogFile)
	if err != nil {
		log.Fatalf("store error: %v", err)
	}

	app, err := NewApp(context.Background(), cfg, store)
	if err != nil {
		log.Fatalf("app error: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("janus listening on %s mode=%s oidc_configured=%t", cfg.Listen, cfg.ProductMode, cfg.OIDCConfigured())
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server stopped: %v", err)
	}
}

func loadConfig() (Config, error) {
	cfg := Config{
		Listen:      envDefault("JANUS_LISTEN", ":8080"),
		PublicURL:   strings.TrimRight(envDefault("JANUS_PUBLIC_URL", "https://vault.barta.cm"), "/"),
		ProductMode: envDefault("JANUS_PRODUCT_MODE", "self_hosted"),
		DataDir:     envDefault("JANUS_DATA_DIR", "/data"),
		CatalogFile: envDefault("JANUS_CATALOG_FILE", ""),
		RequireAuth: envBoolDefault("JANUS_REQUIRE_AUTH", true),
		OIDCIssuer:  strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/"),
	}
	cfg.OIDCClientID = os.Getenv("OIDC_CLIENT_ID")
	cfg.OIDCSecret = os.Getenv("OIDC_CLIENT_SECRET")

	cookieKey := os.Getenv("COOKIE_KEY")
	if cookieKey != "" {
		key, err := decodeKey(cookieKey)
		if err != nil {
			return cfg, fmt.Errorf("COOKIE_KEY must be base64 or hex encoded 32+ bytes: %w", err)
		}
		cfg.CookieKey = key
	}
	cfg.RolePolicy = LoadRolePolicyFromEnv()
	cfg.ScopePolicy = LoadScopePolicyFromEnv()

	if _, err := url.ParseRequestURI(cfg.PublicURL); err != nil {
		return cfg, fmt.Errorf("JANUS_PUBLIC_URL is invalid: %w", err)
	}
	if cfg.RequireAuth && !cfg.OIDCConfigured() {
		log.Printf("auth is required but OIDC is not fully configured; serving setup-only surface")
	}
	return cfg, nil
}

func NewApp(ctx context.Context, cfg Config, store *Store) (*App, error) {
	permitStore, err := NewPermitStore(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("permit store: %w", err)
	}
	evidenceStore, err := NewEvidenceAttachmentStore(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("evidence attachment store: %w", err)
	}
	app := &App{
		cfg:       cfg,
		store:     store,
		broker:    NewBroker(store).WithScopePolicy(cfg.ScopePolicy),
		permits:   permitStore,
		evidence:  evidenceStore,
		limiter:   NewRateLimiter(180, time.Minute),
		templates: mustTemplates(),
	}

	if cfg.OIDCConfigured() {
		provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
		if err != nil {
			return nil, fmt.Errorf("oidc provider: %w", err)
		}
		app.oauth = &oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.PublicURL + "/oidc/callback",
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
		app.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID})
	}

	return app, nil
}

func (app *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", app.handleHealth)
	mux.HandleFunc("GET /readyz", app.handleReady)
	mux.HandleFunc("GET /favicon.ico", app.handleFavicon)
	mux.HandleFunc("GET /login", app.handleLogin)
	mux.HandleFunc("GET /oidc/callback", app.handleCallback)
	mux.HandleFunc("POST /logout", app.withAuth(app.handleLogout))
	mux.HandleFunc("GET /session-witness", app.withAuth(app.handleSessionWitnessPage))
	mux.HandleFunc("GET /session-witness.txt", app.withAuth(app.handleSessionWitnessText))
	mux.HandleFunc("GET /session-witness/proof.txt", app.withAuth(app.handleSessionWitnessProofText))
	mux.HandleFunc("GET /session-witness/verify", app.withAuth(app.handleSessionWitnessVerifyPage))
	mux.HandleFunc("POST /session-witness/verify", app.withAuth(app.handleSessionWitnessVerifyPost))
	mux.HandleFunc("POST /session-witness/verify-pack", app.withAuth(app.handleSessionWitnessVerifyPackPost))
	mux.HandleFunc("POST /session-witness/verify-current", app.withAuth(app.handleSessionWitnessVerifyCurrent))
	mux.HandleFunc("POST /session-witness/verify-current-pack", app.withAuth(app.handleSessionWitnessVerifyCurrentPack))
	mux.HandleFunc("GET /api/warden/descriptors", app.withAuth(app.handleDescriptors))
	mux.HandleFunc("POST /api/warden/resolve", app.withAuth(app.requireRole(RoleOperator, "warden.resolve", app.handleResolveHandle)))
	mux.HandleFunc("GET /api/audit/recent", app.withAuth(app.requireRole(RoleAuditor, "audit.recent", app.handleRecentAudit)))
	mux.HandleFunc("GET /api/auth/session-witness", app.withAuth(app.handleAuthSessionWitness))
	mux.HandleFunc("POST /api/auth/session-witness/verify", app.withAuth(app.handleAuthSessionWitnessVerify))
	mux.HandleFunc("POST /api/auth/session-witness/verify-pack", app.withAuth(app.handleAuthSessionWitnessVerifyPack))
	mux.HandleFunc("POST /api/auth/session-witness/verify-current-pack", app.withAuth(app.handleAuthSessionWitnessVerifyCurrentPack))
	mux.HandleFunc("GET /api/posture", app.withAuth(app.handlePosture))
	mux.HandleFunc("GET /api/evidence", app.withAuth(app.requireRole(RoleAuditor, "evidence.export", app.handleEvidence)))
	mux.HandleFunc("POST /api/evidence/attachments", app.withAuth(app.handleAttachEvidence))
	mux.HandleFunc("POST /api/permits", app.withAuth(app.requireRole(RoleOperator, "permit.create", app.handleCreatePermit)))
	mux.HandleFunc("POST /api/permits/{permitID}/run", app.withAuth(app.requireRole(RoleOperator, "permit.run", app.handleRunPermit)))
	mux.HandleFunc("POST /ui/warden/resolve", app.withAuth(app.handleResolveHandleUI))
	mux.HandleFunc("POST /ui/evidence/attachments", app.withAuth(app.handleAttachEvidenceUI))
	mux.HandleFunc("POST /ui/permits", app.withAuth(app.handleCreatePermitUI))
	mux.HandleFunc("POST /ui/permits/{permitID}/run", app.withAuth(app.handleRunPermitUI))
	mux.HandleFunc("GET /", app.withAuth(app.handleDashboard))
	return app.securityHeaders(app.requestIDs(app.rateLimit(app.limitRequestBody(app.safeHTTPBoundary(mux)))))
}

func (app *App) safeHTTPBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, known := allowedMethodsForPath(r.URL.Path)
		if !known {
			app.renderSafeFailure(w, r, http.StatusNotFound, "route_not_found", "Janus does not expose that route.", nil)
			return
		}
		if !methodAllowed(allowed, r.Method) {
			displayAllowed := displayAllowedMethods(allowed)
			app.renderSafeFailure(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "That route does not accept this action.", displayAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func allowedMethodsForPath(path string) ([]string, bool) {
	switch path {
	case "/", "/session-witness", "/session-witness.txt", "/session-witness/proof.txt", "/healthz", "/readyz", "/favicon.ico", "/login", "/oidc/callback", "/api/warden/descriptors", "/api/audit/recent", "/api/auth/session-witness", "/api/posture", "/api/evidence":
		return []string{http.MethodGet}, true
	case "/session-witness/verify":
		return []string{http.MethodGet, http.MethodPost}, true
	case "/session-witness/verify-current", "/session-witness/verify-current-pack", "/session-witness/verify-pack":
		return []string{http.MethodPost}, true
	case "/logout", "/api/warden/resolve", "/api/evidence/attachments", "/api/permits", "/ui/warden/resolve", "/ui/evidence/attachments", "/ui/permits":
		return []string{http.MethodPost}, true
	case "/api/auth/session-witness/verify", "/api/auth/session-witness/verify-pack", "/api/auth/session-witness/verify-current-pack":
		return []string{http.MethodPost}, true
	}
	switch {
	case singleSegmentRunPath(path, "/api/permits/"):
		return []string{http.MethodPost}, true
	case singleSegmentRunPath(path, "/ui/permits/"):
		return []string{http.MethodPost}, true
	default:
		return nil, false
	}
}

func singleSegmentRunPath(path, prefix string) bool {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return false
	}
	permitID, ok := strings.CutSuffix(rest, "/run")
	return ok && permitID != "" && !strings.Contains(permitID, "/")
}

func methodAllowed(allowed []string, method string) bool {
	for _, item := range allowed {
		if item == method || item == http.MethodGet && method == http.MethodHead {
			return true
		}
	}
	return false
}

func displayAllowedMethods(allowed []string) []string {
	seen := make(map[string]bool, len(allowed)+1)
	for _, method := range allowed {
		seen[method] = true
		if method == http.MethodGet {
			seen[http.MethodHead] = true
		}
	}
	display := make([]string, 0, len(seen))
	for method := range seen {
		display = append(display, method)
	}
	sort.Strings(display)
	return display
}

func (app *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := randomNonce(18)
		r = r.WithContext(context.WithValue(r.Context(), cspNonceKey{}, nonce))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none'; worker-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; font-src 'self'; img-src 'self' data:; manifest-src 'self'; style-src 'self' 'nonce-"+nonce+"'; upgrade-insecure-requests")
		w.Header().Set("Cross-Origin-Embedder-Policy", "credentialless")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Expires", "0")
		w.Header().Set("Origin-Agent-Cluster", "?1")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if app.cfg.SecureCookies() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		w.Header().Set("X-DNS-Prefetch-Control", "off")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		next.ServeHTTP(w, r)
	})
}

func (app *App) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/favicon.ico" {
			next.ServeHTTP(w, r)
			return
		}
		key := clientKey(r) + "|" + r.URL.Path
		if !app.limiter.Allow(key) {
			retryAfter := int(app.limiter.window.Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":               "rate_limited",
				"message":             "Too many requests",
				"request_id":          requestID(r),
				"retry_after_seconds": retryAfter,
				"value_returned":      false,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (app *App) limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > maxRequestBody {
			writeJSONError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "Request body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next.ServeHTTP(w, r)
	})
}

func (app *App) requestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := inboundRequestID(r)
		if id == "" {
			id = randomToken(12)
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

func (app *App) handleFavicon(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !app.cfg.RequireAuth {
			session := Session{Subject: "dev-local", Name: "Local Dev", Roles: AllRoles(), Expiry: time.Now().UTC().Add(time.Hour)}
			next(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session)))
			return
		}

		if !app.cfg.OIDCConfigured() {
			if isAPIRequest(r) {
				app.audit(r, "auth.setup", "denied", "", "auth incomplete")
				writeJSONError(w, r, http.StatusServiceUnavailable, "auth_not_configured", "OIDC is not configured")
				return
			}
			app.renderSetup(w, r)
			return
		}

		session, ok := app.readSession(r)
		if !ok {
			app.audit(r, "auth.required", "denied", "", "missing session")
			if isAPIRequest(r) {
				writeJSONError(w, r, http.StatusUnauthorized, "auth_required", "Authentication required")
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session)))
	}
}

func isAPIRequest(r *http.Request) bool {
	return r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/")
}

func (app *App) requireRole(role, action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := currentSession(r.Context())
		if !HasRole(session, role) {
			app.audit(r, action, "denied", session.Subject, "role "+role+" required")
			writeJSONError(w, r, http.StatusForbidden, "role_denied", role+" role required")
			return
		}
		next(w, r)
	}
}

func (app *App) requireReadyAPI(w http.ResponseWriter, r *http.Request, session Session, action string) bool {
	if _, ready := app.readinessBody(); ready {
		return true
	}
	app.audit(r, action, "denied", session.Subject, "system degraded")
	readiness, _ := app.publicReadinessBody()
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"error":          "system_degraded",
		"message":        "Janus readiness is degraded; sensitive action blocked.",
		"request_id":     requestID(r),
		"readiness":      readiness,
		"value_returned": false,
	})
	return false
}

func (app *App) requireReadyUI(w http.ResponseWriter, r *http.Request, session Session, action, title, selectedRef string) bool {
	if _, ready := app.readinessBody(); ready {
		return true
	}
	app.audit(r, action, "denied", session.Subject, "system degraded")
	result := UIActionResult{
		Title:         title,
		Outcome:       "denied",
		Message:       "Janus readiness is degraded; sensitive action blocked until checks recover.",
		RunReason:     "system_degraded",
		RequestID:     requestID(r),
		ValueReturned: false,
	}
	renderTemplateStatus(w, app.templates, "dashboard", http.StatusServiceUnavailable, app.dashboardData(r, session, &result, selectedRef))
	return false
}

func (app *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "ok",
		"service":        "janus",
		"mode":           app.cfg.ProductMode,
		"redacted":       true,
		"value_returned": false,
	})
}

func (app *App) handleReady(w http.ResponseWriter, _ *http.Request) {
	body, ready := app.publicReadinessBody()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (app *App) publicReadinessBody() (map[string]any, bool) {
	body, ready := app.readinessBody()
	return map[string]any{
		"ready":          ready,
		"service":        body["service"],
		"mode":           body["mode"],
		"checks":         body["checks"],
		"redacted":       true,
		"value_returned": false,
	}, ready
}

func (app *App) readinessBody() (map[string]any, bool) {
	authReady := !app.cfg.RequireAuth || app.cfg.OIDCConfigured()
	descriptorReady := app.store != nil
	descriptorCount := 0
	auditSinkReady := false
	auditChainReady := false
	permitStoreReady := false
	evidenceStoreReady := false

	if app.store != nil {
		descriptorCount = len(app.store.Descriptors())
		audit := app.store.AuditPosture()
		auditSinkReady = audit.SinkWritable
		auditChainReady = audit.ChainVerified
	}
	if app.permits != nil {
		permitStoreReady = app.permits.Posture().Persisted
	}
	if app.evidence != nil {
		evidenceStoreReady = app.evidence.file != ""
	}

	checks := map[string]bool{
		"auth":                      authReady,
		"descriptor_store":          descriptorReady,
		"audit_sink":                auditSinkReady,
		"audit_chain":               auditChainReady,
		"permit_store":              permitStoreReady,
		"evidence_attachment_store": evidenceStoreReady,
		"value_returned":            false,
	}
	ready := authReady && descriptorReady && auditSinkReady && auditChainReady && permitStoreReady && evidenceStoreReady
	return map[string]any{
		"ready":            ready,
		"service":          "janus",
		"mode":             app.cfg.ProductMode,
		"checks":           checks,
		"auth_required":    app.cfg.RequireAuth,
		"oidc_configured":  app.cfg.OIDCConfigured(),
		"descriptor_count": descriptorCount,
		"redacted":         false,
		"value_returned":   false,
	}, ready
}

func (app *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		app.renderSafeFailure(w, r, http.StatusNotFound, "route_not_found", "Janus does not expose that route.", nil)
		return
	}
	app.audit(r, "dashboard.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	renderTemplate(w, app.templates, "dashboard", app.dashboardData(r, session, nil, r.URL.Query().Get("ref")))
}

func (app *App) dashboardData(r *http.Request, session Session, actionResult *UIActionResult, selectedRef string) map[string]any {
	principal := principalFromSession(session)
	descriptors := app.broker.Descriptors(principal)
	if selectedRef == "" && actionResult != nil {
		selectedRef = actionResult.SecretRef
	}
	focus := focusDescriptor(descriptors, selectedRef)
	evidenceAttachments := app.evidenceAttachmentMap()
	issues := enterpriseChecksWithAttachments(app.cfg, evidenceAttachments)
	canViewAudit := HasRole(session, RoleAuditor)
	auditPosture := app.store.AuditPosture()
	var recentAudit []AuditEntry
	if canViewAudit {
		recentAudit = app.store.RecentAudit(8)
	}
	auditTrail := AuditTrailFor(recentAudit, auditPosture, canViewAudit)
	catalogGates := ValidateCatalog(descriptors)
	accessPosture := app.accessPosture()
	rolePolicyReadiness := RolePolicyReadinessFor(app.cfg.RolePolicy, accessPosture)
	readinessBody, ready := app.readinessBody()
	scopePosture := app.scopePosture(app.store.Descriptors())
	lifecyclePosture := LifecyclePostureFor(descriptors, time.Now().UTC())
	approvedUsePosture := ApprovedUsePostureFor(descriptors)
	permitPosture := PermitPosture{ValueReturned: false}
	var recentPermits []Permit
	canOperate := HasRole(session, RoleOperator)
	if app.permits != nil {
		permitPosture = app.permits.Posture()
		if canOperate {
			recentPermits = app.permits.Recent(8)
		}
	}
	evidenceHash := ""
	evidenceHashFull := ""
	if canViewAudit && app.permits != nil {
		evidencePack := app.evidencePack(session)
		if evidencePack.Integrity != nil {
			evidenceHashFull = evidencePack.Integrity.PackHash
			evidenceHash = evidenceHashFull
			if len(evidenceHash) > 12 {
				evidenceHash = evidenceHash[:12]
			}
		}
	}
	evidenceBoundary := EvidenceBoundaryFor(canViewAudit, evidenceHash != "")
	evidenceReceipt := EvidenceReceiptFor(evidenceBoundary, nil)
	supplyChain := SupplyChainPostureFor(evidenceBoundary)
	authFailure := AuthFailurePostureFor(app.cfg)
	authenticatedRole := SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), ready)
	authenticatedBrowser := app.authenticatedBrowserWitness(session, authenticatedRole, ready)
	assuranceSummary := AssuranceSummaryFor(app.cfg.ProductMode, ready, len(issues), len(catalogGates), accessPosture, auditPosture, evidenceBoundary)
	assuranceGates := AssuranceGatesFor(ready, len(catalogGates), accessPosture)
	enterpriseValidation := EnterpriseValidationWithAttachmentsFor(app.cfg, ready, accessPosture, auditPosture, len(catalogGates), evidenceAttachments)
	enterpriseDryRun := EnterpriseDryRunFor(app.cfg.ProductMode, EnterpriseValidationWithAttachmentsFor(Config{ProductMode: "enterprise", RolePolicy: app.cfg.RolePolicy}, ready, accessPosture, auditPosture, len(catalogGates), evidenceAttachments))
	enterpriseClaim := EnterpriseClaimReviewFor(app.cfg.ProductMode, enterpriseValidation, enterpriseDryRun, evidenceBoundary)
	attachmentReview := AttachmentReviewFor(enterpriseValidation)
	externalEvidence := app.externalEvidencePosture(enterpriseValidation, session)
	modeGuardrails := ModeGuardrailsFor(app.cfg, ready, issues, accessPosture, auditPosture, len(catalogGates), enterpriseValidation)
	restoreProof := RestoreDrillProofFor(enterpriseValidation)
	restoreWorkflow := RestoreDrillWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	releaseWorkflow := ReleaseProvenanceWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	privacyWorkflow := PrivacyRetentionWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	integrationWorkflow := IntegrationConformanceWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	remoteAuditWorkflow := RemoteAuditWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	breakGlassWorkflow := BreakGlassReviewWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	enterpriseReleaseGate := EnterpriseReleaseGateFor(app.cfg.ProductMode, enterpriseClaim, supplyChain, remoteAuditWorkflow, restoreWorkflow, releaseWorkflow, privacyWorkflow, integrationWorkflow, breakGlassWorkflow, auditPosture, accessPosture, app.cfg.RolePolicy, evidenceBoundary)
	privacyPosture := PrivacyPostureFor(evidenceBoundary, auditPosture)
	negativePath := NegativePathAssuranceFor(ready, len(catalogGates), accessPosture, auditPosture)
	degradedGuidance := DegradedGuidanceFor(ready, auditPosture, evidenceBoundary, enterpriseValidation)
	auditDrill := AuditFailureDrillFor(ready, auditPosture)
	roleAvailability := RoleAvailabilityFor(session)
	roleWorkbench := RoleWorkbenchFor(session, ready)
	actionReadiness := ActionReadinessFor(session, ready)
	operationalStatus := OperationalStatusFor(ready, scopePosture, assuranceSummary, evidenceBoundary, roleAvailability)
	commandCenter := CommandCenterFor(ready, operationalStatus, actionReadiness, modeGuardrails, attachmentReview, evidenceBoundary)
	data := map[string]any{
		"Title":                "Janus",
		"CSPNonce":             cspNonceFromContext(r.Context()),
		"Session":              session,
		"CSRF":                 app.csrfToken(session),
		"Descriptors":          descriptors,
		"Issues":               issues,
		"Mode":                 app.cfg.ProductMode,
		"Audit":                recentAudit,
		"AuditTrail":           auditTrail,
		"Posture":              auditPosture,
		"CatalogGates":         catalogGates,
		"Access":               accessPosture,
		"RolePolicyReadiness":  rolePolicyReadiness,
		"RoleBoundaries":       RoleBoundariesFor(session),
		"RoleAvailability":     roleAvailability,
		"RoleWorkbench":        roleWorkbench,
		"ActionReadiness":      actionReadiness,
		"OperationalStatus":    operationalStatus,
		"SupplyChain":          supplyChain,
		"AuthFailure":          authFailure,
		"AuthenticatedRole":    authenticatedRole,
		"AuthenticatedBrowser": authenticatedBrowser,
		"CommandCenter":        commandCenter,
		"Ready":                ready,
		"Readiness":            readinessBody,
		"SessionPosture":       app.sessionPosture(session),
		"Scope":                scopePosture,
		"Lifecycle":            lifecyclePosture,
		"ApprovedUse":          approvedUsePosture,
		"ModePosture":          ProductModePostureFor(app.cfg, ready, issues, accessPosture, auditPosture, len(catalogGates)),
		"ModeGuardrails":       modeGuardrails,
		"Enterprise":           enterpriseValidation,
		"EnterpriseDryRun":     enterpriseDryRun,
		"EnterpriseClaim":      enterpriseClaim,
		"EnterpriseRelease":    enterpriseReleaseGate,
		"AttachmentReview":     attachmentReview,
		"ExternalEvidence":     externalEvidence,
		"RestoreProof":         restoreProof,
		"RestoreWorkflow":      restoreWorkflow,
		"ReleaseWorkflow":      releaseWorkflow,
		"PrivacyWorkflow":      privacyWorkflow,
		"IntegrationWorkflow":  integrationWorkflow,
		"RemoteAuditWorkflow":  remoteAuditWorkflow,
		"BreakGlassWorkflow":   breakGlassWorkflow,
		"Privacy":              privacyPosture,
		"AssuranceSummary":     assuranceSummary,
		"AssuranceGates":       assuranceGates,
		"NegativePath":         negativePath,
		"Guidance":             degradedGuidance,
		"AuditDrill":           auditDrill,
		"EvidenceHash":         evidenceHash,
		"EvidenceHashFull":     evidenceHashFull,
		"EvidenceBoundary":     evidenceBoundary,
		"EvidenceReceipt":      evidenceReceipt,
		"CanExportEvidence":    canViewAudit,
		"CanViewAudit":         canViewAudit,
		"CanOperate":           canOperate,
		"ActionResult":         actionResult,
		"Permits":              recentPermits,
		"PermitPosture":        permitPosture,
		"SelectedRef":          focus.Descriptor.ID,
		"Focus":                focus,
	}
	return data
}

func (app *App) authenticatedBrowserWitness(session Session, roleEvidence SessionRoleEvidence, ready bool) AuthenticatedBrowserWitness {
	return AuthenticatedBrowserWitnessFor(session, roleEvidence, app.sessionPosture(session), app.cfg.RequireAuth, app.cfg.OIDCConfigured(), ready)
}

func (app *App) authenticatedBrowserWitnessCapture(session Session) (AuthenticatedBrowserWitness, AuthenticatedBrowserCapture) {
	_, ready := app.readinessBody()
	roleEvidence := SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), ready)
	return app.authenticatedBrowserWitness(session, roleEvidence, ready), AuthenticatedBrowserCaptureFor()
}

func applyAuthenticatedBrowserWitnessHeaders(w http.ResponseWriter, witness AuthenticatedBrowserWitness, capture AuthenticatedBrowserCapture, receipt AuthenticatedBrowserCaptureReceipt) {
	w.Header().Set("X-Janus-Witness-Schema", capture.Schema)
	w.Header().Set("X-Janus-Witness-State", witness.State)
	w.Header().Set("X-Janus-Witness-Flow", witness.Flow)
	w.Header().Set("X-Janus-Witness-Signal", witness.EvidenceSignal)
	w.Header().Set("X-Janus-Witness-Body-Field", capture.BodyField)
	w.Header().Set("X-Janus-Witness-Algorithm", receipt.Algorithm)
	w.Header().Set("X-Janus-Witness-Hash", receipt.Hash)
	w.Header().Set("X-Janus-Witness-Hash-Body-Field", receipt.BodyField)
	w.Header().Set("X-Janus-Witness-Captured-At", receipt.CapturedAt)
	w.Header().Set("X-Janus-Witness-Fresh-Until", receipt.FreshUntil)
	w.Header().Set("X-Janus-Witness-Freshness-Seconds", fmt.Sprintf("%d", receipt.FreshnessSeconds))
	w.Header().Set("X-Janus-Value-Returned", "false")
}

func applyWitnessVerificationHeaders(w http.ResponseWriter, receipt WitnessVerificationReceipt) {
	w.Header().Set("X-Janus-Witness-Verification-Schema", receipt.Schema)
	w.Header().Set("X-Janus-Witness-Verification-Algorithm", receipt.Algorithm)
	w.Header().Set("X-Janus-Witness-Verification-Hash", receipt.Hash)
	w.Header().Set("X-Janus-Witness-Verification-Hash-Body-Field", receipt.BodyField)
	w.Header().Set("X-Janus-Value-Returned", "false")
}

func attachWitnessEvidence(w http.ResponseWriter, verification WitnessReceiptVerification, requestID string) WitnessReceiptVerification {
	receipt := WitnessReceiptVerificationReceiptFor(verification, requestID)
	verification.Receipt = &receipt
	evidence := WitnessEvidenceReceiptFor(verification)
	verification.Evidence = &evidence
	applyWitnessVerificationHeaders(w, receipt)
	return verification
}

func focusDescriptor(descriptors []SecretDescriptor, selectedRef string) DescriptorFocus {
	if len(descriptors) == 0 {
		return DescriptorFocus{}
	}
	selectedRef = strings.TrimSpace(selectedRef)
	focus := descriptors[0]
	for _, desc := range descriptors {
		if desc.ID == selectedRef {
			focus = desc
			break
		}
	}
	gates := ValidateCatalog([]SecretDescriptor{focus})
	lifecycleBlocked, lifecycleReason := LifecycleBlocksNormalUse(focus)
	blocked, reason := DescriptorBlocksNormalUse(focus)
	return DescriptorFocus{
		Descriptor:       focus,
		Gates:            gates,
		GateCount:        len(gates),
		Lifecycle:        DescriptorLifecycle(focus),
		LifecycleBlocked: lifecycleBlocked,
		LifecycleReason:  lifecycleReason,
		NormalUseBlocked: blocked,
		NormalUseReason:  reason,
	}
}

func (app *App) handleDescriptors(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "descriptors.list", "allowed", actorFromContext(r.Context()), "")
	principal := principalFromSession(currentSession(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{
		"descriptors":    app.broker.Descriptors(principal),
		"value_returned": false,
	})
}

func (app *App) handleRecentAudit(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	app.audit(r, "audit.recent", "allowed", session.Subject, "")
	recentAudit := app.store.RecentAudit(50)
	auditPosture := app.store.AuditPosture()
	auditTrail := AuditTrailFor(recentAudit, auditPosture, true)
	writeJSON(w, http.StatusOK, map[string]any{
		"audit":          auditTrail.Rows,
		"audit_trail":    auditTrail,
		"posture":        auditPosture,
		"value_returned": false,
	})
}

func (app *App) handlePosture(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	app.audit(r, "posture.view", "allowed", session.Subject, "")
	writeJSON(w, http.StatusOK, app.postureBody(session))
}

func (app *App) handleSessionWitnessPage(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	witness, capture := app.authenticatedBrowserWitnessCapture(session)
	reqID := requestID(r)
	capturedAt := time.Now().UTC()
	receipt := AuthenticatedBrowserCaptureReceiptFor(witness, capture, reqID, capturedAt)
	applyAuthenticatedBrowserWitnessHeaders(w, witness, capture, receipt)
	app.audit(r, "auth.session.witness.page", "allowed", session.Subject, "")
	renderTemplate(w, app.templates, "session_witness", map[string]any{
		"Title":                "Janus Session Witness",
		"CSPNonce":             cspNonceFromContext(r.Context()),
		"WitnessPage":          true,
		"Session":              session,
		"CSRF":                 app.csrfToken(session),
		"Mode":                 app.cfg.ProductMode,
		"AuthenticatedRole":    SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), witness.Ready),
		"AuthenticatedBrowser": witness,
		"Capture":              capture,
		"CaptureHeaders":       AuthenticatedBrowserCaptureHeadersFor(witness, capture, reqID, receipt),
		"CaptureLine":          receipt.Input,
		"Receipt":              receipt,
		"RequestID":            reqID,
	})
}

func (app *App) handleSessionWitnessText(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	witness, capture := app.authenticatedBrowserWitnessCapture(session)
	reqID := requestID(r)
	capturedAt := time.Now().UTC()
	receipt := AuthenticatedBrowserCaptureReceiptFor(witness, capture, reqID, capturedAt)
	applyAuthenticatedBrowserWitnessHeaders(w, witness, capture, receipt)
	w.Header().Set("Content-Disposition", `inline; filename="janus-session-witness.txt"`)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	app.audit(r, "auth.session.witness.text", "allowed", session.Subject, "")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(AuthenticatedBrowserCaptureTextFor(witness, capture, reqID, receipt)))
}

func (app *App) handleSessionWitnessProofText(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	witness, capture := app.authenticatedBrowserWitnessCapture(session)
	reqID := requestID(r)
	capturedAt := time.Now().UTC()
	witnessReceipt := AuthenticatedBrowserCaptureReceiptFor(witness, capture, reqID, capturedAt)
	verification := VerifyAuthenticatedBrowserCaptureReceipt(WitnessReceiptVerificationRequest{
		ProofLine: witnessReceipt.Input,
		ProofHash: witnessReceipt.Hash,
	}, capturedAt)
	verificationReceipt := WitnessReceiptVerificationReceiptFor(verification, reqID)
	verification.Receipt = &verificationReceipt
	applyAuthenticatedBrowserWitnessHeaders(w, witness, capture, witnessReceipt)
	applyWitnessVerificationHeaders(w, verificationReceipt)
	w.Header().Set("Content-Disposition", `inline; filename="janus-current-session-witness-proof.txt"`)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	app.audit(r, "auth.session.witness.proof_text", "allowed", session.Subject, "")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(CurrentSessionWitnessProofTextFor(witness, capture, reqID, witnessReceipt, verification)))
}

func (app *App) handleAuthSessionWitness(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	witness, capture := app.authenticatedBrowserWitnessCapture(session)
	reqID := requestID(r)
	capturedAt := time.Now().UTC()
	receipt := AuthenticatedBrowserCaptureReceiptFor(witness, capture, reqID, capturedAt)
	applyAuthenticatedBrowserWitnessHeaders(w, witness, capture, receipt)
	app.audit(r, "auth.session.witness", "allowed", session.Subject, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"witness":        witness,
		"capture":        capture,
		"receipt":        receipt,
		"request_id":     reqID,
		"value_returned": false,
	})
}

func (app *App) sessionWitnessVerifyData(r *http.Request, session Session, verification *WitnessReceiptVerification) map[string]any {
	witness, capture := app.authenticatedBrowserWitnessCapture(session)
	return map[string]any{
		"Title":                "Janus Witness Verifier",
		"CSPNonce":             cspNonceFromContext(r.Context()),
		"WitnessPage":          true,
		"WitnessVerifyPage":    true,
		"Session":              session,
		"CSRF":                 app.csrfToken(session),
		"Mode":                 app.cfg.ProductMode,
		"AuthenticatedRole":    SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), witness.Ready),
		"AuthenticatedBrowser": witness,
		"Capture":              capture,
		"Verification":         verification,
		"RequestID":            requestID(r),
	}
}

func (app *App) currentSessionWitnessVerification(r *http.Request, session Session) WitnessReceiptVerification {
	witness, capture := app.authenticatedBrowserWitnessCapture(session)
	reqID := requestID(r)
	capturedAt := time.Now().UTC()
	receipt := AuthenticatedBrowserCaptureReceiptFor(witness, capture, reqID, capturedAt)
	return VerifyAuthenticatedBrowserCaptureReceipt(WitnessReceiptVerificationRequest{
		ProofLine: receipt.Input,
		ProofHash: receipt.Hash,
	}, capturedAt)
}

func (app *App) currentSessionWitnessProofPackVerification(r *http.Request, session Session) WitnessReceiptVerification {
	witness, capture := app.authenticatedBrowserWitnessCapture(session)
	reqID := requestID(r)
	capturedAt := time.Now().UTC()
	witnessReceipt := AuthenticatedBrowserCaptureReceiptFor(witness, capture, reqID, capturedAt)
	currentVerification := VerifyAuthenticatedBrowserCaptureReceipt(WitnessReceiptVerificationRequest{
		ProofLine: witnessReceipt.Input,
		ProofHash: witnessReceipt.Hash,
	}, capturedAt)
	currentReceipt := WitnessReceiptVerificationReceiptFor(currentVerification, reqID)
	currentVerification.Receipt = &currentReceipt
	proofPack := CurrentSessionWitnessProofTextFor(witness, capture, reqID, witnessReceipt, currentVerification)
	return VerifyAuthenticatedBrowserProofPack(proofPack, capturedAt)
}

func (app *App) handleSessionWitnessVerifyPage(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	app.audit(r, "auth.session.witness.verify.page", "allowed", session.Subject, "")
	renderTemplate(w, app.templates, "session_witness_verify", app.sessionWitnessVerifyData(r, session, nil))
}

func (app *App) handleSessionWitnessVerifyPost(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.session.witness.verify.ui", "denied", session.Subject, "csrf failed")
		verification := VerifyAuthenticatedBrowserCaptureReceipt(WitnessReceiptVerificationRequest{}, time.Now().UTC())
		verification.Status = "blocked"
		verification.Summary = "CSRF token required."
		renderTemplateStatus(w, app.templates, "session_witness_verify", http.StatusForbidden, app.sessionWitnessVerifyData(r, session, &verification))
		return
	}
	if err := r.ParseForm(); err != nil {
		app.audit(r, "auth.session.witness.verify.ui", "denied", session.Subject, "bad form")
		verification := VerifyAuthenticatedBrowserCaptureReceipt(WitnessReceiptVerificationRequest{}, time.Now().UTC())
		verification.Status = "blocked"
		verification.Summary = "Verification form could not be read."
		renderTemplateStatus(w, app.templates, "session_witness_verify", http.StatusBadRequest, app.sessionWitnessVerifyData(r, session, &verification))
		return
	}
	req := WitnessReceiptVerificationRequest{
		ProofLine: r.Form.Get("proof_line"),
		ProofHash: r.Form.Get("proof_hash"),
	}
	verification := VerifyAuthenticatedBrowserCaptureReceipt(req, time.Now().UTC())
	verification = attachWitnessEvidence(w, verification, requestID(r))
	status := http.StatusOK
	if !verification.Verified {
		status = http.StatusUnprocessableEntity
	}
	app.audit(r, "auth.session.witness.verify.ui", verification.Status, session.Subject, "")
	renderTemplateStatus(w, app.templates, "session_witness_verify", status, app.sessionWitnessVerifyData(r, session, &verification))
}

func (app *App) handleSessionWitnessVerifyPackPost(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.session.witness.verify_pack.ui", "denied", session.Subject, "csrf failed")
		verification := VerifyAuthenticatedBrowserProofPack("", time.Now().UTC())
		verification.Status = "blocked"
		verification.Summary = "CSRF token required."
		renderTemplateStatus(w, app.templates, "session_witness_verify", http.StatusForbidden, app.sessionWitnessVerifyData(r, session, &verification))
		return
	}
	if err := r.ParseForm(); err != nil {
		app.audit(r, "auth.session.witness.verify_pack.ui", "denied", session.Subject, "bad form")
		verification := VerifyAuthenticatedBrowserProofPack("", time.Now().UTC())
		verification.Status = "blocked"
		verification.Summary = "Verification form could not be read."
		renderTemplateStatus(w, app.templates, "session_witness_verify", http.StatusBadRequest, app.sessionWitnessVerifyData(r, session, &verification))
		return
	}
	verification := VerifyAuthenticatedBrowserProofPack(r.Form.Get("proof_pack"), time.Now().UTC())
	verification = attachWitnessEvidence(w, verification, requestID(r))
	status := http.StatusOK
	if !verification.Verified {
		status = http.StatusUnprocessableEntity
	}
	app.audit(r, "auth.session.witness.verify_pack.ui", verification.Status, session.Subject, "")
	renderTemplateStatus(w, app.templates, "session_witness_verify", status, app.sessionWitnessVerifyData(r, session, &verification))
}

func (app *App) handleSessionWitnessVerifyCurrent(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.session.witness.verify.current", "denied", session.Subject, "csrf failed")
		verification := VerifyAuthenticatedBrowserCaptureReceipt(WitnessReceiptVerificationRequest{}, time.Now().UTC())
		verification.Status = "blocked"
		verification.Summary = "CSRF token required."
		renderTemplateStatus(w, app.templates, "session_witness_verify", http.StatusForbidden, app.sessionWitnessVerifyData(r, session, &verification))
		return
	}
	verification := app.currentSessionWitnessVerification(r, session)
	verification = attachWitnessEvidence(w, verification, requestID(r))
	status := http.StatusOK
	if !verification.Verified {
		status = http.StatusUnprocessableEntity
	}
	app.audit(r, "auth.session.witness.verify.current", verification.Status, session.Subject, "")
	renderTemplateStatus(w, app.templates, "session_witness_verify", status, app.sessionWitnessVerifyData(r, session, &verification))
}

func (app *App) handleSessionWitnessVerifyCurrentPack(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.session.witness.verify.current_pack", "denied", session.Subject, "csrf failed")
		verification := VerifyAuthenticatedBrowserProofPack("", time.Now().UTC())
		verification.Status = "blocked"
		verification.Summary = "CSRF token required."
		renderTemplateStatus(w, app.templates, "session_witness_verify", http.StatusForbidden, app.sessionWitnessVerifyData(r, session, &verification))
		return
	}
	verification := app.currentSessionWitnessProofPackVerification(r, session)
	verification = attachWitnessEvidence(w, verification, requestID(r))
	status := http.StatusOK
	if !verification.Verified {
		status = http.StatusUnprocessableEntity
	}
	app.audit(r, "auth.session.witness.verify.current_pack", verification.Status, session.Subject, "")
	renderTemplateStatus(w, app.templates, "session_witness_verify", status, app.sessionWitnessVerifyData(r, session, &verification))
}

func (app *App) handleAuthSessionWitnessVerify(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.session.witness.verify", "denied", session.Subject, "csrf failed")
		writeJSONError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}
	var req WitnessReceiptVerificationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		app.audit(r, "auth.session.witness.verify", "denied", session.Subject, "bad json")
		writeJSONError(w, r, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	verification := VerifyAuthenticatedBrowserCaptureReceipt(req, time.Now().UTC())
	verification = attachWitnessEvidence(w, verification, requestID(r))
	status := http.StatusOK
	if !verification.Verified {
		status = http.StatusUnprocessableEntity
	}
	app.audit(r, "auth.session.witness.verify", verification.Status, session.Subject, "")
	writeJSON(w, status, map[string]any{
		"verification":   verification,
		"request_id":     requestID(r),
		"value_returned": false,
	})
}

func (app *App) handleAuthSessionWitnessVerifyPack(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.session.witness.verify_pack", "denied", session.Subject, "csrf failed")
		writeJSONError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}
	var req WitnessProofPackVerificationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		app.audit(r, "auth.session.witness.verify_pack", "denied", session.Subject, "bad json")
		writeJSONError(w, r, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	verification := VerifyAuthenticatedBrowserProofPack(req.ProofPack, time.Now().UTC())
	verification = attachWitnessEvidence(w, verification, requestID(r))
	status := http.StatusOK
	if !verification.Verified {
		status = http.StatusUnprocessableEntity
	}
	app.audit(r, "auth.session.witness.verify_pack", verification.Status, session.Subject, "")
	writeJSON(w, status, map[string]any{
		"verification":   verification,
		"request_id":     requestID(r),
		"value_returned": false,
	})
}

func (app *App) handleAuthSessionWitnessVerifyCurrentPack(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.session.witness.verify_current_pack", "denied", session.Subject, "csrf failed")
		writeJSONError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}
	verification := app.currentSessionWitnessProofPackVerification(r, session)
	verification = attachWitnessEvidence(w, verification, requestID(r))
	status := http.StatusOK
	if !verification.Verified {
		status = http.StatusUnprocessableEntity
	}
	app.audit(r, "auth.session.witness.verify_current_pack", verification.Status, session.Subject, "")
	writeJSON(w, status, map[string]any{
		"verification":   verification,
		"request_id":     requestID(r),
		"value_returned": false,
	})
}

func (app *App) handleEvidence(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.requireReadyAPI(w, r, session, "evidence.export") {
		return
	}
	app.audit(r, "evidence.export", "allowed", session.Subject, "")
	pack := app.evidencePack(session)
	if pack.Integrity != nil {
		w.Header().Set("X-Janus-Evidence-Hash", pack.Integrity.PackHash)
		w.Header().Set("X-Janus-Evidence-Algorithm", pack.Integrity.Algorithm)
		w.Header().Set("X-Janus-Evidence-Body-Field", "integrity.pack_hash")
		w.Header().Set("X-Janus-Value-Returned", "false")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="janus-evidence.json"`)
	writeJSON(w, http.StatusOK, pack)
}

func actionReceipt(r *http.Request, action, outcome, next string) ActionReceipt {
	return ActionReceiptIntegrityFor(ActionReceipt{
		Action:              action,
		Outcome:             outcome,
		RequestID:           requestID(r),
		RoleChecked:         true,
		CSRFChecked:         true,
		ReadinessChecked:    true,
		AuditRecorded:       true,
		Boundary:            "metadata_only",
		Next:                next,
		SecretValueReturned: false,
		RequestBodyReturned: false,
		ValueReturned:       false,
	})
}

func (app *App) attachEvidencePresence(r *http.Request, session Session, req EvidenceAttachmentRequest, action string) (EvidenceAttachmentRecord, int, error) {
	spec, ok := enterpriseValidationSpecByKey(req.ControlKey)
	if !ok {
		app.audit(r, action, "denied", session.Subject, "unknown evidence control")
		return EvidenceAttachmentRecord{}, http.StatusBadRequest, errors.New("Unknown enterprise evidence control.")
	}
	if req.Attestation != externalEvidenceAttestation {
		app.audit(r, action, "denied", session.Subject, "attestation required")
		return EvidenceAttachmentRecord{}, http.StatusBadRequest, errors.New("External evidence attestation required.")
	}
	if !HasRole(session, spec.OwnerRole) {
		app.audit(r, action, "denied", session.Subject, "role "+spec.OwnerRole+" required")
		return EvidenceAttachmentRecord{}, http.StatusForbidden, errors.New(spec.OwnerRole + " role required.")
	}
	if !app.requireReadyAPIForAttach(r, session, action) {
		return EvidenceAttachmentRecord{}, http.StatusServiceUnavailable, errors.New("Janus readiness is degraded; evidence presence was not recorded.")
	}
	if app.evidence == nil {
		app.audit(r, action, "denied", session.Subject, "evidence store unavailable")
		return EvidenceAttachmentRecord{}, http.StatusServiceUnavailable, errors.New("Evidence attachment store is unavailable.")
	}
	record := NewEvidenceAttachmentRecord(spec, session.Subject)
	if err := app.evidence.Put(record); err != nil {
		app.audit(r, action, "denied", session.Subject, "evidence persistence failed")
		return EvidenceAttachmentRecord{}, http.StatusInternalServerError, errors.New("Evidence presence could not be recorded.")
	}
	app.audit(r, action, "allowed", session.Subject, spec.Key)
	return record, http.StatusCreated, nil
}

func (app *App) requireReadyAPIForAttach(r *http.Request, session Session, action string) bool {
	if _, ready := app.readinessBody(); ready {
		return true
	}
	app.audit(r, action, "denied", session.Subject, "system degraded")
	return false
}

func evidenceAttachErrorCode(status int) string {
	switch status {
	case http.StatusForbidden:
		return "role_denied"
	case http.StatusServiceUnavailable:
		return "system_degraded"
	case http.StatusInternalServerError:
		return "evidence_store_failed"
	default:
		return "evidence_attestation_invalid"
	}
}

func (app *App) handleAttachEvidence(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "evidence.attach", "denied", session.Subject, "csrf failed")
		writeJSONError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}

	var req EvidenceAttachmentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, r, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	record, status, err := app.attachEvidencePresence(r, session, req, "evidence.attach")
	if err != nil {
		writeJSONError(w, r, status, evidenceAttachErrorCode(status), err.Error())
		return
	}
	receipt := actionReceipt(r, "evidence.attach", "allowed", "Keep the reviewed evidence outside Janus; only presence metadata was recorded.")
	writeJSON(w, http.StatusCreated, map[string]any{
		"attachment":     record,
		"receipt":        receipt,
		"value_returned": false,
	})
}

func (app *App) handleResolveHandle(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "warden.resolve", "denied", session.Subject, "csrf failed")
		writeJSONError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}
	if !app.requireReadyAPI(w, r, session, "warden.resolve") {
		return
	}

	var req HandleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, r, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	handle, err := app.broker.ResolveHandle(principalFromSession(session), req)
	if err != nil {
		app.handleBrokerError(w, r, "warden.resolve", session.Subject, req.Ref, err)
		return
	}
	app.auditWithRef(r, "warden.resolve", "allowed", session.Subject, handle.SecretRef, "")
	receipt := actionReceipt(r, "warden.resolve", "allowed", "Use the handle id for metadata-only follow-up or request a permit.")
	writeJSON(w, http.StatusOK, map[string]any{
		"handle":         handle,
		"receipt":        receipt,
		"value_returned": false,
	})
}

func (app *App) handleResolveHandleUI(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "warden.resolve.ui", "denied", session.Subject, "csrf failed")
		result := UIActionResult{Title: "Handle blocked", Outcome: "denied", Message: "CSRF token required.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusForbidden, app.dashboardData(r, session, &result, ""))
		return
	}
	if err := r.ParseForm(); err != nil {
		app.audit(r, "warden.resolve.ui", "denied", session.Subject, "bad form")
		result := UIActionResult{Title: "Handle blocked", Outcome: "denied", Message: "Request form could not be read.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusBadRequest, app.dashboardData(r, session, &result, ""))
		return
	}
	req := HandleRequest{
		Ref:    strings.TrimSpace(r.Form.Get("ref")),
		Reason: strings.TrimSpace(r.Form.Get("reason")),
	}
	if !app.requireOperatorUI(w, r, session, "warden.resolve.ui", req.Ref) {
		return
	}
	if req.Reason == "" {
		app.audit(r, "warden.resolve.ui", "denied", session.Subject, "reason required")
		result := UIActionResult{Title: "Handle blocked", Outcome: "denied", Message: "Reason required.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusBadRequest, app.dashboardData(r, session, &result, req.Ref))
		return
	}
	if !app.requireReadyUI(w, r, session, "warden.resolve.ui", "Handle blocked", req.Ref) {
		return
	}
	handle, err := app.broker.ResolveHandle(principalFromSession(session), req)
	if err != nil {
		status := http.StatusBadRequest
		message := "Handle request was denied."
		switch {
		case errors.Is(err, ErrNotFound):
			status = http.StatusNotFound
			message = "Descriptor not found."
			app.auditWithRef(r, "warden.resolve.ui", "denied", session.Subject, "", "not found")
		case errors.Is(err, ErrPolicyDenied):
			status = http.StatusForbidden
			message = "Policy denied."
			app.auditWithRef(r, "warden.resolve.ui", "denied", session.Subject, "", err.Error())
		default:
			app.auditWithRef(r, "warden.resolve.ui", "denied", session.Subject, "", "broker error")
		}
		result := UIActionResult{Title: "Handle blocked", Outcome: "denied", Message: message, ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", status, app.dashboardData(r, session, &result, req.Ref))
		return
	}
	app.auditWithRef(r, "warden.resolve.ui", "allowed", session.Subject, handle.SecretRef, "")
	receipt := actionReceipt(r, "warden.resolve.ui", "allowed", "Use this handle for metadata-only follow-up or request a permit.")
	result := UIActionResult{
		Title:         "Handle ready",
		Outcome:       "allowed",
		Message:       "Metadata handle issued. Secret value was not returned.",
		Receipt:       &receipt,
		HandleID:      handle.HandleID,
		SecretRef:     handle.SecretRef,
		ExpiresAt:     handle.ExpiresAt.Format("15:04:05"),
		ValueReturned: false,
	}
	renderTemplate(w, app.templates, "dashboard", app.dashboardData(r, session, &result, handle.SecretRef))
}

func (app *App) handleCreatePermit(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "permit.create", "denied", session.Subject, "csrf failed")
		writeJSONError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}
	if !app.requireReadyAPI(w, r, session, "permit.create") {
		return
	}

	var req PermitRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, r, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	permit, err := app.broker.CreatePermit(principalFromSession(session), req)
	if err != nil {
		app.handleBrokerError(w, r, "permit.create", session.Subject, req.Ref, err)
		return
	}
	if err := app.permits.Put(permit); err != nil {
		app.auditWithRef(r, "permit.create", "denied", session.Subject, permit.SecretRef, "permit persistence failed")
		writeJSONError(w, r, http.StatusInternalServerError, "permit_store_failed", "Permit could not be recorded")
		return
	}
	app.auditWithRef(r, "permit.create", permit.Status, session.Subject, permit.SecretRef, permit.DenialReason)
	receipt := actionReceipt(r, "permit.create", permit.Status, "Run the safety check when you need a no-connector execution verdict.")
	writeJSON(w, http.StatusCreated, map[string]any{
		"permit":         permit,
		"receipt":        receipt,
		"value_returned": false,
	})
}

func (app *App) handleRunPermit(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "permit.run", "denied", session.Subject, "csrf failed")
		writeJSONError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}
	if !app.requireReadyAPI(w, r, session, "permit.run") {
		return
	}

	permitID := r.PathValue("permitID")
	permit, ok := app.permits.Get(permitID)
	if !ok {
		app.audit(r, "permit.run", "denied", session.Subject, "permit not found")
		writeJSONError(w, r, http.StatusNotFound, "permit_not_found", "Permit not found")
		return
	}
	result := RunPermit(permit)
	app.auditWithRef(r, "permit.run", result.Status, session.Subject, permit.SecretRef, result.Reason)
	receipt := actionReceipt(r, "permit.run", result.Status, "Review the scrubbed run verdict and keep the audit trail.")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"result":         result,
		"receipt":        receipt,
		"value_returned": false,
	})
}

func (app *App) handleAttachEvidenceUI(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "evidence.attach.ui", "denied", session.Subject, "csrf failed")
		result := UIActionResult{Title: "Evidence blocked", Outcome: "denied", Message: "CSRF token required.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusForbidden, app.dashboardData(r, session, &result, ""))
		return
	}
	if err := r.ParseForm(); err != nil {
		app.audit(r, "evidence.attach.ui", "denied", session.Subject, "bad form")
		result := UIActionResult{Title: "Evidence blocked", Outcome: "denied", Message: "Request form could not be read.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusBadRequest, app.dashboardData(r, session, &result, ""))
		return
	}
	req := EvidenceAttachmentRequest{
		ControlKey:  strings.TrimSpace(r.Form.Get("control_key")),
		Attestation: strings.TrimSpace(r.Form.Get("attestation")),
	}
	record, status, err := app.attachEvidencePresence(r, session, req, "evidence.attach.ui")
	if err != nil {
		result := UIActionResult{Title: "Evidence blocked", Outcome: "denied", Message: err.Error(), ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", status, app.dashboardData(r, session, &result, ""))
		return
	}
	receipt := actionReceipt(r, "evidence.attach.ui", "allowed", "Keep the reviewed evidence outside Janus; only presence metadata was recorded.")
	result := UIActionResult{
		Title:         "Evidence presence attached",
		Outcome:       "allowed",
		Message:       "Presence recorded. Evidence files, URLs, refs, notes, and values stayed outside Janus.",
		Receipt:       &receipt,
		ControlKey:    record.ControlKey,
		Status:        record.Attachment,
		EvidenceState: record.State,
		ValueReturned: false,
	}
	renderTemplateStatus(w, app.templates, "dashboard", http.StatusCreated, app.dashboardData(r, session, &result, ""))
}

func (app *App) handleCreatePermitUI(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "permit.create.ui", "denied", session.Subject, "csrf failed")
		result := UIActionResult{Title: "Permit blocked", Outcome: "denied", Message: "CSRF token required.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusForbidden, app.dashboardData(r, session, &result, ""))
		return
	}
	if err := r.ParseForm(); err != nil {
		app.audit(r, "permit.create.ui", "denied", session.Subject, "bad form")
		result := UIActionResult{Title: "Permit blocked", Outcome: "denied", Message: "Request form could not be read.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusBadRequest, app.dashboardData(r, session, &result, ""))
		return
	}
	req := PermitRequest{
		Ref:         strings.TrimSpace(r.Form.Get("ref")),
		Action:      strings.TrimSpace(r.Form.Get("action")),
		Destination: strings.TrimSpace(r.Form.Get("destination")),
		Reason:      strings.TrimSpace(r.Form.Get("reason")),
	}
	if !app.requireOperatorUI(w, r, session, "permit.create.ui", req.Ref) {
		return
	}
	if req.Reason == "" {
		app.audit(r, "permit.create.ui", "denied", session.Subject, "reason required")
		result := UIActionResult{Title: "Permit blocked", Outcome: "denied", Message: "Reason required.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusBadRequest, app.dashboardData(r, session, &result, req.Ref))
		return
	}
	if !app.requireReadyUI(w, r, session, "permit.create.ui", "Permit blocked", req.Ref) {
		return
	}

	permit, err := app.broker.CreatePermit(principalFromSession(session), req)
	if err != nil {
		status := http.StatusBadRequest
		message := "Permit request was denied."
		switch {
		case errors.Is(err, ErrNotFound):
			status = http.StatusNotFound
			message = "Descriptor not found."
			app.auditWithRef(r, "permit.create.ui", "denied", session.Subject, "", "not found")
		case errors.Is(err, ErrPolicyDenied):
			status = http.StatusForbidden
			message = "Policy denied."
			app.auditWithRef(r, "permit.create.ui", "denied", session.Subject, "", err.Error())
		default:
			app.auditWithRef(r, "permit.create.ui", "denied", session.Subject, "", "broker error")
		}
		result := UIActionResult{Title: "Permit blocked", Outcome: "denied", Message: message, ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", status, app.dashboardData(r, session, &result, req.Ref))
		return
	}

	if err := app.permits.Put(permit); err != nil {
		app.auditWithRef(r, "permit.create.ui", "denied", session.Subject, permit.SecretRef, "permit persistence failed")
		result := UIActionResult{Title: "Permit blocked", Outcome: "denied", Message: "Permit could not be recorded.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusInternalServerError, app.dashboardData(r, session, &result, permit.SecretRef))
		return
	}
	app.auditWithRef(r, "permit.create.ui", permit.Status, session.Subject, permit.SecretRef, permit.DenialReason)
	outcome := "allowed"
	title := "Permit recorded"
	message := "Metadata-only permit created. Execution stays blocked until an approved connector exists."
	if permit.Status == "denied" {
		outcome = "denied"
		title = "Permit denied"
		message = permit.DenialReason
	}
	receipt := actionReceipt(r, "permit.create.ui", permit.Status, "Run the safety check when you need a no-connector execution verdict.")
	result := UIActionResult{
		Title:         title,
		Outcome:       outcome,
		Message:       message,
		Receipt:       &receipt,
		PermitID:      permit.ID,
		SecretRef:     permit.SecretRef,
		Action:        permit.Action,
		Status:        permit.Status,
		ExpiresAt:     permit.ExpiresAt.Format("15:04:05"),
		ValueReturned: false,
	}
	renderTemplate(w, app.templates, "dashboard", app.dashboardData(r, session, &result, permit.SecretRef))
}

func (app *App) handleRunPermitUI(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "permit.run.ui", "denied", session.Subject, "csrf failed")
		result := UIActionResult{Title: "Run blocked", Outcome: "denied", Message: "CSRF token required.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusForbidden, app.dashboardData(r, session, &result, ""))
		return
	}
	if !app.requireOperatorUI(w, r, session, "permit.run.ui", "") {
		return
	}
	if !app.requireReadyUI(w, r, session, "permit.run.ui", "Run blocked", "") {
		return
	}
	permitID := r.PathValue("permitID")
	permit, ok := app.permits.Get(permitID)
	if !ok {
		app.audit(r, "permit.run.ui", "denied", session.Subject, "permit not found")
		result := UIActionResult{Title: "Run blocked", Outcome: "denied", Message: "Permit not found.", ValueReturned: false}
		renderTemplateStatus(w, app.templates, "dashboard", http.StatusNotFound, app.dashboardData(r, session, &result, ""))
		return
	}
	run := RunPermit(permit)
	app.auditWithRef(r, "permit.run.ui", run.Status, session.Subject, permit.SecretRef, run.Reason)
	outcome := "allowed"
	if run.Status == "denied" {
		outcome = "denied"
	}
	receipt := actionReceipt(r, "permit.run.ui", run.Status, "Review the scrubbed run verdict and keep the audit trail.")
	result := UIActionResult{
		Title:          "Safety check complete",
		Outcome:        outcome,
		Message:        "Run evaluated. No secret value or command output was returned.",
		Receipt:        &receipt,
		PermitID:       permit.ID,
		SecretRef:      permit.SecretRef,
		Action:         permit.Action,
		Status:         run.Status,
		ExpiresAt:      permit.ExpiresAt.Format("15:04:05"),
		RunReason:      run.Reason,
		OutputScrubbed: run.OutputScrubbed,
		ValueReturned:  run.ValueReturned,
	}
	renderTemplateStatus(w, app.templates, "dashboard", http.StatusAccepted, app.dashboardData(r, session, &result, permit.SecretRef))
}

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !app.cfg.OIDCConfigured() || app.oauth == nil {
		app.renderSetup(w, r)
		return
	}
	if r.URL.Query().Get("reset") == "1" {
		app.clearOIDCLoginCookies(w)
		app.clearOIDCLoginAttemptCookie(w)
		app.audit(r, "auth.login.reset", "allowed", "", "")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	attempt := app.bumpOIDCLoginAttempt(w, r)
	if attempt.Count > maxLoginAttempts {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.start", "denied", "", "login loop paused")
		app.renderAuthError(w, r, http.StatusTooManyRequests, "login_loop_paused", "Login paused after several starts. Reset the browser session, then try again from a clean Janus page.")
		return
	}

	state := randomToken(32)
	nonce := randomToken(32)
	verifier := oauth2.GenerateVerifier()
	http.SetCookie(w, &http.Cookie{
		Name:     app.cfg.StateCookieName(),
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     app.cfg.NonceCookieName(),
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     app.cfg.PKCECookieName(),
		Value:    verifier,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	app.audit(r, "auth.login.start", "allowed", "", "")
	http.Redirect(w, r, app.oauth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (app *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	if !app.cfg.OIDCConfigured() || app.oauth == nil || app.verifier == nil {
		app.renderSetup(w, r)
		return
	}
	if r.URL.Query().Get("error") != "" {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "provider error")
		app.renderAuthError(w, r, http.StatusBadRequest, "identity_login_denied", "Zitadel did not complete login. Janus kept the provider details out of the response.")
		return
	}

	state, err := firstCookie(r, app.cfg.StateCookieName(), stateCookie)
	if err != nil || state.Value == "" || state.Value != r.URL.Query().Get("state") {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "bad state")
		app.renderAuthError(w, r, http.StatusBadRequest, "login_restart_required", "Login needs a fresh start.")
		return
	}
	nonce, err := firstCookie(r, app.cfg.NonceCookieName(), nonceCookie)
	if err != nil || nonce.Value == "" {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "missing nonce")
		app.renderAuthError(w, r, http.StatusBadRequest, "login_integrity_check_failed", "Login needs a fresh start.")
		return
	}
	pkce, err := firstCookie(r, app.cfg.PKCECookieName(), pkceCookie)
	if err != nil || pkce.Value == "" {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "missing pkce verifier")
		app.renderAuthError(w, r, http.StatusBadRequest, "login_integrity_check_failed", "Login needs a fresh start.")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "missing code")
		app.renderAuthError(w, r, http.StatusBadRequest, "authorization_code_missing", "Login did not return a usable completion code.")
		return
	}

	token, err := app.oauth.Exchange(r.Context(), code, oauth2.VerifierOption(pkce.Value))
	if err != nil {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "code exchange failed")
		app.renderAuthError(w, r, http.StatusBadGateway, "identity_response_failed", "Zitadel login could not be completed.")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "missing id token")
		app.renderAuthError(w, r, http.StatusBadGateway, "identity_response_failed", "Zitadel login could not be completed.")
		return
	}

	idToken, err := app.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "id token verify failed")
		app.renderAuthError(w, r, http.StatusBadGateway, "identity_response_failed", "Zitadel login could not be verified.")
		return
	}

	var claims struct {
		Subject      string         `json:"sub"`
		Email        string         `json:"email"`
		Name         string         `json:"name"`
		Nonce        string         `json:"nonce"`
		Groups       []string       `json:"groups"`
		Roles        []string       `json:"roles"`
		ProjectRoles map[string]any `json:"urn:zitadel:iam:org:project:roles"`
	}
	if err := idToken.Claims(&claims); err != nil {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "claims failed")
		app.renderAuthError(w, r, http.StatusBadGateway, "identity_response_failed", "Zitadel login could not be read safely.")
		return
	}
	if !validOIDCNonce(nonce.Value, claims.Nonce) {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "bad nonce")
		app.renderAuthError(w, r, http.StatusBadRequest, "login_integrity_check_failed", "Login needs a fresh start.")
		return
	}
	if claims.Subject == "" {
		app.clearOIDCLoginCookies(w)
		app.audit(r, "auth.login.callback", "denied", "", "missing subject")
		app.renderAuthError(w, r, http.StatusBadGateway, "identity_response_failed", "Zitadel login did not include a stable user subject.")
		return
	}

	session := Session{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Roles:   DeriveRoles(claims.Subject, claims.Email, ClaimRoleInputs(claims.Groups, claims.Roles, claims.ProjectRoles), app.cfg.RolePolicy),
		Expiry:  time.Now().UTC().Add(defaultSessionTTL),
	}
	app.writeSession(w, session)
	app.clearOIDCLoginCookies(w)
	app.clearOIDCLoginAttemptCookie(w)
	app.audit(r, "auth.login.complete", "allowed", session.Subject, "")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.logout", "denied", session.Subject, "csrf failed")
		app.renderAuthError(w, r, http.StatusForbidden, "logout_integrity_check_failed", "Sign out needs a fresh page.")
		return
	}
	app.audit(r, "auth.logout", "allowed", session.Subject, "")
	app.clearCookie(w, app.cfg.SessionCookieName())
	if app.cfg.SessionCookieName() != sessionCookie {
		app.clearCookie(w, sessionCookie)
	}
	app.clearOIDCLoginAttemptCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (app *App) renderSetup(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "setup.view", "allowed", "", "auth incomplete")
	renderTemplateStatus(w, app.templates, "setup", http.StatusServiceUnavailable, map[string]any{
		"Title":    "Janus setup",
		"CSPNonce": cspNonceFromContext(r.Context()),
		"Mode":     app.cfg.ProductMode,
		"Session":  Session{},
		"Issues": []string{
			"OIDC issuer, client id, client secret, and cookie key must be present before Janus exposes secret metadata.",
			"The service is live, but locked to setup status until Zitadel credentials are configured.",
		},
	})
}

func (app *App) renderAuthError(w http.ResponseWriter, r *http.Request, status int, reasonCode, message string) {
	headline, nextAction := authErrorCopy(reasonCode)
	primaryHref := "/login"
	primaryLabel := "Try again"
	secondaryHref := "/login?reset=1"
	secondaryText := "Reset login session"
	if reasonCode == "login_loop_paused" {
		primaryHref = "/login?reset=1"
		primaryLabel = "Reset login session"
		secondaryHref = "/"
		secondaryText = "Back to Janus"
	}
	renderTemplateStatus(w, app.templates, "auth_error", status, AuthErrorView{
		Title:         "Janus login",
		CSPNonce:      cspNonceFromContext(r.Context()),
		Mode:          app.cfg.ProductMode,
		CSRF:          "",
		StatusCode:    status,
		ReasonCode:    reasonCode,
		Headline:      headline,
		Message:       message,
		NextAction:    nextAction,
		PrimaryHref:   primaryHref,
		PrimaryLabel:  primaryLabel,
		SecondaryHref: secondaryHref,
		SecondaryText: secondaryText,
		Posture:       AuthFailurePostureFor(app.cfg),
		RequestID:     requestID(r),
		ValueReturned: false,
	})
}

func authErrorCopy(reasonCode string) (string, string) {
	switch reasonCode {
	case "login_loop_paused":
		return "Login loop paused", "Janus stopped before another identity redirect. Reset temporary login cookies, then try once from a clean tab."
	case "identity_login_denied":
		return "Login was not completed", "Retry from Janus. If this repeats, keep the request id and review the identity provider outside Janus."
	case "identity_response_failed", "authorization_code_missing":
		return "Identity response needs review", "Try again once. If it repeats, use the request id for server-side audit lookup."
	case "login_integrity_check_failed", "logout_integrity_check_failed":
		return "Login integrity check failed", "Reload Janus and start again so state, nonce, PKCE, and CSRF checks are fresh."
	default:
		return "Login needs a fresh start", "Start a clean login from Janus."
	}
}

func (app *App) writeSession(w http.ResponseWriter, s Session) {
	raw, _ := json.Marshal(s)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := sign(app.cfg.CookieKey, payload)
	http.SetCookie(w, &http.Cookie{
		Name:     app.cfg.SessionCookieName(),
		Value:    payload + "." + mac,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(time.Until(s.Expiry).Seconds()),
	})
}

func (app *App) readSession(r *http.Request) (Session, bool) {
	cookie, err := firstCookie(r, app.cfg.SessionCookieName(), sessionCookie)
	if err != nil {
		return Session{}, false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 || !verify(app.cfg.CookieKey, parts[0], parts[1]) {
		return Session{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Session{}, false
	}
	var session Session
	if err := json.Unmarshal(raw, &session); err != nil {
		return Session{}, false
	}
	if session.Subject == "" || time.Now().UTC().After(session.Expiry) {
		return Session{}, false
	}
	if len(session.Roles) == 0 {
		session.Roles = DeriveRoles(session.Subject, session.Email, nil, app.cfg.RolePolicy)
	}
	return session, true
}

func (app *App) sessionPosture(session Session) SessionPosture {
	posture := SessionPosture{
		AbsoluteTTLSeconds: int(defaultSessionTTL.Seconds()),
		TTLLabel:           durationLabel(defaultSessionTTL),
		CookieSameSite:     "Strict",
		CookieHostPrefixed: app.cfg.SessionCookieName() == hostSessionCookie,
		CSRFBound:          true,
		CookieSigned:       len(app.cfg.CookieKey) >= 32,
		ValueReturned:      false,
	}
	if !session.Expiry.IsZero() {
		remaining := int(time.Until(session.Expiry).Seconds())
		if remaining < 0 {
			remaining = 0
		}
		posture.ExpiresAt = session.Expiry.UTC().Format(time.RFC3339)
		posture.ExpiresLabel = session.Expiry.UTC().Format("15:04 UTC")
		posture.SecondsRemaining = remaining
	}
	return posture
}

func durationLabel(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return d.String()
}

func firstCookie(r *http.Request, names ...string) (*http.Cookie, error) {
	var firstErr error
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		cookie, err := r.Cookie(name)
		if err == nil {
			return cookie, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, http.ErrNoCookie
}

func validOIDCNonce(expected, got string) bool {
	if expected == "" || got == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(got))
}

func (app *App) clearOIDCLoginCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.StateCookieName())
	if app.cfg.StateCookieName() != stateCookie {
		app.clearCookie(w, stateCookie)
	}
	app.clearCookie(w, app.cfg.NonceCookieName())
	if app.cfg.NonceCookieName() != nonceCookie {
		app.clearCookie(w, nonceCookie)
	}
	app.clearCookie(w, app.cfg.PKCECookieName())
	if app.cfg.PKCECookieName() != pkceCookie {
		app.clearCookie(w, pkceCookie)
	}
}

func (app *App) bumpOIDCLoginAttempt(w http.ResponseWriter, r *http.Request) OIDCLoginAttempt {
	now := time.Now().UTC()
	attempt, ok := app.readOIDCLoginAttempt(r)
	if !ok || time.Unix(attempt.StartedAt, 0).Add(loginAttemptTTL).Before(now) {
		attempt = OIDCLoginAttempt{StartedAt: now.Unix()}
	}
	attempt.Count++
	app.writeOIDCLoginAttempt(w, attempt)
	return attempt
}

func (app *App) readOIDCLoginAttempt(r *http.Request) (OIDCLoginAttempt, bool) {
	if len(app.cfg.CookieKey) < 32 {
		return OIDCLoginAttempt{}, false
	}
	cookie, err := firstCookie(r, app.cfg.AttemptCookieName(), attemptCookie)
	if err != nil || cookie.Value == "" {
		return OIDCLoginAttempt{}, false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 || !verify(app.cfg.CookieKey, parts[0], parts[1]) {
		return OIDCLoginAttempt{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return OIDCLoginAttempt{}, false
	}
	var attempt OIDCLoginAttempt
	if err := json.Unmarshal(raw, &attempt); err != nil || attempt.Count < 0 || attempt.StartedAt <= 0 {
		return OIDCLoginAttempt{}, false
	}
	return attempt, true
}

func (app *App) writeOIDCLoginAttempt(w http.ResponseWriter, attempt OIDCLoginAttempt) {
	raw, _ := json.Marshal(attempt)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := sign(app.cfg.CookieKey, payload)
	http.SetCookie(w, &http.Cookie{
		Name:     app.cfg.AttemptCookieName(),
		Value:    payload + "." + mac,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(loginAttemptTTL.Seconds()),
	})
}

func (app *App) clearOIDCLoginAttemptCookie(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.AttemptCookieName())
	if app.cfg.AttemptCookieName() != attemptCookie {
		app.clearCookie(w, attemptCookie)
	}
}

func (app *App) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (app *App) audit(r *http.Request, action, outcome, actor, reason string) {
	app.auditWithRef(r, action, outcome, actor, "", reason)
}

func (app *App) auditWithRef(r *http.Request, action, outcome, actor, secretRef, reason string) {
	if app.store == nil {
		return
	}
	app.store.AppendAudit(AuditEntry{
		Action:    action,
		Outcome:   outcome,
		ActorHash: actorHash(actor),
		RequestID: requestID(r),
		Method:    r.Method,
		Path:      r.URL.Path,
		SecretRef: secretRef,
		Reason:    reason,
	})
}

type sessionKey struct{}

type cspNonceKey struct{}

type requestIDKey struct{}

func currentSession(ctx context.Context) Session {
	session, _ := ctx.Value(sessionKey{}).(Session)
	return session
}

func cspNonceFromContext(ctx context.Context) string {
	nonce, _ := ctx.Value(cspNonceKey{}).(string)
	return nonce
}

func actorFromContext(ctx context.Context) string {
	return currentSession(ctx).Subject
}

func (app *App) csrfToken(session Session) string {
	if session.Subject == "" || session.Expiry.IsZero() {
		return ""
	}
	return sign(app.cfg.CookieKey, "csrf|"+session.Subject+"|"+session.Expiry.UTC().Format(time.RFC3339Nano))
}

func (app *App) verifyCSRF(r *http.Request, session Session) bool {
	want := app.csrfToken(session)
	if want == "" {
		return false
	}
	if !app.sameOriginMutation(r) {
		return false
	}
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		if err := r.ParseForm(); err == nil {
			got = r.Form.Get("csrf_token")
		}
	}
	return hmac.Equal([]byte(want), []byte(got))
}

func (app *App) sameOriginMutation(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	expected, err := url.Parse(app.cfg.PublicURL)
	if err != nil || expected.Scheme == "" || expected.Host == "" {
		return false
	}
	for _, header := range []string{"Origin", "Referer"} {
		value := strings.TrimSpace(r.Header.Get(header))
		if value == "" {
			continue
		}
		got, err := url.Parse(value)
		if err != nil || got.Scheme == "" || got.Host == "" {
			return false
		}
		return strings.EqualFold(got.Scheme, expected.Scheme) && strings.EqualFold(got.Host, expected.Host)
	}
	return true
}

func (app *App) csrfAllowed(r *http.Request, session Session) bool {
	if !app.cfg.RequireAuth {
		return true
	}
	return app.verifyCSRF(r, session)
}

func (app *App) requireOperatorUI(w http.ResponseWriter, r *http.Request, session Session, action, selectedRef string) bool {
	if HasRole(session, RoleOperator) {
		return true
	}
	app.audit(r, action, "denied", session.Subject, "operator role required")
	result := UIActionResult{
		Title:         "Action blocked",
		Outcome:       "denied",
		Message:       "Operator role required.",
		ValueReturned: false,
	}
	renderTemplateStatus(w, app.templates, "dashboard", http.StatusForbidden, app.dashboardData(r, session, &result, selectedRef))
	return false
}

func sign(key []byte, payload string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verify(key []byte, payload, got string) bool {
	want := sign(key, payload)
	return hmac.Equal([]byte(want), []byte(got))
}

func actorHash(actor string) string {
	if actor == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(actor))
	return hex.EncodeToString(sum[:])
}

func requestID(r *http.Request) string {
	if value, _ := r.Context().Value(requestIDKey{}).(string); value != "" {
		return value
	}
	if value := inboundRequestID(r); value != "" {
		return value
	}
	return randomToken(12)
}

func inboundRequestID(r *http.Request) string {
	for _, header := range []string{"Cf-Ray", "X-Request-Id", "X-Correlation-Id"} {
		if value := sanitizeRequestID(r.Header.Get(header)); value != "" {
			return value
		}
	}
	return ""
}

func sanitizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 96 {
		return ""
	}
	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			continue
		}
		switch ch {
		case '-', '_', '.', ':':
			continue
		default:
			return ""
		}
	}
	return value
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomNonce(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeKey(value string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil && len(raw) >= 32 {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(value); err == nil && len(raw) >= 32 {
		return raw, nil
	}
	if raw, err := hex.DecodeString(value); err == nil && len(raw) >= 32 {
		return raw, nil
	}
	return nil, errors.New("invalid key length or encoding")
}

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBoolDefault(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	case "":
		return fallback
	default:
		return fallback
	}
}

func enterpriseChecks(cfg Config) []string {
	return enterpriseChecksWithAttachments(cfg, nil)
}

func enterpriseChecksWithAttachments(cfg Config, attachments map[string]EvidenceAttachmentRecord) []string {
	var issues []string
	if cfg.RequireAuth && !cfg.OIDCConfigured() {
		issues = append(issues, "Zitadel OIDC is not configured.")
	}
	if cfg.ProductMode == "enterprise" {
		for _, spec := range enterpriseValidationSpecs() {
			if os.Getenv(spec.EnvKey) == "" && !evidenceAttachmentPresent(attachments, spec.Key) {
				issues = append(issues, spec.Missing)
			}
		}
	}
	if !cfg.RolePolicy.Configured() {
		message := "Explicit Janus role bindings are not configured."
		if cfg.RolePolicy.BootstrapOwner {
			message = "Explicit Janus role bindings are not configured; self-hosted bootstrap role policy is active."
		}
		issues = append(issues, message)
	}
	return issues
}

type enterpriseValidationSpec struct {
	Key       string
	Label     string
	EnvKey    string
	Missing   string
	Detail    string
	OwnerRole string
	Next      string
}

func enterpriseValidationSpecs() []enterpriseValidationSpec {
	return []enterpriseValidationSpec{
		{
			Key:       "remote_audit",
			Label:     "Remote audit",
			EnvKey:    "JANUS_REMOTE_AUDIT",
			Missing:   "Enterprise mode needs remote audit shipping before production use.",
			Detail:    "Audit evidence must leave the host and be reviewed outside Janus.",
			OwnerRole: "auditor",
			Next:      "Attach remote audit shipping evidence outside Janus.",
		},
		{
			Key:       "break_glass_review",
			Label:     "Break-glass review",
			EnvKey:    "JANUS_BREAK_GLASS_REVIEW",
			Missing:   "Enterprise mode needs a documented break-glass review owner.",
			Detail:    "Emergency access needs a named review path and owner.",
			OwnerRole: "admin",
			Next:      "Attach break-glass owner and review evidence outside Janus.",
		},
		{
			Key:       "restore_drill",
			Label:     "Restore drill",
			EnvKey:    "JANUS_RESTORE_DRILL",
			Missing:   "Enterprise mode needs a recent restore drill record.",
			Detail:    "Recovery evidence must prove metadata, audit, scope, and policy survive restore.",
			OwnerRole: "operator",
			Next:      "Attach the latest restore drill record outside Janus.",
		},
		{
			Key:       "integration_conformance",
			Label:     "Integration conformance",
			EnvKey:    "JANUS_INTEGRATION_CONFORMANCE",
			Missing:   "Enterprise mode needs integration conformance evidence.",
			Detail:    "Identity, audit, ticketing, SIEM, and custody integrations need reviewed conformance.",
			OwnerRole: "admin",
			Next:      "Attach integration conformance evidence outside Janus.",
		},
		{
			Key:       "release_provenance",
			Label:     "Release provenance",
			EnvKey:    "JANUS_RELEASE_PROVENANCE",
			Missing:   "Enterprise mode needs trusted release provenance.",
			Detail:    "Operators need provenance, channel, and build evidence before stronger claims.",
			OwnerRole: "operator",
			Next:      "Attach release provenance evidence outside Janus.",
		},
		{
			Key:       "privacy_policy",
			Label:     "Privacy policy",
			EnvKey:    "JANUS_PRIVACY_POLICY",
			Missing:   "Enterprise mode needs privacy and retention policy evidence.",
			Detail:    "Evidence exports, audit, retention, and raw metadata access need a reviewed policy.",
			OwnerRole: "admin",
			Next:      "Attach reviewed privacy and retention policy evidence outside Janus.",
		},
	}
}

func enterpriseValidationSpecByKey(key string) (enterpriseValidationSpec, bool) {
	key = strings.TrimSpace(key)
	for _, spec := range enterpriseValidationSpecs() {
		if spec.Key == key {
			return spec, true
		}
	}
	return enterpriseValidationSpec{}, false
}

func EnterpriseValidationFor(cfg Config, ready bool, access AccessPosture, audit AuditPosture, catalogGateCount int) EnterpriseValidation {
	return EnterpriseValidationWithAttachmentsFor(cfg, ready, access, audit, catalogGateCount, nil)
}

func EnterpriseValidationWithAttachmentsFor(cfg Config, ready bool, access AccessPosture, audit AuditPosture, catalogGateCount int, attachments map[string]EvidenceAttachmentRecord) EnterpriseValidation {
	mode := strings.TrimSpace(cfg.ProductMode)
	if mode == "" {
		mode = "self_hosted"
	}
	validation := EnterpriseValidation{
		Mode:          mode,
		Status:        "not_claimed",
		Summary:       "Self-hosted mode can be ready without claiming enterprise evidence.",
		ValueReturned: false,
	}

	enterpriseMode := mode == "enterprise"
	if enterpriseMode {
		validation.Status = "blocked"
		validation.Summary = "Enterprise mode is blocked until every required external control has evidence."
	}

	validation.Controls = append(validation.Controls, EnterpriseValidationControl{
		Key:                 "self_hosted_baseline",
		Label:               "Self-hosted baseline",
		State:               "ready",
		Required:            true,
		Detail:              "Redacted readiness, explicit roles, catalog gates, and local audit must be clear.",
		OwnerRole:           "admin",
		Attachment:          "local_posture",
		EvidenceSignal:      "local_controls",
		Next:                "Keep local readiness, role, audit, and catalog gates clear.",
		EvidenceRefReturned: false,
		ValueReturned:       false,
		Tone:                "ok",
	})
	if !ready || !access.ExplicitBindings || !audit.ChainVerified || catalogGateCount > 0 {
		validation.Controls[0].State = "review"
		validation.Controls[0].Tone = "warn"
		validation.Controls[0].Next = "Clear local readiness, role, audit, and catalog gates first."
		if enterpriseMode {
			validation.MissingCount++
		}
	}

	for _, spec := range enterpriseValidationSpecs() {
		attachedByWorkflow := evidenceAttachmentPresent(attachments, spec.Key)
		control := EnterpriseValidationControl{
			Key:                 spec.Key,
			Label:               spec.Label,
			State:               "not_claimed",
			Required:            enterpriseMode,
			Detail:              spec.Detail,
			OwnerRole:           spec.OwnerRole,
			Attachment:          "not_claimed",
			EvidenceSignal:      "presence_only_env_flag",
			Next:                "Switch to enterprise only after this external evidence exists.",
			EvidenceRefReturned: false,
			ValueReturned:       false,
			Tone:                "info",
		}
		if attachedByWorkflow {
			control.State = "attached"
			control.Attachment = "attached_presence_only"
			control.EvidenceSignal = "presence_only_workflow"
			control.Next = "Keep the external evidence reviewed outside Janus; only presence is recorded here."
			control.Tone = "ok"
		}
		if enterpriseMode {
			if os.Getenv(spec.EnvKey) != "" || attachedByWorkflow {
				control.State = "attached"
				control.Attachment = "attached_presence_only"
				if attachedByWorkflow {
					control.EvidenceSignal = "presence_only_workflow"
					control.Next = "Keep the external evidence reviewed outside Janus; only presence is recorded here."
				} else {
					control.Next = "Keep external evidence current and reviewed outside Janus."
				}
				control.Tone = "ok"
			} else {
				control.State = "missing"
				control.Attachment = "missing"
				control.Next = spec.Next
				control.Tone = "warn"
				validation.MissingCount++
			}
		}
		validation.Controls = append(validation.Controls, control)
	}

	if enterpriseMode && validation.MissingCount == 0 {
		validation.Status = "candidate"
		validation.Summary = "Enterprise controls are attached; keep external review evidence before relying on this claim."
	}
	return validation
}

func evidenceAttachmentPresent(attachments map[string]EvidenceAttachmentRecord, key string) bool {
	if len(attachments) == 0 {
		return false
	}
	record, ok := attachments[key]
	return ok && record.Attachment == "attached_presence_only" && !record.ValueReturned && !record.EvidenceRefReturned
}

func ProductModePostureFor(cfg Config, ready bool, issues []string, access AccessPosture, audit AuditPosture, catalogGateCount int) ProductModePosture {
	mode := strings.TrimSpace(cfg.ProductMode)
	if mode == "" {
		mode = "self_hosted"
	}

	posture := ProductModePosture{
		Mode:          mode,
		Current:       productModeLabel(mode),
		Baseline:      "review",
		Enterprise:    "not_claimed",
		Summary:       "Self-hosted mode can be healthy without claiming enterprise evidence.",
		ValueReturned: false,
	}
	if mode == "dev" {
		posture.Baseline = "dev_only"
		posture.Summary = "Dev mode is local proof only and does not claim production or enterprise evidence."
	} else if ready && catalogGateCount == 0 && len(issues) == 0 {
		posture.Baseline = "ready"
	}

	if mode == "enterprise" {
		posture.Enterprise = "blocked"
		posture.Summary = "Enterprise mode is strict: missing controls stay visible until evidence is complete."
		if ready && len(issues) == 0 && access.ExplicitBindings && audit.ChainVerified {
			posture.Enterprise = "candidate"
		}
	}

	roleState := "bootstrap"
	roleTone := "warn"
	roleDetail := "bootstrap owner policy is active"
	if access.ExplicitBindings {
		roleState = "explicit"
		roleTone = "ok"
		roleDetail = "admin, auditor, and operator bindings are configured"
	}

	auditState := "review"
	auditTone := "warn"
	auditDetail := "audit chain needs review"
	if audit.ChainVerified {
		auditState = "verified"
		auditTone = "ok"
		auditDetail = "local tamper-evident chain is verified"
	}

	baselineTone := "warn"
	baselineDetail := "readiness or catalog gates need review"
	if posture.Baseline == "ready" {
		baselineTone = "ok"
		baselineDetail = "redacted health, catalog gates, local audit, and role gates are clear"
	}
	if posture.Baseline == "dev_only" {
		baselineDetail = "developer posture only"
	}

	enterpriseTone := "info"
	enterpriseDetail := "remote audit, break-glass review, restore drills, and integration conformance are not claimed"
	if posture.Enterprise == "blocked" {
		enterpriseTone = "warn"
		enterpriseDetail = "enterprise mode has open gates"
	}
	if posture.Enterprise == "candidate" {
		enterpriseTone = "ok"
		enterpriseDetail = "configured controls are clear; attach external evidence before relying on this"
	}

	gateState := "clear"
	gateTone := "ok"
	gateDetail := "no dashboard readiness gates"
	if len(issues) > 0 || catalogGateCount > 0 {
		gateState = fmt.Sprintf("%d open", len(issues)+catalogGateCount)
		gateTone = "warn"
		gateDetail = "open gates stay visible"
	}

	posture.Controls = []ProductModeControl{
		{Label: "Current mode", State: posture.Current, Detail: "runtime claim shown in UI, health, and evidence", Tone: "info"},
		{Label: "Self-hosted baseline", State: posture.Baseline, Detail: baselineDetail, Tone: baselineTone},
		{Label: "Role bindings", State: roleState, Detail: roleDetail, Tone: roleTone},
		{Label: "Audit evidence", State: auditState, Detail: auditDetail, Tone: auditTone},
		{Label: "Enterprise evidence", State: posture.Enterprise, Detail: enterpriseDetail, Tone: enterpriseTone},
		{Label: "Open gates", State: gateState, Detail: gateDetail, Tone: gateTone},
	}
	return posture
}

func productModeLabel(mode string) string {
	switch mode {
	case "dev":
		return "Dev"
	case "enterprise":
		return "Enterprise"
	case "self_hosted":
		return "Self-hosted"
	default:
		return mode
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error":          code,
		"message":        message,
		"request_id":     requestID(r),
		"redacted":       true,
		"value_returned": false,
	})
}

func (app *App) renderSafeFailure(w http.ResponseWriter, r *http.Request, status int, code, message string, allowed []string) {
	if status == http.StatusMethodNotAllowed && len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	if isAPIRequest(r) {
		body := map[string]any{
			"error":          code,
			"message":        message,
			"request_id":     requestID(r),
			"value_returned": false,
		}
		if len(allowed) > 0 {
			body["allowed_methods"] = allowed
		}
		writeJSON(w, status, body)
		return
	}
	renderTemplateStatus(w, app.templates, "safe_error", status, SafeFailureView{
		Title:          "Janus",
		CSPNonce:       cspNonceFromContext(r.Context()),
		Mode:           app.cfg.ProductMode,
		Session:        currentSession(r.Context()),
		StatusCode:     status,
		ReasonCode:     code,
		Message:        message,
		RequestID:      requestID(r),
		AllowedMethods: allowed,
		ValueReturned:  false,
	})
}

func (app *App) postureBody(session Session) map[string]any {
	allDescriptors := app.store.Descriptors()
	descriptors := app.cfg.ScopePolicy.Filter(allDescriptors)
	evidenceAttachments := app.evidenceAttachmentMap()
	issues := enterpriseChecksWithAttachments(app.cfg, evidenceAttachments)
	catalogGates := ValidateCatalog(descriptors)
	accessPosture := app.accessPosture()
	rolePolicyReadiness := RolePolicyReadinessFor(app.cfg.RolePolicy, accessPosture)
	scopePosture := app.scopePosture(allDescriptors)
	lifecyclePosture := LifecyclePostureFor(descriptors, time.Now().UTC())
	approvedUsePosture := ApprovedUsePostureFor(descriptors)
	permitPosture := PermitPosture{ValueReturned: false}
	readiness, ready := app.readinessBody()
	auditPosture := app.store.AuditPosture()
	if app.permits != nil {
		permitPosture = app.permits.Posture()
	}
	canExportEvidence := HasRole(session, RoleAuditor)
	evidenceBoundary := EvidenceBoundaryFor(canExportEvidence, canExportEvidence)
	evidenceReceipt := EvidenceReceiptFor(evidenceBoundary, nil)
	supplyChain := SupplyChainPostureFor(evidenceBoundary)
	authFailure := AuthFailurePostureFor(app.cfg)
	authenticatedRole := SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), ready)
	authenticatedBrowser := app.authenticatedBrowserWitness(session, authenticatedRole, ready)
	assuranceSummary := AssuranceSummaryFor(app.cfg.ProductMode, ready, len(issues), len(catalogGates), accessPosture, auditPosture, evidenceBoundary)
	assuranceGates := AssuranceGatesFor(ready, len(catalogGates), accessPosture)
	enterpriseValidation := EnterpriseValidationWithAttachmentsFor(app.cfg, ready, accessPosture, auditPosture, len(catalogGates), evidenceAttachments)
	enterpriseDryRun := EnterpriseDryRunFor(app.cfg.ProductMode, EnterpriseValidationWithAttachmentsFor(Config{ProductMode: "enterprise", RolePolicy: app.cfg.RolePolicy}, ready, accessPosture, auditPosture, len(catalogGates), evidenceAttachments))
	enterpriseClaim := EnterpriseClaimReviewFor(app.cfg.ProductMode, enterpriseValidation, enterpriseDryRun, evidenceBoundary)
	attachmentReview := AttachmentReviewFor(enterpriseValidation)
	externalEvidence := app.externalEvidencePosture(enterpriseValidation, session)
	modeGuardrails := ModeGuardrailsFor(app.cfg, ready, issues, accessPosture, auditPosture, len(catalogGates), enterpriseValidation)
	restoreProof := RestoreDrillProofFor(enterpriseValidation)
	restoreWorkflow := RestoreDrillWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	releaseWorkflow := ReleaseProvenanceWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	privacyWorkflow := PrivacyRetentionWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	integrationWorkflow := IntegrationConformanceWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	remoteAuditWorkflow := RemoteAuditWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	breakGlassWorkflow := BreakGlassReviewWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	enterpriseReleaseGate := EnterpriseReleaseGateFor(app.cfg.ProductMode, enterpriseClaim, supplyChain, remoteAuditWorkflow, restoreWorkflow, releaseWorkflow, privacyWorkflow, integrationWorkflow, breakGlassWorkflow, auditPosture, accessPosture, app.cfg.RolePolicy, evidenceBoundary)
	privacyPosture := PrivacyPostureFor(evidenceBoundary, auditPosture)
	negativePath := NegativePathAssuranceFor(ready, len(catalogGates), accessPosture, auditPosture)
	degradedGuidance := DegradedGuidanceFor(ready, auditPosture, evidenceBoundary, enterpriseValidation)
	auditDrill := AuditFailureDrillFor(ready, auditPosture)
	roleAvailability := RoleAvailabilityFor(session)
	actionReadiness := ActionReadinessFor(session, ready)
	operationalStatus := OperationalStatusFor(ready, scopePosture, assuranceSummary, evidenceBoundary, roleAvailability)
	commandCenter := CommandCenterFor(ready, operationalStatus, actionReadiness, modeGuardrails, attachmentReview, evidenceBoundary)
	return map[string]any{
		"service":               "janus",
		"mode":                  app.cfg.ProductMode,
		"auth_required":         app.cfg.RequireAuth,
		"oidc_configured":       app.cfg.OIDCConfigured(),
		"descriptor_count":      len(descriptors),
		"open_gates":            len(issues),
		"gates":                 issues,
		"catalog_gates":         catalogGates,
		"catalog_gate_count":    len(catalogGates),
		"access":                accessPosture,
		"role_policy_readiness": rolePolicyReadiness,
		"role_availability": map[string]any{
			"dashboard_strip": true,
			"duties":          []string{"posture", "use_actions", "audit_export", "admin_policy"},
			"value_returned":  false,
		},
		"scope":                            scopePosture,
		"lifecycle":                        lifecyclePosture,
		"approved_use":                     approvedUsePosture,
		"permits":                          permitPosture,
		"mode_posture":                     ProductModePostureFor(app.cfg, ready, issues, accessPosture, auditPosture, len(catalogGates)),
		"mode_guardrails":                  modeGuardrails,
		"enterprise_validation":            enterpriseValidation,
		"enterprise_dry_run":               enterpriseDryRun,
		"enterprise_claim_review":          enterpriseClaim,
		"enterprise_release_gate":          enterpriseReleaseGate,
		"attachment_review":                attachmentReview,
		"external_evidence":                externalEvidence,
		"restore_drill_proof":              restoreProof,
		"restore_drill_workflow":           restoreWorkflow,
		"release_provenance_workflow":      releaseWorkflow,
		"privacy_retention_workflow":       privacyWorkflow,
		"integration_conformance_workflow": integrationWorkflow,
		"remote_audit_workflow":            remoteAuditWorkflow,
		"break_glass_review_workflow":      breakGlassWorkflow,
		"privacy_posture":                  privacyPosture,
		"evidence_receipt":                 evidenceReceipt,
		"action_readiness":                 actionReadiness,
		"command_center":                   commandCenter,
		"assurance_summary":                assuranceSummary,
		"assurance_gates":                  assuranceGates,
		"negative_path_assurance":          negativePath,
		"degraded_guidance":                degradedGuidance,
		"audit_failure_drill":              auditDrill,
		"operational_status":               operationalStatus,
		"supply_chain_posture":             supplyChain,
		"auth_failure_posture":             authFailure,
		"authenticated_role_evidence":      authenticatedRole,
		"authenticated_browser_witness":    authenticatedBrowser,
		"auth": map[string]any{
			"oidc_nonce":                  app.cfg.OIDCConfigured(),
			"pkce_s256":                   app.cfg.OIDCConfigured(),
			"oidc_login_cookie_same_site": "Lax",
			"oidc_redirect_loop_guard":    "bounded_attempt_cookie",
			"safe_failure_pages":          true,
			"value_returned":              false,
		},
		"session": app.sessionPosture(session),
		"csrf": map[string]any{
			"bound":                 true,
			"same_origin_mutations": "origin_or_referer_when_present",
			"value_returned":        false,
		},
		"cookies": map[string]any{
			"host_prefixed":        app.cfg.SessionCookieName() == hostSessionCookie && app.cfg.StateCookieName() == hostStateCookie && app.cfg.NonceCookieName() == hostNonceCookie && app.cfg.PKCECookieName() == hostPKCECookie,
			"secure":               app.cfg.SecureCookies(),
			"session_same_site":    "Strict",
			"oidc_login_same_site": "Lax",
			"value_returned":       false,
		},
		"request_correlation": map[string]any{
			"response_header": "X-Request-Id",
			"audit_field":     "request_id",
			"sanitized":       true,
			"value_returned":  false,
		},
		"cors": map[string]any{
			"policy":                      "deny_by_default",
			"access_control_allow_origin": "absent",
			"credentialed_cross_origin":   false,
			"preflight":                   "safe_method_boundary",
			"value_returned":              false,
		},
		"assurance": map[string]any{
			"route_value_leak_sentinel":        true,
			"json_errors_request_id":           true,
			"backend_source_paths":             "not_returned",
			"role_policy_proof":                "explicit_counts_no_values",
			"role_policy_readiness":            "bootstrap_to_explicit_zitadel_lanes",
			"role_claim_policy":                "explicit_only_no_ambient_grants",
			"evidence_export_boundary":         "dashboard_and_json",
			"evidence_download":                "auditor_json_with_pack_hash",
			"evidence_receipt":                 "download_header_body_match",
			"enterprise_validation":            "self_hosted_safe_enterprise_required",
			"enterprise_attachments":           "presence_only_no_refs",
			"enterprise_dry_run":               "self_hosted_to_enterprise_checklist",
			"enterprise_claim_review":          "presence_only_claim_review",
			"enterprise_release_gate":          "single_value_free_release_decision",
			"auth_failure_posture":             "safe_reason_codes_no_provider_values",
			"authenticated_role_evidence":      "signed_in_role_receipt_no_identity_values",
			"authenticated_browser_witness":    "signed_session_browser_proof_no_identity_values",
			"external_evidence_workflow":       "presence_only_no_refs",
			"attachment_review":                "presence_only_owner_review",
			"restore_drill_proof":              "dashboard_posture_evidence",
			"restore_drill_workflow":           "presence_only_recovery_evidence",
			"release_provenance_workflow":      "presence_only_release_evidence",
			"privacy_retention_workflow":       "presence_only_policy_evidence",
			"integration_conformance_workflow": "presence_only_integration_evidence",
			"remote_audit_workflow":            "presence_only_audit_shipping_evidence",
			"break_glass_review_workflow":      "presence_only_emergency_access_evidence",
			"action_readiness":                 "role_and_readiness_matrix",
			"command_center":                   "dashboard_posture_api",
			"action_receipts":                  "mutation_result_receipts",
			"action_receipt_integrity":         "tamper_evident_hash_proof",
			"action_receipt_verification":      "copy_safe_ui_fields",
			"mode_guardrails":                  "dashboard_posture_evidence",
			"privacy_retention":                "dashboard_posture_evidence",
			"negative_path_assurance":          "dashboard_posture_evidence",
			"degraded_guidance":                "dashboard_posture_evidence",
			"audit_failure_drill":              "fail_closed_dashboard_posture_evidence",
			"human_readable_summary":           "dashboard_posture_evidence",
			"assurance_gate_proofs":            "role_catalog_degraded_value_leak",
			"operational_status":               "dashboard_posture_strip",
			"supply_chain_posture":             "summary_only_dependency_security_evidence",
			"value_returned":                   false,
		},
		"response_hardening": map[string]any{
			"cache_control":                  "no-store",
			"auth_error_view":                "safe_category_request_id",
			"oidc_redirect_loop_guard":       "bounded_attempt_cookie_no_values",
			"http_boundary_error_view":       "safe_category_request_id",
			"public_health_redacted":         true,
			"public_readiness_auth_redacted": true,
			"public_readiness_redacted":      true,
			"safe_http_boundary_failures":    true,
			"script_src":                     "none",
			"cross_origin_embedder_policy":   "credentialless",
			"cross_origin_opener_policy":     "same-origin",
			"cross_origin_resource_policy":   "same-origin",
			"cross_domain_policy":            "none",
			"dns_prefetch_control":           "off",
			"legacy_cache_headers":           true,
			"origin_agent_cluster":           true,
			"permissions_policy":             "camera=(), geolocation=(), microphone=()",
			"security_header_regression":     "core_routes",
			"value_returned":                 false,
		},
		"request_limits": map[string]any{
			"max_body_bytes": maxRequestBody,
			"applies_to":     "mutations",
			"value_returned": false,
		},
		"availability": map[string]any{
			"sensitive_actions_require_readiness": true,
			"degraded_action_status":              "system_degraded_503",
			"value_returned":                      false,
		},
		"api_errors": map[string]any{
			"auth_denials_json":           true,
			"rate_limit_retry_after":      true,
			"rate_limit_request_id":       true,
			"rate_limit_error_value_free": true,
			"value_returned":              false,
		},
		"readiness": readiness,
		"audit":     auditPosture,
		"capabilities": []string{
			"value_free_metadata_catalog",
			"broker_principal_chain",
			"warden_handle_only",
			"permit_noop_execution",
			"csrf_guarded_mutations",
			"rate_limited_runtime",
			"role_gated_audit_evidence",
			"safe_audit_trail_export",
			"authenticated_browser_witness",
			"scope_bound_metadata",
			"lifecycle_gated_normal_use",
			"persistent_permit_records",
			"host_prefixed_cookies",
			"request_correlation_ids",
			"oidc_nonce_bound_login",
			"pkce_s256_auth_code",
			"no_store_responses",
			"api_json_auth_errors",
			"value_free_readiness",
			"signed_session_expiry",
			"approved_metadata_use_enforced",
			"no_script_csp",
			"safe_auth_failure_pages",
			"auth_failure_posture",
			"oidc_redirect_loop_guard",
			"audit_event_severity",
			"audit_trail_witness",
			"strict_session_cookie",
			"request_body_size_limit",
			"browser_isolation_headers",
			"security_header_regression_table",
			"same_origin_mutation_guard",
			"safe_http_boundary_failures",
			"role_duty_matrix",
			"role_policy_proof",
			"role_policy_readiness_workflow",
			"strict_role_claim_policy",
			"redacted_public_readiness",
			"redacted_public_health",
			"minimal_public_readiness",
			"degraded_sensitive_action_guard",
			"degraded_dashboard_banner",
			"operational_rate_limit_denials",
			"deny_by_default_cors",
			"request_correlated_json_errors",
			"route_value_leak_sentinel",
			"mode_posture_evidence",
			"mode_guardrails",
			"evidence_export_boundary_ux",
			"role_availability_ux",
			"authenticated_role_receipt",
			"authenticated_browser_witness_api",
			"human_readable_assurance_summary",
			"operational_status_strip",
			"supply_chain_posture_summary",
			"evidence_download_receipt",
			"exact_evidence_download_receipt",
			"enterprise_evidence_attachment_matrix",
			"enterprise_attachment_review_workflow",
			"enterprise_dry_run_checklist",
			"enterprise_claim_review_workflow",
			"enterprise_release_gate_decision",
			"external_evidence_presence_workflow",
			"restore_drill_proof",
			"restore_drill_presence_workflow",
			"release_provenance_presence_workflow",
			"privacy_retention_presence_workflow",
			"integration_conformance_presence_workflow",
			"remote_audit_presence_workflow",
			"break_glass_review_presence_workflow",
			"role_aware_action_readiness",
			"command_center_ux",
			"value_free_action_receipts",
			"tamper_evident_action_receipts",
			"action_receipt_verification_ux",
			"assurance_gate_proof_strip",
			"enterprise_validation_clarity",
			"privacy_retention_posture",
			"negative_path_assurance_matrix",
			"degraded_guidance_panel",
			"audit_failure_drill",
		},
		"value_returned": false,
	}
}

func (app *App) accessPosture() AccessPosture {
	return AccessPostureFor(app.cfg.RolePolicy)
}

func (app *App) evidenceAttachmentMap() map[string]EvidenceAttachmentRecord {
	if app.evidence == nil {
		return nil
	}
	return app.evidence.Map()
}

func (app *App) externalEvidencePosture(enterprise EnterpriseValidation, session Session) ExternalEvidencePosture {
	if app.evidence == nil {
		return ExternalEvidencePostureFor(enterprise, nil, false, session)
	}
	return app.evidence.Posture(enterprise, session)
}

func (app *App) scopePosture(descriptors []SecretDescriptor) ScopePosture {
	return ScopePostureFor(app.cfg.ScopePolicy, descriptors)
}

func (app *App) evidencePack(session Session) EvidencePack {
	allDescriptors := app.store.Descriptors()
	descriptors := app.cfg.ScopePolicy.Filter(allDescriptors)
	evidenceAttachments := app.evidenceAttachmentMap()
	issues := enterpriseChecksWithAttachments(app.cfg, evidenceAttachments)
	catalogGates := ValidateCatalog(descriptors)
	_, ready := app.readinessBody()
	accessPosture := app.accessPosture()
	rolePolicyReadiness := RolePolicyReadinessFor(app.cfg.RolePolicy, accessPosture)
	scopePosture := app.scopePosture(allDescriptors)
	auditPosture := app.store.AuditPosture()
	canExportEvidence := HasRole(session, RoleAuditor)
	recentAudit := app.store.RecentAudit(50)
	auditTrail := AuditTrailFor(recentAudit, auditPosture, canExportEvidence)
	evidenceBoundary := EvidenceBoundaryFor(canExportEvidence, canExportEvidence)
	supplyChain := SupplyChainPostureFor(evidenceBoundary)
	authFailure := AuthFailurePostureFor(app.cfg)
	authenticatedRole := SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), ready)
	authenticatedBrowser := app.authenticatedBrowserWitness(session, authenticatedRole, ready)
	assuranceSummary := AssuranceSummaryFor(app.cfg.ProductMode, ready, len(issues), len(catalogGates), accessPosture, auditPosture, evidenceBoundary)
	assuranceGates := AssuranceGatesFor(ready, len(catalogGates), accessPosture)
	enterpriseValidation := EnterpriseValidationWithAttachmentsFor(app.cfg, ready, accessPosture, auditPosture, len(catalogGates), evidenceAttachments)
	enterpriseDryRun := EnterpriseDryRunFor(app.cfg.ProductMode, EnterpriseValidationWithAttachmentsFor(Config{ProductMode: "enterprise", RolePolicy: app.cfg.RolePolicy}, ready, accessPosture, auditPosture, len(catalogGates), evidenceAttachments))
	enterpriseClaim := EnterpriseClaimReviewFor(app.cfg.ProductMode, enterpriseValidation, enterpriseDryRun, evidenceBoundary)
	attachmentReview := AttachmentReviewFor(enterpriseValidation)
	externalEvidence := app.externalEvidencePosture(enterpriseValidation, session)
	modeGuardrails := ModeGuardrailsFor(app.cfg, ready, issues, accessPosture, auditPosture, len(catalogGates), enterpriseValidation)
	restoreProof := RestoreDrillProofFor(enterpriseValidation)
	restoreWorkflow := RestoreDrillWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	releaseWorkflow := ReleaseProvenanceWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	privacyWorkflow := PrivacyRetentionWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	integrationWorkflow := IntegrationConformanceWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	remoteAuditWorkflow := RemoteAuditWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	breakGlassWorkflow := BreakGlassReviewWorkflowFor(enterpriseValidation, evidenceAttachments, session)
	enterpriseReleaseGate := EnterpriseReleaseGateFor(app.cfg.ProductMode, enterpriseClaim, supplyChain, remoteAuditWorkflow, restoreWorkflow, releaseWorkflow, privacyWorkflow, integrationWorkflow, breakGlassWorkflow, auditPosture, accessPosture, app.cfg.RolePolicy, evidenceBoundary)
	privacyPosture := PrivacyPostureFor(evidenceBoundary, auditPosture)
	negativePath := NegativePathAssuranceFor(ready, len(catalogGates), accessPosture, auditPosture)
	degradedGuidance := DegradedGuidanceFor(ready, auditPosture, evidenceBoundary, enterpriseValidation)
	auditDrill := AuditFailureDrillFor(ready, auditPosture)
	actionReadiness := ActionReadinessFor(session, ready)
	operationalStatus := OperationalStatusFor(ready, scopePosture, assuranceSummary, evidenceBoundary, RoleAvailabilityFor(session))
	pack := EvidencePack{
		GeneratedAt:          time.Now().UTC(),
		Service:              "janus",
		Mode:                 app.cfg.ProductMode,
		Posture:              app.postureBody(session),
		Operational:          operationalStatus,
		SupplyChain:          supplyChain,
		AuthFailure:          authFailure,
		AuthenticatedRole:    authenticatedRole,
		AuthenticatedBrowser: authenticatedBrowser,
		RolePolicyReadiness:  rolePolicyReadiness,
		ModeGuardrails:       modeGuardrails,
		ActionReadiness:      actionReadiness,
		AssuranceGates:       assuranceGates,
		NegativePath:         negativePath,
		Guidance:             degradedGuidance,
		AuditDrill:           auditDrill,
		AssuranceSummary:     assuranceSummary,
		RestoreWorkflow:      restoreWorkflow,
		ReleaseWorkflow:      releaseWorkflow,
		PrivacyWorkflow:      privacyWorkflow,
		IntegrationWorkflow:  integrationWorkflow,
		RemoteAuditWorkflow:  remoteAuditWorkflow,
		BreakGlassWorkflow:   breakGlassWorkflow,
		Enterprise:           enterpriseValidation,
		EnterpriseDryRun:     enterpriseDryRun,
		EnterpriseClaim:      enterpriseClaim,
		EnterpriseRelease:    enterpriseReleaseGate,
		AttachmentReview:     attachmentReview,
		ExternalEvidence:     externalEvidence,
		RestoreProof:         restoreProof,
		Privacy:              privacyPosture,
		Descriptors:          descriptors,
		CatalogGates:         catalogGates,
		ScopePosture:         scopePosture,
		LifecyclePosture:     LifecyclePostureFor(descriptors, time.Now().UTC()),
		PermitPosture:        PermitPosture{ValueReturned: false},
		AccessPosture:        accessPosture,
		AuditPosture:         auditPosture,
		AuditTrail:           auditTrail,
		RecentAudit:          auditTrail.Rows,
		ValueReturned:        false,
		RedactionModel:       "metadata-only; secret values are not stored, read, rendered, logged, or exported by Janus V1.x",
	}
	if app.permits != nil {
		pack.PermitPosture = app.permits.Posture()
	}
	pack.EvidenceBoundary = evidenceBoundary
	integrity := EvidenceIntegrityFor(pack)
	pack.Integrity = &integrity
	receipt := EvidenceReceiptFor(evidenceBoundary, &integrity)
	pack.Receipt = &receipt
	return pack
}

func (app *App) handleBrokerError(w http.ResponseWriter, r *http.Request, action, actor, ref string, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		app.auditWithRef(r, action, "denied", actor, "", "not found")
		writeJSONError(w, r, http.StatusNotFound, "not_found", "Descriptor not found")
	case errors.Is(err, ErrPolicyDenied):
		app.auditWithRef(r, action, "denied", actor, "", err.Error())
		writeJSONError(w, r, http.StatusForbidden, "policy_denied", err.Error())
	default:
		app.auditWithRef(r, action, "denied", actor, "", "broker error")
		writeJSONError(w, r, http.StatusBadRequest, "broker_error", err.Error())
	}
}

func seedCatalog() []SecretDescriptor {
	now := time.Now().UTC()
	return []SecretDescriptor{
		{
			ID:             "zitadel-janus-oidc",
			DisplayName:    "Janus Zitadel application",
			Provider:       "agenix",
			Classification: "high",
			Owner:          "platform",
			Scope:          "csb1",
			Source:         "secrets/csb1-janus-env.age",
			RotationDays:   180,
			LastCheckedAt:  now,
			Lifecycle:      LifecycleActive,
			Status:         "managed",
			RevealAllowed:  false,
			UseEnabled:     true,
			ConsumerCount:  1,
			EgressMode:     "none",
			Tags:           []string{"identity", "oidc"},
		},
		{
			ID:             "csb1-age-identity",
			DisplayName:    "csb1 age identity",
			Provider:       "agenix",
			Classification: "critical",
			Owner:          "platform",
			Scope:          "csb1",
			Source:         "secrets/csb1-age-identity.age",
			RotationDays:   365,
			LastCheckedAt:  now,
			Lifecycle:      LifecycleActive,
			Status:         "external",
			RevealAllowed:  false,
			UseEnabled:     true,
			ConsumerCount:  1,
			EgressMode:     "none",
			Tags:           []string{"host", "decrypt-only"},
		},
	}
}

func renderTemplate(w http.ResponseWriter, templates *template.Template, name string, data any) {
	renderTemplateStatus(w, templates, name, http.StatusOK, data)
}

func renderTemplateStatus(w http.ResponseWriter, templates *template.Template, name string, status int, data any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

func mustTemplates() *template.Template {
	return template.Must(template.New("janus").Parse(`
{{ define "base_top" -}}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {{ if .CSRF }}<meta name="csrf-token" content="{{ .CSRF }}">{{ end }}
  <title>{{ .Title }}</title>
  <style nonce="{{ .CSPNonce }}">
    :root {
      color-scheme: light dark;
      --bg: #f3f5f7;
      --ink: #111418;
      --muted: #66717d;
      --line: #d9e0e7;
      --panel: #ffffff;
      --panel-soft: #f8fafb;
      --accent: #126a5a;
      --accent-ink: #ffffff;
      --blue: #2f5fb3;
      --amber: #9b5d00;
      --danger: #a64242;
      --shadow: 0 18px 44px rgba(18, 25, 33, .08);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #111315;
        --ink: #edf1f5;
        --muted: #9aa6b2;
        --line: #2b333b;
        --panel: #171a1d;
        --panel-soft: #1d2226;
        --accent: #69c8b2;
        --accent-ink: #071411;
        --blue: #86aaf2;
        --amber: #e0a04f;
        --danger: #f08a8a;
        --shadow: none;
      }
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
      -webkit-font-smoothing: antialiased;
    }
    .skip-link {
      position: fixed;
      top: 10px;
      left: 10px;
      z-index: 100;
      transform: translateY(-160%);
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      color: var(--ink);
      padding: 8px 12px;
      text-decoration: none;
      box-shadow: var(--shadow);
    }
    .skip-link:focus { transform: translateY(0); }
    header {
      border-bottom: 1px solid var(--line);
      background: color-mix(in srgb, var(--panel) 90%, transparent);
      position: sticky;
      top: 0;
      z-index: 20;
      backdrop-filter: blur(16px);
    }
    .bar, main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; }
    section { scroll-margin-top: 82px; }
    .bar {
      min-height: 66px;
      display: grid;
      grid-template-columns: auto minmax(0, 1fr) auto auto;
      align-items: center;
      gap: 18px;
    }
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 760; letter-spacing: 0; }
    .mark {
      width: 34px;
      height: 34px;
      border-radius: 8px;
      display: grid;
      place-items: center;
      color: #fff;
      background: var(--accent);
      font-weight: 820;
    }
    .nav { display: flex; justify-content: center; gap: 6px; min-width: 0; }
    .nav a {
      color: var(--muted);
      text-decoration: none;
      padding: 7px 10px;
      border-radius: 8px;
      white-space: nowrap;
    }
    .nav a:hover { background: var(--panel-soft); color: var(--ink); }
    .account {
      display: grid;
      gap: 2px;
      min-width: 0;
      max-width: 280px;
      justify-self: end;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 6px 9px;
      background: var(--panel-soft);
    }
    .account strong {
      font-size: 13px;
      line-height: 1.2;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .account span {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.2;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    main { padding: 26px 0 52px; }
    h1 { margin: 0; font-size: 40px; line-height: 1.04; letter-spacing: 0; overflow-wrap: anywhere; }
    h2 { margin: 0; font-size: 18px; letter-spacing: 0; overflow-wrap: anywhere; }
    h3 { margin: 0; font-size: 14px; letter-spacing: 0; overflow-wrap: anywhere; }
    p { margin: 0; color: var(--muted); overflow-wrap: anywhere; }
    a { color: inherit; }
    button, .button {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px 12px;
      background: var(--panel);
      color: var(--ink);
      font: inherit;
      text-decoration: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 38px;
      max-width: 100%;
      text-align: center;
      white-space: normal;
    }
    .primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
    .quiet { background: var(--panel-soft); }
    .overview {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(340px, .9fr);
      gap: 18px;
      align-items: stretch;
      margin-bottom: 16px;
      min-width: 0;
    }
    .intro, .status, .panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      box-shadow: var(--shadow);
      min-width: 0;
    }
    .security-state {
      border-color: color-mix(in srgb, var(--amber) 48%, var(--line));
      background: color-mix(in srgb, var(--amber) 7%, var(--panel));
    }
    .intro { padding: 22px; display: grid; gap: 16px; align-content: center; min-width: 0; }
    .intro-copy { max-width: 720px; display: grid; gap: 10px; min-width: 0; }
    .eyebrow { color: var(--accent); font-weight: 720; font-size: 13px; letter-spacing: 0; overflow-wrap: anywhere; }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; }
    .safety-ribbon {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
    }
    .safety-chip {
      min-height: 62px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: color-mix(in srgb, var(--panel-soft) 88%, transparent);
      padding: 9px 10px;
      display: grid;
      align-content: space-between;
      gap: 5px;
      min-width: 0;
    }
    .safety-chip span { color: var(--muted); font-size: 12px; line-height: 1.15; }
    .safety-chip strong { font-size: 15px; line-height: 1.12; overflow-wrap: anywhere; }
    .safety-chip.ok strong { color: var(--accent); }
    .safety-chip.info strong { color: var(--blue); }
    .safety-chip.warn strong { color: var(--amber); }
    .session-proof {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
      gap: 8px;
      align-items: stretch;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: color-mix(in srgb, var(--accent) 4%, var(--panel-soft));
      padding: 8px;
      min-width: 0;
    }
    .session-proof-item {
      min-height: 70px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 9px 10px;
      display: grid;
      align-content: space-between;
      gap: 5px;
      min-width: 0;
    }
    .session-proof-item span { color: var(--muted); font-size: 12px; line-height: 1.15; }
    .session-proof-item strong { font-size: 16px; line-height: 1.15; overflow-wrap: anywhere; }
    .session-proof-item.ok strong { color: var(--accent); }
    .session-proof-item.info strong { color: var(--blue); }
    .session-proof-item.warn strong { color: var(--amber); }
    .session-proof-item p { font-size: 12px; line-height: 1.25; }
    .session-proof-item.action { width: 184px; align-content: center; justify-items: stretch; }
    .session-proof-item.action .button { width: 100%; }
    .reviewer-flow {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      align-items: stretch;
      min-width: 0;
    }
    .reviewer-step {
      min-height: 88px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 10px 11px;
      display: grid;
      align-content: space-between;
      gap: 7px;
      min-width: 0;
    }
    .reviewer-step span { color: var(--muted); font-size: 12px; line-height: 1.15; }
    .reviewer-step strong { font-size: 15px; line-height: 1.15; overflow-wrap: anywhere; }
    .reviewer-step p { font-size: 12px; line-height: 1.25; }
    .reviewer-step.ok strong { color: var(--accent); }
    .reviewer-step.info strong { color: var(--blue); }
    .reviewer-step.action { align-content: center; justify-items: stretch; }
    .reviewer-step.action form { display: grid; }
    .reviewer-step.action .button { width: 100%; }
    .ops-strip {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }
    .ops-item {
      min-height: 76px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 10px 11px;
      display: grid;
      align-content: space-between;
      gap: 6px;
      min-width: 0;
    }
    .ops-item span { color: var(--muted); font-size: 12px; line-height: 1.15; }
    .ops-item strong { font-size: 16px; line-height: 1.15; overflow-wrap: anywhere; }
    .ops-item p { font-size: 12px; line-height: 1.25; }
    .ops-item.ok strong { color: var(--accent); }
    .ops-item.warn strong { color: var(--amber); }
    .ops-item.info strong { color: var(--blue); }
    .trust-rail {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    .trust-step {
      min-height: 68px;
      padding: 10px 12px;
      display: grid;
      align-content: space-between;
      gap: 6px;
      border-right: 1px solid var(--line);
      background: var(--panel-soft);
      min-width: 0;
    }
    .trust-step:last-child { border-right: 0; }
	    .trust-step span { color: var(--muted); font-size: 12px; }
	    .trust-step strong { font-size: 16px; line-height: 1.15; overflow-wrap: anywhere; }
	    .trust-step.ok strong { color: var(--accent); }
	    .trust-step.warn strong { color: var(--amber); }
	    .command-top {
	      display: grid;
	      grid-template-columns: minmax(0, 1fr) auto;
	      gap: 14px;
	      align-items: start;
	      margin-bottom: 14px;
	    }
	    .command-state {
	      min-width: 164px;
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      background: var(--panel-soft);
	      padding: 11px 12px;
	      display: grid;
	      gap: 4px;
	    }
	    .command-state span { color: var(--muted); font-size: 12px; }
	    .command-state strong { font-size: 22px; line-height: 1.1; overflow-wrap: anywhere; }
	    .command-state.ok strong { color: var(--accent); }
	    .command-state.warn strong { color: var(--amber); }
	    .command-state.info strong { color: var(--blue); }
	    .command-grid {
	      display: grid;
	      grid-template-columns: repeat(4, minmax(0, 1fr));
	      gap: 10px;
	    }
	    .command-card {
	      min-height: 134px;
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      background: var(--panel-soft);
	      padding: 12px;
	      display: grid;
	      align-content: space-between;
	      gap: 8px;
	      min-width: 0;
	    }
	    .command-card span { color: var(--muted); font-size: 12px; }
	    .command-card strong { font-size: 17px; line-height: 1.15; overflow-wrap: anywhere; }
	    .command-card.ok strong { color: var(--accent); }
	    .command-card.warn strong { color: var(--amber); }
	    .command-card.info strong { color: var(--blue); }
	    .command-actions {
	      display: flex;
	      flex-wrap: wrap;
	      gap: 8px;
	      margin-top: 14px;
	    }
	    .mode-grid {
	      display: grid;
	      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }
    .mode-item {
      min-height: 104px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 12px;
      display: grid;
      align-content: space-between;
      gap: 8px;
      min-width: 0;
    }
    .mode-item span { color: var(--muted); font-size: 12px; }
    .mode-item strong { font-size: 17px; line-height: 1.15; overflow-wrap: anywhere; }
    .mode-item.ok strong { color: var(--accent); }
    .mode-item.warn strong { color: var(--amber); }
    .mode-item.info strong { color: var(--blue); }
    .mode-item p, .command-card p, .ops-item p { font-size: 13px; line-height: 1.35; }
    .witness-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }
    .witness-card {
      min-height: 126px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 12px;
      display: grid;
      align-content: space-between;
      gap: 9px;
      min-width: 0;
    }
    .witness-card span { color: var(--muted); font-size: 12px; }
    .witness-card strong { font-size: 20px; line-height: 1.1; overflow-wrap: anywhere; }
    .witness-card.ok strong { color: var(--accent); }
    .witness-card.warn strong { color: var(--amber); }
    .witness-card.info strong { color: var(--blue); }
    .witness-card p { font-size: 13px; line-height: 1.35; }
    .evidence-flags {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 10px 12px;
    }
    .evidence-flags summary {
      cursor: pointer;
      font-weight: 700;
      line-height: 1.25;
    }
    .flag-cloud {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      padding-top: 10px;
    }
    .assurance-flow {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      align-items: stretch;
    }
    .assurance-step {
      min-height: 86px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: color-mix(in srgb, var(--panel-soft) 78%, transparent);
      padding: 11px 12px;
      display: grid;
      grid-template-rows: auto 1fr auto;
      gap: 7px;
      min-width: 0;
    }
    .assurance-step b {
      width: 24px;
      height: 24px;
      border-radius: 999px;
      display: inline-grid;
      place-items: center;
      background: var(--ink);
      color: var(--panel);
      font-size: 12px;
      line-height: 1;
    }
    .assurance-step strong { font-size: 15px; line-height: 1.2; overflow-wrap: anywhere; }
    .assurance-step span { color: var(--muted); font-size: 12px; line-height: 1.25; }
    .flow {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) minmax(260px, 1.2fr) auto;
      gap: 12px;
      align-items: end;
    }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; }
    select, input, textarea {
      width: 100%;
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      color: var(--ink);
      font: inherit;
      padding: 8px 10px;
    }
    textarea {
      min-height: 112px;
      resize: vertical;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.35;
    }
    select:focus, input:focus, textarea:focus, button:focus, .button:focus, .nav a:focus {
      outline: 2px solid color-mix(in srgb, var(--accent) 45%, transparent);
      outline-offset: 2px;
    }
    .status { padding: 0; overflow: hidden; }
    .status-head, .panel-head {
      padding: 15px 16px;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }
    .status-body { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .signal {
      min-height: 86px;
      padding: 14px 16px;
      border-right: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
      display: grid;
      align-content: space-between;
      gap: 10px;
    }
    .signal:nth-child(2n) { border-right: 0; }
    .signal strong { display: block; font-size: 20px; line-height: 1.1; }
    .grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 16px; margin-bottom: 16px; min-width: 0; }
    .panel { grid-column: span 12; overflow: hidden; min-width: 0; }
    .panel.half { grid-column: span 6; }
    .panel-body { padding: 16px; }
    .facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); border-top: 1px solid var(--line); margin-top: 14px; }
    .fact { padding: 13px 14px 0 0; min-width: 0; }
    .fact strong { display: block; font-size: 22px; line-height: 1.1; overflow-wrap: anywhere; }
    .verdict {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 12px;
    }
    .verdict span {
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      display: grid;
      align-content: center;
      padding: 7px 9px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.2;
      overflow-wrap: anywhere;
    }
    .verdict strong {
      display: block;
      color: var(--ink);
      font-size: 13px;
      line-height: 1.15;
    }
    .role-matrix {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }
    .role-card {
      min-height: 172px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 11px 12px;
      display: grid;
      align-content: start;
      gap: 8px;
      min-width: 0;
    }
    .role-card.active {
      border-color: color-mix(in srgb, var(--accent) 48%, var(--line));
      background: color-mix(in srgb, var(--accent) 8%, var(--panel));
    }
    .role-head {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      align-items: center;
      min-width: 0;
    }
    .role-head strong { overflow-wrap: anywhere; }
    .role-label {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.2;
      text-transform: uppercase;
    }
    .role-card p { font-size: 13px; line-height: 1.3; }
    .receipt {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 12px;
      min-width: 0;
    }
    .receipt strong { display: block; font-size: 16px; line-height: 1.2; }
    .receipt-proof {
      display: grid;
      grid-template-columns: minmax(0, .8fr) minmax(0, 1fr) minmax(0, 2fr);
      gap: 8px;
      margin-bottom: 12px;
    }
    .receipt-proof span {
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: color-mix(in srgb, var(--accent) 6%, var(--panel-soft));
      display: grid;
      align-content: center;
      padding: 7px 9px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.2;
      overflow-wrap: anywhere;
    }
    .receipt-proof strong {
      display: block;
      color: var(--ink);
      font-size: 13px;
      line-height: 1.15;
    }
    .receipt-proof .mono { font-size: 11px; }
    .receipt-copy {
      display: grid;
      grid-template-columns: minmax(0, .85fr) minmax(0, 1.8fr) minmax(0, .9fr);
      gap: 8px;
    }
    .receipt-copy label {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 8px 9px;
      color: var(--muted);
      font-size: 12px;
    }
	    .receipt-copy input {
	      width: 100%;
	      min-height: 34px;
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      padding: 6px 8px;
	      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
	      font-size: 11px;
	      color: var(--ink);
	      background: var(--panel);
	    }
	    .capture-headers {
	      display: grid;
	      gap: 8px;
	    }
	    .capture-header {
	      display: grid;
	      grid-template-columns: minmax(180px, .6fr) minmax(0, 1fr) auto;
	      gap: 8px;
	      align-items: center;
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      background: var(--panel-soft);
	      padding: 9px 10px;
	      min-width: 0;
	    }
	    .capture-header span { color: var(--muted); font-size: 12px; line-height: 1.2; overflow-wrap: anywhere; }
	    .capture-header strong { font-size: 12px; line-height: 1.2; overflow-wrap: anywhere; }
	    .capture-line {
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      background: color-mix(in srgb, var(--accent) 5%, var(--panel-soft));
	      padding: 9px 10px;
	      font-size: 12px;
	      line-height: 1.35;
	      overflow-wrap: anywhere;
	    }
	    .hash-copy input { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
	    .audit-timeline {
	      display: grid;
	      gap: 10px;
	    }
	    .audit-event {
	      display: grid;
	      grid-template-columns: 92px minmax(0, 1fr) minmax(180px, .34fr);
	      gap: 12px;
	      align-items: stretch;
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      background: var(--panel-soft);
	      padding: 12px;
	      min-width: 0;
	    }
	    .audit-event.ok { border-color: color-mix(in srgb, var(--accent) 34%, var(--line)); }
	    .audit-event.warn { border-color: color-mix(in srgb, var(--amber) 38%, var(--line)); }
	    .audit-event.info { border-color: color-mix(in srgb, var(--blue) 30%, var(--line)); }
	    .audit-index {
	      display: grid;
	      align-content: space-between;
	      gap: 8px;
	      min-width: 0;
	    }
	    .audit-index span { color: var(--muted); font-size: 12px; }
	    .audit-index strong { font-size: 15px; line-height: 1.15; overflow-wrap: anywhere; }
	    .audit-main {
	      display: grid;
	      gap: 8px;
	      align-content: start;
	      min-width: 0;
	    }
	    .audit-title {
	      display: flex;
	      flex-wrap: wrap;
	      gap: 7px;
	      align-items: center;
	      min-width: 0;
	    }
	    .audit-title strong { font-size: 16px; line-height: 1.15; overflow-wrap: anywhere; }
	    .audit-proof {
	      display: grid;
	      grid-template-columns: auto minmax(0, 1fr);
	      align-content: center;
	      gap: 5px 8px;
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      background: color-mix(in srgb, var(--accent) 5%, var(--panel));
	      padding: 9px 10px;
	      min-width: 0;
	    }
	    .audit-proof span { color: var(--muted); font-size: 12px; }
	    .audit-proof strong { font-size: 12px; line-height: 1.15; overflow-wrap: anywhere; }
	    .table-wrap { overflow-x: auto; }
	    table { width: 100%; border-collapse: collapse; min-width: 1040px; }
    th, td { padding: 12px 16px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0; }
    tr:hover td { background: var(--panel-soft); }
    tr.selected td { background: color-mix(in srgb, var(--accent) 7%, var(--panel)); }
    .pill {
      display: inline-flex;
      align-items: center;
      justify-self: start;
      min-height: 24px;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      color: var(--muted);
      font-size: 12px;
      line-height: 1.2;
      text-align: center;
      white-space: normal;
      overflow-wrap: anywhere;
      max-width: 100%;
    }
    .pill.ok { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 46%, var(--line)); }
    .pill.info { color: var(--blue); border-color: color-mix(in srgb, var(--blue) 46%, var(--line)); }
    .pill.warn { color: var(--amber); border-color: color-mix(in srgb, var(--amber) 46%, var(--line)); }
    .stack { display: grid; gap: 8px; }
    .muted { color: var(--muted); }
    .warn { color: var(--amber); }
    .danger { color: var(--danger); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
    form { margin: 0; }
    @media (max-width: 860px) {
      section { scroll-margin-top: 154px; }
      .bar { grid-template-columns: 1fr auto; padding: 12px 0; }
      .nav { grid-column: 1 / -1; justify-content: flex-start; overflow-x: auto; padding-bottom: 2px; }
      .account { grid-column: 1 / -1; justify-self: stretch; max-width: none; }
      .overview { grid-template-columns: 1fr; }
      .panel.half { grid-column: span 12; }
      .flow { grid-template-columns: 1fr; }
      .facts { grid-template-columns: 1fr; gap: 10px; }
      .verdict { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .role-matrix { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .safety-ribbon { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .session-proof { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .session-proof-item.action { width: auto; grid-column: 1 / -1; }
      .ops-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .command-top { grid-template-columns: 1fr; }
      .command-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .mode-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .witness-grid { grid-template-columns: 1fr; }
	      .receipt { grid-template-columns: 1fr; }
	      .receipt-proof { grid-template-columns: 1fr; }
	      .receipt-copy { grid-template-columns: 1fr; }
	      .audit-event { grid-template-columns: 1fr; }
	      .audit-proof { grid-template-columns: minmax(0, .3fr) minmax(0, .7fr); }
	      .capture-header { grid-template-columns: 1fr; align-items: start; }
	      .assurance-flow { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .trust-rail { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .trust-step:nth-child(2n) { border-right: 0; }
      .trust-step:nth-child(-n+2) { border-bottom: 1px solid var(--line); }
      h1 { font-size: 32px; }
    }
    @media (max-width: 560px) {
      section { scroll-margin-top: 232px; }
      .bar, main { width: calc(100% - 22px); max-width: 1180px; }
      main { padding-top: 14px; }
      h1 { font-size: 28px; line-height: 1.08; }
      .intro { padding: 16px; gap: 12px; }
      .panel-body { padding: 13px; }
      .status-head, .panel-head { padding: 13px; align-items: flex-start; }
      .signal { min-height: auto; padding: 12px 13px; }
      .mode-item, .command-card, .ops-item, .assurance-step, .safety-chip { min-height: auto; }
      .status-body { grid-template-columns: 1fr; }
      .verdict { grid-template-columns: 1fr; }
      .role-matrix { grid-template-columns: 1fr; }
      .ops-strip { grid-template-columns: 1fr; }
      .safety-ribbon { grid-template-columns: 1fr; }
      .session-proof { grid-template-columns: 1fr; }
      .session-proof-item { min-height: auto; }
      .session-proof-item.action { grid-column: auto; }
      .reviewer-flow { grid-template-columns: 1fr; }
      .reviewer-step { min-height: auto; }
      .command-grid { grid-template-columns: 1fr; }
      .command-actions { display: grid; grid-template-columns: 1fr; }
      .command-actions .button { width: 100%; }
      .mode-grid { grid-template-columns: 1fr; }
      .witness-grid { grid-template-columns: 1fr; }
	      .receipt { grid-template-columns: 1fr; }
	      .receipt-proof { grid-template-columns: 1fr; }
	      .receipt-copy { grid-template-columns: 1fr; }
	      .audit-event { grid-template-columns: 1fr; }
	      .audit-proof { grid-template-columns: minmax(0, .32fr) minmax(0, .68fr); }
	      .capture-header { grid-template-columns: 1fr; }
	      .assurance-flow { grid-template-columns: 1fr; }
      .trust-rail { grid-template-columns: 1fr; }
      .trust-step { border-right: 0; border-bottom: 1px solid var(--line); }
      .trust-step:last-child { border-bottom: 0; }
      .signal { border-right: 0; }
      .toolbar { display: grid; grid-template-columns: 1fr; }
      .toolbar .button { width: 100%; }
    }
    @media (max-width: 380px) {
      .safety-ribbon { grid-template-columns: 1fr; }
      h1 { font-size: 28px; }
    }
  </style>
</head>
<body>
<a class="skip-link" href="#command-center">Skip to command center</a>
<header>
  <div class="bar">
    <div class="brand"><div class="mark">J</div><div>Janus</div></div>
		    {{ if .Session.Subject }}
		    <nav class="nav" aria-label="Primary">
		      {{ if .WitnessPage }}
		      <a href="/">Dashboard</a>
		      <a href="/session-witness">Witness</a>
		      <a href="/session-witness.txt">Text</a>
		      <a href="/session-witness/proof.txt">Proof pack</a>
		      <a href="/session-witness/verify">Verify</a>
		      <a href="/api/auth/session-witness">JSON</a>
		      {{ else }}
		      <a href="#overview">Overview</a>
		      <a href="#command-center">Command</a>
	      {{ if .CanOperate }}
	      <a href="#warden">Warden</a>
      <a href="#permit">Permit</a>
      {{ if .Permits }}<a href="#permits">Permits</a>{{ end }}
	      {{ end }}
	      <a href="#authenticated-role-evidence">Session</a>
      <a href="#posture">Posture</a>
      {{ if .CanViewAudit }}
      <a href="#audit">Audit</a>
	      {{ end }}
	      <a href="#catalog">Catalog</a>
	      {{ end }}
	    </nav>
    {{ else }}
    <div></div>
	    {{ end }}
	    {{ if .Session.Subject }}
	    <div class="account" aria-label="Session identity">
	      <strong>{{ .AuthenticatedRole.IdentityLabel }}</strong>
	      <span>{{ range .Session.Roles }}{{ . }} {{ end }} identity values withheld</span>
	    </div>
    <form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{{ .CSRF }}"><button type="submit">Sign out</button></form>
    {{ else }}
    <a class="button primary" href="/login">Sign in</a>
    {{ end }}
  </div>
</header>
<main>
{{- end }}

{{ define "base_bottom" -}}
</main>
</body>
</html>
{{- end }}

{{ define "dashboard" -}}
{{ template "base_top" . }}
<section class="overview" id="overview">
  <div class="intro">
    <div class="intro-copy">
      <div class="eyebrow">{{ .ModeGuardrails.Current }} / {{ .ModeGuardrails.Claim }} / metadata-only</div>
      <h1>Vault control plane</h1>
      <p>Ownership, posture, and audit-safe descriptors for secrets. Secret values stay outside Janus.</p>
    </div>
    <div class="safety-ribbon" aria-label="Current safety posture">
      <div class="safety-chip info">
        <span>Service</span>
        <strong>Janus</strong>
      </div>
      <div class="safety-chip {{ if eq .ModeGuardrails.Current "enterprise" }}ok{{ else }}info{{ end }}">
        <span>Mode</span>
        <strong>{{ .ModeGuardrails.Current }}</strong>
      </div>
      <div class="safety-chip ok">
        <span>Boundary</span>
        <strong>values withheld</strong>
      </div>
      <div class="safety-chip {{ if .CommandCenter.BlockedActions }}warn{{ else }}ok{{ end }}">
        <span>Actions</span>
        <strong>{{ .CommandCenter.AvailableActions }} safe</strong>
      </div>
    </div>
	    <div class="toolbar">
	      {{ if .CanExportEvidence }}<a class="button primary" href="/api/evidence">Evidence JSON</a>{{ end }}
	      <a class="button quiet" href="/session-witness">Session proof</a>
	      <a class="button quiet" href="/session-witness.txt">Proof text</a>
	      <a class="button quiet" href="/api/auth/session-witness">Witness JSON</a>
	      <a class="button quiet" href="/api/posture">Posture JSON</a>
	      <a class="button quiet" href="/api/warden/descriptors">Descriptors JSON</a>
	    </div>
    <div class="session-proof" aria-label="Browser session witness">
      <div class="session-proof-item {{ if eq .AuthenticatedBrowser.State "authenticated" }}ok{{ else if eq .AuthenticatedBrowser.State "local_smoke" }}info{{ else }}warn{{ end }}">
        <span>Session witness</span>
        <strong>{{ .AuthenticatedBrowser.State }}</strong>
        <p>{{ .AuthenticatedBrowser.Flow }}</p>
      </div>
      <div class="session-proof-item ok">
        <span>Cookie and CSRF</span>
        <strong>{{ .AuthenticatedBrowser.SessionCookiePolicy }}</strong>
        <p>{{ .AuthenticatedBrowser.CSRFBoundary }}; {{ .AuthenticatedBrowser.CSPBoundary }}</p>
	      </div>
	      <div class="session-proof-item action">
	        <a class="button quiet" href="/session-witness/proof.txt">Open proof pack</a>
	      </div>
	    </div>
    <div class="reviewer-flow" aria-label="Signed-browser reviewer handoff">
      <div class="reviewer-step ok">
        <span>Reviewer handoff</span>
        <strong>browser proof ready</strong>
        <p>signed_browser_capture=true</p>
      </div>
      <div class="reviewer-step action">
        <a class="button primary" href="/session-witness/proof.txt">Proof pack</a>
      </div>
      <div class="reviewer-step action">
        <a class="button quiet" href="/session-witness">Inspect witness</a>
      </div>
      <div class="reviewer-step ok">
        <span>Boundary</span>
        <strong>values withheld</strong>
        <p>proof_pack_contains_verification=true</p>
      </div>
    </div>
    <p><span class="pill {{ if eq .OperationalStatus.Verdict "operational" }}ok{{ else }}warn{{ end }}">{{ .OperationalStatus.Verdict }}</span> {{ .OperationalStatus.Summary }}</p>
    <div class="ops-strip" aria-label="Operational status">
      {{ range .OperationalStatus.Items }}
      <div class="ops-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
      </div>
      {{ end }}
    </div>
    <div class="assurance-flow" aria-label="Assurance flow">
	      <div class="assurance-step">
	        <b>1</b>
	        <strong>Signed-in role receipt</strong>
	        <span>{{ .AuthenticatedRole.State }}; identity values withheld</span>
	      </div>
      <div class="assurance-step">
        <b>2</b>
        <strong>Metadata only</strong>
        <span>{{ len .Descriptors }} descriptors, values withheld</span>
      </div>
      <div class="assurance-step">
        <b>3</b>
        <strong>Use gate</strong>
        <span>{{ if .ApprovedUse.BlockedCount }}{{ .ApprovedUse.BlockedCount }} blocked{{ else }}profiled and closed{{ end }}</span>
      </div>
      <div class="assurance-step">
        <b>4</b>
        <strong>Audit trail</strong>
        <span>{{ if .Posture.ChainVerified }}chain verified{{ else }}review needed{{ end }}</span>
      </div>
    </div>
    <div class="trust-rail" aria-label="Trust posture">
      <div class="trust-step {{ if .Ready }}ok{{ else }}warn{{ end }}">
        <span>Readiness</span>
        <strong>{{ if .Ready }}ready{{ else }}review{{ end }}</strong>
      </div>
      <div class="trust-step {{ if .CatalogGates }}warn{{ else }}ok{{ end }}">
        <span>Catalog gates</span>
        <strong>{{ len .CatalogGates }}</strong>
      </div>
      <div class="trust-step {{ if .Access.ExplicitBindings }}ok{{ else }}warn{{ end }}">
        <span>Access</span>
        <strong>{{ if .Access.ExplicitBindings }}explicit{{ else }}bootstrap{{ end }}</strong>
      </div>
      <div class="trust-step {{ if .ApprovedUse.BlockedCount }}warn{{ else }}ok{{ end }}">
        <span>Approved use</span>
        <strong>{{ if .ApprovedUse.BlockedCount }}{{ .ApprovedUse.BlockedCount }} blocked{{ else }}profiled{{ end }}</strong>
      </div>
    </div>
  </div>
  <div class="status">
    <div class="status-head">
      <h2>Live posture</h2>
      {{ if not .Ready }}<span class="pill warn">restricted</span>{{ else if .Issues }}<span class="pill warn">{{ len .Issues }} gates</span>{{ else }}<span class="pill ok">ready</span>{{ end }}
    </div>
    <div class="status-body">
      <div class="signal">
        <span class="muted">Secret values</span>
        <strong>withheld</strong>
        <span class="pill ok">never returned</span>
      </div>
      <div class="signal">
        <span class="muted">Scope</span>
        <strong>{{ range .Scope.AllowedScopes }}{{ . }}{{ end }}</strong>
        {{ if .Scope.Strict }}<span class="pill ok">strict</span>{{ else }}<span class="pill warn">open</span>{{ end }}
      </div>
      <div class="signal">
        <span class="muted">Lifecycle</span>
        {{ if .Lifecycle.BlockedCount }}<strong>review</strong><span class="pill warn">{{ .Lifecycle.BlockedCount }} blocked</span>{{ else }}<strong>clear</strong><span class="pill ok">{{ .Lifecycle.ActiveCount }} active</span>{{ end }}
      </div>
      <div class="signal">
        <span class="muted">Audit chain</span>
        {{ if .Posture.ChainVerified }}<strong>verified</strong><span class="pill ok">hash chained</span>{{ else }}<strong>review</strong><span class="pill warn">needs review</span>{{ end }}
      </div>
      <div class="signal">
        <span class="muted">Evidence hash</span>
        {{ if .CanViewAudit }}
        <strong class="mono">{{ if .EvidenceHash }}{{ .EvidenceHash }}{{ else }}pending{{ end }}</strong>
        <span class="pill info">sha256</span>
        {{ else }}
        <strong>restricted</strong>
        <span class="pill warn">auditor</span>
        {{ end }}
      </div>
    </div>
	  </div>
		</section>
		<section class="panel" style="margin-bottom:16px" id="command-center">
		  <div class="panel-head">
		    <h2>Command center</h2>
		    <span class="pill {{ if eq .CommandCenter.State "ready" }}ok{{ else if eq .CommandCenter.State "review" }}info{{ else }}warn{{ end }}">{{ .CommandCenter.State }}</span>
		  </div>
		  <div class="panel-body">
		    <div class="command-top">
		      <div class="stack">
		        <p>{{ .CommandCenter.Summary }}</p>
		        <p><span class="pill ok">{{ .CommandCenter.Boundary }}</span> <span class="pill ok">value_returned=false</span> <span class="pill info">{{ .CommandCenter.AvailableActions }} safe actions</span> <span class="pill {{ if .CommandCenter.BlockedActions }}warn{{ else }}ok{{ end }}">{{ .CommandCenter.BlockedActions }} blocked</span> <span class="pill {{ if .CommandCenter.ReviewCount }}warn{{ else }}ok{{ end }}">{{ .CommandCenter.ReviewCount }} review</span></p>
		      </div>
		      <div class="command-state {{ if eq .CommandCenter.State "ready" }}ok{{ else if eq .CommandCenter.State "review" }}info{{ else }}warn{{ end }}">
		        <span>Now</span>
		        <strong>{{ .CommandCenter.State }}</strong>
		        <span>metadata only</span>
		      </div>
		    </div>
		    <div class="command-grid" aria-label="Command center status">
		      {{ range .CommandCenter.Cards }}
		      <div class="command-card {{ .Tone }}">
		        <span>{{ .Label }}</span>
		        <strong>{{ .State }}</strong>
		        <p>{{ .Detail }}</p>
		        <p><span class="pill info">next</span> {{ .Next }}</p>
		      </div>
		      {{ end }}
		    </div>
		    {{ if .CommandCenter.QuickActions }}
		    <div class="command-actions" aria-label="Safe quick actions">
		      {{ range .CommandCenter.QuickActions }}
		      <a class="button {{ if eq .Key "evidence_export" }}primary{{ else }}quiet{{ end }}" href="{{ .Href }}">{{ .Label }}</a>
		      {{ end }}
		    </div>
		{{ end }}
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="auth-failure-posture">
	  <div class="panel-head">
	    <h2>Auth failure posture</h2>
	    <span class="pill {{ if eq .AuthFailure.State "ready" }}ok{{ else if eq .AuthFailure.State "local_auth_disabled" }}info{{ else }}warn{{ end }}">{{ .AuthFailure.State }}</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .AuthFailure.Summary }}</p>
	    <p><span class="pill info">{{ .AuthFailure.IdentityProvider }}</span> <span class="pill info">{{ .AuthFailure.EvidenceSignal }}</span> <span class="pill info">Redirect loop guard {{ .AuthFailure.LoopGuard.State }}</span> <span class="pill ok">raw_callback_query_returned=false</span> <span class="pill ok">provider_error_returned=false</span> <span class="pill ok">redirect_url_returned=false</span> <span class="pill ok">token_returned=false</span> <span class="pill ok">cookie_value_returned=false</span> <span class="pill ok">request_body_returned=false</span> <span class="pill ok">env_returned=false</span> <span class="pill ok">backend_path_returned=false</span> <span class="pill ok">value_returned=false</span></p>
	    <p><span class="pill info">loop window</span> {{ .AuthFailure.LoopGuard.MaxAttempts }} starts / {{ .AuthFailure.LoopGuard.WindowSeconds }} seconds <span class="pill info">{{ .AuthFailure.LoopGuard.ResetAction }}</span></p>
	    <div class="mode-grid" aria-label="Auth failure reasons">
	      {{ range .AuthFailure.Reasons }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	        <p><span class="pill info">{{ .Key }}</span> <span class="pill info">next</span> {{ .Next }}</p>
	        <p><span class="pill ok">raw query not returned</span> <span class="pill ok">provider detail not returned</span></p>
	      </div>
	      {{ end }}
	    </div>
	    <p><strong>Safe actions</strong></p>
	    <div class="mode-grid" aria-label="Auth failure actions">
	      {{ range .AuthFailure.Actions }}
	      <div class="mode-item ok">
	        <span>{{ .Label }}</span>
	        <strong>{{ .Key }}</strong>
	        <p>{{ .Safety }}</p>
	        <p><span class="pill info">next</span> {{ .Next }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="supply-chain-posture">
	  <div class="panel-head">
	    <h2>Supply-chain posture</h2>
	    <span class="pill {{ if eq .SupplyChain.Status "clean" }}ok{{ else }}warn{{ end }}">{{ .SupplyChain.Status }}</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .SupplyChain.Summary }}</p>
	    <div class="witness-grid" aria-label="Supply-chain posture witness">
	      <div class="witness-card {{ if eq .SupplyChain.Status "clean" }}ok{{ else }}warn{{ end }}">
	        <span>Dependency state</span>
	        <strong>{{ .SupplyChain.DependencyState }}</strong>
	        <p>Builder {{ .SupplyChain.Builder }}. Review cadence: {{ .SupplyChain.ReviewCadence }}.</p>
	      </div>
	      <div class="witness-card {{ if .SupplyChain.OpenAlerts }}warn{{ else }}ok{{ end }}">
	        <span>Alert posture</span>
	        <strong>{{ .SupplyChain.OpenAlerts }} open</strong>
	        <p>{{ .SupplyChain.FixedAlerts }} fixed alerts retained as safe release evidence.</p>
	      </div>
	      <div class="witness-card ok">
	        <span>Evidence boundary</span>
	        <strong>values withheld</strong>
	        <p>Scanner output, package files, backend paths, env, evidence refs, and values are not returned.</p>
	      </div>
	    </div>
	    <details class="evidence-flags">
	      <summary>Supply-chain evidence flags</summary>
	      <div class="flag-cloud" aria-label="Supply-chain value-free evidence flags">
	        <span class="pill ok">{{ .SupplyChain.DependencyState }}</span>
	        <span class="pill info">builder {{ .SupplyChain.Builder }}</span>
	        <span class="pill ok">{{ .SupplyChain.OpenAlerts }} open alerts</span>
	        <span class="pill info">{{ .SupplyChain.FixedAlerts }} fixed alerts</span>
	        <span class="pill info">review cadence</span>
	        <span class="pill info">{{ .SupplyChain.ReviewCadence }}</span>
	        <span class="pill ok">scanner_output_returned=false</span>
	        <span class="pill ok">package_lock_returned=false</span>
	        <span class="pill ok">backend_path_returned=false</span>
	        <span class="pill ok">env_returned=false</span>
	        <span class="pill ok">evidence_ref_returned=false</span>
	        <span class="pill ok">value_returned=false</span>
	      </div>
	    </details>
	    <div class="mode-grid" aria-label="Supply-chain posture checks">
	      {{ range .SupplyChain.Checks }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	        <p><span class="pill info">next</span> {{ .Next }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="mode-guardrails">
	  <div class="panel-head">
	    <h2>Mode guardrails</h2>
	    <span class="pill {{ if .ModeGuardrails.BlockedCount }}warn{{ else if .ModeGuardrails.ReviewCount }}warn{{ else }}ok{{ end }}">{{ .ModeGuardrails.Claim }}</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .ModeGuardrails.Summary }}</p>
	    <div class="witness-grid" aria-label="Mode guardrails witness">
	      <div class="witness-card {{ if eq .ModeGuardrails.Current "enterprise" }}ok{{ else }}info{{ end }}">
	        <span>Current mode</span>
	        <strong>{{ .ModeGuardrails.Current }}</strong>
	        <p>Mode is explicit before any stronger claim is made.</p>
	      </div>
	      <div class="witness-card {{ if .ModeGuardrails.BlockedCount }}warn{{ else if .ModeGuardrails.ReviewCount }}warn{{ else }}ok{{ end }}">
	        <span>Claim boundary</span>
	        <strong>{{ .ModeGuardrails.Claim }}</strong>
	        <p>{{ .ModeGuardrails.BlockedCount }} blocked, {{ .ModeGuardrails.ReviewCount }} review.</p>
	      </div>
	      <div class="witness-card ok">
	        <span>Value boundary</span>
	        <strong>values withheld</strong>
	        <p>{{ .ModeGuardrails.Boundary }}; no secret values are returned.</p>
	      </div>
	    </div>
	    <details class="evidence-flags">
	      <summary>Mode guardrail evidence flags</summary>
	      <div class="flag-cloud" aria-label="Mode guardrail value-free evidence flags">
	        <span class="pill info">{{ .ModeGuardrails.Current }}</span>
	        <span class="pill warn">{{ .ModeGuardrails.Boundary }}</span>
	        <span class="pill {{ if .ModeGuardrails.BlockedCount }}warn{{ else }}ok{{ end }}">{{ .ModeGuardrails.BlockedCount }} blocked</span>
	        <span class="pill {{ if .ModeGuardrails.ReviewCount }}warn{{ else }}ok{{ end }}">{{ .ModeGuardrails.ReviewCount }} review</span>
	        <span class="pill ok">value_returned=false</span>
	      </div>
	    </details>
	    <div class="mode-grid" aria-label="Mode guardrails">
	      {{ range .ModeGuardrails.Items }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Claim }}</p>
	        <p>{{ .Limit }}</p>
	        <p><span class="pill info">next</span> {{ .Next }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="degraded-guidance">
	  <div class="panel-head">
	    <h2>Next safe steps</h2>
	    <span class="pill {{ if .Guidance.BlockedCount }}warn{{ else if .Guidance.ReviewCount }}warn{{ else }}ok{{ end }}">{{ if .Guidance.BlockedCount }}{{ .Guidance.BlockedCount }} blocked{{ else if .Guidance.ReviewCount }}{{ .Guidance.ReviewCount }} review{{ else }}clear{{ end }}</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .Guidance.Summary }}</p>
	    <div class="witness-grid" aria-label="Next safe steps witness">
	      <div class="witness-card {{ if .Guidance.BlockedCount }}warn{{ else if .Guidance.ReviewCount }}warn{{ else }}ok{{ end }}">
	        <span>Action state</span>
	        <strong>{{ if .Guidance.BlockedCount }}{{ .Guidance.BlockedCount }} blocked{{ else if .Guidance.ReviewCount }}{{ .Guidance.ReviewCount }} review{{ else }}clear{{ end }}</strong>
	        <p>Only safe recovery and review actions are shown.</p>
	      </div>
	      <div class="witness-card info">
	        <span>Role boundary</span>
	        <strong>role gated</strong>
	        <p>Recovery actions stay tied to their required role and next step.</p>
	      </div>
	      <div class="witness-card ok">
	        <span>Value boundary</span>
	        <strong>values withheld</strong>
	        <p>Guidance explains what to do next without returning secret material.</p>
	      </div>
	    </div>
	    <details class="evidence-flags">
	      <summary>Next safe steps evidence flags</summary>
	      <div class="flag-cloud" aria-label="Next safe steps value-free evidence flags">
	        <span class="pill ok">value_returned=false</span>
	        <span class="pill info">safe actions only</span>
	        <span class="pill {{ if .Guidance.BlockedCount }}warn{{ else }}ok{{ end }}">{{ .Guidance.BlockedCount }} blocked</span>
	        <span class="pill {{ if .Guidance.ReviewCount }}warn{{ else }}ok{{ end }}">{{ .Guidance.ReviewCount }} review</span>
	      </div>
	    </details>
	    <div class="mode-grid" aria-label="Degraded-state guidance">
	      {{ range .Guidance.Items }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Impact }}</p>
	        <p><span class="pill info">{{ .Role }}</span> {{ .Action }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="audit-failure-drill">
	  <div class="panel-head">
	    <h2>Audit failure drill</h2>
	    <span class="pill {{ if .AuditDrill.BlockedCount }}warn{{ else }}ok{{ end }}">{{ .AuditDrill.Status }}</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .AuditDrill.Summary }}</p>
	    <div class="witness-grid" aria-label="Audit failure drill witness">
	      <div class="witness-card {{ if .AuditDrill.BlockedCount }}warn{{ else }}ok{{ end }}">
	        <span>Drill state</span>
	        <strong>{{ .AuditDrill.Status }}</strong>
	        <p>{{ .AuditDrill.Scenario }} is visible as a security state.</p>
	      </div>
	      <div class="witness-card info">
	        <span>Recovery role</span>
	        <strong>{{ .AuditDrill.RecoveryRole }}</strong>
	        <p>Recovery stays role-separated before sensitive action resumes.</p>
	      </div>
	      <div class="witness-card ok">
	        <span>Value boundary</span>
	        <strong>values withheld</strong>
	        <p>Audit failure guidance returns status and next step only.</p>
	      </div>
	    </div>
	    <details class="evidence-flags">
	      <summary>Audit failure drill evidence flags</summary>
	      <div class="flag-cloud" aria-label="Audit failure drill value-free evidence flags">
	        <span class="pill info">{{ .AuditDrill.Scenario }}</span>
	        <span class="pill info">role {{ .AuditDrill.RecoveryRole }}</span>
	        <span class="pill {{ if .AuditDrill.BlockedCount }}warn{{ else }}ok{{ end }}">{{ .AuditDrill.BlockedCount }} blocked</span>
	        <span class="pill ok">value_returned=false</span>
	      </div>
	    </details>
	    <div class="mode-grid" aria-label="Audit failure drill">
	      {{ range .AuditDrill.Checks }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Proof }}</p>
	        <p><span class="pill info">next</span> {{ .Next }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="assurance-summary">
	  <div class="panel-head">
	    <h2>Assurance summary</h2>
    <span class="pill {{ if .AssuranceSummary.Review }}warn{{ else }}ok{{ end }}">{{ .AssuranceSummary.Verdict }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .AssuranceSummary.Summary }}</p>
    <div class="witness-grid" aria-label="Assurance summary witness">
      <div class="witness-card {{ if .AssuranceSummary.Review }}warn{{ else }}ok{{ end }}">
        <span>Proof decision</span>
        <strong>{{ .AssuranceSummary.Verdict }}</strong>
        <p>{{ len .AssuranceSummary.Proven }} proven controls; {{ len .AssuranceSummary.Review }} review items.</p>
      </div>
      <div class="witness-card {{ if .AssuranceSummary.Review }}warn{{ else }}ok{{ end }}">
        <span>Review posture</span>
        <strong>{{ if .AssuranceSummary.Review }}review needed{{ else }}clear{{ end }}</strong>
        <p>Review items stay visible before stronger claims are trusted.</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Human-readable evidence is shown without returning secret values.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Assurance summary evidence flags</summary>
      <div class="flag-cloud" aria-label="Assurance summary value-free evidence flags">
        <span class="pill info">verdict {{ .AssuranceSummary.Verdict }}</span>
        <span class="pill ok">{{ len .AssuranceSummary.Proven }} proven</span>
        <span class="pill {{ if .AssuranceSummary.Review }}warn{{ else }}ok{{ end }}">{{ len .AssuranceSummary.Review }} review</span>
        <span class="pill info">human readable evidence</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <p><strong>Proven controls</strong></p>
    <div class="mode-grid" aria-label="Proven assurance controls">
      {{ range .AssuranceSummary.Proven }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
      </div>
      {{ end }}
    </div>
    {{ if .AssuranceSummary.Review }}
    <p><strong>Review items</strong></p>
    <div class="mode-grid" aria-label="Assurance review items">
      {{ range .AssuranceSummary.Review }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
      </div>
      {{ end }}
    </div>
    {{ end }}
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="assurance-gates">
  <div class="panel-head">
    <h2>Assurance gates</h2>
    <span class="pill {{ if .AssuranceGates.ReviewCount }}warn{{ else }}ok{{ end }}">{{ if .AssuranceGates.ReviewCount }}{{ .AssuranceGates.ReviewCount }} review{{ else }}covered{{ end }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .AssuranceGates.Summary }}</p>
    <div class="witness-grid" aria-label="Assurance gates witness">
      <div class="witness-card {{ if .AssuranceGates.ReviewCount }}warn{{ else }}ok{{ end }}">
        <span>Gate coverage</span>
        <strong>{{ if .AssuranceGates.ReviewCount }}{{ .AssuranceGates.ReviewCount }} review{{ else }}covered{{ end }}</strong>
        <p>{{ len .AssuranceGates.Gates }} abuse and invariant gates are visible.</p>
      </div>
      <div class="witness-card ok">
        <span>Abuse posture</span>
        <strong>abuse tested</strong>
        <p>Role denial, catalog metadata, degraded action, and value-leak sentinels stay explicit.</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Gate proof returns control state only, not secret material.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Assurance gate evidence flags</summary>
      <div class="flag-cloud" aria-label="Assurance gate value-free evidence flags">
        <span class="pill info">{{ len .AssuranceGates.Gates }} gates</span>
        <span class="pill {{ if .AssuranceGates.ReviewCount }}warn{{ else }}ok{{ end }}">{{ .AssuranceGates.ReviewCount }} review</span>
        <span class="pill info">abuse tested</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Assurance gate proofs">
      {{ range .AssuranceGates.Gates }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
      </div>
      {{ end }}
    </div>
  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="negative-path-assurance">
	  <div class="panel-head">
	    <h2>Blocked-path checks</h2>
	    <span class="pill {{ if .NegativePath.ReviewCount }}warn{{ else }}ok{{ end }}">{{ if .NegativePath.ReviewCount }}{{ .NegativePath.ReviewCount }} review{{ else }}covered{{ end }}</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .NegativePath.Summary }}</p>
	    <div class="witness-grid" aria-label="Blocked-path witness">
	      <div class="witness-card {{ if .NegativePath.ReviewCount }}warn{{ else }}ok{{ end }}">
	        <span>Denied path coverage</span>
	        <strong>{{ .NegativePath.CoveredCount }} covered</strong>
	        <p>{{ .NegativePath.ReviewCount }} review items across {{ len .NegativePath.Cases }} negative-path cases.</p>
	      </div>
	      <div class="witness-card ok">
	        <span>Failure behavior</span>
	        <strong>fail closed</strong>
	        <p>Wrong roles, catalog gaps, audit-down states, and sensitive actions stay explicit.</p>
	      </div>
	      <div class="witness-card ok">
	        <span>Value boundary</span>
	        <strong>values withheld</strong>
	        <p>Denied paths return safe status and request correlation, not secret data.</p>
	      </div>
	    </div>
	    <details class="evidence-flags">
	      <summary>Blocked-path evidence flags</summary>
	      <div class="flag-cloud" aria-label="Blocked-path value-free evidence flags">
	        <span class="pill info">{{ .NegativePath.CoveredCount }} covered</span>
	        <span class="pill {{ if .NegativePath.ReviewCount }}warn{{ else }}ok{{ end }}">{{ .NegativePath.ReviewCount }} review</span>
	        <span class="pill info">{{ len .NegativePath.Cases }} cases</span>
	        <span class="pill ok">value_returned=false</span>
	      </div>
	    </details>
	    <div class="mode-grid" aria-label="Negative-path assurance">
	      {{ range .NegativePath.Cases }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="available-to-you">
	  <div class="panel-head">
	    <h2>Available to you</h2>
    <span class="pill info">role gated</span>
  </div>
  <div class="panel-body stack">
    <div class="witness-grid" aria-label="Session capability witness">
      <div class="witness-card ok">
        <span>Capability view</span>
        <strong>{{ len .RoleAvailability }} duties</strong>
        <p>Session duties are shown as safe labels, not raw identity data.</p>
      </div>
      <div class="witness-card info">
        <span>Role boundary</span>
        <strong>role gated</strong>
        <p>Controls outside this session's roles stay unavailable or hidden.</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Role availability never returns subjects, groups, claims, tokens, cookies, env, or secret values.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Role availability evidence flags</summary>
      <div class="flag-cloud" aria-label="Role availability value-free evidence flags">
        <span class="pill info">{{ len .RoleAvailability }} duties</span>
        <span class="pill info">role gated</span>
        <span class="pill ok">identity_values_returned=false</span>
        <span class="pill ok">claim_values_returned=false</span>
        <span class="pill ok">group_values_returned=false</span>
        <span class="pill ok">token_returned=false</span>
        <span class="pill ok">cookie_value_returned=false</span>
        <span class="pill ok">env_values_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Available to you">
      {{ range .RoleAvailability }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
      </div>
      {{ end }}
    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="authenticated-role-evidence">
	  <div class="panel-head">
	    <h2>Signed-in role receipt</h2>
	    <span class="pill {{ if eq .AuthenticatedRole.State "signed_in" }}ok{{ else if eq .AuthenticatedRole.State "local_auth_disabled" }}info{{ else }}warn{{ end }}">{{ .AuthenticatedRole.State }}</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .AuthenticatedRole.Summary }}</p>
	    <p><span class="pill info">{{ .AuthenticatedBrowser.Label }}</span> {{ .AuthenticatedBrowser.Summary }}</p>
	    <p><span class="pill info">Human validation witness</span> role gates visible, identity values private</p>
	    <div class="witness-grid" aria-label="Human validation witness">
	      <div class="witness-card {{ if eq .AuthenticatedBrowser.State "authenticated" }}ok{{ else if eq .AuthenticatedBrowser.State "local_smoke" }}info{{ else }}warn{{ end }}">
	        <span>Browser proof</span>
	        <strong>{{ .AuthenticatedBrowser.State }}</strong>
	        <p>{{ if eq .AuthenticatedBrowser.AuthMode "zitadel_oidc" }}Zitadel to Janus flow{{ else }}Local smoke flow{{ end }}, strict signed session, copy-safe browser proof.</p>
	      </div>
	      <div class="witness-card {{ if eq .AuthenticatedRole.State "signed_in" }}ok{{ else if eq .AuthenticatedRole.State "local_auth_disabled" }}info{{ else }}warn{{ end }}">
	        <span>Session</span>
	        <strong>{{ if eq .AuthenticatedRole.State "signed_in" }}Signed in{{ else if eq .AuthenticatedRole.State "local_auth_disabled" }}Local smoke{{ else }}Needs login{{ end }}</strong>
	        <p>Role receipt is present; identity values stay private.</p>
	      </div>
	      <div class="witness-card ok">
	        <span>Roles Janus sees</span>
	        <strong>{{ .AuthenticatedRole.ActiveRoleCount }} active</strong>
	        <p>{{ range .AuthenticatedRole.Roles }}{{ if .Active }}<span class="pill info">{{ .Label }}</span> {{ end }}{{ end }}</p>
	      </div>
	      <div class="witness-card ok">
	        <span>Privacy boundary</span>
	        <strong>values withheld</strong>
	        <p>No subject, email, name, group, claim, token, cookie, env, request body, or backend value is shown.</p>
	      </div>
	    </div>
	    <p><span class="pill info">next</span> {{ .AuthenticatedRole.Next }}</p>
	    <details class="evidence-flags">
	      <summary>Evidence flags</summary>
	      <div class="flag-cloud" aria-label="Signed-in role value-free evidence flags">
	        <span class="pill info">{{ .AuthenticatedRole.AuthMode }}</span>
	        <span class="pill info">{{ .AuthenticatedRole.IdentityBoundary }}</span>
	        <span class="pill ok">{{ .AuthenticatedRole.EvidenceSignal }}</span>
	        <span class="pill ok">{{ .AuthenticatedBrowser.EvidenceSignal }}</span>
	        <span class="pill info">{{ .AuthenticatedBrowser.SessionCookiePolicy }}</span>
	        <span class="pill info">{{ .AuthenticatedBrowser.CSRFBoundary }}</span>
	        <span class="pill info">{{ .AuthenticatedBrowser.CSPBoundary }}</span>
	        <span class="pill ok">identity_values_returned=false</span>
	        <span class="pill ok">subject_returned=false</span>
	        <span class="pill ok">email_returned=false</span>
	        <span class="pill ok">name_returned=false</span>
	        <span class="pill ok">claim_values_returned=false</span>
	        <span class="pill ok">group_values_returned=false</span>
	        <span class="pill ok">token_returned=false</span>
	        <span class="pill ok">cookie_value_returned=false</span>
	        <span class="pill ok">request_body_returned=false</span>
	        <span class="pill ok">env_values_returned=false</span>
	        <span class="pill ok">backend_path_returned=false</span>
	        <span class="pill ok">connector_output_returned=false</span>
	        <span class="pill ok">permit_payload_returned=false</span>
	        <span class="pill ok">secret_value_returned=false</span>
	        <span class="pill ok">value_returned=false</span>
	      </div>
	    </details>
	    <div class="mode-grid" aria-label="Authenticated browser gates">
	      {{ range .AuthenticatedBrowser.Gates }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	        <p><span class="pill ok">value_returned=false</span></p>
	      </div>
	      {{ end }}
	    </div>
	    <div class="mode-grid" aria-label="Signed-in role states">
	      {{ range .AuthenticatedRole.Roles }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	        <p><span class="pill info">role {{ .Role }}</span> <span class="pill ok">value_returned=false</span></p>
	      </div>
	      {{ end }}
	    </div>
	    <div class="mode-grid" aria-label="Authenticated role gates">
	      {{ range .AuthenticatedRole.Gates }}
	      <div class="mode-item {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	        <p><span class="pill info">required {{ .RequiredRole }}</span> <span class="pill ok">value_returned=false</span></p>
	        <p><span class="pill info">next</span> {{ .Next }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="action-readiness">
  <div class="panel-head">
    <h2>Action readiness</h2>
    <span class="pill {{ if .ActionReadiness.Blocked }}warn{{ else if .ActionReadiness.Gated }}warn{{ else }}ok{{ end }}">{{ .ActionReadiness.Available }} available</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .ActionReadiness.Summary }}</p>
    <div class="witness-grid" aria-label="Action readiness witness">
      <div class="witness-card {{ if .ActionReadiness.Blocked }}warn{{ else }}ok{{ end }}">
        <span>Available actions</span>
        <strong>{{ .ActionReadiness.Available }}</strong>
        <p>Safe actions are visible only when their role and readiness checks pass.</p>
      </div>
      <div class="witness-card {{ if or .ActionReadiness.Gated .ActionReadiness.Blocked }}warn{{ else }}ok{{ end }}">
        <span>Action gates</span>
        <strong>{{ .ActionReadiness.Gated }} role / {{ .ActionReadiness.Blocked }} readiness</strong>
        <p>Role-gated or readiness-blocked actions fail closed before connector work.</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Action readiness returns safety labels and next steps, not secret values or connector output.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Action readiness evidence flags</summary>
      <div class="flag-cloud" aria-label="Action readiness value-free evidence flags">
        <span class="pill ok">{{ .ActionReadiness.Available }} available</span>
        <span class="pill info">{{ .ActionReadiness.Gated }} role gated</span>
        <span class="pill {{ if .ActionReadiness.Blocked }}warn{{ else }}ok{{ end }}">{{ .ActionReadiness.Blocked }} readiness blocked</span>
        <span class="pill ok">connector_output_returned=false</span>
        <span class="pill ok">request_body_returned=false</span>
        <span class="pill ok">backend_path_returned=false</span>
        <span class="pill ok">env_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Action readiness">
      {{ range .ActionReadiness.Actions }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Reason }}</p>
        <p><span class="pill info">role {{ .RequiredRole }}</span> <span class="pill ok">value_returned=false</span></p>
        <p><span class="pill info">safety</span> {{ .Safety }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="mode-posture">
  <div class="panel-head">
    <h2>Deployment mode</h2>
    <span class="pill info">{{ .ModePosture.Current }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .ModePosture.Summary }}</p>
    <div class="witness-grid" aria-label="Deployment mode witness">
      <div class="witness-card info">
        <span>Current mode</span>
        <strong>{{ .ModePosture.Current }}</strong>
        <p>Runtime claim is shown in UI, health, and evidence.</p>
      </div>
      <div class="witness-card {{ if eq .ModePosture.Baseline "ready" }}ok{{ else if eq .ModePosture.Baseline "dev_only" }}warn{{ else }}warn{{ end }}">
        <span>Baseline claim</span>
        <strong>{{ .ModePosture.Baseline }}</strong>
        <p>Local readiness stays separate from enterprise evidence.</p>
      </div>
      <div class="witness-card {{ if eq .ModePosture.Enterprise "candidate" }}ok{{ else }}warn{{ end }}">
        <span>Enterprise claim</span>
        <strong>{{ .ModePosture.Enterprise }}</strong>
        <p>Enterprise is not trusted unless external evidence is complete.</p>
      </div>
    </div>
    <div class="witness-grid" aria-label="Deployment mode boundary witness">
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Mode posture returns claim state only, not secret values or backend evidence.</p>
      </div>
      <div class="witness-card info">
        <span>Claim separation</span>
        <strong>explicit</strong>
        <p>Dev, self-hosted, and enterprise promises stay visibly different.</p>
      </div>
      <div class="witness-card {{ if eq .ModePosture.Enterprise "candidate" }}ok{{ else }}warn{{ end }}">
        <span>Next claim</span>
        <strong>enterprise {{ .ModePosture.Enterprise }}</strong>
        <p>Stronger claims wait for release, restore, integration, privacy, and audit evidence.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Deployment mode evidence flags</summary>
      <div class="flag-cloud" aria-label="Deployment mode value-free evidence flags">
        <span class="pill info">current mode {{ .ModePosture.Current }}</span>
        <span class="pill {{ if eq .ModePosture.Baseline "ready" }}ok{{ else }}warn{{ end }}">baseline {{ .ModePosture.Baseline }}</span>
        <span class="pill {{ if eq .ModePosture.Enterprise "candidate" }}ok{{ else }}warn{{ end }}">enterprise {{ .ModePosture.Enterprise }}</span>
        <span class="pill info">claim separation explicit</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">backend_path_returned=false</span>
        <span class="pill ok">env_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Deployment mode posture">
      {{ range .ModePosture.Controls }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
      </div>
      {{ end }}
    </div>
	</div>
</section>
<section class="panel" style="margin-bottom:16px" id="enterprise-release-gate">
  <div class="panel-head">
    <h2>Enterprise release gate</h2>
    <span class="pill {{ if eq .EnterpriseRelease.Status "candidate" }}ok{{ else if eq .EnterpriseRelease.Status "ready_for_review" }}info{{ else }}warn{{ end }}">{{ .EnterpriseRelease.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .EnterpriseRelease.Summary }}</p>
    <p><span class="pill info">Release witness</span> decision visible, external evidence values private</p>
    <div class="witness-grid" aria-label="Enterprise release witness">
      <div class="witness-card {{ if eq .EnterpriseRelease.Claim "enterprise_candidate" }}ok{{ else }}warn{{ end }}">
        <span>Claim</span>
        <strong>{{ .EnterpriseRelease.Claim }}</strong>
        <p>{{ .EnterpriseRelease.CurrentMode }} now; {{ .EnterpriseRelease.TargetMode }} target.</p>
      </div>
      <div class="witness-card {{ if .EnterpriseRelease.Blocked }}warn{{ else }}ok{{ end }}">
        <span>Release decision</span>
        <strong>{{ .EnterpriseRelease.Verdict }}</strong>
        <p>{{ .EnterpriseRelease.Blocked }} blocked, {{ .EnterpriseRelease.Passed }} passed, {{ .EnterpriseRelease.ReviewCount }} review.</p>
      </div>
      <div class="witness-card ok">
        <span>Evidence boundary</span>
        <strong>values withheld</strong>
        <p>No evidence ref, procedure, ticket URL, backend path, request body, env, scanner output, artifact, or payload is shown.</p>
      </div>
    </div>
    <p><span class="pill info">release cadence</span> {{ .EnterpriseRelease.ReleaseCadence }}</p>
    <p><span class="pill info">next</span> {{ .EnterpriseRelease.Next }}</p>
    <details class="evidence-flags">
      <summary>Enterprise release evidence flags</summary>
      <div class="flag-cloud" aria-label="Enterprise release value-free evidence flags">
        <span class="pill info">current mode {{ .EnterpriseRelease.CurrentMode }}</span>
        <span class="pill warn">target mode {{ .EnterpriseRelease.TargetMode }}</span>
        <span class="pill {{ if eq .EnterpriseRelease.Claim "enterprise_candidate" }}ok{{ else }}warn{{ end }}">claim {{ .EnterpriseRelease.Claim }}</span>
        <span class="pill info">verdict {{ .EnterpriseRelease.Verdict }}</span>
        <span class="pill info">{{ .EnterpriseRelease.Required }} required</span>
        <span class="pill ok">{{ .EnterpriseRelease.Passed }} passed</span>
        <span class="pill {{ if .EnterpriseRelease.Blocked }}warn{{ else }}ok{{ end }}">{{ .EnterpriseRelease.Blocked }} blocked</span>
        <span class="pill info">{{ .EnterpriseRelease.ReviewCount }} review</span>
        <span class="pill info">{{ .EnterpriseRelease.EvidenceSignal }}</span>
        <span class="pill info">gate {{ .EnterpriseRelease.EvidenceGate }}</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">procedure_returned=false</span>
        <span class="pill ok">ticket_url_returned=false</span>
        <span class="pill ok">backend_path_returned=false</span>
        <span class="pill ok">request_body_returned=false</span>
        <span class="pill ok">env_returned=false</span>
        <span class="pill ok">scanner_output_returned=false</span>
        <span class="pill ok">artifact_returned=false</span>
        <span class="pill ok">payload_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Enterprise release gate checklist">
      {{ range .EnterpriseRelease.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">owner {{ .OwnerRole }}</span> <span class="pill {{ if .Required }}warn{{ else }}info{{ end }}">required={{ .Required }}</span> <span class="pill info">{{ .EvidenceSignal }}</span> <span class="pill ok">evidence ref not returned</span></p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="enterprise-dry-run">
  <div class="panel-head">
    <h2>Enterprise dry run</h2>
    <span class="pill {{ if eq .EnterpriseDryRun.Status "candidate" }}ok{{ else }}warn{{ end }}">{{ .EnterpriseDryRun.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .EnterpriseDryRun.Summary }}</p>
    <p><span class="pill info">Promotion dry-run witness</span> target path visible, evidence values private</p>
    <div class="witness-grid" aria-label="Enterprise dry-run witness">
      <div class="witness-card info">
        <span>Promotion path</span>
        <strong>{{ .EnterpriseDryRun.CurrentMode }} to {{ .EnterpriseDryRun.TargetMode }}</strong>
        <p>Current mode stays explicit before any enterprise claim.</p>
      </div>
      <div class="witness-card {{ if .EnterpriseDryRun.Missing }}warn{{ else }}ok{{ end }}">
        <span>Blockers</span>
        <strong>{{ .EnterpriseDryRun.Missing }}</strong>
        <p>{{ .EnterpriseDryRun.Required }} controls required before promotion.</p>
      </div>
      <div class="witness-card ok">
        <span>Evidence boundary</span>
        <strong>values withheld</strong>
        <p>No external evidence ref or secret value is shown in the dry run.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Enterprise dry-run evidence flags</summary>
      <div class="flag-cloud" aria-label="Enterprise dry-run value-free evidence flags">
        <span class="pill info">{{ .EnterpriseDryRun.CurrentMode }} now</span>
        <span class="pill warn">{{ .EnterpriseDryRun.TargetMode }} target</span>
        <span class="pill {{ if .EnterpriseDryRun.Missing }}warn{{ else }}ok{{ end }}">{{ .EnterpriseDryRun.Missing }} blockers</span>
        <span class="pill info">{{ .EnterpriseDryRun.Required }} required</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Enterprise dry-run checklist">
      {{ range .EnterpriseDryRun.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">owner {{ .OwnerRole }}</span> <span class="pill {{ if .Required }}warn{{ else }}info{{ end }}">required={{ .Required }}</span></p>
        <p><span class="pill {{ if eq .Attachment "missing" }}warn{{ else if eq .Attachment "attached_presence_only" }}ok{{ else }}info{{ end }}">{{ .Attachment }}</span> <span class="pill info">{{ .EvidenceSignal }}</span> <span class="pill ok">evidence ref not returned</span></p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="enterprise-claim-review">
  <div class="panel-head">
    <h2>Enterprise claim review</h2>
    <span class="pill {{ if eq .EnterpriseClaim.Status "candidate" }}ok{{ else if eq .EnterpriseClaim.Status "ready_for_review" }}info{{ else }}warn{{ end }}">{{ .EnterpriseClaim.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .EnterpriseClaim.Summary }}</p>
    <p><span class="pill info">Claim review witness</span> owner readiness visible, evidence values private</p>
    <div class="witness-grid" aria-label="Enterprise claim witness">
      <div class="witness-card {{ if eq .EnterpriseClaim.Claim "enterprise_candidate" }}ok{{ else }}warn{{ end }}">
        <span>Claim</span>
        <strong>{{ .EnterpriseClaim.Claim }}</strong>
        <p>{{ .EnterpriseClaim.CurrentMode }} now; {{ .EnterpriseClaim.TargetMode }} target.</p>
      </div>
      <div class="witness-card {{ if .EnterpriseClaim.Missing }}warn{{ else }}ok{{ end }}">
        <span>Owner evidence</span>
        <strong>{{ .EnterpriseClaim.Ready }} ready</strong>
        <p>{{ .EnterpriseClaim.Attached }} attached, {{ .EnterpriseClaim.Missing }} missing, {{ .EnterpriseClaim.ReviewCount }} review.</p>
      </div>
      <div class="witness-card ok">
        <span>Evidence boundary</span>
        <strong>values withheld</strong>
        <p>No evidence ref, procedure, ticket URL, backend path, request body, env, or secret value is shown.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Enterprise claim evidence flags</summary>
      <div class="flag-cloud" aria-label="Enterprise claim value-free evidence flags">
        <span class="pill info">current mode {{ .EnterpriseClaim.CurrentMode }}</span>
        <span class="pill warn">target mode {{ .EnterpriseClaim.TargetMode }}</span>
        <span class="pill {{ if eq .EnterpriseClaim.Claim "enterprise_candidate" }}ok{{ else }}warn{{ end }}">claim {{ .EnterpriseClaim.Claim }}</span>
        <span class="pill info">{{ .EnterpriseClaim.Required }} required</span>
        <span class="pill ok">{{ .EnterpriseClaim.Ready }} ready</span>
        <span class="pill info">{{ .EnterpriseClaim.Attached }} attached</span>
        <span class="pill {{ if .EnterpriseClaim.Missing }}warn{{ else }}ok{{ end }}">{{ .EnterpriseClaim.Missing }} missing</span>
        <span class="pill info">{{ .EnterpriseClaim.ReviewCount }} review</span>
        <span class="pill info">{{ .EnterpriseClaim.EvidenceSignal }}</span>
        <span class="pill info">gate {{ .EnterpriseClaim.EvidenceGate }}</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">procedure_returned=false</span>
        <span class="pill ok">ticket_url_returned=false</span>
        <span class="pill ok">backend_path_returned=false</span>
        <span class="pill ok">request_body_returned=false</span>
        <span class="pill ok">env_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <p><span class="pill info">review cadence</span> {{ .EnterpriseClaim.ReviewCadence }}</p>
    <div class="mode-grid" aria-label="Enterprise claim owner review">
      {{ range .EnterpriseClaim.Owners }}
      <div class="mode-item {{ if .Missing }}warn{{ else }}ok{{ end }}">
        <span>owner {{ .Role }}</span>
        <strong>{{ .Ready }} ready</strong>
        <p><span class="pill info">{{ .Required }} required</span> <span class="pill info">{{ .Attached }} attached</span> <span class="pill {{ if .Missing }}warn{{ else }}ok{{ end }}">{{ .Missing }} missing</span> <span class="pill info">{{ .ReviewCount }} review</span></p>
      </div>
      {{ end }}
    </div>
    <div class="mode-grid" aria-label="Enterprise claim checklist">
      {{ range .EnterpriseClaim.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">owner {{ .OwnerRole }}</span> <span class="pill {{ if .Required }}warn{{ else }}info{{ end }}">required={{ .Required }}</span></p>
        <p><span class="pill {{ if eq .Attachment "missing" }}warn{{ else if eq .Attachment "attached_presence_only" }}ok{{ else }}info{{ end }}">{{ .Attachment }}</span> <span class="pill info">{{ .EvidenceSignal }}</span> <span class="pill ok">evidence ref not returned</span></p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="external-evidence">
  <div class="panel-head">
    <h2>External evidence workflow</h2>
    <span class="pill {{ if eq .ExternalEvidence.Status "candidate" }}ok{{ else if eq .ExternalEvidence.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .ExternalEvidence.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .ExternalEvidence.Summary }}</p>
    <p><span class="pill info">Evidence intake witness</span> presence only, evidence values private</p>
    <div class="witness-grid" aria-label="External evidence intake witness">
      <div class="witness-card {{ if eq .ExternalEvidence.Status "candidate" }}ok{{ else if eq .ExternalEvidence.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Intake status</span>
        <strong>{{ .ExternalEvidence.Status }}</strong>
        <p>{{ .ExternalEvidence.Required }} controls tracked for enterprise evidence.</p>
      </div>
      <div class="witness-card {{ if .ExternalEvidence.Missing }}warn{{ else }}ok{{ end }}">
        <span>Presence records</span>
        <strong>{{ .ExternalEvidence.Attached }} attached</strong>
        <p>{{ .ExternalEvidence.Missing }} missing, {{ .ExternalEvidence.ReviewCount }} review.</p>
      </div>
      <div class="witness-card ok">
        <span>Evidence boundary</span>
        <strong>values withheld</strong>
        <p>No files, URLs, refs, notes, or evidence values are stored or shown.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>External evidence intake flags</summary>
      <div class="flag-cloud" aria-label="External evidence value-free intake flags">
        <span class="pill info">{{ .ExternalEvidence.Attached }} attached</span>
        <span class="pill {{ if .ExternalEvidence.Missing }}warn{{ else }}ok{{ end }}">{{ .ExternalEvidence.Missing }} missing</span>
        <span class="pill info">{{ .ExternalEvidence.ReviewCount }} review</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Presence-only external evidence workflow">
      {{ range .ExternalEvidence.Items }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .Attachment }}</strong>
        <p>{{ .Next }}</p>
        <p><span class="pill info">owner {{ .OwnerRole }}</span> <span class="pill info">{{ .EvidenceSignal }}</span> <span class="pill ok">no refs stored</span></p>
        {{ if eq .Attachment "attached_presence_only" }}
        <p><span class="pill ok">presence recorded</span> <span class="pill ok">evidence stays external</span></p>
        {{ else if .CanAttach }}
        <form method="post" action="/ui/evidence/attachments">
          <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
          <input type="hidden" name="control_key" value="{{ .Key }}">
          <input type="hidden" name="attestation" value="external_evidence_exists">
          <button class="button quiet" type="submit">Mark present</button>
        </form>
        {{ else }}
        <p><span class="pill warn">{{ .OwnerRole }} role required</span></p>
        {{ end }}
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="enterprise-validation">
  <div class="panel-head">
    <h2>Enterprise validation</h2>
    <span class="pill {{ if eq .Enterprise.Status "candidate" }}ok{{ else if eq .Enterprise.Status "not_claimed" }}info{{ else }}warn{{ end }}">{{ .Enterprise.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .Enterprise.Summary }}</p>
    <p><span class="pill info">Enterprise validation witness</span> control state visible, evidence values private</p>
    <div class="witness-grid" aria-label="Enterprise validation witness">
      <div class="witness-card {{ if eq .Enterprise.Status "candidate" }}ok{{ else if eq .Enterprise.Status "not_claimed" }}info{{ else }}warn{{ end }}">
        <span>Validation status</span>
        <strong>{{ .Enterprise.Status }}</strong>
        <p>{{ .Enterprise.Mode }} mode is explicit.</p>
      </div>
      <div class="witness-card {{ if .Enterprise.MissingCount }}warn{{ else }}ok{{ end }}">
        <span>Control gaps</span>
        <strong>{{ .Enterprise.MissingCount }}</strong>
        <p>{{ len .Enterprise.Controls }} controls tracked for review.</p>
      </div>
      <div class="witness-card ok">
        <span>Evidence boundary</span>
        <strong>values withheld</strong>
        <p>Only presence and state are shown; evidence refs and secret values stay outside Janus.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Enterprise validation evidence flags</summary>
      <div class="flag-cloud" aria-label="Enterprise validation value-free evidence flags">
        <span class="pill ok">value_returned=false</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill info">presence only</span>
        <span class="pill info">self-hosted safe</span>
        <span class="pill warn">enterprise required</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Enterprise validation controls">
      {{ range .Enterprise.Controls }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">owner {{ .OwnerRole }}</span> <span class="pill {{ if eq .Attachment "missing" }}warn{{ else if eq .Attachment "attached_presence_only" }}ok{{ else }}info{{ end }}">{{ .Attachment }}</span></p>
        <p><span class="pill info">{{ .EvidenceSignal }}</span> <span class="pill ok">evidence ref not returned</span></p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
	</div>
</section>
<section class="panel" style="margin-bottom:16px" id="attachment-review">
  <div class="panel-head">
    <h2>Attachment review</h2>
    <span class="pill {{ if eq .AttachmentReview.Status "candidate" }}ok{{ else if eq .AttachmentReview.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .AttachmentReview.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .AttachmentReview.Summary }}</p>
    <p><span class="pill info">Attachment review witness</span> owner readiness visible, evidence values private</p>
    <div class="witness-grid" aria-label="Enterprise attachment review witness">
      <div class="witness-card {{ if eq .AttachmentReview.Status "candidate" }}ok{{ else if eq .AttachmentReview.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Review status</span>
        <strong>{{ .AttachmentReview.Status }}</strong>
        <p>{{ .AttachmentReview.ReviewCount }} owner review items.</p>
      </div>
      <div class="witness-card {{ if .AttachmentReview.Missing }}warn{{ else }}ok{{ end }}">
        <span>Attachments</span>
        <strong>{{ .AttachmentReview.Attached }} attached</strong>
        <p>{{ .AttachmentReview.ReviewCount }} review items, {{ .AttachmentReview.Missing }} missing before enterprise promotion.</p>
      </div>
      <div class="witness-card ok">
        <span>Evidence boundary</span>
        <strong>values withheld</strong>
        <p>Owner review shows presence only; evidence refs and values stay external.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Attachment review evidence flags</summary>
      <div class="flag-cloud" aria-label="Attachment review value-free evidence flags">
        <span class="pill {{ if .AttachmentReview.Required }}warn{{ else }}info{{ end }}">{{ .AttachmentReview.Required }} required</span>
        <span class="pill {{ if .AttachmentReview.Attached }}ok{{ else }}info{{ end }}">{{ .AttachmentReview.Attached }} attached</span>
        <span class="pill {{ if .AttachmentReview.Missing }}warn{{ else }}ok{{ end }}">{{ .AttachmentReview.Missing }} missing</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Enterprise attachment owner review">
      {{ range .AttachmentReview.Owners }}
      <div class="mode-item {{ if .Missing }}warn{{ else if .Attached }}ok{{ else }}info{{ end }}">
        <span>owner {{ .Role }}</span>
        <strong>{{ .Attached }} / {{ len .Controls }} attached</strong>
        <p><span class="pill {{ if .Required }}warn{{ else }}info{{ end }}">{{ .Required }} required</span> <span class="pill {{ if .Missing }}warn{{ else }}ok{{ end }}">{{ .Missing }} missing</span> <span class="pill info">{{ .ReviewCount }} review</span></p>
        {{ range .Controls }}
        <p><strong>{{ .Label }}</strong> <span class="pill {{ if eq .Attachment "missing" }}warn{{ else if eq .Attachment "attached_presence_only" }}ok{{ else }}info{{ end }}">{{ .Attachment }}</span> <span class="pill info">{{ .State }}</span></p>
        <p><span class="pill info">{{ .EvidenceSignal }}</span> <span class="pill ok">evidence ref not returned</span></p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
        {{ end }}
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="break-glass-review-workflow">
  <div class="panel-head">
    <h2>Break-glass review workflow</h2>
    <span class="pill {{ if eq .BreakGlassWorkflow.Status "attached" }}ok{{ else if eq .BreakGlassWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .BreakGlassWorkflow.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .BreakGlassWorkflow.Summary }}</p>
    <div class="witness-grid" aria-label="Break-glass review workflow witness">
      <div class="witness-card {{ if eq .BreakGlassWorkflow.Status "attached" }}ok{{ else if eq .BreakGlassWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Workflow state</span>
        <strong>{{ .BreakGlassWorkflow.Status }}</strong>
        <p>Owner: {{ .BreakGlassWorkflow.OwnerRole }}. Review cadence: {{ .BreakGlassWorkflow.ReviewCadence }}.</p>
      </div>
      <div class="witness-card {{ if .BreakGlassWorkflow.Attached }}ok{{ else if .BreakGlassWorkflow.Missing }}warn{{ else }}info{{ end }}">
        <span>Evidence handoff</span>
        <strong>{{ .BreakGlassWorkflow.Attachment }}</strong>
        <p>{{ if .BreakGlassWorkflow.Attached }}Presence recorded; emergency evidence stays external.{{ else if .BreakGlassWorkflow.CanAttach }}Ready for presence-only attachment after external review.{{ else }}Role-gated until the owner can attest external evidence.{{ end }}</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Procedures, contacts, targets, credentials, and evidence refs are not returned.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Break-glass review evidence flags</summary>
      <div class="flag-cloud" aria-label="Break-glass review value-free evidence flags">
        <span class="pill info">owner {{ .BreakGlassWorkflow.OwnerRole }}</span>
        <span class="pill {{ if .BreakGlassWorkflow.Required }}warn{{ else }}info{{ end }}">required={{ .BreakGlassWorkflow.Required }}</span>
        <span class="pill {{ if .BreakGlassWorkflow.Attached }}ok{{ else if .BreakGlassWorkflow.Missing }}warn{{ else }}info{{ end }}">{{ .BreakGlassWorkflow.Attachment }}</span>
        <span class="pill info">{{ .BreakGlassWorkflow.EvidenceSignal }}</span>
        <span class="pill info">review cadence</span>
        <span class="pill info">{{ .BreakGlassWorkflow.ReviewCadence }}</span>
        <span class="pill ok">procedure_returned=false</span>
        <span class="pill ok">contact_path_returned=false</span>
        <span class="pill ok">access_target_returned=false</span>
        <span class="pill ok">credential_returned=false</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    {{ if .BreakGlassWorkflow.Attached }}
    <p><span class="pill ok">presence recorded</span> <span class="pill ok">emergency evidence stays external</span> {{ .BreakGlassWorkflow.Next }}</p>
    {{ else if .BreakGlassWorkflow.CanAttach }}
    <form method="post" action="/ui/evidence/attachments">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <input type="hidden" name="control_key" value="{{ .BreakGlassWorkflow.ControlKey }}">
      <input type="hidden" name="attestation" value="external_evidence_exists">
      <button class="button quiet" type="submit">Mark break-glass review present</button>
    </form>
    <p>{{ .BreakGlassWorkflow.Next }}</p>
    {{ else }}
    <p><span class="pill warn">{{ .BreakGlassWorkflow.OwnerRole }} role required</span> {{ .BreakGlassWorkflow.Next }}</p>
    {{ end }}
    <div class="mode-grid" aria-label="Break-glass review workflow checks">
      {{ range .BreakGlassWorkflow.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="remote-audit-workflow">
  <div class="panel-head">
    <h2>Remote audit workflow</h2>
    <span class="pill {{ if eq .RemoteAuditWorkflow.Status "attached" }}ok{{ else if eq .RemoteAuditWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .RemoteAuditWorkflow.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .RemoteAuditWorkflow.Summary }}</p>
    <div class="witness-grid" aria-label="Remote audit workflow witness">
      <div class="witness-card {{ if eq .RemoteAuditWorkflow.Status "attached" }}ok{{ else if eq .RemoteAuditWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Workflow state</span>
        <strong>{{ .RemoteAuditWorkflow.Status }}</strong>
        <p>Owner: {{ .RemoteAuditWorkflow.OwnerRole }}. Review cadence: {{ .RemoteAuditWorkflow.ReviewCadence }}.</p>
      </div>
      <div class="witness-card {{ if .RemoteAuditWorkflow.Attached }}ok{{ else if .RemoteAuditWorkflow.Missing }}warn{{ else }}info{{ end }}">
        <span>Evidence handoff</span>
        <strong>{{ .RemoteAuditWorkflow.Attachment }}</strong>
        <p>{{ if .RemoteAuditWorkflow.Attached }}Presence recorded; audit shipping evidence stays external.{{ else if .RemoteAuditWorkflow.CanAttach }}Ready for presence-only attachment after external review.{{ else }}Role-gated until the owner can attest external evidence.{{ end }}</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Endpoints, payloads, audit tokens, and evidence refs are not returned.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Remote audit evidence flags</summary>
      <div class="flag-cloud" aria-label="Remote audit value-free evidence flags">
        <span class="pill info">owner {{ .RemoteAuditWorkflow.OwnerRole }}</span>
        <span class="pill {{ if .RemoteAuditWorkflow.Required }}warn{{ else }}info{{ end }}">required={{ .RemoteAuditWorkflow.Required }}</span>
        <span class="pill {{ if .RemoteAuditWorkflow.Attached }}ok{{ else if .RemoteAuditWorkflow.Missing }}warn{{ else }}info{{ end }}">{{ .RemoteAuditWorkflow.Attachment }}</span>
        <span class="pill info">{{ .RemoteAuditWorkflow.EvidenceSignal }}</span>
        <span class="pill info">review cadence</span>
        <span class="pill info">{{ .RemoteAuditWorkflow.ReviewCadence }}</span>
        <span class="pill ok">endpoint_returned=false</span>
        <span class="pill ok">payload_returned=false</span>
        <span class="pill ok">audit_token_returned=false</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    {{ if .RemoteAuditWorkflow.Attached }}
    <p><span class="pill ok">presence recorded</span> <span class="pill ok">audit shipping evidence stays external</span> {{ .RemoteAuditWorkflow.Next }}</p>
    {{ else if .RemoteAuditWorkflow.CanAttach }}
    <form method="post" action="/ui/evidence/attachments">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <input type="hidden" name="control_key" value="{{ .RemoteAuditWorkflow.ControlKey }}">
      <input type="hidden" name="attestation" value="external_evidence_exists">
      <button class="button quiet" type="submit">Mark remote audit present</button>
    </form>
    <p>{{ .RemoteAuditWorkflow.Next }}</p>
    {{ else }}
    <p><span class="pill warn">{{ .RemoteAuditWorkflow.OwnerRole }} role required</span> {{ .RemoteAuditWorkflow.Next }}</p>
    {{ end }}
    <div class="mode-grid" aria-label="Remote audit workflow checks">
      {{ range .RemoteAuditWorkflow.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="integration-conformance-workflow">
  <div class="panel-head">
    <h2>Integration conformance workflow</h2>
    <span class="pill {{ if eq .IntegrationWorkflow.Status "attached" }}ok{{ else if eq .IntegrationWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .IntegrationWorkflow.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .IntegrationWorkflow.Summary }}</p>
    <div class="witness-grid" aria-label="Integration conformance workflow witness">
      <div class="witness-card {{ if eq .IntegrationWorkflow.Status "attached" }}ok{{ else if eq .IntegrationWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Workflow state</span>
        <strong>{{ .IntegrationWorkflow.Status }}</strong>
        <p>Owner: {{ .IntegrationWorkflow.OwnerRole }}. Review cadence: {{ .IntegrationWorkflow.ReviewCadence }}.</p>
      </div>
      <div class="witness-card {{ if .IntegrationWorkflow.Attached }}ok{{ else if .IntegrationWorkflow.Missing }}warn{{ else }}info{{ end }}">
        <span>Evidence handoff</span>
        <strong>{{ .IntegrationWorkflow.Attachment }}</strong>
        <p>{{ if .IntegrationWorkflow.Attached }}Presence recorded; connector evidence stays external.{{ else if .IntegrationWorkflow.CanAttach }}Ready for presence-only attachment after external review.{{ else }}Role-gated until the owner can attest external evidence.{{ end }}</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Connector config, endpoints, payloads, and evidence refs are not returned.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Integration conformance evidence flags</summary>
      <div class="flag-cloud" aria-label="Integration conformance value-free evidence flags">
        <span class="pill info">owner {{ .IntegrationWorkflow.OwnerRole }}</span>
        <span class="pill {{ if .IntegrationWorkflow.Required }}warn{{ else }}info{{ end }}">required={{ .IntegrationWorkflow.Required }}</span>
        <span class="pill {{ if .IntegrationWorkflow.Attached }}ok{{ else if .IntegrationWorkflow.Missing }}warn{{ else }}info{{ end }}">{{ .IntegrationWorkflow.Attachment }}</span>
        <span class="pill info">{{ .IntegrationWorkflow.EvidenceSignal }}</span>
        <span class="pill info">review cadence</span>
        <span class="pill info">{{ .IntegrationWorkflow.ReviewCadence }}</span>
        <span class="pill ok">connector_config_returned=false</span>
        <span class="pill ok">endpoint_returned=false</span>
        <span class="pill ok">payload_returned=false</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    {{ if .IntegrationWorkflow.Attached }}
    <p><span class="pill ok">presence recorded</span> <span class="pill ok">connector evidence stays external</span> {{ .IntegrationWorkflow.Next }}</p>
    {{ else if .IntegrationWorkflow.CanAttach }}
    <form method="post" action="/ui/evidence/attachments">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <input type="hidden" name="control_key" value="{{ .IntegrationWorkflow.ControlKey }}">
      <input type="hidden" name="attestation" value="external_evidence_exists">
      <button class="button quiet" type="submit">Mark integration conformance present</button>
    </form>
    <p>{{ .IntegrationWorkflow.Next }}</p>
    {{ else }}
    <p><span class="pill warn">{{ .IntegrationWorkflow.OwnerRole }} role required</span> {{ .IntegrationWorkflow.Next }}</p>
    {{ end }}
    <div class="mode-grid" aria-label="Integration conformance workflow checks">
      {{ range .IntegrationWorkflow.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="restore-drill-workflow">
  <div class="panel-head">
    <h2>Restore drill workflow</h2>
    <span class="pill {{ if eq .RestoreWorkflow.Status "attached" }}ok{{ else if eq .RestoreWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .RestoreWorkflow.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .RestoreWorkflow.Summary }}</p>
    <div class="witness-grid" aria-label="Restore drill workflow witness">
      <div class="witness-card {{ if eq .RestoreWorkflow.Status "attached" }}ok{{ else if eq .RestoreWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Workflow state</span>
        <strong>{{ .RestoreWorkflow.Status }}</strong>
        <p>Owner: {{ .RestoreWorkflow.OwnerRole }}. Review cadence: {{ .RestoreWorkflow.ReviewCadence }}.</p>
      </div>
      <div class="witness-card {{ if .RestoreWorkflow.Attached }}ok{{ else if .RestoreWorkflow.Missing }}warn{{ else }}info{{ end }}">
        <span>Evidence handoff</span>
        <strong>{{ .RestoreWorkflow.Attachment }}</strong>
        <p>{{ if .RestoreWorkflow.Attached }}Presence recorded; recovery evidence stays external.{{ else if .RestoreWorkflow.CanAttach }}Ready for presence-only attachment after external review.{{ else }}Role-gated until the owner can attest external evidence.{{ end }}</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Restore evidence refs and recovery material are not returned.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Restore drill evidence flags</summary>
      <div class="flag-cloud" aria-label="Restore drill value-free evidence flags">
        <span class="pill info">owner {{ .RestoreWorkflow.OwnerRole }}</span>
        <span class="pill {{ if .RestoreWorkflow.Required }}warn{{ else }}info{{ end }}">required={{ .RestoreWorkflow.Required }}</span>
        <span class="pill {{ if .RestoreWorkflow.Attached }}ok{{ else if .RestoreWorkflow.Missing }}warn{{ else }}info{{ end }}">{{ .RestoreWorkflow.Attachment }}</span>
        <span class="pill info">{{ .RestoreWorkflow.EvidenceSignal }}</span>
        <span class="pill info">review cadence</span>
        <span class="pill info">{{ .RestoreWorkflow.ReviewCadence }}</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    {{ if .RestoreWorkflow.Attached }}
    <p><span class="pill ok">presence recorded</span> <span class="pill ok">recovery evidence stays external</span> {{ .RestoreWorkflow.Next }}</p>
    {{ else if .RestoreWorkflow.CanAttach }}
    <form method="post" action="/ui/evidence/attachments">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <input type="hidden" name="control_key" value="{{ .RestoreWorkflow.ControlKey }}">
      <input type="hidden" name="attestation" value="external_evidence_exists">
      <button class="button quiet" type="submit">Mark restore drill present</button>
    </form>
    <p>{{ .RestoreWorkflow.Next }}</p>
    {{ else }}
    <p><span class="pill warn">{{ .RestoreWorkflow.OwnerRole }} role required</span> {{ .RestoreWorkflow.Next }}</p>
    {{ end }}
    <div class="mode-grid" aria-label="Restore drill workflow recovery checks">
      {{ range .RestoreWorkflow.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="release-provenance-workflow">
  <div class="panel-head">
    <h2>Release provenance workflow</h2>
    <span class="pill {{ if eq .ReleaseWorkflow.Status "attached" }}ok{{ else if eq .ReleaseWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .ReleaseWorkflow.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .ReleaseWorkflow.Summary }}</p>
    <div class="witness-grid" aria-label="Release provenance workflow witness">
      <div class="witness-card {{ if eq .ReleaseWorkflow.Status "attached" }}ok{{ else if eq .ReleaseWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Workflow state</span>
        <strong>{{ .ReleaseWorkflow.Status }}</strong>
        <p>Owner: {{ .ReleaseWorkflow.OwnerRole }}. Review cadence: {{ .ReleaseWorkflow.ReviewCadence }}.</p>
      </div>
      <div class="witness-card {{ if .ReleaseWorkflow.Attached }}ok{{ else if .ReleaseWorkflow.Missing }}warn{{ else }}info{{ end }}">
        <span>Evidence handoff</span>
        <strong>{{ .ReleaseWorkflow.Attachment }}</strong>
        <p>{{ if .ReleaseWorkflow.Attached }}Presence recorded; release evidence stays external.{{ else if .ReleaseWorkflow.CanAttach }}Ready for presence-only attachment after external review.{{ else }}Role-gated until the owner can attest external evidence.{{ end }}</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Build artifacts, release material, and evidence refs are not returned.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Release provenance evidence flags</summary>
      <div class="flag-cloud" aria-label="Release provenance value-free evidence flags">
        <span class="pill info">owner {{ .ReleaseWorkflow.OwnerRole }}</span>
        <span class="pill {{ if .ReleaseWorkflow.Required }}warn{{ else }}info{{ end }}">required={{ .ReleaseWorkflow.Required }}</span>
        <span class="pill {{ if .ReleaseWorkflow.Attached }}ok{{ else if .ReleaseWorkflow.Missing }}warn{{ else }}info{{ end }}">{{ .ReleaseWorkflow.Attachment }}</span>
        <span class="pill info">{{ .ReleaseWorkflow.EvidenceSignal }}</span>
        <span class="pill info">review cadence</span>
        <span class="pill info">{{ .ReleaseWorkflow.ReviewCadence }}</span>
        <span class="pill ok">artifact_returned=false</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    {{ if .ReleaseWorkflow.Attached }}
    <p><span class="pill ok">presence recorded</span> <span class="pill ok">release evidence stays external</span> {{ .ReleaseWorkflow.Next }}</p>
    {{ else if .ReleaseWorkflow.CanAttach }}
    <form method="post" action="/ui/evidence/attachments">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <input type="hidden" name="control_key" value="{{ .ReleaseWorkflow.ControlKey }}">
      <input type="hidden" name="attestation" value="external_evidence_exists">
      <button class="button quiet" type="submit">Mark release provenance present</button>
    </form>
    <p>{{ .ReleaseWorkflow.Next }}</p>
    {{ else }}
    <p><span class="pill warn">{{ .ReleaseWorkflow.OwnerRole }} role required</span> {{ .ReleaseWorkflow.Next }}</p>
    {{ end }}
    <div class="mode-grid" aria-label="Release provenance workflow checks">
      {{ range .ReleaseWorkflow.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="privacy-retention-workflow">
  <div class="panel-head">
    <h2>Privacy and retention workflow</h2>
    <span class="pill {{ if eq .PrivacyWorkflow.Status "attached" }}ok{{ else if eq .PrivacyWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .PrivacyWorkflow.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .PrivacyWorkflow.Summary }}</p>
    <div class="witness-grid" aria-label="Privacy and retention workflow witness">
      <div class="witness-card {{ if eq .PrivacyWorkflow.Status "attached" }}ok{{ else if eq .PrivacyWorkflow.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Workflow state</span>
        <strong>{{ .PrivacyWorkflow.Status }}</strong>
        <p>Owner: {{ .PrivacyWorkflow.OwnerRole }}. Review cadence: {{ .PrivacyWorkflow.ReviewCadence }}.</p>
      </div>
      <div class="witness-card {{ if .PrivacyWorkflow.Attached }}ok{{ else if .PrivacyWorkflow.Missing }}warn{{ else }}info{{ end }}">
        <span>Evidence handoff</span>
        <strong>{{ .PrivacyWorkflow.Attachment }}</strong>
        <p>{{ if .PrivacyWorkflow.Attached }}Presence recorded; policy evidence stays external.{{ else if .PrivacyWorkflow.CanAttach }}Ready for presence-only attachment after external review.{{ else }}Role-gated until the owner can attest external evidence.{{ end }}</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Policy docs, raw metadata, evidence refs, and secret values are not returned.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Privacy and retention evidence flags</summary>
      <div class="flag-cloud" aria-label="Privacy and retention value-free evidence flags">
	        <span class="pill info">owner {{ .PrivacyWorkflow.OwnerRole }}</span>
	        <span class="pill info">control_key={{ .PrivacyWorkflow.ControlKey }}</span>
	        <span class="pill {{ if .PrivacyWorkflow.Required }}warn{{ else }}info{{ end }}">required={{ .PrivacyWorkflow.Required }}</span>
        <span class="pill {{ if .PrivacyWorkflow.Attached }}ok{{ else if .PrivacyWorkflow.Missing }}warn{{ else }}info{{ end }}">{{ .PrivacyWorkflow.Attachment }}</span>
        <span class="pill info">{{ .PrivacyWorkflow.EvidenceSignal }}</span>
        <span class="pill info">review cadence</span>
        <span class="pill info">{{ .PrivacyWorkflow.ReviewCadence }}</span>
        <span class="pill ok">policy_doc_returned=false</span>
        <span class="pill ok">raw_metadata_returned=false</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    {{ if .PrivacyWorkflow.Attached }}
    <p><span class="pill ok">presence recorded</span> <span class="pill ok">policy evidence stays external</span> {{ .PrivacyWorkflow.Next }}</p>
    {{ else if .PrivacyWorkflow.CanAttach }}
    <form method="post" action="/ui/evidence/attachments">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <input type="hidden" name="control_key" value="{{ .PrivacyWorkflow.ControlKey }}">
      <input type="hidden" name="attestation" value="external_evidence_exists">
      <button class="button quiet" type="submit">Mark privacy policy present</button>
    </form>
    <p>{{ .PrivacyWorkflow.Next }}</p>
    {{ else }}
    <p><span class="pill warn">{{ .PrivacyWorkflow.OwnerRole }} role required</span> {{ .PrivacyWorkflow.Next }}</p>
    {{ end }}
    <div class="mode-grid" aria-label="Privacy and retention workflow checks">
      {{ range .PrivacyWorkflow.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="restore-drill-proof">
  <div class="panel-head">
    <h2>Restore drill proof</h2>
    <span class="pill {{ if eq .RestoreProof.Status "candidate" }}ok{{ else if eq .RestoreProof.Status "blocked" }}warn{{ else }}info{{ end }}">{{ .RestoreProof.Status }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .RestoreProof.Summary }}</p>
    <div class="witness-grid" aria-label="Restore drill proof witness">
      <div class="witness-card {{ if eq .RestoreProof.Status "candidate" }}ok{{ else if eq .RestoreProof.Status "blocked" }}warn{{ else }}info{{ end }}">
        <span>Recovery claim</span>
        <strong>{{ .RestoreProof.Status }}</strong>
        <p>{{ .RestoreProof.Mode }} recovery proof is evaluated from safe metadata only.</p>
      </div>
      <div class="witness-card {{ if eq .RestoreProof.Attachment "attached_presence_only" }}ok{{ else if eq .RestoreProof.Attachment "missing" }}warn{{ else }}info{{ end }}">
        <span>Drill record</span>
        <strong>{{ .RestoreProof.Attachment }}</strong>
        <p>Janus records whether the external drill exists, not the drill contents.</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Restore evidence refs, raw recovery notes, and secret values are not returned.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Restore drill proof evidence flags</summary>
      <div class="flag-cloud" aria-label="Restore drill proof value-free evidence flags">
        <span class="pill info">{{ .RestoreProof.Mode }}</span>
        <span class="pill {{ if eq .RestoreProof.Attachment "attached_presence_only" }}ok{{ else if eq .RestoreProof.Attachment "missing" }}warn{{ else }}info{{ end }}">{{ .RestoreProof.Attachment }}</span>
        <span class="pill ok">evidence_ref_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <div class="mode-grid" aria-label="Restore drill proof">
      {{ range .RestoreProof.Checks }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Proof }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="privacy-retention">
  <div class="panel-head">
    <h2>Privacy and retention</h2>
    <span class="pill {{ if .Privacy.ReviewCount }}warn{{ else }}ok{{ end }}">{{ if .Privacy.ReviewCount }}{{ .Privacy.ReviewCount }} review{{ else }}clear{{ end }}</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .Privacy.Summary }}</p>
    <p><span class="pill ok">{{ .Privacy.Redaction }}</span> <span class="pill info">{{ .Privacy.Retention }}</span> <span class="pill ok">value_returned=false</span></p>
    <div class="mode-grid" aria-label="Privacy and retention posture">
      {{ range .Privacy.Surfaces }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">{{ .Retention }}</span></p>
      </div>
      {{ end }}
    </div>
    <p><strong>Excluded from evidence</strong><br>{{ range .Privacy.Excluded }}<span class="pill warn">{{ . }}</span> {{ end }}</p>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="evidence-boundary">
  <div class="panel-head">
    <h2>Evidence export</h2>
    <span class="pill {{ if .CanExportEvidence }}ok{{ else }}warn{{ end }}">{{ .EvidenceBoundary.Gate }}</span>
  </div>
  <div class="panel-body stack">
    <p><span class="pill ok">{{ .EvidenceBoundary.RedactionModel }}</span> <span class="pill ok">value_returned=false</span> <span class="pill info">audience {{ .EvidenceBoundary.Audience }}</span></p>
    <div class="witness-grid" aria-label="Evidence export witness">
      <div class="witness-card {{ if .CanExportEvidence }}ok{{ else }}warn{{ end }}">
        <span>Audit proof</span>
        <strong>{{ if .CanExportEvidence }}ready{{ else }}role gated{{ end }}</strong>
        <p>Export proves posture, controls, recent audit refs, and integrity without carrying secret-bearing payloads.</p>
      </div>
      <div class="witness-card {{ if .EvidenceBoundary.HashAvailable }}ok{{ else }}warn{{ end }}">
        <span>Download gate</span>
        <strong>{{ if .CanExportEvidence }}exact receipt{{ else }}auditor only{{ end }}</strong>
        <p>{{ .EvidenceReceipt.Verification }}</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>metadata only</strong>
        <p>Secret values, tokens, cookies, request bodies, env, command output, and backend paths stay out.</p>
      </div>
      <div class="witness-card info">
        <span>Retention posture</span>
        <strong>{{ .Privacy.Retention }}</strong>
        <p>Evidence is useful for review while excluded data remains outside Janus retention and export.</p>
      </div>
    </div>
    {{ if .CanExportEvidence }}
    <div class="receipt" aria-label="Evidence download receipt">
      <div>
        <strong>Exact download receipt</strong>
        <p>The downloaded JSON includes <span class="mono">{{ .EvidenceReceipt.BodyField }}</span>, and the response header <span class="mono">{{ .EvidenceReceipt.HashHeader }}</span> matches it.</p>
      </div>
      <a class="button primary" href="/api/evidence" download="janus-evidence.json">Download JSON</a>
    </div>
    {{ if .EvidenceHashFull }}
    <label class="hash-copy">Current preview
      <input readonly value="{{ .EvidenceHashFull }}" aria-label="Evidence hash preview">
    </label>
    <p><span class="pill info">{{ .EvidenceReceipt.Algorithm }}</span> <span class="pill ok">copy-safe metadata</span> <span class="pill info">exact hash returned on download</span></p>
    {{ end }}
    {{ else }}
    <div class="receipt" aria-label="Evidence download receipt">
      <div>
        <strong>Download restricted</strong>
        <p>Auditor role is required before Janus returns an evidence pack or exact receipt.</p>
      </div>
      <span class="pill warn">auditor required</span>
    </div>
    {{ end }}
    <div class="mode-grid" aria-label="Evidence export boundary">
      <div class="mode-item {{ if .CanExportEvidence }}ok{{ else }}warn{{ end }}">
        <span>Export role</span>
        <strong>{{ .EvidenceBoundary.Audience }}</strong>
        <p>{{ if .CanExportEvidence }}Evidence JSON is available to this session.{{ else }}Evidence JSON is gated from this session.{{ end }}</p>
      </div>
      <div class="mode-item {{ if .EvidenceBoundary.HashAvailable }}ok{{ else }}warn{{ end }}">
        <span>Integrity</span>
        <strong>{{ if .EvidenceBoundary.HashAvailable }}hash ready{{ else }}restricted{{ end }}</strong>
        <p>{{ .EvidenceBoundary.Integrity }}</p>
      </div>
      <div class="mode-item {{ if .CanExportEvidence }}ok{{ else }}warn{{ end }}">
        <span>Receipt</span>
        <strong>{{ .EvidenceReceipt.State }}</strong>
        <p>{{ .EvidenceReceipt.Verification }}</p>
      </div>
      <div class="mode-item ok">
        <span>Boundary</span>
        <strong>metadata only</strong>
        <p>No secret-bearing payloads are exported. Coverage: {{ .EvidenceReceipt.Coverage }}.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Evidence export evidence flags</summary>
      <div class="flag-cloud" aria-label="Included evidence">
        <span class="pill ok">Included evidence</span>
        {{ range .EvidenceBoundary.Includes }}<span class="pill info">{{ . }}</span>{{ end }}
      </div>
      <div class="flag-cloud" aria-label="Never exported evidence">
        <span class="pill ok">Never exported</span>
        {{ range .EvidenceBoundary.Excludes }}<span class="pill warn">{{ . }}</span>{{ end }}
      </div>
    </details>
  </div>
</section>
<section class="panel" style="margin-bottom:16px" id="role-workbench">
  <div class="panel-head">
    <h2>Role workbench</h2>
    <span class="pill info">least privilege</span>
  </div>
  <div class="panel-body stack">
    <p>{{ .RoleWorkbench.Summary }}</p>
    <p><span class="pill ok">value_returned=false</span> <span class="pill ok">hidden controls not rendered</span></p>
    <div class="witness-grid" aria-label="Role workbench witness">
      <div class="witness-card ok">
        <span>Available controls</span>
        <strong>{{ len .RoleWorkbench.Available }} rendered</strong>
        <p>This session only sees controls allowed by its active roles and current readiness.</p>
      </div>
      <div class="witness-card {{ if .RoleWorkbench.Hidden }}warn{{ else }}ok{{ end }}">
        <span>Hidden controls</span>
        <strong>{{ len .RoleWorkbench.Hidden }} hidden</strong>
        <p>Controls outside this role boundary are withheld instead of shown as tempting dead ends.</p>
      </div>
      <div class="witness-card info">
        <span>Least privilege</span>
        <strong>role boundary</strong>
        <p>Viewer, operator, auditor, and admin duties stay separated before any action is offered.</p>
      </div>
      <div class="witness-card ok">
        <span>Value boundary</span>
        <strong>values withheld</strong>
        <p>Role checks use labels and counts; identity, claim, token, cookie, and secret values stay private.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Role workbench evidence flags</summary>
      <div class="flag-cloud" aria-label="Role workbench value-free evidence flags">
        <span class="pill ok">available_controls={{ len .RoleWorkbench.Available }}</span>
        <span class="pill ok">hidden_controls={{ len .RoleWorkbench.Hidden }}</span>
        <span class="pill ok">hidden_controls_not_rendered=true</span>
        <span class="pill ok">role_boundary_enforced=true</span>
        <span class="pill ok">identity_values_returned=false</span>
        <span class="pill ok">claim_values_returned=false</span>
        <span class="pill ok">token_returned=false</span>
        <span class="pill ok">cookie_value_returned=false</span>
        <span class="pill ok">secret_value_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    <p><strong>Rendered now</strong></p>
    <div class="mode-grid" aria-label="Rendered role controls">
      {{ range .RoleWorkbench.Available }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
    {{ if .RoleWorkbench.Hidden }}
    <p><strong>Hidden by role</strong></p>
    <div class="mode-grid" aria-label="Hidden role controls">
      {{ range .RoleWorkbench.Hidden }}
      <div class="mode-item {{ .Tone }}">
        <span>{{ .Label }}</span>
        <strong>{{ .State }}</strong>
        <p>{{ .Detail }}</p>
        <p><span class="pill info">next</span> {{ .Next }}</p>
      </div>
      {{ end }}
    </div>
    {{ end }}
  </div>
</section>
{{ if not .Ready }}
<section class="panel security-state" style="margin-bottom:16px" id="security-state">
  <div class="panel-head"><h2>Security state</h2><span class="pill warn">restricted</span></div>
  <div class="panel-body stack">
    <p>Sensitive actions are blocked until readiness checks recover.</p>
    <p><span class="pill warn">ready=false</span> <span class="pill ok">value_returned=false</span></p>
  </div>
</section>
{{ end }}
{{ if .Issues }}
<section class="panel" style="margin-bottom:16px" id="gates">
  <div class="panel-head"><h2>Readiness gates</h2><span class="pill warn">action needed</span></div>
  <div class="panel-body stack">
    {{ range .Issues }}<p class="warn">{{ . }}</p>{{ end }}
  </div>
</section>
{{ end }}
{{ if .ActionResult }}
<section class="panel" style="margin-bottom:16px" id="result">
  <div class="panel-head">
    <h2>{{ .ActionResult.Title }}</h2>
    {{ if eq .ActionResult.Outcome "allowed" }}<span class="pill ok">allowed</span>{{ else }}<span class="pill warn">denied</span>{{ end }}
  </div>
  <div class="panel-body stack">
    <p>{{ .ActionResult.Message }}</p>
    {{ if .ActionResult.RunReason }}<p class="warn">{{ .ActionResult.RunReason }}</p>{{ end }}
    {{ if .ActionResult.RequestID }}<p class="mono">request_id={{ .ActionResult.RequestID }}</p>{{ end }}
    {{ if .ActionResult.Receipt }}
    <div class="receipt" aria-label="Action receipt">
      <div>
        <strong>Action receipt</strong>
        <p><span class="mono">request_id={{ .ActionResult.Receipt.RequestID }}</span></p>
      </div>
      <span class="pill {{ if eq .ActionResult.Receipt.Outcome "allowed" }}ok{{ else }}info{{ end }}">{{ .ActionResult.Receipt.Outcome }}</span>
    </div>
    <div class="verdict" aria-label="Action receipt checks">
      <span><strong>Role</strong>{{ if .ActionResult.Receipt.RoleChecked }} checked{{ else }} pending{{ end }}</span>
      <span><strong>CSRF</strong>{{ if .ActionResult.Receipt.CSRFChecked }} checked{{ else }} pending{{ end }}</span>
      <span><strong>Readiness</strong>{{ if .ActionResult.Receipt.ReadinessChecked }} checked{{ else }} pending{{ end }}</span>
      <span><strong>Audit</strong>{{ if .ActionResult.Receipt.AuditRecorded }} recorded{{ else }} pending{{ end }}</span>
    </div>
    <div class="receipt-proof" aria-label="Action receipt proof">
      <span><strong>Proof</strong>{{ if .ActionResult.Receipt.TamperEvident }}hash locked{{ else }}pending{{ end }}</span>
      <span><strong>ID</strong><span class="mono">{{ .ActionResult.Receipt.ReceiptID }}</span></span>
      <span><strong>Hash</strong><span class="mono">{{ .ActionResult.Receipt.ReceiptHash }}</span></span>
    </div>
    <div class="receipt-copy" aria-label="Copy-safe action receipt fields">
      <label>Receipt id
        <input readonly value="{{ .ActionResult.Receipt.ReceiptID }}" aria-label="Receipt id">
      </label>
      <label>Receipt hash
        <input readonly value="{{ .ActionResult.Receipt.ReceiptHash }}" aria-label="Receipt hash">
      </label>
      <label>Request id
        <input readonly value="{{ .ActionResult.Receipt.RequestID }}" aria-label="Receipt request id">
      </label>
    </div>
    <div class="receipt" aria-label="Action receipt verification">
      <div>
        <strong>Verify receipt</strong>
        <p>{{ .ActionResult.Receipt.Verification }}</p>
      </div>
      <span class="pill ok">copy-safe</span>
    </div>
    <p><strong>Covered checks</strong><br><span class="pill ok">role_checked={{ .ActionResult.Receipt.RoleChecked }}</span> <span class="pill ok">csrf_checked={{ .ActionResult.Receipt.CSRFChecked }}</span> <span class="pill ok">readiness_checked={{ .ActionResult.Receipt.ReadinessChecked }}</span> <span class="pill ok">audit_recorded={{ .ActionResult.Receipt.AuditRecorded }}</span></p>
    <p><span class="pill ok">{{ .ActionResult.Receipt.Boundary }}</span> <span class="pill ok">secret_value_returned=false</span> <span class="pill ok">request_body_returned=false</span></p>
    <p><span class="pill ok">tamper_evident=true</span> <span class="pill info">{{ .ActionResult.Receipt.Algorithm }}</span> <span class="pill info">{{ .ActionResult.Receipt.Schema }}</span></p>
    <p><span class="pill info">covers</span> {{ .ActionResult.Receipt.Coverage }}</p>
    <p><span class="pill info">next</span> {{ .ActionResult.Receipt.Next }}</p>
    {{ end }}
    {{ if .ActionResult.PermitID }}
    {{ if .ActionResult.OutputScrubbed }}
    <div class="witness-grid" aria-label="Permit safety check result witness">
      <div class="witness-card ok">
        <span>Execution verdict</span>
        <strong>{{ .ActionResult.Status }}</strong>
        <p>The safety check returns a closed result instead of executing a connector.</p>
      </div>
      <div class="witness-card ok">
        <span>Scrubbed output</span>
        <strong>confirmed</strong>
        <p>No command output, connector response, payload, or secret value is returned.</p>
      </div>
      <div class="witness-card info">
        <span>Run denial reason</span>
        <strong>closed</strong>
        <p>{{ .ActionResult.RunReason }}</p>
      </div>
      <div class="witness-card ok">
        <span>Permit context</span>
        <strong>short lived</strong>
        <p>Permit <span class="mono">{{ .ActionResult.PermitID }}</span> stays metadata-only until it expires at {{ .ActionResult.ExpiresAt }}.</p>
      </div>
    </div>
    <details class="evidence-flags">
      <summary>Permit safety check evidence flags</summary>
      <div class="flag-cloud" aria-label="Permit safety check value-free evidence flags">
        <span class="pill ok">run_status={{ .ActionResult.Status }}</span>
        <span class="pill ok">run_reason_returned=true</span>
        <span class="pill ok">output_scrubbed={{ .ActionResult.OutputScrubbed }}</span>
        <span class="pill ok">connector_execution=false</span>
        <span class="pill ok">connector_output_returned=false</span>
        <span class="pill ok">permit_payload_returned=false</span>
        <span class="pill ok">secret_value_returned=false</span>
        <span class="pill ok">backend_path_returned=false</span>
        <span class="pill ok">source_path_returned=false</span>
        <span class="pill ok">request_body_returned=false</span>
        <span class="pill ok">env_returned=false</span>
        <span class="pill ok">value_returned=false</span>
      </div>
    </details>
    {{ end }}
    <div class="verdict" aria-label="Permit safety verdict">
      <span><strong>Metadata only</strong> secret value withheld</span>
      <span><strong>No connector</strong> execution unavailable</span>
      <span><strong>Scrubbed output</strong>{{ if .ActionResult.OutputScrubbed }} confirmed{{ else }} pending check{{ end }}</span>
      <span><strong>Audited</strong> value_returned=false</span>
    </div>
    {{ end }}
    {{ if .ActionResult.ControlKey }}
    <div class="facts">
      <div class="fact"><strong>{{ .ActionResult.ControlKey }}</strong><span class="muted">control key</span></div>
      <div class="fact"><strong>{{ .ActionResult.EvidenceState }}</strong><span class="muted">evidence state</span></div>
      <div class="fact"><strong>{{ .ActionResult.Status }}</strong><span class="muted">attachment</span></div>
    </div>
    <p><span class="pill ok">presence only</span> <span class="pill ok">evidence_ref_returned=false</span> <span class="pill ok">request_body_returned=false</span></p>
    {{ end }}
    {{ if .ActionResult.HandleID }}
    <div class="facts">
      <div class="fact"><strong class="mono">{{ .ActionResult.HandleID }}</strong><span class="muted">handle id</span></div>
      <div class="fact"><strong>{{ .ActionResult.SecretRef }}</strong><span class="muted">secret ref</span></div>
      <div class="fact"><strong>{{ .ActionResult.ExpiresAt }}</strong><span class="muted">expires</span></div>
    </div>
    {{ end }}
    {{ if .ActionResult.PermitID }}
    <div class="facts">
      <div class="fact"><strong class="mono">{{ .ActionResult.PermitID }}</strong><span class="muted">permit id</span></div>
      <div class="fact"><strong>{{ .ActionResult.Status }}</strong><span class="muted">status</span></div>
      <div class="fact"><strong>{{ .ActionResult.Action }}</strong><span class="muted">action</span></div>
    </div>
    {{ if .ActionResult.OutputScrubbed }}<p><span class="pill ok">output_scrubbed=true</span></p>{{ end }}
    {{ if .CanOperate }}
    <form method="post" action="/ui/permits/{{ .ActionResult.PermitID }}/run">
      <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
      <button class="button quiet" type="submit">Run safety check</button>
    </form>
    {{ else }}
    <p><span class="pill warn">operator role required</span></p>
    {{ end }}
    {{ end }}
    <p><span class="pill ok">value_returned=false</span></p>
  </div>
</section>
{{ end }}
{{ if .Focus.Descriptor.ID }}
<section class="grid" id="focus">
  <div class="panel">
    <div class="panel-head">
      <h2>Descriptor focus</h2>
      {{ if .Focus.Gates }}<span class="pill warn">{{ .Focus.GateCount }} gates</span>{{ else }}<span class="pill ok">clear</span>{{ end }}
    </div>
    <div class="panel-body stack">
      <div class="intro-copy">
        <h2>{{ .Focus.Descriptor.DisplayName }}</h2>
        <p><span class="mono">{{ .Focus.Descriptor.ID }}</span></p>
      </div>
      <div class="facts">
        <div class="fact"><strong>{{ .Focus.Descriptor.Classification }}</strong><span class="muted">classification</span></div>
        <div class="fact"><strong>{{ .Focus.Lifecycle }}</strong><span class="muted">lifecycle</span></div>
        <div class="fact"><strong>{{ .Focus.Descriptor.Owner }}</strong><span class="muted">owner</span></div>
      </div>
      <div class="facts">
        <div class="fact"><strong>{{ .Focus.Descriptor.Scope }}</strong><span class="muted">scope</span></div>
        <div class="fact"><strong>{{ .Focus.Descriptor.Provider }}</strong><span class="muted">provider</span></div>
        <div class="fact"><strong>{{ .Focus.Descriptor.Status }}</strong><span class="muted">provider status</span></div>
      </div>
      <div class="facts">
        <div class="fact"><strong>{{ .Focus.Descriptor.ConsumerCount }}</strong><span class="muted">consumers</span></div>
        <div class="fact"><strong>{{ .Focus.Descriptor.RotationDays }} days</strong><span class="muted">rotation</span></div>
        <div class="fact"><strong>{{ if .Focus.NormalUseBlocked }}blocked{{ else }}allowed{{ end }}</strong><span class="muted">normal use</span></div>
      </div>
      <p>
        <span class="pill ok">value-free metadata</span>
        {{ if .Focus.Descriptor.UseEnabled }}<span class="pill ok">use profiled</span>{{ else }}<span class="pill warn">approved use missing</span>{{ end }}
        {{ if .Focus.LifecycleBlocked }}<span class="pill warn">lifecycle blocked</span>{{ else }}<span class="pill ok">lifecycle allowed</span>{{ end }}
        <span class="pill ok">reveal disabled</span>
        {{ range .Focus.Descriptor.Tags }}<span class="pill info">{{ . }}</span> {{ end }}
      </p>
      {{ if .Focus.NormalUseReason }}<p class="warn">{{ .Focus.NormalUseReason }}</p>{{ end }}
      {{ range .Focus.Gates }}<p class="warn">{{ .Message }}</p>{{ end }}
    </div>
  </div>
</section>
{{ end }}
{{ if .CanOperate }}
<section class="grid" id="warden">
  <div class="panel">
    <div class="panel-head">
      <h2>Request metadata handle</h2>
      <span class="pill ok">value-free</span>
    </div>
    <div class="panel-body stack">
      {{ if .CanOperate }}
      <div class="witness-grid" aria-label="Request handle witness">
        <div class="witness-card ok">
          <span>Intent boundary</span>
          <strong>metadata handle</strong>
          <p>This action creates a short-lived handle for the selected descriptor and never asks for a secret value.</p>
        </div>
        <div class="witness-card ok">
          <span>Role and readiness</span>
          <strong>checked first</strong>
          <p>Operator role, CSRF, and readiness must pass before Janus issues anything.</p>
        </div>
        <div class="witness-card ok">
          <span>No connector</span>
          <strong>no execution</strong>
          <p>The request does not run a connector, call a backend secret path, or return command output.</p>
        </div>
        <div class="witness-card info">
          <span>Metadata receipt</span>
          <strong>audit linked</strong>
          <p>A successful request returns a copy-safe action receipt with request id, receipt id, and receipt hash.</p>
        </div>
      </div>
      <div class="receipt" aria-label="Request metadata handle boundary">
        <div>
          <strong>Before you issue</strong>
          <p>Form sends descriptor id and reason only. Result returns a handle id, descriptor ref, expiry, and receipt proof.</p>
        </div>
        <span class="pill ok">values withheld</span>
      </div>
      <details class="evidence-flags">
        <summary>Request handle evidence flags</summary>
        <div class="flag-cloud" aria-label="Request handle value-free evidence flags">
          <span class="pill ok">will_create=metadata_handle</span>
          <span class="pill ok">operator_role_required=true</span>
          <span class="pill ok">csrf_required=true</span>
          <span class="pill ok">readiness_required=true</span>
          <span class="pill ok">audit_receipt_returned=true</span>
          <span class="pill ok">connector_execution=false</span>
          <span class="pill ok">secret_value_returned=false</span>
          <span class="pill ok">backend_path_returned=false</span>
          <span class="pill ok">source_path_returned=false</span>
          <span class="pill ok">request_body_returned=false</span>
          <span class="pill ok">env_returned=false</span>
          <span class="pill ok">value_returned=false</span>
        </div>
      </details>
      <form class="flow" method="post" action="/ui/warden/resolve">
        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
        <label>Descriptor
          <select name="ref" required>
            {{ range .Descriptors }}<option value="{{ .ID }}" {{ if eq .ID $.SelectedRef }}selected{{ end }}>{{ .DisplayName }}</option>{{ end }}
          </select>
        </label>
        <label>Reason
          <input name="reason" maxlength="160" required placeholder="maintenance, audit, rotation">
        </label>
        <button class="primary" type="submit">Issue metadata handle</button>
      </form>
      {{ else }}
      <div class="stack">
        <p class="warn">Operator role required.</p>
        <p>Viewing posture is allowed, but requesting handles is role-gated.</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
<section class="grid" id="permit">
  <div class="panel">
    <div class="panel-head">
      <h2>Request permit</h2>
      <span class="pill warn">no execution connector</span>
    </div>
    <div class="panel-body stack">
      {{ if .CanOperate }}
      <div class="witness-grid" aria-label="Request permit witness">
        <div class="witness-card ok">
          <span>Permit intent</span>
          <strong>metadata only</strong>
          <p>The permit records approved use for the selected descriptor without opening secret value access.</p>
        </div>
        <div class="witness-card ok">
          <span>No connector</span>
          <strong>run stays closed</strong>
          <p>Permit creation does not execute a connector, call a backend secret path, or return command output.</p>
        </div>
        <div class="witness-card info">
          <span>Reason and destination</span>
          <strong>audit context</strong>
          <p>Reason and destination are short labels for review; they are not used as payloads or instructions.</p>
        </div>
        <div class="witness-card ok">
          <span>Short-lived status</span>
          <strong>10 minutes</strong>
          <p>Permit records expire automatically and return a copy-safe action receipt when created.</p>
        </div>
      </div>
      <div class="receipt" aria-label="Request permit boundary">
        <div>
          <strong>Before you create</strong>
          <p>Form sends descriptor id, approved action, destination label, and reason only. Result returns permit id, descriptor ref, status, expiry, and receipt proof.</p>
        </div>
        <span class="pill ok">values withheld</span>
      </div>
      <details class="evidence-flags">
        <summary>Request permit evidence flags</summary>
        <div class="flag-cloud" aria-label="Request permit value-free evidence flags">
          <span class="pill ok">will_create=metadata_permit</span>
          <span class="pill ok">permit_intent=metadata_only</span>
          <span class="pill ok">operator_role_required=true</span>
          <span class="pill ok">csrf_required=true</span>
          <span class="pill ok">readiness_required=true</span>
          <span class="pill ok">audit_receipt_returned=true</span>
          <span class="pill ok">connector_execution=false</span>
          <span class="pill ok">connector_output_returned=false</span>
          <span class="pill ok">permit_payload_returned=false</span>
          <span class="pill ok">secret_value_returned=false</span>
          <span class="pill ok">backend_path_returned=false</span>
          <span class="pill ok">source_path_returned=false</span>
          <span class="pill ok">request_body_returned=false</span>
          <span class="pill ok">env_returned=false</span>
          <span class="pill ok">value_returned=false</span>
        </div>
      </details>
      <form class="flow" method="post" action="/ui/permits">
        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
        <label>Descriptor
          <select name="ref" required>
            {{ range .Descriptors }}<option value="{{ .ID }}" {{ if eq .ID $.SelectedRef }}selected{{ end }}>{{ .DisplayName }}</option>{{ end }}
          </select>
        </label>
        <label>Action
          <select name="action" required>
            <option value="metadata_use">metadata_use</option>
            <option value="resolve_handle">resolve_handle</option>
          </select>
        </label>
        <label>Destination
          <input name="destination" maxlength="120" placeholder="janus dashboard">
        </label>
        <label>Reason
          <input name="reason" maxlength="160" required placeholder="audit, rotation, incident review">
        </label>
        <button class="primary" type="submit">Create metadata permit</button>
      </form>
      {{ else }}
      <div class="stack">
        <p class="warn">Operator role required.</p>
        <p>Viewing posture is allowed, but permit requests are role-gated.</p>
      </div>
      {{ end }}
    </div>
  </div>
</section>
{{ end }}
{{ if and .CanOperate .Permits }}
<section class="grid" id="permits">
  <div class="panel">
    <div class="panel-head">
      <h2>Recent permits</h2>
      {{ if .PermitPosture.Persisted }}<span class="pill ok">{{ len .Permits }} durable</span>{{ else }}<span class="pill warn">{{ len .Permits }} in memory</span>{{ end }}
    </div>
    <div class="panel-body stack">
      <div class="witness-grid" aria-label="Recent permit safety witness">
        <div class="witness-card ok">
          <span>Check boundary</span>
          <strong>metadata only</strong>
          <p>Running a safety check evaluates the permit record and never asks for a secret value.</p>
        </div>
        <div class="witness-card ok">
          <span>No connector execution</span>
          <strong>closed</strong>
          <p>V1 has no execution connector, so permit checks return a no-execution verdict.</p>
        </div>
        <div class="witness-card ok">
          <span>Scrubbed result</span>
          <strong>required</strong>
          <p>Check output is scrubbed and no connector output, payload, request body, or env data is returned.</p>
        </div>
        <div class="witness-card info">
          <span>Receipt after check</span>
          <strong>copy-safe</strong>
          <p>Each check writes audit evidence and returns request id, receipt id, and receipt hash.</p>
        </div>
      </div>
      <details class="evidence-flags">
        <summary>Recent permit evidence flags</summary>
        <div class="flag-cloud" aria-label="Recent permit value-free evidence flags">
          <span class="pill ok">permit_count={{ len .Permits }}</span>
          <span class="pill ok">run_check_available=true</span>
          <span class="pill ok">connector_execution=false</span>
          <span class="pill ok">connector_output_returned=false</span>
          <span class="pill ok">permit_payload_returned=false</span>
          <span class="pill ok">request_body_returned=false</span>
          <span class="pill ok">env_returned=false</span>
          <span class="pill ok">secret_value_returned=false</span>
          <span class="pill ok">value_returned=false</span>
        </div>
      </details>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Permit</th><th>Secret ref</th><th>Action</th><th>Status</th><th>Expires</th><th>Check</th></tr></thead>
        <tbody>
        {{ range .Permits }}
          <tr>
            <td class="mono">{{ .ID }}</td>
            <td>{{ .SecretRef }}</td>
            <td>{{ .Action }}</td>
            <td>{{ .Status }}</td>
            <td>{{ .ExpiresAt.Format "15:04:05" }}</td>
            <td>
              {{ if $.CanOperate }}
              <form method="post" action="/ui/permits/{{ .ID }}/run">
                <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
                <button class="button quiet" type="submit">Run safety check</button>
              </form>
              {{ else }}
              <span class="pill warn">operator role required</span>
              {{ end }}
            </td>
          </tr>
        {{ end }}
        </tbody>
      </table>
    </div>
  </div>
</section>
{{ end }}
<section class="grid" id="posture">
  <div class="panel half">
    <div class="panel-head">
      <h2>Access policy</h2>
      {{ if .Access.ExplicitBindings }}<span class="pill ok">explicit bindings</span>{{ else }}<span class="pill warn">bootstrap</span>{{ end }}
    </div>
    <div class="panel-body stack">
      <p>
        {{ range .Session.Roles }}<span class="pill info">{{ . }}</span> {{ end }}
      </p>
      <div class="facts">
        <div class="fact"><strong>{{ .Access.GateCount }}</strong><span class="muted">role gates</span></div>
        <div class="fact"><strong>{{ if .Access.BootstrapOwner }}on{{ else }}off{{ end }}</strong><span class="muted">bootstrap owner</span></div>
        <div class="fact"><strong>{{ .Access.ClaimPolicy }}</strong><span class="muted">claim policy</span></div>
        <div class="fact"><strong>{{ .Access.SubjectBindingCount }}</strong><span class="muted">subject bindings</span></div>
        <div class="fact"><strong>{{ .Access.GroupBindingCount }}</strong><span class="muted">group bindings</span></div>
        <div class="fact"><strong>auditor</strong><span class="muted">evidence role</span></div>
        <div class="fact"><strong>{{ .SessionPosture.TTLLabel }}</strong><span class="muted">session ttl</span></div>
        <div class="fact"><strong>{{ .SessionPosture.ExpiresLabel }}</strong><span class="muted">expires</span></div>
        <div class="fact"><strong>{{ .SessionPosture.CookieSameSite }}</strong><span class="muted">session cookie</span></div>
      </div>
      <div class="mode-grid" aria-label="Role policy proof">
        {{ range .Access.BindingSources }}
        <div class="mode-item {{ .Tone }}">
          <span>{{ .Label }}</span>
          <strong>{{ .State }}</strong>
          <p><span class="pill info">{{ .Count }} bindings</span> <span class="pill ok">value_returned=false</span></p>
          <p>{{ .Detail }}</p>
        </div>
        {{ end }}
      </div>
      {{ range .Access.Gates }}<p class="warn">{{ .Message }}</p>{{ end }}
    </div>
  </div>
  <div class="panel half">
    <div class="panel-head">
      <h2>Scope boundary</h2>
      {{ if .Scope.Gates }}<span class="pill warn">review</span>{{ else }}<span class="pill ok">enforced</span>{{ end }}
    </div>
    <div class="panel-body stack">
      <p>{{ range .Scope.AllowedScopes }}<span class="pill info">{{ . }}</span> {{ end }}</p>
      <div class="facts">
        <div class="fact"><strong>{{ .Scope.DescriptorCount }}</strong><span class="muted">catalog descriptors</span></div>
        <div class="fact"><strong>{{ .Scope.OutOfScopeCount }}</strong><span class="muted">out of scope</span></div>
        <div class="fact"><strong>{{ if .Scope.Strict }}on{{ else }}off{{ end }}</strong><span class="muted">strict mode</span></div>
      </div>
      {{ range .Scope.Gates }}<p class="warn">{{ .Message }}</p>{{ end }}
    </div>
  </div>
  <div class="panel" id="role-policy-readiness">
    <div class="panel-head">
      <h2>Role policy readiness</h2>
      <span class="pill {{ if eq .RolePolicyReadiness.Status "ready" }}ok{{ else }}warn{{ end }}">{{ .RolePolicyReadiness.Status }}</span>
    </div>
    <div class="panel-body stack">
      <p>{{ .RolePolicyReadiness.Summary }}</p>
      <p><span class="pill {{ if .RolePolicyReadiness.Ready }}ok{{ else }}warn{{ end }}">{{ .RolePolicyReadiness.ReadyLanes }} ready lanes</span> <span class="pill {{ if .RolePolicyReadiness.MissingLanes }}warn{{ else }}ok{{ end }}">{{ .RolePolicyReadiness.MissingLanes }} missing lanes</span> <span class="pill info">bootstrap {{ .RolePolicyReadiness.BootstrapOwnerState }}</span> <span class="pill info">{{ .RolePolicyReadiness.EvidenceSignal }}</span> <span class="pill ok">subject_values_returned=false</span> <span class="pill ok">group_values_returned=false</span> <span class="pill ok">claim_values_returned=false</span> <span class="pill ok">env_values_returned=false</span> <span class="pill ok">backend_path_returned=false</span> <span class="pill ok">token_returned=false</span> <span class="pill ok">value_returned=false</span></p>
      <p><span class="pill info">next</span> {{ .RolePolicyReadiness.Next }}</p>
      <div class="mode-grid" aria-label="Role policy readiness lanes">
        {{ range .RolePolicyReadiness.Lanes }}
        <div class="mode-item {{ .Tone }}">
          <span>{{ .Label }}</span>
          <strong>{{ .State }}</strong>
          <p>{{ .Detail }}</p>
          <p><span class="pill info">role {{ .Role }}</span> <span class="pill {{ if .Ready }}ok{{ else }}warn{{ end }}">{{ .BindingCount }} bindings</span> <span class="pill info">subject_binding_configured={{ .SubjectBindingConfigured }}</span> <span class="pill info">group_binding_configured={{ .GroupBindingConfigured }}</span></p>
          <p><span class="pill info">next</span> {{ .Next }}</p>
        </div>
        {{ end }}
      </div>
      <div class="mode-grid" aria-label="Bootstrap to explicit role setup path">
        {{ range .RolePolicyReadiness.Steps }}
        <div class="mode-item {{ .Tone }}">
          <span>{{ .Label }}</span>
          <strong>{{ .State }}</strong>
          <p>{{ .Detail }}</p>
          <p><span class="pill info">owner {{ .OwnerRole }}</span> <span class="pill ok">value_returned=false</span></p>
          <p><span class="pill info">next</span> {{ .Next }}</p>
        </div>
        {{ end }}
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <h2>Duty boundary</h2>
      <span class="pill info">role matrix</span>
    </div>
    <div class="panel-body">
      <div class="role-matrix" aria-label="Role duty matrix">
        {{ range .RoleBoundaries }}
        <div class="role-card {{ if .Active }}active{{ end }}">
          <div class="role-head">
            <strong>{{ .Role }}</strong>
            {{ if .Active }}<span class="pill ok">active</span>{{ else }}<span class="pill">inactive</span>{{ end }}
          </div>
          <div class="role-label">{{ .Duty }}</div>
          <p>{{ .Allowed }}</p>
          <p class="warn">{{ .Blocked }}</p>
        </div>
        {{ end }}
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <h2>Lifecycle posture</h2>
      {{ if .Lifecycle.Gates }}<span class="pill warn">{{ .Lifecycle.GateCount }} gates</span>{{ else }}<span class="pill ok">normal use clear</span>{{ end }}
    </div>
    <div class="panel-body stack">
      <div class="witness-grid" aria-label="Lifecycle posture witness">
        <div class="witness-card {{ if .Lifecycle.Gates }}warn{{ else }}ok{{ end }}">
          <span>Normal-use gate</span>
          <strong>{{ if .Lifecycle.Gates }}review{{ else }}clear{{ end }}</strong>
          <p>Only active or rotating descriptors with an approved profile can move into normal metadata use.</p>
        </div>
        <div class="witness-card {{ if .Lifecycle.BlockedCount }}warn{{ else }}ok{{ end }}">
          <span>Blocked lifecycle</span>
          <strong>{{ .Lifecycle.BlockedCount }} blocked</strong>
          <p>Draft, deprecated, disabled, pending-delete, destroyed, or unknown states fail closed.</p>
        </div>
        <div class="witness-card {{ if .Lifecycle.StaleCount }}warn{{ else }}ok{{ end }}">
          <span>Freshness review</span>
          <strong>{{ .Lifecycle.StaleCount }} stale</strong>
          <p>Missing or old freshness timestamps stay visible before stronger lifecycle claims.</p>
        </div>
        <div class="witness-card ok">
          <span>Value boundary</span>
          <strong>metadata only</strong>
          <p>Lifecycle evidence uses state, counts, safe refs, and reasons; secret values stay outside Janus.</p>
        </div>
      </div>
      <p>{{ range .Lifecycle.StateCounts }}<span class="pill info">{{ .State }} {{ .Count }}</span> {{ end }}</p>
      <div class="facts">
        <div class="fact"><strong>{{ .Lifecycle.ActiveCount }}</strong><span class="muted">active</span></div>
        <div class="fact"><strong>{{ .Lifecycle.BlockedCount }}</strong><span class="muted">blocked</span></div>
        <div class="fact"><strong>{{ .Lifecycle.StaleCount }}</strong><span class="muted">stale</span></div>
      </div>
      <details class="evidence-flags">
        <summary>Lifecycle posture evidence flags</summary>
        <div class="flag-cloud" aria-label="Lifecycle value-free evidence flags">
          <span class="pill ok">supported_states={{ len .Lifecycle.SupportedStates }}</span>
          <span class="pill ok">active_count={{ .Lifecycle.ActiveCount }}</span>
          <span class="pill {{ if .Lifecycle.BlockedCount }}warn{{ else }}ok{{ end }}">blocked_count={{ .Lifecycle.BlockedCount }}</span>
          <span class="pill {{ if .Lifecycle.StaleCount }}warn{{ else }}ok{{ end }}">stale_count={{ .Lifecycle.StaleCount }}</span>
          <span class="pill {{ if .Lifecycle.Gates }}warn{{ else }}ok{{ end }}">gate_count={{ .Lifecycle.GateCount }}</span>
          <span class="pill ok">normal_use_fail_closed=true</span>
          <span class="pill ok">secret_value_returned=false</span>
          <span class="pill ok">backend_path_returned=false</span>
          <span class="pill ok">request_body_returned=false</span>
          <span class="pill ok">value_returned=false</span>
        </div>
      </details>
      {{ range .Lifecycle.Gates }}<p class="warn">{{ .SecretRef }}: {{ .Message }}</p>{{ end }}
    </div>
  </div>
</section>
	<section class="grid" id="audit">
	  <div class="panel">
	    <div class="panel-head">
	      <h2>Audit trail</h2>
	      {{ if .CanViewAudit }}
	      <span class="pill {{ .AuditTrail.ChainTone }}">{{ .AuditTrail.ChainState }}</span>
	      {{ else }}
	      <span class="pill warn">auditor required</span>
	      {{ end }}
	    </div>
	    <div class="panel-body stack">
	      <p>{{ .AuditTrail.Summary }}</p>
	      {{ if .CanViewAudit }}
	      <p>
	      {{ range .Posture.SeverityCounts }}
	        <span class="pill {{ if or (eq .Severity "critical") (eq .Severity "warning") }}warn{{ else }}info{{ end }}">{{ .Severity }} {{ .Count }}</span>
	      {{ end }}
	      <span class="pill info">visible {{ .AuditTrail.VisibleCount }}</span>
	      <span class="pill ok">value_returned=false</span>
	      </p>
	      <div class="witness-grid" aria-label="Recent audit trail witness">
	        <div class="witness-card ok">
	          <span>Chronological history</span>
	          <strong>{{ .AuditTrail.VisibleCount }} visible</strong>
	          <p>Rows show safe action labels in event order with raw route paths and raw reasons withheld.</p>
	        </div>
	        <div class="witness-card {{ .AuditTrail.ChainTone }}">
	          <span>Hash chain</span>
	          <strong>{{ .AuditTrail.ChainState }}</strong>
	          <p>Each chained event keeps a previous hash and event hash for tamper review.</p>
	        </div>
	        <div class="witness-card info">
	          <span>Receipt linkage</span>
	          <strong>request id</strong>
	          <p>Request ids connect browser actions, action receipts, and audit events without identity values.</p>
	        </div>
	        <div class="witness-card ok">
	          <span>Value boundary</span>
	          <strong>metadata only</strong>
	          <p>Subjects, claims, tokens, cookies, request bodies, env data, backend paths, and secret values stay out.</p>
	        </div>
	      </div>
	      <details class="evidence-flags">
	        <summary>Recent audit evidence flags</summary>
	        <div class="flag-cloud" aria-label="Recent audit value-free evidence flags">
	          <span class="pill ok">audit_entries={{ .AuditTrail.EntryCount }}</span>
	          <span class="pill ok">visible_audit_rows={{ .AuditTrail.VisibleCount }}</span>
	          <span class="pill ok">chronological_history=true</span>
	          <span class="pill {{ if .Posture.ChainVerified }}ok{{ else }}warn{{ end }}">hash_chain_verified={{ .Posture.ChainVerified }}</span>
	          <span class="pill ok">receipt_hash_linkage=true</span>
	          <span class="pill ok">raw_path_returned=false</span>
	          <span class="pill ok">raw_reason_returned=false</span>
	          <span class="pill ok">subject_returned=false</span>
	          <span class="pill ok">email_returned=false</span>
	          <span class="pill ok">name_returned=false</span>
	          <span class="pill ok">group_claim_returned=false</span>
	          <span class="pill ok">token_returned=false</span>
	          <span class="pill ok">cookie_value_returned=false</span>
	          <span class="pill ok">request_body_returned=false</span>
	          <span class="pill ok">env_returned=false</span>
	          <span class="pill ok">backend_path_returned=false</span>
	          <span class="pill ok">source_path_returned=false</span>
	          <span class="pill ok">connector_output_returned=false</span>
	          <span class="pill ok">permit_payload_value_returned=false</span>
	          <span class="pill ok">secret_value_returned=false</span>
	          <span class="pill ok">value_returned=false</span>
	        </div>
	      </details>
	      {{ if .AuditTrail.Rows }}
	      <div class="audit-timeline" aria-label="Recent audit action history">
	        {{ range .AuditTrail.Rows }}
	        <div class="audit-event {{ .OutcomeTone }}">
	          <div class="audit-index">
	            <span>event {{ .Step }}</span>
	            <strong>{{ .TimeLabel }}</strong>
	          </div>
	          <div class="audit-main">
	            <div class="audit-title">
	              <strong>{{ .Action }}</strong>
	              <span class="pill {{ .OutcomeTone }}">{{ .Outcome }}</span>
	              <span class="pill {{ .SeverityTone }}">{{ .Severity }}</span>
	            </div>
	            <p><span class="pill info">{{ .Channel }}</span> <span class="pill ok">scope {{ .Scope }}</span> <span class="pill info">{{ .ReasonClass }}</span></p>
	            <p class="mono">request_id={{ .RequestID }}</p>
	          </div>
	          <div class="audit-proof" aria-label="Audit hash link">
	            <span>prev</span><strong class="mono">{{ .PrevHashShort }}</strong>
	            <span>event</span><strong class="mono">{{ .EventHashShort }}</strong>
	          </div>
	        </div>
	        {{ end }}
	      </div>
	      {{ end }}
	      {{ else }}
	      <div class="witness-grid" aria-label="Restricted audit trail witness">
	        <div class="witness-card warn">
	          <span>Audit rows</span>
	          <strong>restricted</strong>
	          <p>Auditor role required before Janus renders recent audit rows.</p>
	        </div>
	        <div class="witness-card warn">
	          <span>Evidence hash</span>
	          <strong>auditor only</strong>
	          <p>Exact audit and evidence hashes are withheld from this session.</p>
	        </div>
	        <div class="witness-card ok">
	          <span>Value boundary</span>
	          <strong>protected</strong>
	          <p>Restricted sessions do not receive audit refs, request ids, subjects, claims, tokens, cookies, or values.</p>
	        </div>
	      </div>
	      <p class="warn">Auditor role required.</p>
	      <p>Audit rows and evidence hashes are restricted to auditor sessions.</p>
	      <details class="evidence-flags">
	        <summary>Restricted audit evidence flags</summary>
	        <div class="flag-cloud" aria-label="Restricted audit value-free evidence flags">
	          <span class="pill warn">auditor_required=true</span>
	          <span class="pill ok">audit_rows_rendered=false</span>
	          <span class="pill ok">request_id_returned=false</span>
	          <span class="pill ok">subject_returned=false</span>
	          <span class="pill ok">group_claim_returned=false</span>
	          <span class="pill ok">token_returned=false</span>
	          <span class="pill ok">cookie_value_returned=false</span>
	          <span class="pill ok">secret_ref_returned=false</span>
	          <span class="pill ok">secret_value_returned=false</span>
	          <span class="pill ok">value_returned=false</span>
	        </div>
	      </details>
	      {{ end }}
	    </div>
	  </div>
	</section>
{{ if .CatalogGates }}
<section class="grid" id="catalog-gates">
  <div class="panel">
    <div class="panel-head">
      <h2>Catalog gates</h2>
      <span class="pill warn">{{ len .CatalogGates }} open</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Secret ref</th><th>Severity</th><th>Code</th><th>Message</th></tr></thead>
        <tbody>
        {{ range .CatalogGates }}
          <tr>
            <td>{{ .SecretRef }}</td>
            <td>{{ .Severity }}</td>
            <td>{{ .Code }}</td>
            <td>{{ .Message }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
    </div>
  </div>
</section>
{{ end }}
<section class="grid" id="catalog">
  <div class="panel">
    <div class="panel-head">
      <h2>Warden descriptors</h2>
      <span class="pill ok">values never returned</span>
    </div>
    <div class="panel-body stack">
      <div class="witness-grid" aria-label="Warden descriptor catalog witness">
        <div class="witness-card ok">
          <span>Visible metadata</span>
          <strong>{{ len .Descriptors }} descriptors</strong>
          <p>Catalog rows describe ownership, scope, lifecycle, and use posture without exposing secret material.</p>
        </div>
        <div class="witness-card {{ if .Scope.Gates }}warn{{ else }}ok{{ end }}">
          <span>Scope boundary</span>
          <strong>{{ if .Scope.Strict }}strict{{ else }}open{{ end }}</strong>
          <p>Broker-filtered descriptors stay inside the configured scope before any handle or permit is offered.</p>
        </div>
        <div class="witness-card {{ if .ApprovedUse.BlockedCount }}warn{{ else }}ok{{ end }}">
          <span>Use profile</span>
          <strong>{{ .ApprovedUse.ProfiledCount }} profiled</strong>
          <p>{{ .ApprovedUse.BlockedCount }} descriptors still need an approved metadata-only use profile.</p>
        </div>
        <div class="witness-card ok">
          <span>Value boundary</span>
          <strong>reveal disabled</strong>
          <p>Secret values, backend paths, source files, request bodies, and env data are not returned here.</p>
        </div>
      </div>
      <details class="evidence-flags">
        <summary>Warden catalog evidence flags</summary>
        <div class="flag-cloud" aria-label="Warden catalog value-free evidence flags">
          <span class="pill ok">descriptor_count={{ len .Descriptors }}</span>
          <span class="pill {{ if .Scope.Strict }}ok{{ else }}warn{{ end }}">scope_strict={{ .Scope.Strict }}</span>
          <span class="pill ok">profiled_count={{ .ApprovedUse.ProfiledCount }}</span>
          <span class="pill {{ if .ApprovedUse.BlockedCount }}warn{{ else }}ok{{ end }}">unprofiled_count={{ .ApprovedUse.BlockedCount }}</span>
          <span class="pill ok">reveal_allowed=false</span>
          <span class="pill ok">secret_value_returned=false</span>
          <span class="pill ok">backend_path_returned=false</span>
          <span class="pill ok">source_path_returned=false</span>
          <span class="pill ok">request_body_returned=false</span>
          <span class="pill ok">env_returned=false</span>
          <span class="pill ok">value_returned=false</span>
        </div>
      </details>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Provider</th><th>Scope</th><th>Owner</th><th>Class</th><th>Lifecycle</th><th>Status</th><th>Consumers</th><th>Rotation</th><th>Use</th><th>Reveal</th><th>Inspect</th></tr></thead>
        <tbody>
        {{ range .Descriptors }}
          <tr {{ if eq .ID $.SelectedRef }}class="selected"{{ end }}>
            <td><strong>{{ .DisplayName }}</strong><br><span class="muted">{{ .ID }}</span></td>
            <td>{{ .Provider }}</td>
            <td>{{ .Scope }}</td>
            <td>{{ .Owner }}</td>
            <td>{{ .Classification }}</td>
            <td>{{ .Lifecycle }}</td>
            <td>{{ .Status }}</td>
            <td>{{ .ConsumerCount }}</td>
            <td>{{ .RotationDays }} days</td>
            <td>{{ if .UseEnabled }}<span class="pill">profiled</span>{{ else }}<span class="pill">blocked</span>{{ end }}</td>
            <td><span class="pill">disabled</span></td>
            <td><a class="button quiet" href="/?ref={{ .ID }}#focus">Inspect</a></td>
          </tr>
        {{ end }}
        </tbody>
      </table>
    </div>
  </div>
	</section>
	{{ template "base_bottom" . }}
	{{- end }}

	{{ define "session_witness_verify" -}}
	{{ template "base_top" . }}
	<section class="overview" id="witness-verifier">
	  <div class="intro">
	    <div class="intro-copy">
	      <div class="eyebrow">{{ .Mode }} / {{ .Capture.Schema }} / verifier</div>
	      <h1>Witness receipt verifier</h1>
	      <p>Checks a copy-safe witness proof line and hash. Pasted input is not echoed, stored, or returned.</p>
	    </div>
	    <div class="toolbar">
	      <a class="button primary" href="/session-witness">Witness</a>
	      <a class="button quiet" href="/session-witness.txt">Proof text</a>
	      <a class="button quiet" href="/session-witness/proof.txt">Proof pack</a>
	      <a class="button quiet" href="/api/auth/session-witness">Witness JSON</a>
		      <form method="post" action="/session-witness/verify-current-pack">
		        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
		        <button class="button quiet" type="submit">Verify current proof pack</button>
		      </form>
	      <a class="button quiet" href="/">Dashboard</a>
	    </div>
	    <div class="safety-ribbon" aria-label="Witness verifier posture">
	      <div class="safety-chip {{ if and .Verification .Verification.Verified }}ok{{ else if .Verification }}warn{{ else }}info{{ end }}">
	        <span>Status</span>
	        <strong>{{ if .Verification }}{{ .Verification.Status }}{{ else }}ready{{ end }}</strong>
	      </div>
	      <div class="safety-chip {{ if and .Verification .Verification.HashMatch }}ok{{ else if .Verification }}warn{{ else }}info{{ end }}">
	        <span>Hash</span>
	        <strong>{{ if .Verification }}{{ .Verification.HashMatch }}{{ else }}not checked{{ end }}</strong>
	      </div>
	      <div class="safety-chip {{ if and .Verification .Verification.Fresh }}ok{{ else if .Verification }}warn{{ else }}info{{ end }}">
	        <span>Fresh</span>
	        <strong>{{ if .Verification }}{{ .Verification.Fresh }}{{ else }}not checked{{ end }}</strong>
	      </div>
	      <div class="safety-chip ok">
	        <span>Values</span>
	        <strong>withheld</strong>
	      </div>
	    </div>
	  </div>
	  <div class="status">
	    <div class="status-head"><h2>Verify proof pack</h2><span class="pill ok">input not returned</span></div>
	    <div class="panel-body stack">
	      <form class="stack" method="post" action="/session-witness/verify-pack">
	        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
	        <label>Proof pack<textarea name="proof_pack" required spellcheck="false" autocomplete="off"></textarea></label>
	        <button class="button primary" type="submit">Verify proof pack</button>
	      </form>
	      <p><span class="pill ok">proof_pack_returned=false</span> <span class="pill ok">request_body_returned=false</span> <span class="pill ok">value_returned=false</span></p>
	    </div>
	  </div>
	  <div class="status">
	    <div class="status-head"><h2>Verify proof line</h2><span class="pill ok">input not returned</span></div>
	    <div class="panel-body stack">
	      <form class="stack" method="post" action="/session-witness/verify">
	        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
	        <label>Proof line<textarea name="proof_line" required spellcheck="false" autocomplete="off"></textarea></label>
	        <label>Proof hash<input name="proof_hash" required autocomplete="off" spellcheck="false"></label>
	        <button class="button primary" type="submit">Verify witness receipt</button>
	      </form>
	      <p><span class="pill ok">request_body_returned=false</span> <span class="pill ok">input_returned=false</span> <span class="pill ok">value_returned=false</span></p>
	    </div>
	  </div>
	</section>
	{{ if .Verification }}
	<section class="panel" style="margin-bottom:16px" id="verification-result">
	  <div class="panel-head">
	    <h2>Verification result</h2>
	    <span class="pill {{ if .Verification.Verified }}ok{{ else }}warn{{ end }}">{{ .Verification.Status }}</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .Verification.Summary }}</p>
	    <div class="receipt-proof" aria-label="Normalized witness verification fields">
	      <span>State<strong>{{ .Verification.State }}</strong></span>
	      <span>Flow<strong>{{ .Verification.Flow }}</strong></span>
	      <span>Request<strong>{{ .Verification.RequestID }}</strong></span>
	      <span>Captured<strong>{{ .Verification.CapturedAt }}</strong></span>
	      <span>Fresh until<strong>{{ .Verification.FreshUntil }}</strong></span>
	      <span>Hash match<strong>{{ .Verification.HashMatch }}</strong></span>
	      <span>Fresh<strong>{{ .Verification.Fresh }}</strong></span>
	      <span>Expected hash<strong class="mono">{{ .Verification.ExpectedHash }}</strong></span>
	      {{ if .Verification.Receipt }}
	      <span>Verification hash<strong class="mono">{{ .Verification.Receipt.Hash }}</strong></span>
	      {{ end }}
	    </div>
	    <p><span class="pill info">freshness_seconds={{ .Verification.FreshnessSeconds }}</span>{{ if .Verification.Receipt }} <span class="pill info">{{ .Verification.Receipt.Algorithm }}</span> <span class="pill ok">verification_hash_header={{ .Verification.Receipt.HashHeader }}</span> <span class="pill ok">verification_hash_body_field={{ .Verification.Receipt.BodyField }}</span>{{ end }} <span class="pill ok">input_returned={{ .Verification.InputReturned }}</span> <span class="pill ok">request_body_returned={{ .Verification.RequestBodyReturned }}</span> <span class="pill ok">value_returned={{ .Verification.ValueReturned }}</span></p>
	    {{ if .Verification.Receipt }}
	    <p class="capture-line mono">{{ .Verification.Receipt.Input }}</p>
	    {{ end }}
	  </div>
	</section>
	{{ if .Verification.Evidence }}
	<section class="panel" style="margin-bottom:16px" id="copy-safe-evidence">
	  <div class="panel-head">
	    <h2>Copy-safe evidence receipt</h2>
	    <span class="pill ok">cite this</span>
	  </div>
	  <div class="panel-body stack">
	    <p>{{ .Verification.Evidence.Summary }}</p>
	    <div class="receipt-proof" aria-label="Copy-safe signed-browser evidence fields">
	      <span>Status<strong>{{ .Verification.Evidence.Status }}</strong></span>
	      <span>Source request<strong>{{ .Verification.Evidence.SourceRequestID }}</strong></span>
	      <span>Captured<strong>{{ .Verification.Evidence.CapturedAt }}</strong></span>
	      <span>Fresh until<strong>{{ .Verification.Evidence.FreshUntil }}</strong></span>
	      <span>Verified<strong>{{ .Verification.Evidence.Verified }}</strong></span>
	      <span>Proof pack<strong>{{ .Verification.Evidence.ProofPackVerified }}</strong></span>
	      <span>Verification hash<strong class="mono">{{ .Verification.Evidence.VerificationHash }}</strong></span>
	    </div>
	    <p class="capture-line mono">{{ .Verification.Evidence.Line }}</p>
	    <p><span class="pill ok">copy_safe={{ .Verification.Evidence.CopySafe }}</span> <span class="pill ok">input_returned={{ .Verification.Evidence.InputReturned }}</span> <span class="pill ok">request_body_returned={{ .Verification.Evidence.RequestBodyReturned }}</span> <span class="pill ok">value_returned={{ .Verification.Evidence.ValueReturned }}</span></p>
	    <details class="evidence-flags">
	      <summary>Excluded from this receipt</summary>
	      <div class="flag-cloud" aria-label="Excluded signed-browser evidence fields">
	        {{ range .Verification.Evidence.Excluded }}
	        <span class="pill ok">{{ . }}_returned=false</span>
	        {{ end }}
	      </div>
	    </details>
	  </div>
	</section>
	{{ end }}
	<section class="panel" style="margin-bottom:16px" id="verification-checks">
	  <div class="panel-head">
	    <h2>Verification checks</h2>
	    <span class="pill info">{{ len .Verification.Checks }} checks</span>
	  </div>
	  <div class="panel-body">
	    <div class="witness-grid" aria-label="Witness receipt verification checks">
	      {{ range .Verification.Checks }}
	      <div class="witness-card {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	{{ end }}
	{{ template "base_bottom" . }}
	{{- end }}

	{{ define "session_witness" -}}
	{{ template "base_top" . }}
	<section class="overview" id="witness-capture">
	  <div class="intro">
	    <div class="intro-copy">
	      <div class="eyebrow">{{ .Mode }} / {{ .Capture.Schema }} / value-free</div>
	      <h1>Session witness capture</h1>
	      <p>{{ .AuthenticatedBrowser.Summary }}</p>
	    </div>
	    <div class="toolbar">
	      <a class="button primary" href="/">Dashboard</a>
	      <a class="button quiet" href="/session-witness.txt">Proof text</a>
	      <a class="button quiet" href="/session-witness/proof.txt">Proof pack</a>
	      <a class="button quiet" href="/session-witness/verify">Verify proof</a>
	      <a class="button quiet" href="/api/auth/session-witness">Witness JSON</a>
		      <form method="post" action="/session-witness/verify-current-pack">
		        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
		        <button class="button quiet" type="submit">Verify current proof pack</button>
		      </form>
	    </div>
	    <div class="reviewer-flow" aria-label="Signed-browser reviewer handoff">
	      <div class="reviewer-step ok">
	        <span>Reviewer handoff</span>
	        <strong>browser proof ready</strong>
	        <p>signed_browser_capture=true</p>
	      </div>
	      <div class="reviewer-step action">
	        <a class="button primary" href="/session-witness/proof.txt">Open proof pack</a>
	      </div>
	      <div class="reviewer-step action">
		        <form method="post" action="/session-witness/verify-current-pack">
		          <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
		          <button class="button quiet" type="submit">Verify proof pack</button>
		        </form>
	      </div>
	      <div class="reviewer-step ok">
	        <span>Boundary</span>
	        <strong>values withheld</strong>
	        <p>proof_pack_contains_verification=true</p>
	      </div>
	    </div>
	    <div class="safety-ribbon" aria-label="Session witness posture">
	      <div class="safety-chip {{ if eq .AuthenticatedBrowser.State "authenticated" }}ok{{ else if eq .AuthenticatedBrowser.State "local_smoke" }}info{{ else }}warn{{ end }}">
	        <span>State</span>
	        <strong>{{ .AuthenticatedBrowser.State }}</strong>
	      </div>
	      <div class="safety-chip info">
	        <span>Flow</span>
	        <strong>{{ .AuthenticatedBrowser.Flow }}</strong>
	      </div>
	      <div class="safety-chip ok">
	        <span>Values</span>
	        <strong>withheld</strong>
	      </div>
	      <div class="safety-chip info">
	        <span>Request</span>
	        <strong>{{ .RequestID }}</strong>
	      </div>
	      <div class="safety-chip ok">
	        <span>Fresh until</span>
	        <strong>{{ .Receipt.FreshUntil }}</strong>
	      </div>
	    </div>
	  </div>
	  <div class="status">
	    <div class="status-head"><h2>Capture proof</h2><span class="pill ok">copy-safe</span></div>
	    <div class="panel-body stack">
	      <div class="receipt-proof" aria-label="Session witness capture proof">
	        <span>Schema<strong>{{ .Capture.Schema }}</strong></span>
	        <span>Body field<strong>{{ .Capture.BodyField }}</strong></span>
	        <span>Signal<strong>{{ .AuthenticatedBrowser.EvidenceSignal }}</strong></span>
	        <span>Captured<strong>{{ .Receipt.CapturedAt }}</strong></span>
	        <span>Fresh until<strong>{{ .Receipt.FreshUntil }}</strong></span>
	        <span>Proof hash<strong class="mono">{{ .Receipt.Hash }}</strong></span>
	      </div>
	      <div class="receipt-copy" aria-label="Copy-safe session witness fields">
	        <label>State<input readonly value="state={{ .AuthenticatedBrowser.State }}"></label>
	        <label>Flow<input readonly value="flow={{ .AuthenticatedBrowser.Flow }}"></label>
	        <label>Request<input readonly value="request_id={{ .RequestID }}"></label>
	        <label>Captured<input readonly value="captured_at={{ .Receipt.CapturedAt }}"></label>
	        <label>Fresh until<input readonly value="fresh_until={{ .Receipt.FreshUntil }}"></label>
	      </div>
	      <p class="capture-line mono">{{ .CaptureLine }}</p>
	      <p><span class="pill info">{{ .Receipt.Algorithm }}</span> <span class="pill ok">freshness_seconds={{ .Receipt.FreshnessSeconds }}</span> <span class="pill ok">hash_header={{ .Receipt.HashHeader }}</span> <span class="pill ok">hash_body_field={{ .Receipt.BodyField }}</span> <span class="pill ok">copy_safe={{ .Capture.CopySafe }}</span> <span class="pill ok">replay_safe={{ .Capture.ReplaySafe }}</span> <span class="pill ok">value_returned=false</span></p>
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="capture-headers">
	  <div class="panel-head">
	    <h2>Witness headers</h2>
	    <span class="pill info">{{ len .CaptureHeaders }} headers</span>
	  </div>
	  <div class="panel-body stack">
	    <div class="capture-headers" aria-label="Copy-safe witness response headers">
	      {{ range .CaptureHeaders }}
	      <div class="capture-header">
	        <span>{{ .Name }}</span>
	        <strong class="mono">{{ .Value }}</strong>
	        <span class="pill ok">value_returned={{ .ValueReturned }}</span>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	</section>
	<section class="panel" style="margin-bottom:16px" id="value-boundary">
	  <div class="panel-head">
	    <h2>Value boundary</h2>
	    <span class="pill ok">metadata only</span>
	  </div>
	  <div class="panel-body stack">
	    <div class="witness-grid" aria-label="Session witness value boundary">
	      {{ range .AuthenticatedBrowser.Gates }}
	      <div class="witness-card {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	      </div>
	      {{ end }}
	    </div>
	    <details class="evidence-flags">
	      <summary>Session witness evidence flags</summary>
	      <div class="flag-cloud" aria-label="Session witness value-free evidence flags">
	        <span class="pill info">{{ .AuthenticatedBrowser.AuthMode }}</span>
	        <span class="pill info">{{ .AuthenticatedBrowser.SessionCookiePolicy }}</span>
	        <span class="pill info">{{ .AuthenticatedBrowser.CSRFBoundary }}</span>
	        <span class="pill info">{{ .AuthenticatedBrowser.CSPBoundary }}</span>
	        <span class="pill ok">identity_values_returned=false</span>
	        <span class="pill ok">subject_returned=false</span>
	        <span class="pill ok">email_returned=false</span>
	        <span class="pill ok">name_returned=false</span>
	        <span class="pill ok">claim_values_returned=false</span>
	        <span class="pill ok">group_values_returned=false</span>
	        <span class="pill ok">token_returned=false</span>
	        <span class="pill ok">cookie_value_returned=false</span>
	        <span class="pill ok">request_body_returned=false</span>
	        <span class="pill ok">env_values_returned=false</span>
	        <span class="pill ok">backend_path_returned=false</span>
	        <span class="pill ok">connector_output_returned=false</span>
	        <span class="pill ok">permit_payload_returned=false</span>
	        <span class="pill ok">secret_value_returned=false</span>
	        <span class="pill ok">value_returned=false</span>
	      </div>
	    </details>
	  </div>
	</section>
	{{ template "base_bottom" . }}
	{{- end }}

	{{ define "setup" -}}
{{ template "base_top" . }}
<section class="overview">
  <div class="intro">
    <div class="intro-copy">
      <div class="eyebrow">{{ .Mode }} / locked</div>
      <h1>Janus is locked</h1>
      <p>The service is deployed, but secret metadata stays closed until Zitadel login is configured.</p>
    </div>
  </div>
  <div class="status">
    <div class="status-head"><h2>Setup gates</h2><span class="pill warn">locked</span></div>
    <div class="panel-body stack">
      {{ range .Issues }}<p class="warn">{{ . }}</p>{{ end }}
    </div>
  </div>
</section>
{{ template "base_bottom" . }}
{{- end }}

{{ define "auth_error" -}}
{{ template "base_top" . }}
<section class="overview">
  <div class="intro">
    <div class="intro-copy">
      <div class="eyebrow">{{ .Mode }} / login</div>
      <h1>{{ .Headline }}</h1>
      <p>{{ .Message }}</p>
      <p>{{ .NextAction }}</p>
    </div>
    <div class="toolbar">
      <a class="button primary" href="{{ .PrimaryHref }}">{{ .PrimaryLabel }}</a>
      <a class="button quiet" href="{{ .SecondaryHref }}">{{ .SecondaryText }}</a>
    </div>
  </div>
  <div class="status">
    <div class="status-head"><h2>Safe login failure</h2><span class="pill warn">{{ .ReasonCode }}</span></div>
    <div class="panel-body stack">
      <p>Janus cleared the temporary login cookies and did not create a session.</p>
      <p><span class="pill info">{{ .StatusCode }}</span> <span class="pill ok">value_returned=false</span> <span class="pill ok">raw_callback_query_returned=false</span> <span class="pill ok">provider_error_returned=false</span> <span class="pill ok">token_returned=false</span> <span class="pill ok">cookie_value_returned=false</span></p>
      <p class="mono">request_id={{ .RequestID }}</p>
      <div class="mode-grid" aria-label="Auth recovery posture">
        <div class="mode-item info">
          <span>Redirect loop guard</span>
          <strong>{{ .Posture.LoopGuard.State }}</strong>
          <p>{{ .Posture.LoopGuard.MaxAttempts }} starts in {{ .Posture.LoopGuard.WindowSeconds }} seconds before Janus pauses.</p>
        </div>
        <div class="mode-item ok">
          <span>Support handle</span>
          <strong>request id</strong>
          <p>No token, callback query, provider detail, or cookie value is returned.</p>
        </div>
        <div class="mode-item warn">
          <span>Next</span>
          <strong>clean retry</strong>
          <p>Reset temporary login cookies if this repeats.</p>
        </div>
      </div>
    </div>
  </div>
</section>
{{ template "base_bottom" . }}
{{- end }}

{{ define "safe_error" -}}
{{ template "base_top" . }}
<section class="overview">
  <div class="intro">
    <div class="intro-copy">
      <div class="eyebrow">{{ .Mode }} / boundary</div>
      <h1>Janus stopped at the edge</h1>
      <p>{{ .Message }}</p>
    </div>
    <div class="toolbar">
      <a class="button primary" href="/">Return to Janus</a>
      <a class="button quiet" href="/login">Sign in</a>
    </div>
  </div>
  <div class="status">
    <div class="status-head"><h2>Safe boundary</h2><span class="pill warn">{{ .ReasonCode }}</span></div>
    <div class="panel-body stack">
      <p>Janus returned a controlled failure and did not reveal secret data.</p>
      <p><span class="pill ok">value_returned=false</span> <span class="pill">{{ .StatusCode }}</span></p>
      {{ if .AllowedMethods }}<p class="mono">allow={{ range $index, $method := .AllowedMethods }}{{ if $index }},{{ end }}{{ $method }}{{ end }}</p>{{ end }}
      <p class="mono">request_id={{ .RequestID }}</p>
    </div>
  </div>
</section>
{{ template "base_bottom" . }}
{{- end }}
`))
}
