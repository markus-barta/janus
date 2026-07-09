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
	"path"
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
	returnCookie      = "janus_oidc_return"
	hostReturnCookie  = "__Host-janus_oidc_return"
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

func (c Config) ReturnCookieName() string {
	if c.SecureCookies() {
		return hostReturnCookie
	}
	return returnCookie
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

type AuthResetView struct {
	Title         string
	CSPNonce      string
	Mode          string
	Session       Session
	CSRF          string
	RequestID     string
	Posture       AuthFailurePosture
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
	app := &App{
		cfg:       cfg,
		store:     store,
		broker:    NewBroker(store).WithScopePolicy(cfg.ScopePolicy),
		permits:   permitStore,
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
	mux.HandleFunc("GET /buildz", app.handleBuildReceipt)
	mux.HandleFunc("GET /favicon.ico", app.handleFavicon)
	mux.HandleFunc("GET /login", app.handleLogin)
	mux.HandleFunc("GET /auth/reset", app.handleAuthReset)
	mux.HandleFunc("GET /oidc/callback", app.handleCallback)
	mux.HandleFunc("POST /logout", app.withAuth(app.handleLogout))
	mux.HandleFunc("GET /auth/smoke", app.withAuth(app.handleAuthSmokePage))
	mux.HandleFunc("GET /session-witness", app.withAuth(app.handleSessionWitnessPage))
	mux.HandleFunc("GET /session-witness.txt", app.withAuth(app.handleSessionWitnessText))
	mux.HandleFunc("GET /session-witness/verify", app.withAuth(app.handleSessionWitnessVerifyPage))
	mux.HandleFunc("POST /session-witness/verify", app.withAuth(app.handleSessionWitnessVerifyPost))
	mux.HandleFunc("POST /session-witness/verify-current", app.withAuth(app.handleSessionWitnessVerifyCurrent))
	mux.HandleFunc("GET /api/warden/descriptors", app.withAuth(app.handleDescriptors))
	mux.HandleFunc("POST /api/warden/resolve", app.withAuth(app.requireRole(RoleOperator, "warden.resolve", app.handleResolveHandle)))
	mux.HandleFunc("GET /api/audit/recent", app.withAuth(app.requireRole(RoleAuditor, "audit.recent", app.handleRecentAudit)))
	mux.HandleFunc("GET /api/auth/session-witness", app.withAuth(app.handleAuthSessionWitness))
	mux.HandleFunc("POST /api/auth/session-witness/verify", app.withAuth(app.handleAuthSessionWitnessVerify))
	mux.HandleFunc("GET /api/posture", app.withAuth(app.handlePosture))
	mux.HandleFunc("GET /api/evidence", app.withAuth(app.requireRole(RoleAuditor, "evidence.export", app.handleEvidence)))
	mux.HandleFunc("POST /api/permits", app.withAuth(app.requireRole(RoleOperator, "permit.create", app.handleCreatePermit)))
	mux.HandleFunc("POST /api/permits/{permitID}/run", app.withAuth(app.requireRole(RoleOperator, "permit.run", app.handleRunPermit)))
	mux.HandleFunc("POST /ui/warden/resolve", app.withAuth(app.handleResolveHandleUI))
	mux.HandleFunc("POST /ui/permits", app.withAuth(app.handleCreatePermitUI))
	mux.HandleFunc("POST /ui/permits/{permitID}/run", app.withAuth(app.handleRunPermitUI))
	mux.HandleFunc("GET /access", app.withAuth(app.handleAccessPage))
	mux.HandleFunc("GET /requests", app.withAuth(app.handleRequestsPage))
	mux.HandleFunc("GET /ledger", app.withAuth(app.handleLedgerPage))
	mux.HandleFunc("GET /assurance", app.withAuth(app.handleAssurancePage))
	mux.HandleFunc("GET /settings", app.withAuth(app.handleSettingsPage))
	mux.HandleFunc("GET /vault/new", app.withAuth(app.handleNewSecretPage))
	mux.HandleFunc("GET /vault/new/plan.sh", app.withAuth(app.handleNewSecretScript))
	mux.HandleFunc("GET /static/", app.handleStatic)
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
	case "/", "/access", "/requests", "/ledger", "/assurance", "/settings", "/vault/new", "/vault/new/plan.sh", "/auth/smoke", "/session-witness", "/session-witness.txt", "/healthz", "/readyz", "/buildz", "/favicon.ico", "/login", "/auth/reset", "/oidc/callback", "/api/warden/descriptors", "/api/audit/recent", "/api/auth/session-witness", "/api/posture", "/api/evidence":
		return []string{http.MethodGet}, true
	case "/session-witness/verify":
		return []string{http.MethodGet, http.MethodPost}, true
	case "/session-witness/verify-current":
		return []string{http.MethodPost}, true
	case "/logout", "/api/warden/resolve", "/api/permits", "/ui/warden/resolve", "/ui/permits":
		return []string{http.MethodPost}, true
	case "/api/auth/session-witness/verify":
		return []string{http.MethodPost}, true
	}
	switch {
	case strings.HasPrefix(path, "/static/"):
		return []string{http.MethodGet}, true
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
		w.Header().Set("X-Janus-Build-Commit", shortCommit(buildCommit))
		w.Header().Set("X-Janus-Build-Time", cleanBuildField(buildTime))
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
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/buildz" || r.URL.Path == "/favicon.ico" {
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
			http.Redirect(w, r, loginRedirectTarget(r), http.StatusFound)
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

func (app *App) handleBuildReceipt(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schema":                  "janus-runtime-build-receipt-v1",
		"status":                  "ok",
		"service":                 "janus",
		"mode":                    app.cfg.ProductMode,
		"serving_binary":          "go-envelope",
		"engine_state":            "rust_engine_in_repo_transitional",
		"build_provenance":        BuildProvenanceFor(),
		"signed_image_expected":   true,
		"sbom_expected":           true,
		"provenance_expected":     true,
		"digest_pinned_expected":  true,
		"redacted":                true,
		"artifact_returned":       false,
		"sbom_returned":           false,
		"scanner_output_returned": false,
		"env_returned":            false,
		"backend_path_returned":   false,
		"secret_value_returned":   false,
		"value_returned":          false,
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

	if app.store != nil {
		descriptorCount = len(app.store.Descriptors())
		audit := app.store.AuditPosture()
		auditSinkReady = audit.SinkWritable
		auditChainReady = audit.ChainVerified
	}
	if app.permits != nil {
		permitStoreReady = app.permits.Posture().Persisted
	}

	checks := map[string]bool{
		"auth":             authReady,
		"descriptor_store": descriptorReady,
		"audit_sink":       auditSinkReady,
		"audit_chain":      auditChainReady,
		"permit_store":     permitStoreReady,
		"value_returned":   false,
	}
	ready := authReady && descriptorReady && auditSinkReady && auditChainReady && permitStoreReady
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
	data := app.dashboardData(r, session, nil, r.URL.Query().Get("ref"))
	applyVaultFilters(data, r)
	renderTemplate(w, app.templates, "dashboard", data)
}

func (app *App) dashboardData(r *http.Request, session Session, actionResult *UIActionResult, selectedRef string) map[string]any {
	principal := principalFromSession(session)
	descriptors := app.broker.Descriptors(principal)
	if selectedRef == "" && actionResult != nil {
		selectedRef = actionResult.SecretRef
	}
	focus := focusDescriptor(descriptors, selectedRef)
	canViewAudit := HasRole(session, RoleAuditor)
	auditPosture := app.store.AuditPosture()
	var recentAudit []AuditEntry
	if canViewAudit {
		recentAudit = app.store.RecentAudit(8)
	}
	catalogGates := ValidateCatalog(descriptors)
	accessPosture := app.accessPosture()
	rolePolicyReadiness := RolePolicyReadinessFor(app.cfg.RolePolicy, accessPosture)
	_, ready := app.readinessBody()
	scopePosture := app.scopePosture(app.store.Descriptors())
	lifecyclePosture := LifecyclePostureFor(descriptors, time.Now().UTC())
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
	if canViewAudit && app.permits != nil {
		evidencePack := app.evidencePack(session)
		if evidencePack.Integrity != nil {
			evidenceHash = evidencePack.Integrity.PackHash
			if len(evidenceHash) > 12 {
				evidenceHash = evidenceHash[:12]
			}
		}
	}
	data := map[string]any{
		"Title":               "Janus",
		"ActivePage":          "vault",
		"CSPNonce":            cspNonceFromContext(r.Context()),
		"Now":                 time.Now().UTC(),
		"VaultTiles":          vaultTilesFor(descriptors, lifecyclePosture, permitPosture),
		"View":                "grid",
		"Query":               "",
		"FilterProvider":      "",
		"FilterState":         "",
		"Providers":           descriptorProviders(descriptors),
		"TotalCount":          len(descriptors),
		"Session":             session,
		"CSRF":                app.csrfToken(session),
		"Descriptors":         descriptors,
		"Mode":                app.cfg.ProductMode,
		"Audit":               recentAudit,
		"Posture":             auditPosture,
		"CatalogGates":        catalogGates,
		"Access":              accessPosture,
		"RolePolicyReadiness": rolePolicyReadiness,
		"RoleBoundaries":      RoleBoundariesFor(session),
		"RouteGates":          RouteGateViewsFor(session, accessPosture, ready),
		"Ready":               ready,
		"AuthRequired":        app.cfg.RequireAuth,
		"OIDCConfigured":      app.cfg.OIDCConfigured(),
		"Scope":               scopePosture,
		"Lifecycle":           lifecyclePosture,
		"EvidenceHash":        evidenceHash,
		"EvidenceBoundary":    EvidenceBoundaryFor(canViewAudit, evidenceHash != ""),
		"ActionReadiness":     ActionReadinessFor(session, ready),
		"CanExportEvidence":   canViewAudit,
		"CanViewAudit":        canViewAudit,
		"CanOperate":          canOperate,
		"ActionResult":        actionResult,
		"Permits":             recentPermits,
		"PermitPosture":       permitPosture,
		"SelectedRef":         focus.Descriptor.ID,
		"Focus":               focus,
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
	if w != nil {
		applyWitnessVerificationHeaders(w, receipt)
	}
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
		"LaunchChecklist":      ReviewerLaunchChecklistFor(witness, nil),
		"Capture":              capture,
		"CaptureHeaders":       AuthenticatedBrowserCaptureHeadersFor(witness, capture, reqID, receipt),
		"CaptureLine":          receipt.Input,
		"Receipt":              receipt,
		"RequestID":            reqID,
	})
}

func (app *App) handleAuthSmokePage(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	witness, capture := app.authenticatedBrowserWitnessCapture(session)
	reqID := requestID(r)
	capturedAt := time.Now().UTC()
	receipt := AuthenticatedBrowserCaptureReceiptFor(witness, capture, reqID, capturedAt)
	applyAuthenticatedBrowserWitnessHeaders(w, witness, capture, receipt)
	app.audit(r, "auth.smoke.page", "allowed", session.Subject, "")
	renderTemplate(w, app.templates, "auth_smoke", map[string]any{
		"Title":                "Janus Auth Smoke",
		"CSPNonce":             cspNonceFromContext(r.Context()),
		"WitnessPage":          true,
		"Session":              session,
		"CSRF":                 app.csrfToken(session),
		"Mode":                 app.cfg.ProductMode,
		"AuthenticatedRole":    SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), witness.Ready),
		"AuthenticatedBrowser": witness,
		"Capture":              capture,
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
		"LaunchChecklist":      ReviewerLaunchChecklistFor(witness, verification),
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
		app.handleAuthReset(w, r)
		return
	}
	if rawNext := r.URL.Query().Get("next"); rawNext != "" {
		if returnPath, ok := safeLoginReturnPath(rawNext); ok {
			app.writeOIDCLoginReturnPath(w, returnPath)
		} else {
			app.clearOIDCLoginReturnCookie(w)
		}
	} else if _, err := firstCookie(r, app.cfg.ReturnCookieName(), returnCookie); err == nil {
		app.clearOIDCLoginReturnCookie(w)
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

func (app *App) handleAuthReset(w http.ResponseWriter, r *http.Request) {
	app.clearAllAuthCookies(w)
	app.audit(r, "auth.login.clean_reset", "allowed", "", "first party auth cookies cleared")
	renderTemplateStatus(w, app.templates, "auth_reset", http.StatusOK, AuthResetView{
		Title:         "Janus login",
		CSPNonce:      cspNonceFromContext(r.Context()),
		Mode:          app.cfg.ProductMode,
		Session:       Session{},
		CSRF:          "",
		RequestID:     requestID(r),
		Posture:       AuthFailurePostureFor(app.cfg),
		ValueReturned: false,
	})
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
	returnPath, ok := app.readOIDCLoginReturnPath(r)
	if !ok {
		returnPath = "/"
	}
	app.clearOIDCLoginCookies(w)
	app.clearOIDCLoginAttemptCookie(w)
	app.audit(r, "auth.login.complete", "allowed", session.Subject, "")
	http.Redirect(w, r, returnPath, http.StatusFound)
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.logout", "denied", session.Subject, "csrf failed")
		app.renderAuthError(w, r, http.StatusForbidden, "logout_integrity_check_failed", "Sign out needs a fresh page.")
		return
	}
	app.audit(r, "auth.logout", "allowed", session.Subject, "")
	app.clearSessionCookies(w)
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
	secondaryHref := "/auth/reset"
	secondaryText := "Reset login session"
	if reasonCode == "login_loop_paused" {
		primaryHref = "/auth/reset"
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

func loginRedirectTarget(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/login"
	}
	returnPath, ok := safeLoginReturnPath(r.URL.RequestURI())
	if !ok || returnPath == "/" {
		return "/login"
	}
	return "/login?next=" + url.QueryEscape(returnPath)
}

func safeLoginReturnPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n\t") || strings.HasPrefix(raw, "//") {
		return "/", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/", false
	}
	if u.Path == "" {
		return "/", false
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	if !loginReturnPathAllowed(cleanPath) {
		return "/", false
	}
	return cleanPath, true
}

func loginReturnPathAllowed(returnPath string) bool {
	switch returnPath {
	case "/", "/auth/smoke", "/session-witness", "/session-witness/verify":
		return true
	default:
		return false
	}
}

func (app *App) writeOIDCLoginReturnPath(w http.ResponseWriter, returnPath string) {
	returnPath, ok := safeLoginReturnPath(returnPath)
	if !ok {
		app.clearOIDCLoginReturnCookie(w)
		return
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(returnPath))
	http.SetCookie(w, &http.Cookie{
		Name:     app.cfg.ReturnCookieName(),
		Value:    payload + "." + sign(app.cfg.CookieKey, payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
}

func (app *App) readOIDCLoginReturnPath(r *http.Request) (string, bool) {
	cookie, err := firstCookie(r, app.cfg.ReturnCookieName(), returnCookie)
	if err != nil || cookie.Value == "" {
		return "/", false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 || !verify(app.cfg.CookieKey, parts[0], parts[1]) {
		return "/", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "/", false
	}
	return safeLoginReturnPath(string(raw))
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
	app.clearOIDCLoginReturnCookie(w)
}

func (app *App) clearSessionCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.SessionCookieName())
	if app.cfg.SessionCookieName() != sessionCookie {
		app.clearCookie(w, sessionCookie)
	}
}

func (app *App) clearAllAuthCookies(w http.ResponseWriter) {
	app.clearSessionCookies(w)
	app.clearOIDCLoginCookies(w)
	app.clearOIDCLoginAttemptCookie(w)
}

func (app *App) clearOIDCLoginReturnCookie(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.ReturnCookieName())
	if app.cfg.ReturnCookieName() != returnCookie {
		app.clearCookie(w, returnCookie)
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

func (app *App) audit(r *http.Request, action, outcome, actor, reason string) (AuditEntry, bool) {
	return app.auditWithRef(r, action, outcome, actor, "", reason)
}

func (app *App) auditWithRef(r *http.Request, action, outcome, actor, secretRef, reason string) (AuditEntry, bool) {
	entry := AuditEntry{
		Action:    action,
		Outcome:   outcome,
		ActorHash: actorHash(actor),
		RequestID: requestID(r),
		Method:    r.Method,
		Path:      r.URL.Path,
		SecretRef: secretRef,
		Reason:    reason,
	}
	if app.store == nil {
		return entry, false
	}
	return app.store.AppendAudit(entry)
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
	if !app.sameOriginMutation(r) {
		return false
	}
	return app.validCSRFToken(r, session)
}

func (app *App) validCSRFToken(r *http.Request, session Session) bool {
	want := app.csrfToken(session)
	if want == "" {
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

// configGates lists the configuration-level readiness gates that stay
// visible on posture surfaces (the self-hosted remainder of the former
// enterprise checks).
func configGates(cfg Config) []string {
	var issues []string
	if cfg.RequireAuth && !cfg.OIDCConfigured() {
		issues = append(issues, "Zitadel OIDC is not configured.")
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
	issues := configGates(app.cfg)
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
	authFailure := AuthFailurePostureFor(app.cfg)
	authenticatedRole := SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), ready)
	authenticatedBrowser := app.authenticatedBrowserWitness(session, authenticatedRole, ready)
	assuranceSummary := AssuranceSummaryFor(app.cfg.ProductMode, ready, len(issues), len(catalogGates), accessPosture, auditPosture, evidenceBoundary)
	assuranceGates := AssuranceGatesFor(ready, len(catalogGates), accessPosture)
	privacyPosture := PrivacyPostureFor(evidenceBoundary, auditPosture)
	negativePath := NegativePathAssuranceFor(ready, len(catalogGates), accessPosture, auditPosture)
	degradedGuidance := DegradedGuidanceFor(ready, auditPosture, evidenceBoundary)
	auditDrill := AuditFailureDrillFor(ready, auditPosture)
	roleAvailability := RoleAvailabilityFor(session)
	actionReadiness := ActionReadinessFor(session, ready)
	operationalStatus := OperationalStatusFor(ready, scopePosture, assuranceSummary, evidenceBoundary, roleAvailability)
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
		"scope":                         scopePosture,
		"lifecycle":                     lifecyclePosture,
		"approved_use":                  approvedUsePosture,
		"permits":                       permitPosture,
		"mode_posture":                  ProductModePostureFor(app.cfg, ready, issues, accessPosture, auditPosture, len(catalogGates)),
		"privacy_posture":               privacyPosture,
		"evidence_receipt":              evidenceReceipt,
		"action_readiness":              actionReadiness,
		"assurance_summary":             assuranceSummary,
		"assurance_gates":               assuranceGates,
		"negative_path_assurance":       negativePath,
		"degraded_guidance":             degradedGuidance,
		"audit_failure_drill":           auditDrill,
		"operational_status":            operationalStatus,
		"auth_failure_posture":          authFailure,
		"authenticated_role_evidence":   authenticatedRole,
		"authenticated_browser_witness": authenticatedBrowser,
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
			"route_value_leak_sentinel":     true,
			"json_errors_request_id":        true,
			"backend_source_paths":          "not_returned",
			"role_policy_proof":             "explicit_counts_no_values",
			"role_policy_readiness":         "bootstrap_to_explicit_zitadel_lanes",
			"role_claim_policy":             "explicit_only_no_ambient_grants",
			"evidence_export_boundary":      "dashboard_and_json",
			"evidence_download":             "auditor_json_with_pack_hash",
			"evidence_receipt":              "download_header_body_match",
			"auth_failure_posture":          "safe_reason_codes_no_provider_values",
			"authenticated_role_evidence":   "signed_in_role_receipt_no_identity_values",
			"authenticated_browser_witness": "signed_session_browser_proof_no_identity_values",
			"action_readiness":              "role_and_readiness_matrix",
			"action_receipts":               "mutation_result_receipts",
			"action_receipt_integrity":      "tamper_evident_hash_proof",
			"action_receipt_verification":   "copy_safe_ui_fields",
			"privacy_retention":             "dashboard_posture_evidence",
			"negative_path_assurance":       "dashboard_posture_evidence",
			"degraded_guidance":             "dashboard_posture_evidence",
			"audit_failure_drill":           "fail_closed_dashboard_posture_evidence",
			"human_readable_summary":        "dashboard_posture_evidence",
			"assurance_gate_proofs":         "role_catalog_degraded_value_leak",
			"operational_status":            "dashboard_posture_strip",
			"value_returned":                false,
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
			"evidence_export_boundary_ux",
			"role_availability_ux",
			"authenticated_role_receipt",
			"authenticated_browser_witness_api",
			"human_readable_assurance_summary",
			"operational_status_strip",
			"evidence_download_receipt",
			"exact_evidence_download_receipt",
			"role_aware_action_readiness",
			"value_free_action_receipts",
			"tamper_evident_action_receipts",
			"action_receipt_verification_ux",
			"assurance_gate_proof_strip",
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

func (app *App) scopePosture(descriptors []SecretDescriptor) ScopePosture {
	return ScopePostureFor(app.cfg.ScopePolicy, descriptors)
}

func (app *App) evidencePack(session Session) EvidencePack {
	allDescriptors := app.store.Descriptors()
	descriptors := app.cfg.ScopePolicy.Filter(allDescriptors)
	issues := configGates(app.cfg)
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
	authFailure := AuthFailurePostureFor(app.cfg)
	authenticatedRole := SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), ready)
	authenticatedBrowser := app.authenticatedBrowserWitness(session, authenticatedRole, ready)
	assuranceSummary := AssuranceSummaryFor(app.cfg.ProductMode, ready, len(issues), len(catalogGates), accessPosture, auditPosture, evidenceBoundary)
	assuranceGates := AssuranceGatesFor(ready, len(catalogGates), accessPosture)
	privacyPosture := PrivacyPostureFor(evidenceBoundary, auditPosture)
	negativePath := NegativePathAssuranceFor(ready, len(catalogGates), accessPosture, auditPosture)
	degradedGuidance := DegradedGuidanceFor(ready, auditPosture, evidenceBoundary)
	auditDrill := AuditFailureDrillFor(ready, auditPosture)
	actionReadiness := ActionReadinessFor(session, ready)
	operationalStatus := OperationalStatusFor(ready, scopePosture, assuranceSummary, evidenceBoundary, RoleAvailabilityFor(session))
	pack := EvidencePack{
		GeneratedAt:          time.Now().UTC(),
		Service:              "janus",
		Mode:                 app.cfg.ProductMode,
		Posture:              app.postureBody(session),
		Operational:          operationalStatus,
		AuthFailure:          authFailure,
		AuthenticatedRole:    authenticatedRole,
		AuthenticatedBrowser: authenticatedBrowser,
		RolePolicyReadiness:  rolePolicyReadiness,
		ActionReadiness:      actionReadiness,
		AssuranceGates:       assuranceGates,
		NegativePath:         negativePath,
		Guidance:             degradedGuidance,
		AuditDrill:           auditDrill,
		AssuranceSummary:     assuranceSummary,
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
	t := template.Must(template.New("janus").Funcs(template.FuncMap{
		"buildCommitShort": func() string { return shortCommit(buildCommit) },
		"since":            humanSince,
	}).Parse(`
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
      overflow-x: hidden;
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
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 760; letter-spacing: 0; min-width: 0; }
    .brand small { color: var(--muted); font-size: 12px; font-weight: 700; overflow-wrap: anywhere; }
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
    .toolbar form { min-width: 0; }
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
    .reviewer-step.warn strong { color: var(--amber); }
    .reviewer-step.action { align-content: center; justify-items: stretch; }
    .reviewer-step.action form { display: grid; }
    .reviewer-step.action .button { width: 100%; }
    .evidence-workstation {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: color-mix(in srgb, var(--accent) 4%, var(--panel-soft));
      padding: 12px;
      display: grid;
      gap: 12px;
      min-width: 0;
    }
    .workstation-head {
      display: grid;
      gap: 4px;
      min-width: 0;
    }
    .workstation-head span {
      color: var(--accent);
      font-weight: 720;
      font-size: 12px;
      line-height: 1.15;
    }
    .workstation-head strong {
      font-size: 18px;
      line-height: 1.15;
      overflow-wrap: anywhere;
    }
    .workstation-head p { font-size: 13px; line-height: 1.35; }
    .handoff-path {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      align-items: stretch;
      min-width: 0;
    }
    .handoff-step {
      min-height: 154px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 12px;
      display: grid;
      grid-template-rows: auto auto 1fr auto;
      gap: 8px;
      min-width: 0;
    }
    .handoff-step b {
      width: 26px;
      height: 26px;
      border-radius: 999px;
      display: inline-grid;
      place-items: center;
      background: var(--ink);
      color: var(--panel);
      font-size: 12px;
      line-height: 1;
    }
    .handoff-step strong {
      font-size: 16px;
      line-height: 1.15;
      overflow-wrap: anywhere;
    }
    .handoff-step p { font-size: 13px; line-height: 1.35; }
    .handoff-step.ok { border-color: color-mix(in srgb, var(--accent) 42%, var(--line)); }
    .handoff-step.info { border-color: color-mix(in srgb, var(--blue) 36%, var(--line)); }
    .handoff-step.warn { border-color: color-mix(in srgb, var(--amber) 40%, var(--line)); }
    .handoff-step.ok strong { color: var(--accent); }
    .handoff-step.info strong { color: var(--blue); }
    .handoff-step.warn strong { color: var(--amber); }
    .handoff-actions {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }
    .handoff-step form { display: grid; min-width: 0; }
    .handoff-step .button { width: 100%; min-width: 0; overflow-wrap: anywhere; }
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
      .handoff-path { grid-template-columns: 1fr; }
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
      .handoff-path { grid-template-columns: 1fr; }
      .handoff-step { min-height: auto; }
      .handoff-actions { grid-template-columns: 1fr; }
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
      main, .overview, .intro, .status, .panel, .intro-copy, .toolbar, .evidence-workstation, .handoff-path, .handoff-step, .workstation-head {
        min-width: 0;
        max-width: 100%;
      }
      .intro-copy p, .workstation-head p, .handoff-step p {
        max-width: 100%;
        overflow-wrap: anywhere;
      }
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
    <div class="brand"><div class="mark">J</div><div>Janus</div><small>build {{ buildCommitShort }}</small></div>
		    {{ if .Session.Subject }}
		    <nav class="nav" aria-label="Primary">
			      {{ if .WitnessPage }}
			      <a href="/">Dashboard</a>
			      <a href="/auth/smoke">Smoke</a>
			      <a href="/session-witness">Witness</a>
			      <a href="/session-witness.txt">Text</a>
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

		{{ define "auth_smoke" -}}
		{{ template "base_top" . }}
		<section class="overview" id="command-center">
		  <div class="intro">
		    <div class="intro-copy">
		      <div class="eyebrow">{{ .Mode }} / browser smoke / value-free</div>
		      <h1>Authenticated smoke</h1>
		      <p>A short proof path for this browser: reset stale login state, prove the signed session, then keep one receipt hash. Identity and secret values stay out of the page.</p>
		    </div>
		    <div class="toolbar">
		      <a class="button primary" href="/auth/reset">Clean sign-in reset</a>
		      <a class="button quiet" href="/session-witness">Full witness</a>
		      <a class="button quiet" href="/session-witness/verify">Verifier</a>
		      <a class="button quiet" href="/">Dashboard</a>
		    </div>
		    <div class="evidence-workstation" aria-label="Authenticated browser smoke path">
		      <div class="workstation-head">
		        <span>Smoke path</span>
		        <strong>Three checks, one receipt</strong>
		        <p>Use this page after login. It keeps the browser flow simple and leaves the heavy witness tools one click away.</p>
		      </div>
		      <div class="handoff-path">
		        <div class="handoff-step info">
		          <b>1</b>
		          <strong>Clean start</strong>
		          <p>If the browser feels stale, clear Janus auth cookies and start a fresh Zitadel login.</p>
		          <a class="button quiet" href="/auth/reset">Reset sign-in</a>
		        </div>
		        <div class="handoff-step ok">
		          <b>2</b>
		          <strong>Prove session</strong>
		          <p>This browser reached an auth-only page and has a signed Janus session. The proof is the request id and witness hash.</p>
		          <a class="button primary" href="/session-witness">Session witness</a>
		        </div>
		        <div class="handoff-step ok">
		          <b>3</b>
		          <strong>Keep receipt</strong>
		          <p>Keep the request id and hash. Do not copy identity values, cookies, tokens, request bodies, or secret material.</p>
		          <a class="button quiet" href="/session-witness/verify">Open verifier</a>
		        </div>
		      </div>
		      <p><span class="pill ok">auth_smoke_launchpad=true</span> <span class="pill ok">csrf_bound=true</span> <span class="pill ok">value_returned=false</span></p>
		    </div>
		    <div class="safety-ribbon" aria-label="Authenticated smoke posture">
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
		    </div>
		  </div>
		  <div class="status">
		    <div class="status-head"><h2>Receipt proof</h2><span class="pill ok">copy-safe</span></div>
		    <div class="panel-body stack">
		      <div class="receipt-proof" aria-label="Authenticated smoke receipt proof">
		        <span>Schema<strong>{{ .Capture.Schema }}</strong></span>
		        <span>Body field<strong>{{ .Capture.BodyField }}</strong></span>
		        <span>Signal<strong>{{ .AuthenticatedBrowser.EvidenceSignal }}</strong></span>
		        <span>Fresh until<strong>{{ .Receipt.FreshUntil }}</strong></span>
		        <span>Hash header<strong>{{ .Receipt.HashHeader }}</strong></span>
		        <span>Proof hash<strong class="mono">{{ .Receipt.Hash }}</strong></span>
		      </div>
		      <div class="receipt-copy" aria-label="Authenticated smoke copy-safe fields">
		        <label>State<input readonly value="state={{ .AuthenticatedBrowser.State }}"></label>
		        <label>Flow<input readonly value="flow={{ .AuthenticatedBrowser.Flow }}"></label>
		        <label>Request<input readonly value="request_id={{ .RequestID }}"></label>
		        <label>Hash<input readonly value="proof_hash={{ .Receipt.Hash }}"></label>
		      </div>
		      <div class="witness-grid" aria-label="Authenticated smoke guardrails">
		        <div class="witness-card ok">
		          <span>Login</span>
		          <strong>{{ .AuthenticatedRole.IdentityLabel }}</strong>
		          <p>{{ .AuthenticatedRole.IdentityBoundary }}</p>
		        </div>
		        <div class="witness-card ok">
		          <span>Cookie</span>
		          <strong>{{ .AuthenticatedBrowser.SessionCookiePolicy }}</strong>
		          <p>Session proof is signed and cookie values are never rendered.</p>
		        </div>
		        <div class="witness-card ok">
		          <span>CSRF</span>
		          <strong>{{ .AuthenticatedBrowser.CSRFBoundary }}</strong>
		          <p>The receipt action is bound to this signed browser session.</p>
		        </div>
		        <div class="witness-card ok">
		          <span>Page</span>
		          <strong>{{ .AuthenticatedBrowser.CSPBoundary }}</strong>
		          <p>The smoke page renders without browser script and with hardened headers.</p>
		        </div>
		      </div>
		      <details class="evidence-flags">
		        <summary>Authenticated smoke evidence flags</summary>
		        <div class="flag-cloud" aria-label="Authenticated smoke value-free evidence flags">
		          <span class="pill ok">authenticated_smoke_launchpad=true</span>
		          <span class="pill ok">state={{ .AuthenticatedBrowser.State }}</span>
		          <span class="pill ok">flow={{ .AuthenticatedBrowser.Flow }}</span>
		          <span class="pill ok">request_id={{ .RequestID }}</span>
		          <span class="pill ok">proof_hash_header={{ .Receipt.HashHeader }}</span>
		          <span class="pill ok">hash_body_field={{ .Receipt.BodyField }}</span>
		          <span class="pill ok">freshness_seconds={{ .Receipt.FreshnessSeconds }}</span>
		          <span class="pill ok">identity_values_returned=false</span>
		          <span class="pill ok">subject_returned=false</span>
		          <span class="pill ok">email_returned=false</span>
		          <span class="pill ok">name_returned=false</span>
		          <span class="pill ok">claim_values_returned=false</span>
		          <span class="pill ok">group_values_returned=false</span>
		          <span class="pill ok">token_returned=false</span>
		          <span class="pill ok">cookie_value_returned=false</span>
		          <span class="pill ok">request_body_returned=false</span>
		          <span class="pill ok">proof_body_returned=false</span>
		          <span class="pill ok">env_returned=false</span>
		          <span class="pill ok">backend_path_returned=false</span>
		          <span class="pill ok">secret_value_returned=false</span>
		          <span class="pill ok">value_returned=false</span>
		        </div>
		      </details>
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
	      <p>Checks copy-safe evidence and proof receipts. Pasted input is not returned.</p>
	    </div>
	    <div class="toolbar">
	      <a class="button quiet" href="/session-witness">Witness</a>
	      <a class="button quiet" href="/session-witness.txt">Proof text</a>
	      <a class="button quiet" href="/api/auth/session-witness">Witness JSON</a>
		      <form method="post" action="/session-witness/verify-current">
		        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
		        <button class="button quiet" type="submit">Verify current session</button>
		      </form>
	      <a class="button quiet" href="/">Dashboard</a>
	    </div>
	    <div class="evidence-workstation" aria-label="Evidence verification workstation">
	      <div class="workstation-head">
	        <span>Evidence workstation</span>
	        <strong>Verify without pasting values</strong>
	        <p>One click verifies the current session witness receipt.</p>
	      </div>
	      <div class="handoff-path">
	        <div class="handoff-step ok">
	          <b>1</b>
	          <strong>Verify this session</strong>
	          <p>Runs the current witness roundtrip. No paste needed.</p>
		          <form method="post" action="/session-witness/verify-current">
		            <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
		            <button class="button primary" type="submit">Verify current session</button>
		          </form>
	        </div>
	        <div class="handoff-step info">
	          <b>2</b>
	          <strong>Paste a proof line</strong>
	          <p>Use this when a reviewer sends a proof line and hash from another browser session.</p>
	          <a class="button quiet" href="#proof-line-form">Paste proof line</a>
	        </div>
	        <div class="handoff-step ok">
	          <b>3</b>
	          <strong>Keep the receipt</strong>
	          <p>Verification returns normalized facts and a receipt hash, never the submitted input.</p>
	          <a class="button quiet" href="/session-witness.txt">Open proof text</a>
	        </div>
	      </div>
	      <p><span class="pill ok">input_not_returned=true</span> <span class="pill ok">request_body_returned=false</span> <span class="pill ok">value_returned=false</span></p>
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
	    <div class="reviewer-flow" aria-label="Reviewer launch checklist">
	      {{ range .LaunchChecklist }}
	      <div class="reviewer-step {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	      </div>
	      {{ end }}
	    </div>
	  </div>
	  <div class="status" id="proof-line-form">
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
	      <a class="button quiet" href="/">Dashboard</a>
	      <a class="button quiet" href="/session-witness.txt">Proof text</a>
	      <a class="button quiet" href="/session-witness/verify">Verify proof</a>
	      <a class="button quiet" href="/api/auth/session-witness">Witness JSON</a>
	    </div>
	    <div class="evidence-workstation" aria-label="Evidence handoff workstation">
	      <div class="workstation-head">
	        <span>Evidence handoff</span>
	        <strong>Capture, verify, retain</strong>
	        <p>Capture the copy-safe session witness, verify it, then keep the receipt.</p>
	      </div>
	      <div class="handoff-path">
	        <div class="handoff-step ok">
	          <b>1</b>
	          <strong>Capture the witness</strong>
	          <p>This page is the capture: a copy-safe proof line and hash for the signed session.</p>
	          <a class="button quiet" href="/session-witness.txt">Open proof text</a>
	        </div>
	        <div class="handoff-step ok">
	          <b>2</b>
	          <strong>Verify the session</strong>
	          <p>The verifier checks the current session or a pasted proof line without returning the input.</p>
	          <a class="button primary" href="/session-witness/verify">Open verifier</a>
	        </div>
	        <div class="handoff-step info">
	          <b>3</b>
	          <strong>Keep the receipt</strong>
	          <p>Keep the request id and proof hash. Identity, cookie, and secret values stay out.</p>
	        </div>
	      </div>
	      <p><span class="pill ok">current_session_verifier=true</span> <span class="pill ok">value_returned=false</span></p>
	    </div>
	    <div class="reviewer-flow" aria-label="Reviewer launch checklist">
	      {{ range .LaunchChecklist }}
	      <div class="reviewer-step {{ .Tone }}">
	        <span>{{ .Label }}</span>
	        <strong>{{ .State }}</strong>
	        <p>{{ .Detail }}</p>
	      </div>
	      {{ end }}
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

	{{ define "auth_reset" -}}
	{{ template "base_top" . }}
	<section class="overview">
	  <div class="intro">
	    <div class="intro-copy">
	      <div class="eyebrow">{{ .Mode }} / login recovery</div>
	      <h1>Clean sign-in reset</h1>
	      <p>Janus cleared its own session and temporary login cookies. Start sign-in again from a clean Janus page.</p>
	      <p>If the identity provider itself still loops, use a fresh browser profile or clear that provider session outside Janus.</p>
	    </div>
	    <div class="toolbar">
	      <a class="button primary" href="/login">Sign in cleanly</a>
	      <a class="button quiet" href="/">Return to Janus</a>
	    </div>
	  </div>
	  <div class="status">
	    <div class="status-head"><h2>Auth recovery</h2><span class="pill ok">reset_complete</span></div>
	    <div class="panel-body stack">
	      <p>Only first-party Janus cookies were cleared. No token, cookie value, provider detail, or identity value is returned.</p>
	      <p><span class="pill ok">session_cookie_cleared=true</span> <span class="pill ok">oidc_cookies_cleared=true</span> <span class="pill ok">attempt_cookie_cleared=true</span> <span class="pill ok">cookie_value_returned=false</span> <span class="pill ok">value_returned=false</span></p>
	      <p class="mono">request_id={{ .RequestID }}</p>
	      <div class="mode-grid" aria-label="Clean sign-in reset posture">
	        <div class="mode-item ok">
	          <span>Session</span>
	          <strong>cleared</strong>
	          <p>Janus session cookies are expired before the next login starts.</p>
	        </div>
	        <div class="mode-item ok">
	          <span>Login attempt</span>
	          <strong>fresh</strong>
	          <p>State, nonce, PKCE, and loop-guard cookies are expired.</p>
	        </div>
	        <div class="mode-item info">
	          <span>Boundary</span>
	          <strong>first party</strong>
	          <p>Provider cookies are not read or shown by Janus.</p>
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
	      <a class="button quiet" href="/auth/reset">Reset sign-in</a>
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
	return template.Must(t.ParseFS(vaultTemplateFS, "ui/*.html"))
}
