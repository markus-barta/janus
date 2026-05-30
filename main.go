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
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "janus_session"
	stateCookie   = "janus_oidc_state"
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
	Status         string    `json:"status"`
	RevealAllowed  bool      `json:"reveal_allowed"`
	UseEnabled     bool      `json:"use_enabled"`
	ConsumerCount  int       `json:"consumer_count"`
	EgressMode     string    `json:"egress_mode,omitempty"`
	Tags           []string  `json:"tags"`
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
	app := &App{
		cfg:       cfg,
		store:     store,
		broker:    NewBroker(store).WithScopePolicy(cfg.ScopePolicy),
		permits:   NewPermitStore(),
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
	mux.HandleFunc("GET /api/warden/descriptors", app.withAuth(app.handleDescriptors))
	mux.HandleFunc("POST /api/warden/resolve", app.withAuth(app.handleResolveHandle))
	mux.HandleFunc("GET /api/audit/recent", app.withAuth(app.requireRole(RoleAuditor, "audit.recent", app.handleRecentAudit)))
	mux.HandleFunc("GET /api/posture", app.withAuth(app.handlePosture))
	mux.HandleFunc("GET /api/evidence", app.withAuth(app.requireRole(RoleAuditor, "evidence.export", app.handleEvidence)))
	mux.HandleFunc("POST /api/permits", app.withAuth(app.handleCreatePermit))
	mux.HandleFunc("POST /api/permits/{permitID}/run", app.withAuth(app.handleRunPermit))
	mux.HandleFunc("GET /", app.withAuth(app.handleDashboard))
	return app.securityHeaders(app.rateLimit(mux))
}

func (app *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if app.cfg.SecureCookies() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
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
			writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
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
			app.renderSetup(w, r)
			return
		}

		session, ok := app.readSession(r)
		if !ok {
			app.audit(r, "auth.required", "denied", "", "missing session")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session)))
	}
}

func (app *App) requireRole(role, action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := currentSession(r.Context())
		if !HasRole(session, role) {
			app.audit(r, action, "denied", session.Subject, "role "+role+" required")
			writeJSONError(w, http.StatusForbidden, "role_denied", role+" role required")
			return
		}
		next(w, r)
	}
}

func (app *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "ok",
		"service":         "janus",
		"oidc_configured": app.cfg.OIDCConfigured(),
	})
}

func (app *App) handleReady(w http.ResponseWriter, _ *http.Request) {
	ready := !app.cfg.RequireAuth || app.cfg.OIDCConfigured()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ready":           ready,
		"auth_required":   app.cfg.RequireAuth,
		"oidc_configured": app.cfg.OIDCConfigured(),
	})
}

func (app *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	app.audit(r, "dashboard.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	principal := principalFromSession(session)
	descriptors := app.broker.Descriptors(principal)
	issues := enterpriseChecks(app.cfg)
	auditPosture := app.store.AuditPosture()
	recentAudit := app.store.RecentAudit(8)
	catalogGates := ValidateCatalog(descriptors)
	accessPosture := app.accessPosture()
	scopePosture := app.scopePosture(app.store.Descriptors())
	evidencePack := app.evidencePack()
	evidenceHash := ""
	if evidencePack.Integrity != nil {
		evidenceHash = evidencePack.Integrity.PackHash
		if len(evidenceHash) > 12 {
			evidenceHash = evidenceHash[:12]
		}
	}
	data := map[string]any{
		"Title":             "Janus",
		"Session":           session,
		"CSRF":              app.csrfToken(session),
		"Descriptors":       descriptors,
		"Issues":            issues,
		"Mode":              app.cfg.ProductMode,
		"Audit":             recentAudit,
		"Posture":           auditPosture,
		"CatalogGates":      catalogGates,
		"Access":            accessPosture,
		"Scope":             scopePosture,
		"EvidenceHash":      evidenceHash,
		"CanExportEvidence": HasRole(session, RoleAuditor),
	}
	renderTemplate(w, app.templates, "dashboard", data)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"audit":          app.store.RecentAudit(50),
		"posture":        app.store.AuditPosture(),
		"value_returned": false,
	})
}

func (app *App) handlePosture(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	app.audit(r, "posture.view", "allowed", session.Subject, "")
	writeJSON(w, http.StatusOK, app.postureBody())
}

func (app *App) handleEvidence(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	app.audit(r, "evidence.export", "allowed", session.Subject, "")
	writeJSON(w, http.StatusOK, app.evidencePack())
}

func (app *App) handleResolveHandle(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "warden.resolve", "denied", session.Subject, "csrf failed")
		writeJSONError(w, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}

	var req HandleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	handle, err := app.broker.ResolveHandle(principalFromSession(session), req)
	if err != nil {
		app.handleBrokerError(w, r, "warden.resolve", session.Subject, req.Ref, err)
		return
	}
	app.auditWithRef(r, "warden.resolve", "allowed", session.Subject, handle.SecretRef, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"handle":         handle,
		"value_returned": false,
	})
}

func (app *App) handleCreatePermit(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "permit.create", "denied", session.Subject, "csrf failed")
		writeJSONError(w, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}

	var req PermitRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	permit, err := app.broker.CreatePermit(principalFromSession(session), req)
	if err != nil {
		app.handleBrokerError(w, r, "permit.create", session.Subject, req.Ref, err)
		return
	}
	app.permits.Put(permit)
	app.auditWithRef(r, "permit.create", permit.Status, session.Subject, permit.SecretRef, permit.DenialReason)
	writeJSON(w, http.StatusCreated, map[string]any{
		"permit":         permit,
		"value_returned": false,
	})
}

func (app *App) handleRunPermit(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "permit.run", "denied", session.Subject, "csrf failed")
		writeJSONError(w, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}

	permitID := r.PathValue("permitID")
	permit, ok := app.permits.Get(permitID)
	if !ok {
		app.audit(r, "permit.run", "denied", session.Subject, "permit not found")
		writeJSONError(w, http.StatusNotFound, "permit_not_found", "Permit not found")
		return
	}
	result := RunPermit(permit)
	app.auditWithRef(r, "permit.run", result.Status, session.Subject, permit.SecretRef, result.Reason)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"result":         result,
		"value_returned": false,
	})
}

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !app.cfg.OIDCConfigured() || app.oauth == nil {
		app.renderSetup(w, r)
		return
	}

	state := randomToken(32)
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	app.audit(r, "auth.login.start", "allowed", "", "")
	http.Redirect(w, r, app.oauth.AuthCodeURL(state), http.StatusFound)
}

func (app *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	if !app.cfg.OIDCConfigured() || app.oauth == nil || app.verifier == nil {
		app.renderSetup(w, r)
		return
	}

	state, err := r.Cookie(stateCookie)
	if err != nil || state.Value == "" || state.Value != r.URL.Query().Get("state") {
		app.audit(r, "auth.login.callback", "denied", "", "bad state")
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}

	token, err := app.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		app.audit(r, "auth.login.callback", "denied", "", "code exchange failed")
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		app.audit(r, "auth.login.callback", "denied", "", "missing id token")
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	idToken, err := app.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		app.audit(r, "auth.login.callback", "denied", "", "id token verify failed")
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	var claims struct {
		Subject      string         `json:"sub"`
		Email        string         `json:"email"`
		Name         string         `json:"name"`
		Groups       []string       `json:"groups"`
		Roles        []string       `json:"roles"`
		ProjectRoles map[string]any `json:"urn:zitadel:iam:org:project:roles"`
	}
	if err := idToken.Claims(&claims); err != nil {
		app.audit(r, "auth.login.callback", "denied", "", "claims failed")
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	if claims.Subject == "" {
		app.audit(r, "auth.login.callback", "denied", "", "missing subject")
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	session := Session{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Roles:   DeriveRoles(claims.Subject, claims.Email, ClaimRoleInputs(claims.Groups, claims.Roles, claims.ProjectRoles), app.cfg.RolePolicy),
		Expiry:  time.Now().UTC().Add(12 * time.Hour),
	}
	app.writeSession(w, session)
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: app.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode})
	app.audit(r, "auth.login.complete", "allowed", session.Subject, "")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "auth.logout", "denied", session.Subject, "csrf failed")
		http.Error(w, "CSRF token required", http.StatusForbidden)
		return
	}
	app.audit(r, "auth.logout", "allowed", session.Subject, "")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (app *App) renderSetup(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "setup.view", "allowed", "", "auth incomplete")
	renderTemplateStatus(w, app.templates, "setup", http.StatusServiceUnavailable, map[string]any{
		"Title":   "Janus setup",
		"Mode":    app.cfg.ProductMode,
		"Session": Session{},
		"Issues": []string{
			"OIDC issuer, client id, client secret, and cookie key must be present before Janus exposes secret metadata.",
			"The service is live, but locked to setup status until Zitadel credentials are configured.",
		},
	})
}

func (app *App) writeSession(w http.ResponseWriter, s Session) {
	raw, _ := json.Marshal(s)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := sign(app.cfg.CookieKey, payload)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    payload + "." + mac,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Until(s.Expiry).Seconds()),
	})
}

func (app *App) readSession(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie(sessionCookie)
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

func (app *App) audit(r *http.Request, action, outcome, actor, reason string) {
	app.auditWithRef(r, action, outcome, actor, "", reason)
}

func (app *App) auditWithRef(r *http.Request, action, outcome, actor, secretRef, reason string) {
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

func currentSession(ctx context.Context) Session {
	session, _ := ctx.Value(sessionKey{}).(Session)
	return session
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
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		if err := r.ParseForm(); err == nil {
			got = r.Form.Get("csrf_token")
		}
	}
	return hmac.Equal([]byte(want), []byte(got))
}

func (app *App) csrfAllowed(r *http.Request, session Session) bool {
	if !app.cfg.RequireAuth {
		return true
	}
	return app.verifyCSRF(r, session)
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
	for _, header := range []string{"Cf-Ray", "X-Request-Id", "X-Correlation-Id"} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			return value
		}
	}
	return randomToken(12)
}

func randomToken(n int) string {
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
	var issues []string
	if cfg.RequireAuth && !cfg.OIDCConfigured() {
		issues = append(issues, "Zitadel OIDC is not configured.")
	}
	if cfg.ProductMode == "enterprise" && os.Getenv("JANUS_REMOTE_AUDIT") == "" {
		issues = append(issues, "Enterprise mode needs remote audit shipping before production use.")
	}
	if cfg.ProductMode == "enterprise" && os.Getenv("JANUS_BREAK_GLASS_REVIEW") == "" {
		issues = append(issues, "Enterprise mode needs a documented break-glass review owner.")
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

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error":          code,
		"message":        message,
		"value_returned": false,
	})
}

func (app *App) postureBody() map[string]any {
	allDescriptors := app.store.Descriptors()
	descriptors := app.cfg.ScopePolicy.Filter(allDescriptors)
	issues := enterpriseChecks(app.cfg)
	catalogGates := ValidateCatalog(descriptors)
	accessPosture := app.accessPosture()
	scopePosture := app.scopePosture(allDescriptors)
	return map[string]any{
		"service":            "janus",
		"mode":               app.cfg.ProductMode,
		"auth_required":      app.cfg.RequireAuth,
		"oidc_configured":    app.cfg.OIDCConfigured(),
		"descriptor_count":   len(descriptors),
		"open_gates":         len(issues),
		"gates":              issues,
		"catalog_gates":      catalogGates,
		"catalog_gate_count": len(catalogGates),
		"access":             accessPosture,
		"scope":              scopePosture,
		"audit":              app.store.AuditPosture(),
		"capabilities": []string{
			"value_free_metadata_catalog",
			"broker_principal_chain",
			"warden_handle_only",
			"permit_noop_execution",
			"csrf_guarded_mutations",
			"rate_limited_runtime",
			"role_gated_audit_evidence",
			"scope_bound_metadata",
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

func (app *App) evidencePack() EvidencePack {
	allDescriptors := app.store.Descriptors()
	descriptors := app.cfg.ScopePolicy.Filter(allDescriptors)
	pack := EvidencePack{
		GeneratedAt:    time.Now().UTC(),
		Service:        "janus",
		Mode:           app.cfg.ProductMode,
		Posture:        app.postureBody(),
		Descriptors:    descriptors,
		CatalogGates:   ValidateCatalog(descriptors),
		ScopePosture:   app.scopePosture(allDescriptors),
		AccessPosture:  app.accessPosture(),
		AuditPosture:   app.store.AuditPosture(),
		RecentAudit:    app.store.RecentAudit(50),
		ValueReturned:  false,
		RedactionModel: "metadata-only; secret values are not stored, read, rendered, logged, or exported by Janus V1.x",
	}
	integrity := EvidenceIntegrityFor(pack)
	pack.Integrity = &integrity
	return pack
}

func (app *App) handleBrokerError(w http.ResponseWriter, r *http.Request, action, actor, ref string, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		app.auditWithRef(r, action, "denied", actor, "", "not found")
		writeJSONError(w, http.StatusNotFound, "not_found", "Descriptor not found")
	case errors.Is(err, ErrPolicyDenied):
		app.auditWithRef(r, action, "denied", actor, "", err.Error())
		writeJSONError(w, http.StatusForbidden, "policy_denied", err.Error())
	default:
		app.auditWithRef(r, action, "denied", actor, "", "broker error")
		writeJSONError(w, http.StatusBadRequest, "broker_error", err.Error())
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
			RotationDays:   180,
			LastCheckedAt:  now,
			Status:         "managed",
			RevealAllowed:  false,
			Tags:           []string{"identity", "oidc"},
		},
		{
			ID:             "csb1-age-identity",
			DisplayName:    "csb1 age identity",
			Provider:       "agenix",
			Classification: "critical",
			Owner:          "platform",
			RotationDays:   365,
			LastCheckedAt:  now,
			Status:         "external",
			RevealAllowed:  false,
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
  <style>
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
    }
    header {
      border-bottom: 1px solid var(--line);
      background: color-mix(in srgb, var(--panel) 90%, transparent);
      position: sticky;
      top: 0;
      z-index: 20;
      backdrop-filter: blur(16px);
    }
    .bar, main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; }
    .bar {
      min-height: 66px;
      display: grid;
      grid-template-columns: auto 1fr auto;
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
    main { padding: 26px 0 52px; }
    h1 { margin: 0; font-size: 40px; line-height: 1.04; letter-spacing: 0; }
    h2 { margin: 0; font-size: 18px; letter-spacing: 0; }
    h3 { margin: 0; font-size: 14px; letter-spacing: 0; }
    p { margin: 0; color: var(--muted); }
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
      white-space: nowrap;
    }
    .primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
    .quiet { background: var(--panel-soft); }
    .overview {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(340px, .9fr);
      gap: 18px;
      align-items: stretch;
      margin-bottom: 16px;
    }
    .intro, .status, .panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      box-shadow: var(--shadow);
    }
    .intro { padding: 22px; display: grid; gap: 16px; align-content: center; }
    .intro-copy { max-width: 720px; display: grid; gap: 10px; }
    .eyebrow { color: var(--accent); font-weight: 720; font-size: 13px; letter-spacing: 0; }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; }
    .status { padding: 0; overflow: hidden; }
    .status-head, .panel-head {
      padding: 15px 16px;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
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
    .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; margin-bottom: 16px; }
    .panel { grid-column: span 12; overflow: hidden; }
    .panel.half { grid-column: span 6; }
    .panel-body { padding: 16px; }
    .facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); border-top: 1px solid var(--line); margin-top: 14px; }
    .fact { padding: 13px 14px 0 0; min-width: 0; }
    .fact strong { display: block; font-size: 22px; line-height: 1.1; overflow-wrap: anywhere; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; min-width: 900px; }
    th, td { padding: 12px 16px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0; }
    tr:hover td { background: var(--panel-soft); }
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
      white-space: nowrap;
      max-width: 100%;
    }
    .pill.ok { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 46%, var(--line)); }
    .pill.info { color: var(--blue); border-color: color-mix(in srgb, var(--blue) 46%, var(--line)); }
    .pill.warn { color: var(--amber); border-color: color-mix(in srgb, var(--amber) 46%, var(--line)); }
    .stack { display: grid; gap: 8px; }
    .muted { color: var(--muted); }
    .warn { color: var(--amber); }
    .danger { color: var(--danger); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    form { margin: 0; }
    @media (max-width: 860px) {
      .bar { grid-template-columns: 1fr auto; padding: 12px 0; }
      .nav { grid-column: 1 / -1; justify-content: flex-start; overflow-x: auto; padding-bottom: 2px; }
      .overview { grid-template-columns: 1fr; }
      .panel.half { grid-column: span 12; }
      .facts { grid-template-columns: 1fr; gap: 10px; }
      h1 { font-size: 32px; }
    }
    @media (max-width: 560px) {
      .bar, main { width: min(100% - 22px, 1180px); }
      .status-body { grid-template-columns: 1fr; }
      .signal { border-right: 0; }
      .toolbar { display: grid; grid-template-columns: 1fr; }
      .toolbar .button { width: 100%; }
    }
  </style>
</head>
<body>
<header>
  <div class="bar">
    <div class="brand"><div class="mark">J</div><div>Janus</div></div>
    {{ if .Session.Subject }}
    <nav class="nav" aria-label="Primary">
      <a href="#overview">Overview</a>
      <a href="#posture">Posture</a>
      <a href="#audit">Audit</a>
      <a href="#catalog">Catalog</a>
    </nav>
    {{ else }}
    <div></div>
    {{ end }}
    {{ if .Session.Subject }}
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
      <div class="eyebrow">{{ .Mode }} / metadata-only</div>
      <h1>Vault control plane</h1>
      <p>Ownership, posture, and audit-safe descriptors for secrets. Secret values stay outside Janus.</p>
    </div>
    <div class="toolbar">
      {{ if .CanExportEvidence }}<a class="button primary" href="/api/evidence">Evidence JSON</a>{{ end }}
      <a class="button quiet" href="/api/posture">Posture JSON</a>
      <a class="button quiet" href="/api/warden/descriptors">Descriptors JSON</a>
    </div>
  </div>
  <div class="status">
    <div class="status-head">
      <h2>Live posture</h2>
      {{ if .Issues }}<span class="pill warn">{{ len .Issues }} gates</span>{{ else }}<span class="pill ok">ready</span>{{ end }}
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
        <span class="muted">Audit chain</span>
        {{ if .Posture.ChainVerified }}<strong>verified</strong><span class="pill ok">hash chained</span>{{ else }}<strong>review</strong><span class="pill warn">needs review</span>{{ end }}
      </div>
      <div class="signal">
        <span class="muted">Evidence hash</span>
        <strong class="mono">{{ if .EvidenceHash }}{{ .EvidenceHash }}{{ else }}pending{{ end }}</strong>
        <span class="pill info">sha256</span>
      </div>
    </div>
  </div>
</section>
{{ if .Issues }}
<section class="panel" style="margin-bottom:16px" id="gates">
  <div class="panel-head"><h2>Readiness gates</h2><span class="pill warn">action needed</span></div>
  <div class="panel-body stack">
    {{ range .Issues }}<p class="warn">{{ . }}</p>{{ end }}
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
        <div class="fact"><strong>auditor</strong><span class="muted">evidence role</span></div>
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
</section>
<section class="grid" id="audit">
  <div class="panel">
    <div class="panel-head">
      <h2>Audit posture</h2>
      {{ if .Posture.LegacyEntries }}<span class="pill warn">chain partial</span>{{ else if .Posture.ChainVerified }}<span class="pill ok">chain verified</span>{{ else }}<span class="pill warn">chain needs review</span>{{ end }}
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Action</th><th>Outcome</th><th>Method</th><th>Path</th><th>Secret ref</th><th>Reason</th></tr></thead>
        <tbody>
        {{ range .Audit }}
          <tr>
            <td>{{ .Time.Format "15:04:05" }}</td>
            <td>{{ .Action }}</td>
            <td>{{ .Outcome }}</td>
            <td>{{ .Method }}</td>
            <td>{{ .Path }}</td>
            <td>{{ if .SecretRef }}{{ .SecretRef }}{{ else }}<span class="muted">none</span>{{ end }}</td>
            <td>{{ if .Reason }}{{ .Reason }}{{ else }}<span class="muted">none</span>{{ end }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
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
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Provider</th><th>Scope</th><th>Owner</th><th>Class</th><th>Status</th><th>Consumers</th><th>Rotation</th><th>Use</th><th>Reveal</th></tr></thead>
        <tbody>
        {{ range .Descriptors }}
          <tr>
            <td><strong>{{ .DisplayName }}</strong><br><span class="muted">{{ .ID }}</span></td>
            <td>{{ .Provider }}</td>
            <td>{{ .Scope }}</td>
            <td>{{ .Owner }}</td>
            <td>{{ .Classification }}</td>
            <td>{{ .Status }}</td>
            <td>{{ .ConsumerCount }}</td>
            <td>{{ .RotationDays }} days</td>
            <td>{{ if .UseEnabled }}<span class="pill">profiled</span>{{ else }}<span class="pill">blocked</span>{{ end }}</td>
            <td><span class="pill">disabled</span></td>
          </tr>
        {{ end }}
        </tbody>
      </table>
    </div>
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
`))
}
