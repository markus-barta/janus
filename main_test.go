package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func testConfig() Config {
	return Config{
		Listen:       ":0",
		PublicURL:    "https://vault.barta.cm",
		ProductMode:  "self_hosted",
		DataDir:      tTempDir,
		RequireAuth:  true,
		OIDCIssuer:   "https://auth.inspr.at",
		OIDCClientID: "client",
		OIDCSecret:   "secret",
		CookieKey:    []byte("0123456789abcdef0123456789abcdef"),
		RolePolicy:   RolePolicy{BootstrapOwner: true},
		ScopePolicy:  ScopePolicy{AllowedScopes: map[string]bool{"csb1": true}, Strict: true},
	}
}

var tTempDir = ""

func newTestApp(t *testing.T) *App {
	t.Helper()
	tTempDir = t.TempDir()
	store, err := NewStore(tTempDir, "")
	if err != nil {
		t.Fatal(err)
	}
	permitStore, err := NewPermitStore(tTempDir)
	if err != nil {
		t.Fatal(err)
	}
	return &App{
		cfg:       testConfig(),
		store:     store,
		broker:    NewBroker(store),
		permits:   permitStore,
		templates: mustTemplates(),
	}
}

func cookieByName(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("expected cookie %s in %#v", name, cookies)
	return nil
}

func testOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:    "client",
		RedirectURL: "https://vault.barta.cm/oidc/callback",
		Scopes:      []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://auth.example.test/oauth/v2/authorize",
			TokenURL: "https://auth.example.test/oauth/v2/token",
		},
	}
}

func TestDescriptorsNeverExposeValues(t *testing.T) {
	tTempDir = t.TempDir()
	store, err := NewStore(tTempDir, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(store.Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, forbidden := range []string{"\"value\"", "\"secret_value\"", "\"plaintext\""} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("descriptor response exposed forbidden field %s in %s", forbidden, body)
		}
	}
}

func TestLoadsExternalAgenixCatalog(t *testing.T) {
	dataDir := t.TempDir()
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`[{
		"id":"csb1-real-env",
		"display_name":"Real env metadata",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"source":"secrets/csb1-real-env.age",
		"consumer_count":2
	}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dataDir, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	descriptors := store.Descriptors()
	if len(descriptors) != 1 {
		t.Fatalf("expected one descriptor, got %d", len(descriptors))
	}
	if descriptors[0].ID != "csb1-real-env" || descriptors[0].RevealAllowed {
		t.Fatalf("unexpected descriptor: %#v", descriptors[0])
	}
	if descriptors[0].Scope != "csb1" || descriptors[0].EgressMode != "none" || descriptors[0].Lifecycle != LifecycleActive {
		t.Fatalf("expected normalized safe metadata: %#v", descriptors[0])
	}
}

func TestBundledAgenixCatalogHasNoGovernanceGates(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("catalog", "agenix-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var descriptors []SecretDescriptor
	if err := json.Unmarshal(raw, &descriptors); err != nil {
		t.Fatal(err)
	}
	if len(descriptors) == 0 {
		t.Fatal("expected bundled catalog descriptors")
	}
	if gates := ValidateCatalog(descriptors); len(gates) != 0 {
		t.Fatalf("bundled catalog should have no governance gates: %#v", gates)
	}
	for _, desc := range descriptors {
		if desc.RevealAllowed {
			t.Fatalf("bundled catalog must remain no-reveal: %#v", desc)
		}
	}
}

func TestAuditHashChainAndRecentAudit(t *testing.T) {
	store, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	store.AppendAudit(AuditEntry{Action: "one", Outcome: "allowed", Method: http.MethodGet, Path: "/"})
	store.AppendAudit(AuditEntry{Action: "two", Outcome: "denied", Method: http.MethodPost, Path: "/api"})

	posture := store.AuditPosture()
	if posture.Entries != 2 || posture.ChainedEntries != 2 || !posture.ChainVerified || posture.LastHash == "" {
		t.Fatalf("unexpected audit posture: %#v", posture)
	}
	if posture.WarningCount != 1 || auditSeverityCount(posture, "info") != 1 || auditSeverityCount(posture, "warning") != 1 {
		t.Fatalf("unexpected audit severity posture: %#v", posture)
	}
	recent := store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Action != "two" || recent[0].Severity != "warning" || recent[0].PrevHash == "" || recent[0].EventHash == "" {
		t.Fatalf("unexpected recent audit: %#v", recent)
	}
}

func TestAuditExplicitCriticalSeverity(t *testing.T) {
	store, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	store.AppendAudit(AuditEntry{Action: "audit.chain", Outcome: "failed", Severity: "critical", Method: http.MethodGet, Path: "/readyz"})
	posture := store.AuditPosture()
	if posture.CriticalCount != 1 || auditSeverityCount(posture, "critical") != 1 || !posture.ChainVerified {
		t.Fatalf("unexpected critical audit posture: %#v", posture)
	}
	recent := store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Severity != "critical" {
		t.Fatalf("expected critical audit event: %#v", recent)
	}
}

func TestAuditPostureAcceptsPreSeverityHashChain(t *testing.T) {
	store, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	legacy := AuditEntry{
		Time:    time.Now().UTC(),
		Action:  "legacy.event",
		Outcome: "allowed",
		Method:  http.MethodGet,
		Path:    "/",
	}
	legacy.EventHash = hashAuditEntry(legacy)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.auditFile, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	posture := store.AuditPosture()
	if !posture.ChainVerified || posture.UnknownSeverityCount != 1 || auditSeverityCount(posture, "unknown") != 1 {
		t.Fatalf("pre-severity audit row should remain verified and counted unknown: %#v", posture)
	}
}

func auditSeverityCount(posture AuditPosture, severity string) int {
	for _, count := range posture.SeverityCounts {
		if count.Severity == severity {
			return count.Count
		}
	}
	return 0
}

func TestSessionRejectsTamper(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	cookie := rr.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, ok := app.readSession(req); !ok {
		t.Fatal("expected valid session")
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		t.Fatalf("unexpected cookie format: %s", cookie.Value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 'x')
	cookie.Value = base64.RawURLEncoding.EncodeToString(raw) + "." + parts[1]

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, ok := app.readSession(req); ok {
		t.Fatal("tampered session was accepted")
	}
}

func TestSessionCookieIsStrictAndHostPrefixed(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie must be Strict; OIDC redirect cookies carry Lax separately, got %v", cookies[0].SameSite)
	}
	if cookies[0].Name != hostSessionCookie {
		t.Fatalf("secure deployments should use host-prefixed session cookie, got %s", cookies[0].Name)
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("session cookie must be secure and httponly: %#v", cookies[0])
	}
}

func TestReadSessionAcceptsLegacyCookieDuringHostPrefixMigration(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	cookie := rr.Result().Cookies()[0]
	if cookie.Name != hostSessionCookie {
		t.Fatalf("expected host-prefixed cookie, got %s", cookie.Name)
	}
	cookie.Name = sessionCookie

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, ok := app.readSession(req); !ok {
		t.Fatal("legacy session cookie should be accepted during migration")
	}
}

func TestSessionPostureIsValueFree(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "user-1", Email: "user@example.test", Expiry: time.Now().UTC().Add(time.Hour)}

	posture := app.sessionPosture(session)
	if posture.AbsoluteTTLSeconds != int(defaultSessionTTL.Seconds()) || posture.TTLLabel != "12h" {
		t.Fatalf("unexpected session ttl posture: %#v", posture)
	}
	if posture.SecondsRemaining <= 0 || posture.ExpiresAt == "" || posture.ExpiresLabel == "" {
		t.Fatalf("session expiry should be visible without values: %#v", posture)
	}
	if !posture.CSRFBound || !posture.CookieSigned || posture.ValueReturned {
		t.Fatalf("unexpected session controls: %#v", posture)
	}
	raw, err := json.Marshal(posture)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "user-1") || strings.Contains(string(raw), "user@example.test") {
		t.Fatalf("session posture should not include identity values: %s", raw)
	}
}

func TestConfigUsesHostPrefixedStateCookieForHTTPS(t *testing.T) {
	app := newTestApp(t)

	if app.cfg.StateCookieName() != hostStateCookie {
		t.Fatalf("secure deployments should use host-prefixed state cookie, got %s", app.cfg.StateCookieName())
	}
}

func TestConfigUsesHostPrefixedNonceCookieForHTTPS(t *testing.T) {
	app := newTestApp(t)

	if app.cfg.NonceCookieName() != hostNonceCookie {
		t.Fatalf("secure deployments should use host-prefixed nonce cookie, got %s", app.cfg.NonceCookieName())
	}
}

func TestConfigUsesHostPrefixedPKCECookieForHTTPS(t *testing.T) {
	app := newTestApp(t)

	if app.cfg.PKCECookieName() != hostPKCECookie {
		t.Fatalf("secure deployments should use host-prefixed PKCE cookie, got %s", app.cfg.PKCECookieName())
	}
}

func TestLoginRedirectBindsOIDCStateNonceAndPKCE(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	out := httptest.NewRecorder()
	app.handleLogin(out, req)
	if out.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d body=%s", out.Code, out.Body.String())
	}

	cookies := out.Result().Cookies()
	if len(cookies) != 3 {
		t.Fatalf("expected state, nonce, and PKCE cookies, got %#v", cookies)
	}
	state := cookieByName(t, cookies, hostStateCookie)
	nonce := cookieByName(t, cookies, hostNonceCookie)
	pkce := cookieByName(t, cookies, hostPKCECookie)
	for _, cookie := range []*http.Cookie{state, nonce, pkce} {
		if cookie.Value == "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 300 {
			t.Fatalf("OIDC cookie should be short-lived, secure, httponly, lax: %#v", cookie)
		}
	}

	redirectURL, err := url.Parse(out.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := redirectURL.Query().Get("state"); got != state.Value {
		t.Fatalf("redirect state should match state cookie, got %q want %q", got, state.Value)
	}
	if got := redirectURL.Query().Get("nonce"); got != nonce.Value {
		t.Fatalf("redirect nonce should match nonce cookie, got %q want %q", got, nonce.Value)
	}
	if got := redirectURL.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("redirect should request S256 PKCE challenge, got %q", got)
	}
	if got := redirectURL.Query().Get("code_challenge"); got == "" || got == pkce.Value {
		t.Fatalf("redirect should include derived PKCE challenge, got %q verifier %q", got, pkce.Value)
	}
	if got := redirectURL.Query().Get("code_verifier"); got != "" {
		t.Fatalf("redirect must not leak PKCE verifier, got %q", got)
	}
}

func TestLoginRedirectUsesNoStoreHeaders(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("login redirect should not be cached, got Cache-Control %q", got)
	}
	if got := out.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("login redirect should include legacy no-cache pragma, got %q", got)
	}
	if got := out.Header().Get("Expires"); got != "0" {
		t.Fatalf("login redirect should include legacy expires header, got %q", got)
	}
}

func TestCallbackBadStateRendersValueFreeAuthError(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()
	app.verifier = &oidc.IDTokenVerifier{}

	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=bad", nil)
	req.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "state-cookie-secret"})
	req.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: "nonce-cookie-secret"})
	req.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: "pkce-cookie-secret"})
	req.Header.Set("X-Request-Id", "auth-test-123")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Login needs a fresh start", "login_restart_required", "value_returned=false", "request_id=auth-test-123", "Try again"} {
		if !strings.Contains(body, want) {
			t.Fatalf("auth error page should include %q: %s", want, body)
		}
	}
	if got := out.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("auth error page should be HTML, got %q", got)
	}
	if got := out.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("auth error page should not be cached, got %q", got)
	}
	if got := out.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'none'") {
		t.Fatalf("auth error page should keep no-script CSP, got %q", got)
	}
	for _, forbidden := range []string{"bad_state", "missing_nonce", "missing_pkce", "code_exchange_failed", "id_token_verify_failed"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("auth error page should not expose internal reason %q: %s", forbidden, body)
		}
	}
	for _, forbidden := range []string{"state-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret", "plaintext"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("auth error page leaked %q: %s", forbidden, body)
		}
	}
	cleared := map[string]bool{}
	for _, cookie := range out.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
	}
	for _, name := range []string{hostStateCookie, hostNonceCookie, hostPKCECookie, stateCookie, nonceCookie, pkceCookie} {
		if !cleared[name] {
			t.Fatalf("expected callback failure to clear %s; cleared=%#v cookies=%#v", name, cleared, out.Result().Cookies())
		}
	}
}

func TestAPIRequiresAuthReturnsValueFreeJSON(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Location"); got != "" {
		t.Fatalf("API auth denial should not redirect, got Location %q", got)
	}
	if got := out.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("API auth denial should be JSON, got %q", got)
	}
	body := out.Body.String()
	if !strings.Contains(body, `"error":"auth_required"`) || !strings.Contains(body, `"value_returned":false`) {
		t.Fatalf("API auth denial should be value-free JSON: %s", body)
	}
}

func TestAPISetupIncompleteReturnsValueFreeJSON(t *testing.T) {
	app := newTestApp(t)
	app.cfg.OIDCSecret = ""

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("API setup denial should be JSON, got %q", got)
	}
	body := out.Body.String()
	if !strings.Contains(body, `"error":"auth_not_configured"`) || !strings.Contains(body, `"value_returned":false`) {
		t.Fatalf("API setup denial should be value-free JSON: %s", body)
	}
}

func TestValidOIDCNonce(t *testing.T) {
	if !validOIDCNonce("nonce-123", "nonce-123") {
		t.Fatal("matching nonce should be valid")
	}
	for _, tc := range []struct {
		name     string
		expected string
		got      string
	}{
		{name: "missing expected", expected: "", got: "nonce-123"},
		{name: "missing claim", expected: "nonce-123", got: ""},
		{name: "mismatch", expected: "nonce-123", got: "nonce-456"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validOIDCNonce(tc.expected, tc.got) {
				t.Fatal("nonce should be rejected")
			}
		})
	}
}

func TestLogoutRequiresCSRF(t *testing.T) {
	app := newTestApp(t)
	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	req.Header.Set("X-Request-Id", "logout-test-123")

	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected CSRF denial, got %d", out.Code)
	}
	body := out.Body.String()
	for _, want := range []string{"Sign out needs a fresh page", "logout_integrity_check_failed", "value_returned=false", "request_id=logout-test-123"} {
		if !strings.Contains(body, want) {
			t.Fatalf("logout CSRF page should include %q: %s", want, body)
		}
	}
}

func TestWardenResolveReturnsHandleOnly(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://vault.barta.cm")
	req.Header.Set("X-CSRF-Token", app.csrfToken(session))
	req.AddCookie(rr.Result().Cookies()[0])

	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandle)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, `"plaintext"`) {
		t.Fatalf("handle response is not value-free: %s", body)
	}
}

func TestCrossOriginMutationDeniedWithValidCSRF(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "operator", Roles: []string{RoleOperator, RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-CSRF-Token", app.csrfToken(session))
	req.AddCookie(rr.Result().Cookies()[0])

	out := httptest.NewRecorder()
	app.withAuth(app.requireRole(RoleOperator, "warden.resolve", app.handleResolveHandle))(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), `"csrf_failed"`) || !strings.Contains(out.Body.String(), `"value_returned":false`) {
		t.Fatalf("cross-origin denial should be value-free CSRF JSON: %s", out.Body.String())
	}
}

func TestWardenResolveWorksWhenAuthDisabledForLocalSmoke(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"local smoke"}`))
	req.Header.Set("Content-Type", "application/json")

	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandle)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	if strings.Contains(out.Body.String(), `"plaintext"`) {
		t.Fatalf("response should be value-free: %s", out.Body.String())
	}
}

func TestSensitiveAPIFailsClosedWhenReadinessDegraded(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.permits = nil

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"local smoke"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "degraded-api-1")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`"error":"system_degraded"`, `"request_id":"degraded-api-1"`, `"redacted":true`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("degraded API denial should include %s: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") || strings.Contains(body, "secret-cookie-secret") {
		t.Fatalf("degraded API denial should remain value-free: %s", body)
	}
}

func TestOversizedAPIRequestIsRejectedValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(strings.Repeat("x", int(maxRequestBody)+1)))
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, `"request_too_large"`) || !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, "plaintext") {
		t.Fatalf("oversized denial should be value-free JSON: %s", body)
	}
}

func TestFailedLookupDoesNotEchoRefIntoAuditSecretRef(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"do-not-echo-this","reason":"local smoke"}`))
	req.Header.Set("Content-Type", "application/json")

	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandle)(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", out.Code, out.Body.String())
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 {
		t.Fatalf("expected one audit event, got %d", len(recent))
	}
	if recent[0].SecretRef != "" {
		t.Fatalf("failed lookup echoed ref into audit secret_ref: %#v", recent[0])
	}
}

func TestPostureAPIIsValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	out := httptest.NewRecorder()
	app.withAuth(app.handlePosture)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, `"plaintext"`) {
		t.Fatalf("posture response should be value-free: %s", body)
	}
	if !strings.Contains(body, `"catalog_gate_count"`) {
		t.Fatalf("posture response should include catalog gates: %s", body)
	}
	if !strings.Contains(body, `"access"`) || !strings.Contains(body, `"role_gated_audit_evidence"`) {
		t.Fatalf("posture response should include access policy: %s", body)
	}
	if !strings.Contains(body, `"role_duty_matrix":true`) || !strings.Contains(body, `"duty_model":"separated_admin_auditor_operator_viewer"`) {
		t.Fatalf("posture response should include role duty matrix posture: %s", body)
	}
	if !strings.Contains(body, `"scope"`) || !strings.Contains(body, `"scope_bound_metadata"`) {
		t.Fatalf("posture response should include scope policy: %s", body)
	}
	if !strings.Contains(body, `"lifecycle"`) || !strings.Contains(body, `"lifecycle_gated_normal_use"`) {
		t.Fatalf("posture response should include lifecycle policy: %s", body)
	}
	if !strings.Contains(body, `"permits"`) || !strings.Contains(body, `"persistent_permit_records"`) {
		t.Fatalf("posture response should include permit persistence: %s", body)
	}
	if !strings.Contains(body, `"cookies"`) || !strings.Contains(body, `"host_prefixed_cookies"`) {
		t.Fatalf("posture response should include cookie hardening: %s", body)
	}
	if !strings.Contains(body, `"request_correlation"`) || !strings.Contains(body, `"request_correlation_ids"`) {
		t.Fatalf("posture response should include request correlation: %s", body)
	}
	if !strings.Contains(body, `"response_hardening"`) || !strings.Contains(body, `"no_store_responses"`) {
		t.Fatalf("posture response should include response hardening: %s", body)
	}
	if !strings.Contains(body, `"request_limits"`) || !strings.Contains(body, `"max_body_bytes":4096`) || !strings.Contains(body, `"request_body_size_limit"`) {
		t.Fatalf("posture response should include request body limits: %s", body)
	}
	if !strings.Contains(body, `"availability"`) || !strings.Contains(body, `"sensitive_actions_require_readiness":true`) || !strings.Contains(body, `"degraded_sensitive_action_guard"`) {
		t.Fatalf("posture response should include degraded sensitive-action guard: %s", body)
	}
	if !strings.Contains(body, `"degraded_dashboard_banner"`) {
		t.Fatalf("posture response should include degraded dashboard banner capability: %s", body)
	}
	if !strings.Contains(body, `"safe_failure_pages":true`) || !strings.Contains(body, `"safe_auth_failure_pages"`) || !strings.Contains(body, `"auth_error_view":"safe_category_request_id"`) {
		t.Fatalf("posture response should include safe auth failure pages: %s", body)
	}
	if !strings.Contains(body, `"safe_http_boundary_failures":true`) || !strings.Contains(body, `"safe_http_boundary_failures"`) || !strings.Contains(body, `"http_boundary_error_view":"safe_category_request_id"`) {
		t.Fatalf("posture response should include safe HTTP boundary failures: %s", body)
	}
	if !strings.Contains(body, `"public_health_redacted":true`) || !strings.Contains(body, `"redacted_public_health"`) {
		t.Fatalf("posture response should include redacted public health: %s", body)
	}
	if !strings.Contains(body, `"public_readiness_redacted":true`) || !strings.Contains(body, `"redacted_public_readiness"`) {
		t.Fatalf("posture response should include redacted public readiness: %s", body)
	}
	if !strings.Contains(body, `"public_readiness_auth_redacted":true`) || !strings.Contains(body, `"minimal_public_readiness"`) {
		t.Fatalf("posture response should include minimal public readiness: %s", body)
	}
	if !strings.Contains(body, `"script_src":"none"`) || !strings.Contains(body, `"no_script_csp"`) {
		t.Fatalf("posture response should include no-script CSP hardening: %s", body)
	}
	if !strings.Contains(body, `"cross_origin_resource_policy":"same-origin"`) || !strings.Contains(body, `"cross_domain_policy":"none"`) || !strings.Contains(body, `"browser_isolation_headers"`) {
		t.Fatalf("posture response should include browser isolation headers: %s", body)
	}
	if !strings.Contains(body, `"audit_event_severity"`) || !strings.Contains(body, `"severity_counts"`) {
		t.Fatalf("posture response should include audit severity: %s", body)
	}
	if !strings.Contains(body, `"api_errors"`) || !strings.Contains(body, `"api_json_auth_errors"`) {
		t.Fatalf("posture response should include API error posture: %s", body)
	}
	if !strings.Contains(body, `"rate_limit_retry_after":true`) || !strings.Contains(body, `"rate_limit_request_id":true`) || !strings.Contains(body, `"operational_rate_limit_denials"`) {
		t.Fatalf("posture response should include operational rate-limit denials: %s", body)
	}
	if !strings.Contains(body, `"readiness"`) || !strings.Contains(body, `"value_free_readiness"`) {
		t.Fatalf("posture response should include readiness posture: %s", body)
	}
	if !strings.Contains(body, `"auth"`) || !strings.Contains(body, `"oidc_nonce_bound_login"`) || !strings.Contains(body, `"pkce_s256_auth_code"`) {
		t.Fatalf("posture response should include hardened OIDC login controls: %s", body)
	}
	if !strings.Contains(body, `"session"`) || !strings.Contains(body, `"signed_session_expiry"`) {
		t.Fatalf("posture response should include session posture: %s", body)
	}
	if !strings.Contains(body, `"cookie_same_site":"Strict"`) || !strings.Contains(body, `"session_same_site":"Strict"`) || !strings.Contains(body, `"oidc_login_same_site":"Lax"`) || !strings.Contains(body, `"strict_session_cookie"`) {
		t.Fatalf("posture response should include strict session cookie split: %s", body)
	}
	if !strings.Contains(body, `"same_origin_mutations":"origin_or_referer_when_present"`) || !strings.Contains(body, `"same_origin_mutation_guard"`) {
		t.Fatalf("posture response should include same-origin mutation guard: %s", body)
	}
	if !strings.Contains(body, `"approved_use"`) || !strings.Contains(body, `"approved_metadata_use_enforced"`) {
		t.Fatalf("posture response should include approved-use enforcement: %s", body)
	}
}

func TestEvidenceExportIsValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/api/evidence", nil)
	out := httptest.NewRecorder()
	app.withAuth(app.handleEvidence)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, `"plaintext"`) {
		t.Fatalf("evidence response should be value-free: %s", body)
	}
	if !strings.Contains(body, `"redaction_model"`) {
		t.Fatalf("evidence response should explain redaction model: %s", body)
	}
	if !strings.Contains(body, `"scope_posture"`) {
		t.Fatalf("evidence response should include scope posture: %s", body)
	}
	if !strings.Contains(body, `"lifecycle_posture"`) {
		t.Fatalf("evidence response should include lifecycle posture: %s", body)
	}
	if !strings.Contains(body, `"permit_posture"`) {
		t.Fatalf("evidence response should include permit posture: %s", body)
	}
	if !strings.Contains(body, `"integrity"`) || !strings.Contains(body, `"pack_hash"`) {
		t.Fatalf("evidence response should include integrity metadata: %s", body)
	}
}

func TestEvidenceExportRequiresAuditorRole(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RolePolicy = RolePolicy{
		AuditorSubjects: map[string]bool{"auditor": true},
		BootstrapOwner:  false,
	}
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/api/evidence", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.withAuth(app.requireRole(RoleAuditor, "evidence.export", app.handleEvidence))(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), `"value_returned":false`) {
		t.Fatalf("denial must be value-free: %s", out.Body.String())
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Outcome != "denied" || !strings.Contains(recent[0].Reason, "auditor") {
		t.Fatalf("expected denied role audit event: %#v", recent)
	}
}

func TestWardenAPIRequiresOperatorRole(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.withAuth(app.requireRole(RoleOperator, "warden.resolve", app.handleResolveHandle))(out, req)

	if out.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), `"role_denied"`) || !strings.Contains(out.Body.String(), `"value_returned":false`) {
		t.Fatalf("operator denial should be value-free: %s", out.Body.String())
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Outcome != "denied" || !strings.Contains(recent[0].Reason, "operator") {
		t.Fatalf("expected denied operator audit event: %#v", recent)
	}
}

func TestRolePolicyMapsZitadelClaims(t *testing.T) {
	roles := DeriveRoles("user-1", "user@example.test", []string{"janus:auditor"}, RolePolicy{BootstrapOwner: false})
	if !hasTestRole(roles, RoleViewer) || !hasTestRole(roles, RoleAuditor) {
		t.Fatalf("expected viewer and auditor roles, got %#v", roles)
	}
	if hasTestRole(roles, RoleAdmin) {
		t.Fatalf("auditor claim should not grant admin: %#v", roles)
	}
}

func TestRolePolicyBootstrapOwnerGrantsV1Roles(t *testing.T) {
	roles := DeriveRoles("owner", "", nil, RolePolicy{BootstrapOwner: true})
	for _, role := range []string{RoleViewer, RoleAdmin, RoleAuditor, RoleOperator} {
		if !hasTestRole(roles, role) {
			t.Fatalf("expected bootstrap role %s in %#v", role, roles)
		}
	}
}

func TestRolePolicyExplicitOwnerBindingClosesBootstrapGate(t *testing.T) {
	policy := RolePolicy{
		AdminSubjects:    map[string]bool{"markus@barta.com": true},
		AuditorSubjects:  map[string]bool{"markus@barta.com": true},
		OperatorSubjects: map[string]bool{"markus@barta.com": true},
		BootstrapOwner:   false,
	}
	roles := DeriveRoles("zitadel-subject", "markus@barta.com", nil, policy)
	for _, role := range []string{RoleViewer, RoleAdmin, RoleAuditor, RoleOperator} {
		if !hasTestRole(roles, role) {
			t.Fatalf("expected explicit owner role %s in %#v", role, roles)
		}
	}
	posture := AccessPostureFor(policy)
	if !posture.ExplicitBindings || posture.BootstrapOwner || posture.GateCount != 0 || posture.ValueReturned {
		t.Fatalf("explicit role policy should close bootstrap gate: %#v", posture)
	}
}

func TestDockerComposePinsExplicitJanusRoleBindings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		"JANUS_BOOTSTRAP_OWNER=false",
		"JANUS_ADMIN_SUBJECTS=markus@barta.com",
		"JANUS_AUDITOR_SUBJECTS=markus@barta.com",
		"JANUS_OPERATOR_SUBJECTS=markus@barta.com",
		"JANUS_ADMIN_GROUPS=janus:admin",
		"JANUS_AUDITOR_GROUPS=janus:auditor",
		"JANUS_OPERATOR_GROUPS=janus:operator",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("compose should pin explicit Janus role binding %q", want)
		}
	}
}

func TestDashboardRendersAccessPolicy(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.withAuth(app.handleDashboard)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Session identity", "Local Dev", "admin", "Live posture", "Assurance flow", "Known human", "Metadata only", "Use gate", "Audit trail", "Trust posture", "Catalog gates", "Approved use", "Evidence JSON", "Request metadata handle", "Request permit", "Access policy", "bootstrap owner", "session ttl", "session cookie", "Scope boundary", "Duty boundary", "role matrix", "Policy and ownership", "Evidence and audit", "Posture only", "Lifecycle posture"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard should render %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"plaintext", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("dashboard should remain value-free, found %q: %s", forbidden, body)
		}
	}
}

func TestDashboardShowsRestrictedStateWhenReadinessDegraded(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.permits = nil

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Security state", "restricted", "Sensitive actions are blocked", "ready=false", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("degraded dashboard should render %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"plaintext", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("degraded dashboard leaked %q: %s", forbidden, body)
		}
	}
}

func TestSecurityHeadersUseStyleNonce(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	csp := out.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "style-src 'self' 'nonce-") {
		t.Fatalf("CSP should use style nonce without unsafe-inline: %s", csp)
	}
	for _, want := range []string{"script-src 'none'", "object-src 'none'", "worker-src 'none'", "connect-src 'self'", "upgrade-insecure-requests"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP should include %q: %s", want, csp)
		}
	}
	parts := strings.SplitN(out.Body.String(), `<style nonce="`, 2)
	if len(parts) != 2 {
		t.Fatalf("dashboard style tag should include nonce: %s", out.Body.String())
	}
	nonce := strings.SplitN(parts[1], `"`, 2)[0]
	if nonce == "" || !strings.Contains(csp, "'nonce-"+nonce+"'") {
		t.Fatalf("CSP nonce should match style nonce: csp=%s nonce=%q", csp, nonce)
	}
	if got := out.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Fatalf("expected same-origin CORP header, got %q", got)
	}
	if got := out.Header().Get("X-Permitted-Cross-Domain-Policies"); got != "none" {
		t.Fatalf("expected cross-domain policy lockout, got %q", got)
	}
}

func TestSafeBrowserBoundaryFailurePage(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.Header.Set("X-Request-Id", "edge-browser-404")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("browser boundary failure should be HTML, got %q", got)
	}
	body := out.Body.String()
	for _, want := range []string{"Janus stopped at the edge", "Safe boundary", "route_not_found", "value_returned=false", "request_id=edge-browser-404"} {
		if !strings.Contains(body, want) {
			t.Fatalf("safe boundary page should render %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"plaintext", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("safe boundary page leaked %q: %s", forbidden, body)
		}
	}
	if got := out.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'none'") {
		t.Fatalf("safe boundary page should keep no-script CSP, got %q", got)
	}
}

func TestSafeAPIBoundaryFailureJSON(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/api/missing", nil)
	req.Header.Set("X-Request-Id", "edge-api-404")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`"error":"route_not_found"`, `"request_id":"edge-api-404"`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("API boundary failure should include %s: %s", want, body)
		}
	}
	if strings.Contains(body, "<!doctype") || strings.Contains(body, "plaintext") {
		t.Fatalf("API boundary failure should stay JSON and value-free: %s", body)
	}
}

func TestSafeMethodBoundaryFailureJSON(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/posture", nil)
	req.Header.Set("X-Request-Id", "edge-api-405")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("expected Allow GET, HEAD, got %q", got)
	}
	body := out.Body.String()
	for _, want := range []string{`"error":"method_not_allowed"`, `"allowed_methods":["GET","HEAD"]`, `"request_id":"edge-api-405"`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("method boundary failure should include %s: %s", want, body)
		}
	}
	if strings.Contains(body, "Method Not Allowed") || strings.Contains(body, "plaintext") {
		t.Fatalf("method boundary failure should not use default plain response: %s", body)
	}
}

func TestRandomNonceIsTemplateSafe(t *testing.T) {
	nonce := randomNonce(64)
	if nonce == "" || strings.ContainsAny(nonce, "+/=") {
		t.Fatalf("CSP nonce should be URL-safe and unpadded, got %q", nonce)
	}
}

func TestRequestIDHeaderAndAuditCorrelation(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	req.Header.Set("X-Request-Id", "req-test_123")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("X-Request-Id"); got != "req-test_123" {
		t.Fatalf("expected request id response header, got %q", got)
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 || recent[0].RequestID != "req-test_123" {
		t.Fatalf("expected audit event to reuse request id: %#v", recent)
	}
}

func TestRequestIDRejectsUnsafeInboundValue(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	req.Header.Set("X-Request-Id", "bad\r\nInjected: yes")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	got := out.Header().Get("X-Request-Id")
	if got == "" || strings.Contains(got, "Injected") || got == "bad\r\nInjected: yes" {
		t.Fatalf("unsafe request id should be replaced, got %q", got)
	}
}

func TestDashboardHidesOperatorActionsForViewer(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.withAuth(app.handleDashboard)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, "Operator role required") {
		t.Fatalf("viewer dashboard should explain operator gate: %s", body)
	}
	for _, forbidden := range []string{"Issue handle</button>", "Create permit</button>"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("viewer dashboard rendered operator action %q: %s", forbidden, body)
		}
	}
}

func TestDashboardAuditRowsRequireAuditorRole(t *testing.T) {
	app := newTestApp(t)
	app.store.AppendAudit(AuditEntry{
		Action:    "secret.review",
		Outcome:   "allowed",
		Method:    http.MethodPost,
		Path:      "/api/example",
		SecretRef: "private-ref",
		Reason:    "audit seed",
	})

	viewer := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	viewerCookie := httptest.NewRecorder()
	app.writeSession(viewerCookie, viewer)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(viewerCookie.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.withAuth(app.handleDashboard)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected viewer dashboard 200, got %d body=%s", out.Code, out.Body.String())
	}
	viewerBody := out.Body.String()
	if !strings.Contains(viewerBody, "Auditor role required") || !strings.Contains(viewerBody, "restricted") {
		t.Fatalf("viewer dashboard should gate audit rows: %s", viewerBody)
	}
	if strings.Contains(viewerBody, "private-ref") {
		t.Fatalf("viewer dashboard leaked audit secret ref: %s", viewerBody)
	}

	auditor := Session{Subject: "auditor", Roles: []string{RoleAuditor, RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	auditorCookie := httptest.NewRecorder()
	app.writeSession(auditorCookie, auditor)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(auditorCookie.Result().Cookies()[0])
	out = httptest.NewRecorder()
	app.withAuth(app.handleDashboard)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected auditor dashboard 200, got %d body=%s", out.Code, out.Body.String())
	}
	auditorBody := out.Body.String()
	if !strings.Contains(auditorBody, "private-ref") || !strings.Contains(auditorBody, "<th>Severity</th>") || !strings.Contains(auditorBody, ">info<") {
		t.Fatalf("auditor dashboard should include audit rows and severity posture: %s", auditorBody)
	}
}

func TestDashboardRendersDescriptorFocus(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/?ref=csb1-age-identity", nil)
	out := httptest.NewRecorder()
	app.withAuth(app.handleDashboard)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Descriptor focus", "csb1-age-identity", "classification", "value-free metadata", "normal use", "Inspect"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard focus should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") {
		t.Fatalf("dashboard focus should remain value-free: %s", body)
	}
}

func TestWardenResolveUIReturnsValueFreeHandle(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/ui/warden/resolve", strings.NewReader("ref=zitadel-janus-oidc&reason=local+smoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandleUI)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Handle ready", "value_returned=false", "zitadel-janus-oidc"} {
		if !strings.Contains(body, want) {
			t.Fatalf("UI handle response should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") {
		t.Fatalf("UI handle response should remain value-free: %s", body)
	}
}

func TestSensitiveUIFailsClosedWhenReadinessDegraded(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.permits = nil

	req := httptest.NewRequest(http.MethodPost, "/ui/warden/resolve", strings.NewReader("ref=zitadel-janus-oidc&reason=local+smoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Request-Id", "degraded-ui-1")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Handle blocked", "system_degraded", "request_id=degraded-ui-1", "sensitive action blocked", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("degraded UI denial should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") || strings.Contains(body, "secret-cookie-secret") {
		t.Fatalf("degraded UI denial should remain value-free: %s", body)
	}
}

func TestWardenResolveUIRequiresReason(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/ui/warden/resolve", strings.NewReader("ref=zitadel-janus-oidc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandleUI)(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "Reason required") || strings.Contains(out.Body.String(), "plaintext") {
		t.Fatalf("UI denial should be clear and value-free: %s", out.Body.String())
	}
}

func TestWardenResolveUIRequiresOperatorRole(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	form := "ref=zitadel-janus-oidc&reason=local+smoke&csrf_token=" + app.csrfToken(session)
	req := httptest.NewRequest(http.MethodPost, "/ui/warden/resolve", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandleUI)(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "Operator role required") || strings.Contains(out.Body.String(), "plaintext") {
		t.Fatalf("operator UI denial should be clear and value-free: %s", out.Body.String())
	}
}

func TestPermitCreateUIReturnsValueFreePermit(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/ui/permits", strings.NewReader("ref=zitadel-janus-oidc&action=metadata_use&destination=dashboard&reason=local+smoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	app.withAuth(app.handleCreatePermitUI)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Permit recorded", "Permit safety verdict", "Metadata only", "No connector", "Audited", "approved_metadata_only", "Run safety check", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("permit UI response should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") {
		t.Fatalf("permit UI response should remain value-free: %s", body)
	}
}

func TestPermitCreateUIRequiresReason(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/ui/permits", strings.NewReader("ref=zitadel-janus-oidc&action=metadata_use"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	app.withAuth(app.handleCreatePermitUI)(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "Reason required") || strings.Contains(out.Body.String(), "plaintext") {
		t.Fatalf("permit UI denial should be clear and value-free: %s", out.Body.String())
	}
}

func TestPermitRunUIReturnsNoExecutionValueFreeResult(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	permit, err := app.broker.CreatePermit(principalFromSession(Session{Subject: "user-1"}), PermitRequest{
		Ref:    "zitadel-janus-oidc",
		Action: "metadata_use",
		Reason: "local smoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.permits.Put(permit); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/permits/"+permit.ID+"/run", nil)
	req.SetPathValue("permitID", permit.ID)
	out := httptest.NewRecorder()
	app.withAuth(app.handleRunPermitUI)(out, req)
	if out.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Safety check complete", "Permit safety verdict", "Metadata only", "No connector", "Scrubbed output", "not_executed", "output_scrubbed=true", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("permit run UI response should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") {
		t.Fatalf("permit run UI response should remain value-free: %s", body)
	}
}

func TestDashboardRendersRecentPermits(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	permit, err := app.broker.CreatePermit(principalFromSession(Session{Subject: "user-1"}), PermitRequest{
		Ref:    "zitadel-janus-oidc",
		Action: "metadata_use",
		Reason: "local smoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.permits.Put(permit); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.withAuth(app.handleDashboard)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Recent permits", permit.ID, "Run safety check", "approved_metadata_only", "durable"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard should render recent permit %q: %s", want, body)
		}
	}
}

func TestScopePolicyFiltersDescriptorsAndDeniesResolve(t *testing.T) {
	dataDir := t.TempDir()
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`[{
		"id":"in-scope",
		"display_name":"In scope",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"scope":"csb1",
		"source":"secrets/in-scope.age",
		"consumer_count":1
	},{
		"id":"out-of-scope",
		"display_name":"Out of scope",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"scope":"csb2",
		"source":"secrets/out-of-scope.age",
		"consumer_count":1
	}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dataDir, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	broker := NewBroker(store).WithScopePolicy(ScopePolicy{AllowedScopes: map[string]bool{"csb1": true}, Strict: true})
	descriptors := broker.Descriptors(PrincipalChain{HumanSubject: "user-1"})
	if len(descriptors) != 1 || descriptors[0].ID != "in-scope" {
		t.Fatalf("expected only in-scope descriptor, got %#v", descriptors)
	}
	_, err = broker.ResolveHandle(PrincipalChain{HumanSubject: "user-1"}, HandleRequest{Ref: "out-of-scope"})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("expected out-of-scope denial, got %v", err)
	}
	posture := ScopePostureFor(broker.scopePolicy, store.Descriptors())
	if posture.OutOfScopeCount != 1 || posture.GateCount != 1 || posture.ValueReturned {
		t.Fatalf("unexpected scope posture: %#v", posture)
	}
}

func TestLifecycleBlocksUnsafeDescriptorUse(t *testing.T) {
	dataDir := t.TempDir()
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`[{
		"id":"disabled-secret",
		"display_name":"Disabled secret",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"scope":"csb1",
		"source":"secrets/disabled-secret.age",
		"lifecycle":"disabled",
		"consumer_count":1,
		"use_enabled":true
	}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dataDir, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	broker := NewBroker(store)
	principal := PrincipalChain{HumanSubject: "user-1"}

	_, err = broker.ResolveHandle(principal, HandleRequest{Ref: "disabled-secret", Reason: "test"})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected lifecycle policy denial, got %v", err)
	}
	_, err = broker.CreatePermit(principal, PermitRequest{Ref: "disabled-secret", Action: "metadata_use", Reason: "test"})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected lifecycle permit denial, got %v", err)
	}

	posture := LifecyclePostureFor(store.Descriptors(), time.Now().UTC())
	if posture.BlockedCount != 1 || posture.GateCount != 1 || posture.ValueReturned {
		t.Fatalf("unexpected lifecycle posture: %#v", posture)
	}
}

func TestBrokerRequiresApprovedMetadataUseProfile(t *testing.T) {
	dataDir := t.TempDir()
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`[{
		"id":"unprofiled-secret",
		"display_name":"Unprofiled secret",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"scope":"csb1",
		"source":"secrets/unprofiled-secret.age",
		"lifecycle":"active",
		"consumer_count":1,
		"use_enabled":false
	}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dataDir, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	broker := NewBroker(store)
	principal := PrincipalChain{HumanSubject: "user-1"}

	_, err = broker.ResolveHandle(principal, HandleRequest{Ref: "unprofiled-secret", Reason: "test"})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "approved metadata-only use profile") {
		t.Fatalf("expected approved-use policy denial, got %v", err)
	}
	_, err = broker.CreatePermit(principal, PermitRequest{Ref: "unprofiled-secret", Action: "metadata_use", Reason: "test"})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "approved metadata-only use profile") {
		t.Fatalf("expected approved-use permit denial, got %v", err)
	}

	focus := focusDescriptor(store.Descriptors(), "unprofiled-secret")
	if !focus.NormalUseBlocked || focus.NormalUseReason == "" || focus.LifecycleBlocked {
		t.Fatalf("focus should show approved-use block without lifecycle block: %#v", focus)
	}
	posture := ApprovedUsePostureFor(store.Descriptors())
	if posture.Profile != "metadata_only" || !posture.Enforced || posture.ProfiledCount != 0 || posture.BlockedCount != 1 || posture.SecretValuesAllowed || posture.ValueReturned {
		t.Fatalf("unexpected approved-use posture: %#v", posture)
	}
}

func TestEvidenceIntegrityIsValueFreeAndStableShape(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	pack := app.evidencePack()
	if pack.Integrity == nil {
		t.Fatal("expected evidence integrity metadata")
	}
	if pack.Integrity.Algorithm != "sha256-json-v1" || len(pack.Integrity.PackHash) != 64 {
		t.Fatalf("unexpected integrity metadata: %#v", pack.Integrity)
	}
	if pack.Integrity.ValueReturned || pack.Integrity.GeneratedAt.IsZero() {
		t.Fatalf("integrity metadata should be value-free and timestamped: %#v", pack.Integrity)
	}
}

func TestCatalogGovernanceFlagsDisabledUseProfiles(t *testing.T) {
	gates := ValidateCatalog([]SecretDescriptor{{
		ID:             "example",
		DisplayName:    "Example",
		Provider:       "agenix",
		Classification: "high",
		Owner:          "platform",
		Scope:          "csb1",
		Source:         "secrets/example.age",
		ConsumerCount:  1,
		UseEnabled:     false,
	}})
	if len(gates) != 1 || gates[0].Code != "no_approved_use_profile" {
		t.Fatalf("unexpected gates: %#v", gates)
	}
}

func hasTestRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}

func TestRateLimiterBlocksBurst(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)
	if !limiter.Allow("test") || !limiter.Allow("test") {
		t.Fatal("expected first two requests to pass")
	}
	if limiter.Allow("test") {
		t.Fatal("expected third request to be limited")
	}
}

func TestRateLimitDenialIsOperationalAndValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.limiter = NewRateLimiter(1, time.Minute)

	first := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	first.RemoteAddr = "192.0.2.8:1234"
	firstOut := httptest.NewRecorder()
	app.routes().ServeHTTP(firstOut, first)
	if firstOut.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d body=%s", firstOut.Code, firstOut.Body.String())
	}

	second := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	second.RemoteAddr = "192.0.2.8:1234"
	second.Header.Set("X-Request-Id", "rate-limit-2")
	secondOut := httptest.NewRecorder()
	app.routes().ServeHTTP(secondOut, second)
	if secondOut.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", secondOut.Code, secondOut.Body.String())
	}
	if got := secondOut.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("expected Retry-After 60, got %q", got)
	}
	body := secondOut.Body.String()
	for _, want := range []string{`"error":"rate_limited"`, `"request_id":"rate-limit-2"`, `"retry_after_seconds":60`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("rate-limit denial should include %s: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") || strings.Contains(body, "secret-cookie-secret") {
		t.Fatalf("rate-limit denial should remain value-free: %s", body)
	}
}

func TestPermitRunIsNoopAndValueFree(t *testing.T) {
	app := newTestApp(t)
	permit, err := app.broker.CreatePermit(principalFromSession(Session{Subject: "user-1"}), PermitRequest{
		Ref:    "zitadel-janus-oidc",
		Action: "metadata_use",
		Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	result := RunPermit(permit)
	if result.ValueReturned || !result.OutputScrubbed || result.Status != "not_executed" {
		t.Fatalf("unexpected permit run result: %#v", result)
	}
}

func TestPermitStorePersistsAndReloadsValueFreeRecords(t *testing.T) {
	dataDir := t.TempDir()
	store, err := NewPermitStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	permit := Permit{
		ID:            "p_test",
		SecretRef:     "zitadel-janus-oidc",
		Action:        "metadata_use",
		Reason:        "audit trail",
		Status:        "approved_metadata_only",
		ValueReturned: true,
		PrincipalHash: "actor-hash",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(time.Minute),
	}
	if err := store.Put(permit); err != nil {
		t.Fatal(err)
	}
	permitFile := filepath.Join(dataDir, "permits.json")
	info, err := os.Stat(permitFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permit file mode should be 0600, got %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(permitFile)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, `"value_returned": false`) || strings.Contains(body, "plaintext") {
		t.Fatalf("permit store should be value-free: %s", body)
	}

	reloaded, err := NewPermitStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.Get("p_test")
	if !ok || got.SecretRef != permit.SecretRef || got.ValueReturned {
		t.Fatalf("unexpected reloaded permit: %#v ok=%t", got, ok)
	}
	posture := reloaded.Posture()
	if posture.Count != 1 || !posture.Persisted || posture.ValueReturned {
		t.Fatalf("unexpected permit posture: %#v", posture)
	}
}

func TestPermitStoreRejectsCorruptPersistenceFile(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "permits.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPermitStore(dataDir); err == nil {
		t.Fatal("expected corrupt permit store to fail closed")
	}
}

func TestHealthzIsRedactedLivenessOnly(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{`"status":"ok"`, `"service":"janus"`, `"mode":"self_hosted"`, `"redacted":true`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("healthz should include %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"oidc_configured", "auth_required", "descriptor_count", "audit_entries", "secret_count", "plaintext", "secret-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("healthz should not expose %q: %s", forbidden, body)
		}
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("healthz should keep no-store header, got %q", got)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("healthz should keep nosniff header, got %q", got)
	}
}

func TestReadyzLockedWhenAuthMissing(t *testing.T) {
	tTempDir = t.TempDir()
	store, err := NewStore(tTempDir, "")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: Config{PublicURL: "https://vault.barta.cm", RequireAuth: true}, store: store}

	rr := httptest.NewRecorder()
	app.handleReady(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"auth":false`) || !strings.Contains(rr.Body.String(), `"value_returned":false`) {
		t.Fatalf("readyz should explain value-free failed checks: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"redacted":true`) || strings.Contains(rr.Body.String(), "descriptor_count") || strings.Contains(rr.Body.String(), "oidc_configured") || strings.Contains(rr.Body.String(), "auth_required") {
		t.Fatalf("readyz should stay public-redacted: %s", rr.Body.String())
	}
}

func TestReadyzReportsValueFreeChecks(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.handleReady(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{`"ready":true`, `"mode":"self_hosted"`, `"auth":true`, `"descriptor_store":true`, `"audit_sink":true`, `"audit_chain":true`, `"permit_store":true`, `"redacted":true`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("readyz should include %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"descriptor_count", "audit_entries", "secret_count", "oidc_configured", "auth_required"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("readyz should not expose inventory count %q: %s", forbidden, body)
		}
	}
}

func TestReadyzRequiresPermitStore(t *testing.T) {
	app := newTestApp(t)
	app.permits = nil

	rr := httptest.NewRecorder()
	app.handleReady(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"permit_store":false`) {
		t.Fatalf("readyz should fail when permit store is unavailable: %s", rr.Body.String())
	}
}

func TestDockerfileHealthcheckUsesReadyz(t *testing.T) {
	raw, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{"HEALTHCHECK", "/readyz", `"ready":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dockerfile healthcheck should include %q: %s", want, body)
		}
	}
}

func TestSetupPageRendersWhenAuthMissing(t *testing.T) {
	tTempDir = t.TempDir()
	store, err := NewStore(tTempDir, "")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{
		cfg:       Config{PublicURL: "https://vault.barta.cm", ProductMode: "self_hosted", RequireAuth: true},
		store:     store,
		templates: mustTemplates(),
	}

	rr := httptest.NewRecorder()
	app.withAuth(app.handleDashboard)(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected setup 503, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Janus is locked") {
		t.Fatalf("setup page did not render expected body: %s", rr.Body.String())
	}
}

func TestEnterpriseChecksRequireAuditControls(t *testing.T) {
	issues := enterpriseChecks(Config{
		ProductMode:  "enterprise",
		RequireAuth:  true,
		OIDCIssuer:   "https://auth.inspr.at",
		OIDCClientID: "client",
		OIDCSecret:   "secret",
		CookieKey:    []byte("0123456789abcdef0123456789abcdef"),
	})
	if len(issues) != 3 {
		t.Fatalf("expected three enterprise gates, got %d: %#v", len(issues), issues)
	}
}
