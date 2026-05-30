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
	"reflect"
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
	for _, forbidden := range []string{"\"value\"", "\"secret_value\"", "\"plaintext\"", "\"source\"", "secrets/"} {
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
	req.Header.Set("X-Request-Id", "receipt-handle-1")
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
	for _, want := range []string{`"receipt"`, `"action":"warden.resolve"`, `"request_id":"receipt-handle-1"`, `"role_checked":true`, `"csrf_checked":true`, `"readiness_checked":true`, `"audit_recorded":true`, `"boundary":"metadata_only"`, `"secret_value_returned":false`, `"request_body_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("handle response should include action receipt %s: %s", want, body)
		}
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

func TestPermitAPIsReturnValueFreeActionReceipts(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	create := httptest.NewRequest(http.MethodPost, "/api/permits", strings.NewReader(`{"ref":"zitadel-janus-oidc","action":"metadata_use","destination":"dashboard","reason":"local smoke"}`))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("X-Request-Id", "receipt-permit-create")
	createOut := httptest.NewRecorder()
	app.routes().ServeHTTP(createOut, create)
	if createOut.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", createOut.Code, createOut.Body.String())
	}
	createBody := createOut.Body.String()
	for _, want := range []string{`"receipt"`, `"action":"permit.create"`, `"request_id":"receipt-permit-create"`, `"audit_recorded":true`, `"boundary":"metadata_only"`, `"secret_value_returned":false`, `"request_body_returned":false`, `"value_returned":false`} {
		if !strings.Contains(createBody, want) {
			t.Fatalf("permit create should include action receipt %s: %s", want, createBody)
		}
	}
	assertRouteResponseValueFree(t, "permit create receipt", createOut)

	var created struct {
		Permit Permit `json:"permit"`
	}
	if err := json.Unmarshal(createOut.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	run := httptest.NewRequest(http.MethodPost, "/api/permits/"+created.Permit.ID+"/run", nil)
	run.SetPathValue("permitID", created.Permit.ID)
	run.Header.Set("X-Request-Id", "receipt-permit-run")
	runOut := httptest.NewRecorder()
	app.routes().ServeHTTP(runOut, run)
	if runOut.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", runOut.Code, runOut.Body.String())
	}
	runBody := runOut.Body.String()
	for _, want := range []string{`"receipt"`, `"action":"permit.run"`, `"request_id":"receipt-permit-run"`, `"audit_recorded":true`, `"boundary":"metadata_only"`, `"secret_value_returned":false`, `"request_body_returned":false`, `"value_returned":false`} {
		if !strings.Contains(runBody, want) {
			t.Fatalf("permit run should include action receipt %s: %s", want, runBody)
		}
	}
	assertRouteResponseValueFree(t, "permit run receipt", runOut)
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
	if !strings.Contains(body, `"role_availability"`) || !strings.Contains(body, `"dashboard_strip":true`) || !strings.Contains(body, `"role_availability_ux"`) {
		t.Fatalf("posture response should include role availability UX: %s", body)
	}
	if !strings.Contains(body, `"action_readiness"`) || !strings.Contains(body, `"key":"evidence_export"`) || !strings.Contains(body, `"key":"handle_issue"`) || !strings.Contains(body, `"key":"permit_run_check"`) || !strings.Contains(body, `"action_readiness":"role_and_readiness_matrix"`) || !strings.Contains(body, `"role_aware_action_readiness"`) {
		t.Fatalf("posture response should include action readiness matrix: %s", body)
	}
	if !strings.Contains(body, `"action_receipts":"mutation_result_receipts"`) || !strings.Contains(body, `"value_free_action_receipts"`) {
		t.Fatalf("posture response should include action receipt capability: %s", body)
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
	if !strings.Contains(body, `"cors"`) || !strings.Contains(body, `"policy":"deny_by_default"`) || !strings.Contains(body, `"access_control_allow_origin":"absent"`) || !strings.Contains(body, `"deny_by_default_cors"`) {
		t.Fatalf("posture response should include deny-by-default CORS posture: %s", body)
	}
	if !strings.Contains(body, `"assurance"`) || !strings.Contains(body, `"route_value_leak_sentinel":true`) || !strings.Contains(body, `"json_errors_request_id":true`) || !strings.Contains(body, `"backend_source_paths":"not_returned"`) || !strings.Contains(body, `"route_value_leak_sentinel"`) || !strings.Contains(body, `"request_correlated_json_errors"`) {
		t.Fatalf("posture response should include route value-leak assurance: %s", body)
	}
	if !strings.Contains(body, `"evidence_export_boundary":"dashboard_and_json"`) || !strings.Contains(body, `"evidence_export_boundary_ux"`) {
		t.Fatalf("posture response should include evidence export boundary posture: %s", body)
	}
	if !strings.Contains(body, `"evidence_download":"auditor_json_with_pack_hash"`) || !strings.Contains(body, `"evidence_download_receipt"`) {
		t.Fatalf("posture response should include evidence download affordance: %s", body)
	}
	if !strings.Contains(body, `"evidence_receipt"`) || !strings.Contains(body, `"state":"ready"`) || !strings.Contains(body, `"hash_header":"X-Janus-Evidence-Hash"`) || !strings.Contains(body, `"body_field":"integrity.pack_hash"`) || !strings.Contains(body, `"evidence_receipt":"download_header_body_match"`) || !strings.Contains(body, `"exact_evidence_download_receipt"`) {
		t.Fatalf("posture response should include exact evidence receipt posture: %s", body)
	}
	if !strings.Contains(body, `"assurance_summary"`) || !strings.Contains(body, `"verdict"`) || !strings.Contains(body, `"Value boundary"`) || !strings.Contains(body, `"human_readable_assurance_summary"`) || !strings.Contains(body, `"human_readable_summary":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include human-readable assurance summary: %s", body)
	}
	if !strings.Contains(body, `"assurance_gates"`) || !strings.Contains(body, `"key":"role_denial"`) || !strings.Contains(body, `"key":"catalog_metadata"`) || !strings.Contains(body, `"key":"degraded_actions"`) || !strings.Contains(body, `"key":"value_leak_sentinel"`) || !strings.Contains(body, `"assurance_gate_proof_strip"`) {
		t.Fatalf("posture response should include assurance gate proofs: %s", body)
	}
	if !strings.Contains(body, `"negative_path_assurance"`) || !strings.Contains(body, `"key":"audit_sink_degraded"`) || !strings.Contains(body, `"key":"sensitive_action_guard"`) || !strings.Contains(body, `"negative_path_assurance_matrix"`) || !strings.Contains(body, `"negative_path_assurance":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include negative-path assurance: %s", body)
	}
	if !strings.Contains(body, `"degraded_guidance"`) || !strings.Contains(body, `"key":"audit_sink"`) || !strings.Contains(body, `"key":"evidence_export"`) || !strings.Contains(body, `"key":"enterprise_controls"`) || !strings.Contains(body, `"degraded_guidance_panel"`) || !strings.Contains(body, `"degraded_guidance":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include degraded-state guidance: %s", body)
	}
	if !strings.Contains(body, `"operational_status"`) || !strings.Contains(body, `"key":"role_duties"`) || !strings.Contains(body, `"key":"value_boundary"`) || !strings.Contains(body, `"operational_status_strip"`) || !strings.Contains(body, `"operational_status":"dashboard_posture_strip"`) {
		t.Fatalf("posture response should include operational status strip: %s", body)
	}
	if !strings.Contains(body, `"mode_posture"`) || !strings.Contains(body, `"current":"Self-hosted"`) || !strings.Contains(body, `"enterprise":"not_claimed"`) || !strings.Contains(body, `"mode_posture_evidence"`) {
		t.Fatalf("posture response should include product-mode evidence: %s", body)
	}
	if !strings.Contains(body, `"mode_guardrails"`) || !strings.Contains(body, `"current":"Self-hosted"`) || !strings.Contains(body, `"boundary":"enterprise_not_claimed"`) || !strings.Contains(body, `"key":"enterprise_claim"`) || !strings.Contains(body, `"mode_guardrails":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include mode guardrails: %s", body)
	}
	if !strings.Contains(body, `"enterprise_validation"`) || !strings.Contains(body, `"status":"not_claimed"`) || !strings.Contains(body, `"key":"remote_audit"`) || !strings.Contains(body, `"enterprise_validation_clarity"`) || !strings.Contains(body, `"enterprise_validation":"self_hosted_safe_enterprise_required"`) || !strings.Contains(body, `"enterprise_attachments":"presence_only_no_refs"`) || !strings.Contains(body, `"enterprise_evidence_attachment_matrix"`) {
		t.Fatalf("posture response should include enterprise validation clarity: %s", body)
	}
	if !strings.Contains(body, `"privacy_posture"`) || !strings.Contains(body, `"key":"request_bodies"`) || !strings.Contains(body, `"key":"prompt_command_env"`) || !strings.Contains(body, `"key":"auth_cookie_secrets"`) || !strings.Contains(body, `"privacy_retention_posture"`) || !strings.Contains(body, `"privacy_retention":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include privacy and retention posture: %s", body)
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
	if !strings.Contains(body, `"cross_origin_embedder_policy":"credentialless"`) || !strings.Contains(body, `"cross_origin_opener_policy":"same-origin"`) || !strings.Contains(body, `"dns_prefetch_control":"off"`) || !strings.Contains(body, `"origin_agent_cluster":true`) || !strings.Contains(body, `"security_header_regression":"core_routes"`) || !strings.Contains(body, `"security_header_regression_table"`) {
		t.Fatalf("posture response should include security header regression posture: %s", body)
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
	if got := out.Header().Get("Content-Disposition"); !strings.Contains(got, "janus-evidence.json") {
		t.Fatalf("evidence response should be downloadable, got Content-Disposition %q", got)
	}
	headerHash := out.Header().Get("X-Janus-Evidence-Hash")
	if len(headerHash) != 64 || out.Header().Get("X-Janus-Evidence-Algorithm") != "sha256-json-v1" || out.Header().Get("X-Janus-Evidence-Body-Field") != "integrity.pack_hash" || out.Header().Get("X-Janus-Value-Returned") != "false" {
		t.Fatalf("evidence response should include exact value-free receipt headers: %#v", out.Header())
	}
	body := out.Body.String()
	if !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, `"plaintext"`) {
		t.Fatalf("evidence response should be value-free: %s", body)
	}
	var pack EvidencePack
	if err := json.Unmarshal(out.Body.Bytes(), &pack); err != nil {
		t.Fatalf("evidence response should decode: %v", err)
	}
	if pack.Integrity == nil || pack.Integrity.PackHash != headerHash {
		t.Fatalf("evidence body hash should match exact download header: header=%q pack=%#v", headerHash, pack.Integrity)
	}
	if pack.Receipt == nil || pack.Receipt.PackHash != headerHash || pack.Receipt.HashHeader != "X-Janus-Evidence-Hash" || pack.Receipt.BodyField != "integrity.pack_hash" || pack.Receipt.ValueReturned {
		t.Fatalf("evidence response should include exact value-free receipt: %#v", pack.Receipt)
	}
	if !strings.Contains(body, `"redaction_model"`) {
		t.Fatalf("evidence response should explain redaction model: %s", body)
	}
	if !strings.Contains(body, `"evidence_boundary"`) || !strings.Contains(body, `"gate":"export_ready"`) || !strings.Contains(body, `"secret_values"`) || !strings.Contains(body, `"backend_source_paths"`) || !strings.Contains(body, `"hash_available":true`) {
		t.Fatalf("evidence response should include export boundary: %s", body)
	}
	if !strings.Contains(body, `"evidence_receipt"`) || !strings.Contains(body, `"hash_header":"X-Janus-Evidence-Hash"`) || !strings.Contains(body, `"body_field":"integrity.pack_hash"`) || !strings.Contains(body, `"coverage":"evidence_json_without_integrity_or_receipt"`) {
		t.Fatalf("evidence response should include exact receipt body: %s", body)
	}
	if !strings.Contains(body, `"assurance_summary"`) || !strings.Contains(body, `"proven"`) || !strings.Contains(body, `"review"`) || !strings.Contains(body, `"Browser and API boundary"`) {
		t.Fatalf("evidence response should include assurance summary: %s", body)
	}
	if !strings.Contains(body, `"operational_status"`) || !strings.Contains(body, `"key":"evidence_export"`) || !strings.Contains(body, `"key":"scope_boundary"`) {
		t.Fatalf("evidence response should include operational status: %s", body)
	}
	if !strings.Contains(body, `"action_readiness"`) || !strings.Contains(body, `"key":"posture_view"`) || !strings.Contains(body, `"key":"admin_policy_review"`) || !strings.Contains(body, `"value_returned":false`) {
		t.Fatalf("evidence response should include action readiness: %s", body)
	}
	if !strings.Contains(body, `"assurance_gates"`) || !strings.Contains(body, `"key":"value_leak_sentinel"`) {
		t.Fatalf("evidence response should include assurance gates: %s", body)
	}
	if !strings.Contains(body, `"negative_path_assurance"`) || !strings.Contains(body, `"key":"role_denial"`) || !strings.Contains(body, `"key":"audit_sink_degraded"`) || !strings.Contains(body, `"key":"request_correlation"`) {
		t.Fatalf("evidence response should include negative-path assurance: %s", body)
	}
	if !strings.Contains(body, `"degraded_guidance"`) || !strings.Contains(body, `"key":"readiness"`) || !strings.Contains(body, `"key":"audit_sink"`) || !strings.Contains(body, `"key":"enterprise_controls"`) {
		t.Fatalf("evidence response should include degraded-state guidance: %s", body)
	}
	if !strings.Contains(body, `"mode_guardrails"`) || !strings.Contains(body, `"key":"current_mode"`) || !strings.Contains(body, `"key":"enterprise_claim"`) || !strings.Contains(body, `"value_returned":false`) {
		t.Fatalf("evidence response should include mode guardrails: %s", body)
	}
	if !strings.Contains(body, `"enterprise_validation"`) || !strings.Contains(body, `"key":"privacy_policy"`) || !strings.Contains(body, `"attachment":"not_claimed"`) || !strings.Contains(body, `"evidence_ref_returned":false`) {
		t.Fatalf("evidence response should include enterprise validation: %s", body)
	}
	if !strings.Contains(body, `"privacy_posture"`) || !strings.Contains(body, `"key":"raw_metadata"`) || !strings.Contains(body, `"cookie_secrets"`) {
		t.Fatalf("evidence response should include privacy posture: %s", body)
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

func TestAssuranceGateProofDirectAbuseCases(t *testing.T) {
	t.Run("viewer role denial is value-free and audited", func(t *testing.T) {
		app := newTestApp(t)
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
		assertRouteResponseValueFree(t, "viewer role denial", out)
		recent := app.store.RecentAudit(1)
		if len(recent) != 1 || recent[0].Outcome != "denied" || !strings.Contains(recent[0].Reason, "auditor") {
			t.Fatalf("expected denied auditor audit event: %#v", recent)
		}
	})

	t.Run("malformed catalog metadata opens gates", func(t *testing.T) {
		gates := ValidateCatalog([]SecretDescriptor{{}})
		for _, code := range []string{"missing_id", "missing_owner", "weak_classification", "missing_scope", "missing_source", "missing_consumers", "no_approved_use_profile"} {
			if !catalogGateHasCode(gates, code) {
				t.Fatalf("expected catalog gate %q in %#v", code, gates)
			}
		}
		proof := AssuranceGatesFor(true, len(gates), AccessPosture{RoleDutyMatrix: true, RequiredRoles: map[string]string{"/api/evidence": RoleAuditor}})
		if proof.ValueReturned || proof.ReviewCount == 0 || !assuranceGateHasKey(proof.Gates, "catalog_metadata") {
			t.Fatalf("assurance gate proof should expose catalog review without values: %#v", proof)
		}
	})

	t.Run("degraded sensitive action is blocked value-free", func(t *testing.T) {
		app := newTestApp(t)
		app.cfg.RequireAuth = false
		app.permits = nil

		req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"local smoke"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", "assurance-degraded-1")
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
		}
		assertRouteResponseValueFree(t, "degraded sensitive action", out)
		if !strings.Contains(out.Body.String(), `"system_degraded"`) || !strings.Contains(out.Body.String(), `"request_id":"assurance-degraded-1"`) {
			t.Fatalf("degraded denial should be clear and correlated: %s", out.Body.String())
		}
	})
}

func TestNegativePathAssuranceMatrix(t *testing.T) {
	proof := NegativePathAssuranceFor(true, 0, AccessPosture{
		RoleDutyMatrix: true,
		RequiredRoles: map[string]string{
			"/api/evidence":            RoleAuditor,
			"POST /api/warden/resolve": RoleOperator,
		},
	}, AuditPosture{SinkWritable: true, ChainVerified: true})
	if proof.ValueReturned || proof.ReviewCount != 0 || proof.CoveredCount < 5 {
		t.Fatalf("negative-path assurance should be covered and value-free: %#v", proof)
	}
	for _, key := range []string{"role_denial", "catalog_gate", "audit_sink_degraded", "sensitive_action_guard", "value_leak_sentinel", "request_correlation"} {
		if !negativePathHasKey(proof.Cases, key) {
			t.Fatalf("negative-path assurance should cover %q: %#v", key, proof)
		}
	}

	degraded := NegativePathAssuranceFor(false, 2, AccessPosture{}, AuditPosture{})
	if degraded.ReviewCount == 0 || !negativePathHasState(degraded.Cases, "audit_sink_degraded", "blocking") || !negativePathHasState(degraded.Cases, "sensitive_action_guard", "blocking") {
		t.Fatalf("degraded negative-path assurance should show blocking states: %#v", degraded)
	}
}

func TestNegativePathAssuranceSharedByPostureAndEvidence(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	session := Session{Subject: "dev-local", Roles: AllRoles(), Expiry: time.Now().UTC().Add(time.Hour)}

	posture := app.postureBody(session)
	postureProof, ok := posture["negative_path_assurance"].(NegativePathAssurance)
	if !ok {
		t.Fatalf("posture should expose typed negative-path assurance")
	}
	postureGuidance, ok := posture["degraded_guidance"].(DegradedGuidance)
	if !ok {
		t.Fatalf("posture should expose typed degraded-state guidance")
	}
	postureModeGuardrails, ok := posture["mode_guardrails"].(ModeGuardrails)
	if !ok {
		t.Fatalf("posture should expose typed mode guardrails")
	}
	postureActionReadiness, ok := posture["action_readiness"].(ActionReadiness)
	if !ok {
		t.Fatalf("posture should expose typed action readiness")
	}
	pack := app.evidencePack(session)
	if !reflect.DeepEqual(postureProof, pack.NegativePath) {
		t.Fatalf("posture and evidence should share the same negative-path proof: posture=%#v evidence=%#v", postureProof, pack.NegativePath)
	}
	if !reflect.DeepEqual(postureGuidance, pack.Guidance) {
		t.Fatalf("posture and evidence should share the same degraded guidance: posture=%#v evidence=%#v", postureGuidance, pack.Guidance)
	}
	if !reflect.DeepEqual(postureModeGuardrails, pack.ModeGuardrails) {
		t.Fatalf("posture and evidence should share the same mode guardrails: posture=%#v evidence=%#v", postureModeGuardrails, pack.ModeGuardrails)
	}
	if !reflect.DeepEqual(postureActionReadiness, pack.ActionReadiness) {
		t.Fatalf("posture and evidence should share the same action readiness: posture=%#v evidence=%#v", postureActionReadiness, pack.ActionReadiness)
	}
	if pack.NegativePath.ValueReturned || !negativePathHasKey(pack.NegativePath.Cases, "value_leak_sentinel") {
		t.Fatalf("negative-path evidence should stay value-free and include leak sentinel: %#v", pack.NegativePath)
	}
}

func TestDegradedGuidanceCoversReadyBlockedAndRoleGatedStates(t *testing.T) {
	access := AccessPosture{ExplicitBindings: true}
	audit := AuditPosture{SinkWritable: true, ChainVerified: true}
	selfHosted := EnterpriseValidationFor(Config{ProductMode: "self_hosted"}, true, access, audit, 0)
	ready := DegradedGuidanceFor(true, audit, EvidenceBoundaryFor(true, true), selfHosted)
	if ready.ValueReturned || ready.BlockedCount != 0 || ready.ReviewCount != 0 {
		t.Fatalf("ready self-hosted guidance should be clear and value-free: %#v", ready)
	}
	if !degradedGuidanceHasState(ready.Items, "readiness", "ready") || !degradedGuidanceHasState(ready.Items, "audit_sink", "ready") || !degradedGuidanceHasState(ready.Items, "enterprise_controls", "not_claimed") {
		t.Fatalf("ready guidance should name clear states: %#v", ready)
	}

	auditDown := DegradedGuidanceFor(false, AuditPosture{ChainVerified: true}, EvidenceBoundaryFor(true, true), selfHosted)
	if auditDown.BlockedCount == 0 || !degradedGuidanceHasState(auditDown.Items, "audit_sink", "blocked") || !degradedGuidanceHasAction(auditDown.Items, "audit_sink", "Recover audit storage") {
		t.Fatalf("audit-down guidance should explain recovery: %#v", auditDown)
	}

	viewer := DegradedGuidanceFor(true, audit, EvidenceBoundaryFor(false, false), selfHosted)
	if viewer.ReviewCount == 0 || !degradedGuidanceHasState(viewer.Items, "evidence_export", "role gated") || !degradedGuidanceHasAction(viewer.Items, "evidence_export", "Use an auditor session") {
		t.Fatalf("viewer guidance should explain evidence role gate: %#v", viewer)
	}

	for _, spec := range enterpriseValidationSpecs() {
		t.Setenv(spec.EnvKey, "")
	}
	enterprise := EnterpriseValidationFor(Config{ProductMode: "enterprise"}, true, access, audit, 0)
	blocked := DegradedGuidanceFor(true, audit, EvidenceBoundaryFor(true, true), enterprise)
	if blocked.BlockedCount == 0 || !degradedGuidanceHasState(blocked.Items, "enterprise_controls", "blocked") || !degradedGuidanceHasAction(blocked.Items, "enterprise_controls", "Attach external evidence") {
		t.Fatalf("enterprise guidance should explain missing controls: %#v", blocked)
	}
}

func TestPostureGuidanceIsSessionAwareForEvidenceGate(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`"degraded_guidance"`, `"key":"evidence_export"`, `"state":"role gated"`, `"evidence_receipt"`, `"state":"role_gated"`, `"hash_header":"X-Janus-Evidence-Hash"`, `"body_field":"integrity.pack_hash"`, "Use an auditor session", `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("viewer posture guidance should include %s: %s", want, body)
		}
	}
	assertRouteResponseValueFree(t, "viewer posture guidance", out)
}

func TestAuditSinkDegradedBlocksSensitiveActions(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.store.auditFile = filepath.Join(t.TempDir(), "missing-parent", "audit.jsonl")

	readiness, ready := app.readinessBody()
	if ready {
		t.Fatalf("audit sink degradation should fail readiness: %#v", readiness)
	}
	checks, ok := readiness["checks"].(map[string]bool)
	if !ok || checks["audit_sink"] {
		t.Fatalf("readiness should show audit sink degraded: %#v", readiness)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"raw-secret-value","reason":"plaintext body should not echo"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "audit-down-1")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	assertRouteResponseValueFree(t, "audit sink degraded", out)
	assertJSONErrorRequestCorrelated(t, "audit sink degraded", "audit-down-1", out)
	if !strings.Contains(out.Body.String(), `"audit_sink":false`) || !strings.Contains(out.Body.String(), `"system_degraded"`) {
		t.Fatalf("audit degradation denial should be explicit and safe: %s", out.Body.String())
	}
}

func TestSensitiveAPIsFailClosedWhenReadinessDegraded(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
	}{
		{name: "evidence export", method: http.MethodGet, path: "/api/evidence"},
		{name: "resolve handle", method: http.MethodPost, path: "/api/warden/resolve", body: `{"ref":"raw-secret-value","reason":"plaintext body should not echo"}`, contentType: "application/json"},
		{name: "create permit", method: http.MethodPost, path: "/api/permits", body: `{"ref":"raw-secret-value","action":"metadata_use","destination":"secrets/backend","reason":"plaintext body should not echo"}`, contentType: "application/json"},
		{name: "run permit", method: http.MethodPost, path: "/api/permits/raw-secret-value/run"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newTestApp(t)
			app.cfg.RequireAuth = false
			app.permits = nil

			reqID := "degraded-" + strings.NewReplacer(" ", "-", "/", "-").Replace(tc.name)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("X-Request-Id", reqID)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
			}
			assertRouteResponseValueFree(t, tc.name, out)
			assertJSONErrorRequestCorrelated(t, tc.name, reqID, out)
			for _, want := range []string{`"error":"system_degraded"`, `"redacted":true`, `"value_returned":false`} {
				if !strings.Contains(out.Body.String(), want) {
					t.Fatalf("%s degraded denial should include %s: %s", tc.name, want, out.Body.String())
				}
			}
		})
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

func TestProductModePostureDistinguishesClaims(t *testing.T) {
	policy := RolePolicy{
		AdminSubjects:    map[string]bool{"markus@barta.com": true},
		AuditorSubjects:  map[string]bool{"markus@barta.com": true},
		OperatorSubjects: map[string]bool{"markus@barta.com": true},
		BootstrapOwner:   false,
	}
	access := AccessPostureFor(policy)
	audit := AuditPosture{ChainVerified: true, SinkWritable: true}

	selfHosted := ProductModePostureFor(Config{ProductMode: "self_hosted", RolePolicy: policy}, true, nil, access, audit, 0)
	if selfHosted.Current != "Self-hosted" || selfHosted.Baseline != "ready" || selfHosted.Enterprise != "not_claimed" || selfHosted.ValueReturned {
		t.Fatalf("self-hosted mode should be healthy without claiming enterprise: %#v", selfHosted)
	}

	dev := ProductModePostureFor(Config{ProductMode: "dev", RolePolicy: policy}, true, nil, access, audit, 0)
	if dev.Current != "Dev" || dev.Baseline != "dev_only" || dev.Enterprise != "not_claimed" {
		t.Fatalf("dev mode should stay clearly non-enterprise: %#v", dev)
	}

	enterpriseBlocked := ProductModePostureFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, []string{"remote audit missing"}, access, audit, 0)
	if enterpriseBlocked.Current != "Enterprise" || enterpriseBlocked.Enterprise != "blocked" {
		t.Fatalf("enterprise mode with gates should be blocked: %#v", enterpriseBlocked)
	}

	enterpriseCandidate := ProductModePostureFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, nil, access, audit, 0)
	if enterpriseCandidate.Enterprise != "candidate" || enterpriseCandidate.Baseline != "ready" {
		t.Fatalf("enterprise mode with clear gates should be a candidate: %#v", enterpriseCandidate)
	}
}

func TestModeGuardrailsDistinguishClaims(t *testing.T) {
	policy := RolePolicy{
		AdminSubjects:    map[string]bool{"markus@barta.com": true},
		AuditorSubjects:  map[string]bool{"markus@barta.com": true},
		OperatorSubjects: map[string]bool{"markus@barta.com": true},
		BootstrapOwner:   false,
	}
	access := AccessPostureFor(policy)
	audit := AuditPosture{ChainVerified: true, SinkWritable: true}

	devEnterprise := EnterpriseValidationFor(Config{ProductMode: "dev", RolePolicy: policy}, true, access, audit, 0)
	dev := ModeGuardrailsFor(Config{ProductMode: "dev", RolePolicy: policy}, true, nil, access, audit, 0, devEnterprise)
	if dev.Claim != "local_only" || dev.Boundary != "no_production_or_enterprise_claim" || dev.BlockedCount == 0 || dev.ValueReturned {
		t.Fatalf("dev guardrails should block production and enterprise claims while staying value-free: %#v", dev)
	}
	if !modeGuardrailHasState(dev.Items, "enterprise_claim", "blocked") || !modeGuardrailHasLimit(dev.Items, "current_mode", "No production or enterprise claim") {
		t.Fatalf("dev guardrails should be explicit about limits: %#v", dev)
	}

	selfHostedEnterprise := EnterpriseValidationFor(Config{ProductMode: "self_hosted", RolePolicy: policy}, true, access, audit, 0)
	selfHosted := ModeGuardrailsFor(Config{ProductMode: "self_hosted", RolePolicy: policy}, true, nil, access, audit, 0, selfHostedEnterprise)
	if selfHosted.Claim != "ready" || selfHosted.Boundary != "enterprise_not_claimed" || selfHosted.BlockedCount != 0 || selfHosted.ValueReturned {
		t.Fatalf("self-hosted guardrails should allow local readiness without enterprise claim: %#v", selfHosted)
	}
	if !modeGuardrailHasState(selfHosted.Items, "enterprise_claim", "not_claimed") || !modeGuardrailHasLimit(selfHosted.Items, "enterprise_claim", "Remote audit") {
		t.Fatalf("self-hosted guardrails should name excluded enterprise evidence: %#v", selfHosted)
	}

	for _, spec := range enterpriseValidationSpecs() {
		t.Setenv(spec.EnvKey, "")
	}
	enterpriseBlockedValidation := EnterpriseValidationFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, access, audit, 0)
	enterpriseBlocked := ModeGuardrailsFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, nil, access, audit, 0, enterpriseBlockedValidation)
	if enterpriseBlocked.Claim != "blocked" || enterpriseBlocked.Boundary != "external_evidence_required" || enterpriseBlocked.BlockedCount == 0 {
		t.Fatalf("enterprise guardrails should block missing external evidence: %#v", enterpriseBlocked)
	}
	if !modeGuardrailHasState(enterpriseBlocked.Items, "external_controls", "missing") || !modeGuardrailHasState(enterpriseBlocked.Items, "enterprise_claim", "blocked") {
		t.Fatalf("enterprise guardrails should show missing external controls: %#v", enterpriseBlocked)
	}

	for _, spec := range enterpriseValidationSpecs() {
		t.Setenv(spec.EnvKey, "attached")
	}
	enterpriseCandidateValidation := EnterpriseValidationFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, access, audit, 0)
	enterpriseCandidate := ModeGuardrailsFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, nil, access, audit, 0, enterpriseCandidateValidation)
	if enterpriseCandidate.Claim != "candidate" || enterpriseCandidate.BlockedCount != 0 || !modeGuardrailHasState(enterpriseCandidate.Items, "enterprise_claim", "candidate") {
		t.Fatalf("enterprise guardrails should make full evidence a candidate claim: %#v", enterpriseCandidate)
	}
	if !modeGuardrailHasLimit(enterpriseCandidate.Items, "enterprise_claim", "not a silent guarantee") {
		t.Fatalf("enterprise candidate guardrails should avoid silent guarantees: %#v", enterpriseCandidate)
	}
}

func TestEnterpriseValidationDistinguishesClaims(t *testing.T) {
	policy := RolePolicy{
		AdminSubjects:    map[string]bool{"markus@barta.com": true},
		AuditorSubjects:  map[string]bool{"markus@barta.com": true},
		OperatorSubjects: map[string]bool{"markus@barta.com": true},
		BootstrapOwner:   false,
	}
	access := AccessPostureFor(policy)
	audit := AuditPosture{ChainVerified: true, SinkWritable: true}

	selfHosted := EnterpriseValidationFor(Config{ProductMode: "self_hosted", RolePolicy: policy}, true, access, audit, 0)
	if selfHosted.Status != "not_claimed" || selfHosted.MissingCount != 0 || selfHosted.ValueReturned {
		t.Fatalf("self-hosted validation should not claim enterprise evidence: %#v", selfHosted)
	}
	if !enterpriseControlHasState(selfHosted.Controls, "remote_audit", "not_claimed") {
		t.Fatalf("self-hosted validation should list enterprise requirements as not claimed: %#v", selfHosted)
	}
	if !enterpriseControlHasAttachment(selfHosted.Controls, "remote_audit", "not_claimed") || !enterpriseControlIsValueFree(selfHosted.Controls, "remote_audit") {
		t.Fatalf("self-hosted validation should keep enterprise attachment refs withheld: %#v", selfHosted)
	}

	t.Run("enterprise missing external controls", func(t *testing.T) {
		for _, spec := range enterpriseValidationSpecs() {
			t.Setenv(spec.EnvKey, "")
		}
		validation := EnterpriseValidationFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, access, audit, 0)
		if validation.Status != "blocked" || validation.MissingCount != len(enterpriseValidationSpecs()) {
			t.Fatalf("enterprise validation should be blocked when external controls are missing: %#v", validation)
		}
		for _, spec := range enterpriseValidationSpecs() {
			if !enterpriseControlHasState(validation.Controls, spec.Key, "missing") {
				t.Fatalf("enterprise validation should mark %s missing: %#v", spec.Key, validation)
			}
			if !enterpriseControlHasAttachment(validation.Controls, spec.Key, "missing") || !enterpriseControlHasNext(validation.Controls, spec.Key) || !enterpriseControlIsValueFree(validation.Controls, spec.Key) {
				t.Fatalf("enterprise validation should make %s attachment action explicit and value-free: %#v", spec.Key, validation)
			}
		}
	})

	t.Run("enterprise attached controls become candidate", func(t *testing.T) {
		for _, spec := range enterpriseValidationSpecs() {
			t.Setenv(spec.EnvKey, "secret-cookie-secret-/run/agenix/"+spec.Key)
		}
		validation := EnterpriseValidationFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, access, audit, 0)
		if validation.Status != "candidate" || validation.MissingCount != 0 {
			t.Fatalf("enterprise validation should become candidate when external controls are attached: %#v", validation)
		}
		for _, spec := range enterpriseValidationSpecs() {
			if !enterpriseControlHasState(validation.Controls, spec.Key, "attached") {
				t.Fatalf("enterprise validation should mark %s attached: %#v", spec.Key, validation)
			}
			if !enterpriseControlHasAttachment(validation.Controls, spec.Key, "attached_presence_only") || !enterpriseControlIsValueFree(validation.Controls, spec.Key) {
				t.Fatalf("enterprise validation should mark %s presence-only and value-free: %#v", spec.Key, validation)
			}
		}
		raw, err := json.Marshal(validation)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "secret-cookie-secret") || strings.Contains(string(raw), "/run/agenix") {
			t.Fatalf("enterprise validation leaked env-backed evidence refs: %s", raw)
		}
	})
}

func TestPrivacyPostureKeepsEvidenceUsefulAndValueFree(t *testing.T) {
	posture := PrivacyPostureFor(EvidenceBoundaryFor(true, true), AuditPosture{ChainVerified: true, SinkWritable: true})
	if posture.Redaction != "metadata_only" || posture.ValueReturned {
		t.Fatalf("privacy posture should be metadata-only and value-free: %#v", posture)
	}
	for _, key := range []string{"audit_events", "evidence_export", "request_bodies", "prompt_command_env", "raw_metadata", "auth_cookie_secrets"} {
		if !privacySurfaceHasKey(posture.Surfaces, key) {
			t.Fatalf("privacy posture should cover %q: %#v", key, posture)
		}
	}
	for _, excluded := range []string{"secret_values", "request_bodies", "prompt_text", "command_output", "env_dumps", "backend_source_paths", "cookie_secrets"} {
		if !stringSliceHas(posture.Excluded, excluded) {
			t.Fatalf("privacy posture should exclude %q: %#v", excluded, posture)
		}
	}

	restricted := PrivacyPostureFor(EvidenceBoundaryFor(false, false), AuditPosture{})
	if restricted.ReviewCount == 0 || !privacySurfaceHasState(restricted.Surfaces, "evidence_export", "role gated") {
		t.Fatalf("restricted privacy posture should call out review items: %#v", restricted)
	}
}

func TestAssuranceSummaryDistinguishesProofAndReview(t *testing.T) {
	access := AccessPosture{ExplicitBindings: true}
	audit := AuditPosture{ChainVerified: true}
	boundary := EvidenceBoundaryFor(true, true)

	ready := AssuranceSummaryFor("self_hosted", true, 0, 0, access, audit, boundary)
	if ready.Verdict != "self_hosted_ready" || ready.ValueReturned || len(ready.Review) != 0 {
		t.Fatalf("expected ready self-hosted summary without review: %#v", ready)
	}
	for _, want := range []string{"Readiness", "Open gates", "Value boundary", "Browser and API boundary", "Role gates", "Audit evidence", "Evidence export", "Enterprise claim"} {
		if !assuranceHasLabel(ready.Proven, want) {
			t.Fatalf("ready summary should prove %q: %#v", want, ready)
		}
	}

	review := AssuranceSummaryFor("self_hosted", false, 1, 0, AccessPosture{}, AuditPosture{}, EvidenceBoundaryFor(false, false))
	if review.Verdict != "review_needed" || len(review.Review) == 0 {
		t.Fatalf("expected review summary: %#v", review)
	}
	for _, want := range []string{"Readiness", "Open gates", "Role gates", "Audit evidence", "Evidence export"} {
		if !assuranceHasLabel(review.Review, want) {
			t.Fatalf("review summary should call out %q: %#v", want, review)
		}
	}

	roleGated := AssuranceSummaryFor("self_hosted", true, 0, 0, access, audit, EvidenceBoundaryFor(false, false))
	if roleGated.Verdict != "review_needed" || !assuranceHasLabel(roleGated.Review, "Evidence export") {
		t.Fatalf("role-gated evidence export should stay in review: %#v", roleGated)
	}

	enterprise := AssuranceSummaryFor("enterprise", true, 0, 0, access, audit, boundary)
	if enterprise.Verdict != "enterprise_review_needed" || !assuranceHasLabel(enterprise.Review, "Enterprise claim") {
		t.Fatalf("enterprise mode should require review before stronger claims: %#v", enterprise)
	}
}

func assuranceHasLabel(items []AssuranceItem, label string) bool {
	for _, item := range items {
		if item.Label == label {
			return true
		}
	}
	return false
}

func assuranceGateHasKey(items []AssuranceGateItem, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func negativePathHasKey(items []NegativePathCase, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func negativePathHasState(items []NegativePathCase, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state {
			return true
		}
	}
	return false
}

func actionReadinessHasState(items []ActionReadinessItem, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state && !item.ValueReturned {
			return true
		}
	}
	return false
}

func degradedGuidanceHasState(items []DegradedGuidanceItem, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state {
			return true
		}
	}
	return false
}

func degradedGuidanceHasAction(items []DegradedGuidanceItem, key, action string) bool {
	for _, item := range items {
		if item.Key == key && strings.Contains(item.Action, action) {
			return true
		}
	}
	return false
}

func modeGuardrailHasState(items []ModeGuardrailItem, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state {
			return true
		}
	}
	return false
}

func modeGuardrailHasLimit(items []ModeGuardrailItem, key, limit string) bool {
	for _, item := range items {
		if item.Key == key && strings.Contains(item.Limit, limit) {
			return true
		}
	}
	return false
}

func catalogGateHasCode(items []CatalogGate, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

func enterpriseControlHasState(items []EnterpriseValidationControl, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state {
			return true
		}
	}
	return false
}

func enterpriseControlHasAttachment(items []EnterpriseValidationControl, key, attachment string) bool {
	for _, item := range items {
		if item.Key == key && item.Attachment == attachment {
			return true
		}
	}
	return false
}

func enterpriseControlHasNext(items []EnterpriseValidationControl, key string) bool {
	for _, item := range items {
		if item.Key == key && item.Next != "" && item.OwnerRole != "" {
			return true
		}
	}
	return false
}

func enterpriseControlIsValueFree(items []EnterpriseValidationControl, key string) bool {
	for _, item := range items {
		if item.Key == key && !item.EvidenceRefReturned && !item.ValueReturned {
			return true
		}
	}
	return false
}

func privacySurfaceHasKey(items []PrivacySurface, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func privacySurfaceHasState(items []PrivacySurface, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state {
			return true
		}
	}
	return false
}

func stringSliceHas(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func issueContains(items []string, want string) bool {
	for _, item := range items {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
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
	for _, want := range []string{"Session identity", "Local Dev", "admin", "Live posture", "Operational status", "Assurance verdict", "Role duties", "Scope boundary", "Janus is serving value-free posture", "Assurance flow", "Known human", "Metadata only", "Use gate", "Audit trail", "Trust posture", "Catalog gates", "Approved use", "Next safe steps", "Audit storage", "Enterprise controls", "safe actions only", "Keep monitoring posture", "Assurance summary", "Proven controls", "Review items", "Assurance gates", "Role denial", "Catalog metadata", "Degraded actions", "Value leak sentinel", "abuse tested", "Blocked-path checks", "Wrong role", "Catalog gate", "Audit down", "Sensitive action", "Value leak check", "Request id", "Value boundary", "Browser and API boundary", "human readable evidence", "Available to you", "Posture", "Use actions", "Audit export", "Admin policy", "Handle and permit controls are available", "Audit rows and evidence export are available", "Admin policy review is available", "Action readiness", "Posture view", "Issue metadata handle", "Create permit", "Run permit check", "readiness blocked", "role operator", "Never reveals a secret value", "No connector executes and output is scrubbed", "Deployment mode", "Self-hosted baseline", "Enterprise evidence", "Enterprise validation", "Remote audit", "Break-glass review", "Restore drill", "Integration conformance", "Release provenance", "Privacy policy", "self-hosted safe", "enterprise required", "evidence_ref_returned=false", "presence only", "owner auditor", "presence_only_env_flag", "evidence ref not returned", "Switch to enterprise only after this external evidence exists", "Mode guardrails", "Secure local control plane", "No enterprise claim", "Switch to enterprise only after external controls exist", "Privacy and retention", "Audit events", "Request bodies", "Prompts, command output, env dumps", "Raw metadata", "Auth and cookie secrets", "Excluded from evidence", "not retained", "not_claimed", "Evidence export", "Exact download receipt", "integrity.pack_hash", "X-Janus-Evidence-Hash", "Download JSON", "Current preview", "copy-safe metadata", "exact hash returned on download", "matches integrity.pack_hash", "evidence_json_without_integrity_or_receipt", "Included evidence", "Never exported", "export_ready", "secret_values", "backend_source_paths", "value_returned=false", "Evidence JSON", "Request metadata handle", "Request permit", "Access policy", "bootstrap owner", "session ttl", "session cookie", "Duty boundary", "role matrix", "Policy and ownership", "Evidence and audit", "Posture only", "Lifecycle posture"} {
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
	for _, want := range []string{"Security state", "restricted", "Sensitive actions are blocked", "ready=false", "Next safe steps", "Restore the failed readiness check", "Action readiness", "readiness_blocked", "Recover readiness before using this action", "value_returned=false"} {
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

func TestDashboardShowsAuditSinkRecoveryGuidance(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.store.auditFile = filepath.Join(t.TempDir(), "missing-parent", "audit.jsonl")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Next safe steps", "Audit storage", "Required-audit actions stay blocked", "Recover audit storage", "chain verifies", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit sink guidance should render %q: %s", want, body)
		}
	}
	assertRouteResponseValueFree(t, "audit sink dashboard guidance", out)
}

func TestDashboardShowsEnterpriseMissingControlGuidance(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.cfg.ProductMode = "enterprise"
	app.cfg.RolePolicy = RolePolicy{
		AdminSubjects:    map[string]bool{"markus@barta.com": true},
		AuditorSubjects:  map[string]bool{"markus@barta.com": true},
		OperatorSubjects: map[string]bool{"markus@barta.com": true},
		BootstrapOwner:   false,
	}
	for _, spec := range enterpriseValidationSpecs() {
		t.Setenv(spec.EnvKey, "")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Next safe steps", "Enterprise controls", "Attach external evidence before claiming enterprise readiness", "Enterprise validation", "blocked", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("enterprise guidance should render %q: %s", want, body)
		}
	}
	assertRouteResponseValueFree(t, "enterprise dashboard guidance", out)
}

func TestEnterpriseEvidenceAttachmentsArePresenceOnlyAcrossRoutes(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.cfg.ProductMode = "enterprise"
	app.cfg.RolePolicy = RolePolicy{
		AdminSubjects:    map[string]bool{"markus@barta.com": true},
		AuditorSubjects:  map[string]bool{"markus@barta.com": true},
		OperatorSubjects: map[string]bool{"markus@barta.com": true},
		BootstrapOwner:   false,
	}
	for _, spec := range enterpriseValidationSpecs() {
		t.Setenv(spec.EnvKey, "secret-cookie-secret-/run/agenix/"+spec.Key)
	}

	routes := []struct {
		name string
		path string
	}{
		{name: "dashboard", path: "/"},
		{name: "posture", path: "/api/posture"},
		{name: "evidence", path: "/api/evidence"},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route.path, nil)
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
			}
			body := out.Body.String()
			for _, want := range []string{"attached_presence_only", "presence_only_env_flag", "evidence_ref_returned", "value_returned"} {
				if !strings.Contains(body, want) {
					t.Fatalf("%s should render presence-only enterprise attachment marker %q: %s", route.name, want, body)
				}
			}
			for _, forbidden := range []string{"secret-cookie-secret", "/run/agenix"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("%s leaked env-backed evidence ref %q: %s", route.name, forbidden, body)
				}
			}
			assertRouteResponseValueFree(t, route.name+" enterprise attachments", out)
		})
	}
}

func TestDashboardShowsDevModeGuardrails(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.cfg.ProductMode = "dev"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Mode guardrails", "Dev mode is local proof only", "no_production_or_enterprise_claim", "No production or enterprise claim", "Never claimed in dev mode", "Switch to self-hosted before serving real users", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dev dashboard mode guardrails should render %q: %s", want, body)
		}
	}
	assertRouteResponseValueFree(t, "dev dashboard mode guardrails", out)
}

func TestSecurityHeadersAcrossCoreRoutes(t *testing.T) {
	cases := []struct {
		name            string
		method          string
		path            string
		status          int
		setup           func(*App, *http.Request)
		expectBodyNonce bool
	}{
		{name: "health", method: http.MethodGet, path: "/healthz", status: http.StatusOK},
		{name: "ready", method: http.MethodGet, path: "/readyz", status: http.StatusOK},
		{name: "login", method: http.MethodGet, path: "/login", status: http.StatusFound, setup: func(app *App, _ *http.Request) {
			app.oauth = testOAuthConfig()
		}},
		{name: "auth callback failure", method: http.MethodGet, path: "/oidc/callback?state=bad", status: http.StatusBadRequest, setup: func(app *App, req *http.Request) {
			app.oauth = testOAuthConfig()
			app.verifier = &oidc.IDTokenVerifier{}
			req.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "state-cookie-secret"})
			req.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: "nonce-cookie-secret"})
			req.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: "pkce-cookie-secret"})
		}},
		{name: "browser safe error", method: http.MethodGet, path: "/missing", status: http.StatusNotFound},
		{name: "api safe error", method: http.MethodGet, path: "/api/missing", status: http.StatusNotFound},
		{name: "api auth error", method: http.MethodGet, path: "/api/posture", status: http.StatusUnauthorized},
		{name: "dashboard", method: http.MethodGet, path: "/", status: http.StatusOK, expectBodyNonce: true, setup: func(app *App, _ *http.Request) {
			app.cfg.RequireAuth = false
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newTestApp(t)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Origin", "https://evil.example")
			req.Header.Set("X-Request-Id", "security-headers-"+strings.ReplaceAll(tc.name, " ", "-"))
			if tc.setup != nil {
				tc.setup(app, req)
			}
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%s", tc.status, out.Code, out.Body.String())
			}
			assertCoreSecurityHeaders(t, tc.name, out)
			if tc.expectBodyNonce {
				assertStyleNonceMatchesCSP(t, out)
			}
		})
	}
}

func assertCoreSecurityHeaders(t *testing.T, name string, out *httptest.ResponseRecorder) {
	t.Helper()
	headers := out.Header()
	for header, want := range map[string]string{
		"Cache-Control":                     "no-store",
		"Cross-Origin-Embedder-Policy":      "credentialless",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"Expires":                           "0",
		"Origin-Agent-Cluster":              "?1",
		"Permissions-Policy":                "camera=(), geolocation=(), microphone=()",
		"Pragma":                            "no-cache",
		"Referrer-Policy":                   "no-referrer",
		"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":            "nosniff",
		"X-DNS-Prefetch-Control":            "off",
		"X-Frame-Options":                   "DENY",
		"X-Permitted-Cross-Domain-Policies": "none",
	} {
		if got := headers.Get(header); got != want {
			t.Fatalf("%s: expected %s %q, got %q", name, header, want, got)
		}
	}
	csp := headers.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'none'", "object-src 'none'", "worker-src 'none'", "base-uri 'self'", "frame-ancestors 'none'", "form-action 'self'", "connect-src 'self'", "font-src 'self'", "img-src 'self' data:", "manifest-src 'self'", "style-src 'self' 'nonce-", "upgrade-insecure-requests"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("%s: CSP should include %q: %s", name, want, csp)
		}
	}
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval"} {
		if strings.Contains(csp, forbidden) {
			t.Fatalf("%s: CSP should not include %q: %s", name, forbidden, csp)
		}
	}
	for _, header := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods"} {
		if got := headers.Get(header); got != "" {
			t.Fatalf("%s: expected no %s header, got %q", name, header, got)
		}
	}
}

func assertStyleNonceMatchesCSP(t *testing.T, out *httptest.ResponseRecorder) {
	t.Helper()
	csp := out.Header().Get("Content-Security-Policy")
	parts := strings.SplitN(out.Body.String(), `<style nonce="`, 2)
	if len(parts) != 2 {
		t.Fatalf("dashboard style tag should include nonce: %s", out.Body.String())
	}
	nonce := strings.SplitN(parts[1], `"`, 2)[0]
	if nonce == "" || !strings.Contains(csp, "'nonce-"+nonce+"'") {
		t.Fatalf("CSP nonce should match style nonce: csp=%s nonce=%q", csp, nonce)
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

func TestCORSDeniedByDefault(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	cases := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		{http.MethodGet, "/api/posture", http.StatusOK},
		{http.MethodGet, "/missing", http.StatusNotFound},
		{http.MethodOptions, "/api/posture", http.StatusMethodNotAllowed},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Access-Control-Request-Method", "GET")
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != tc.status {
			t.Fatalf("%s %s: expected %d, got %d body=%s", tc.method, tc.path, tc.status, out.Code, out.Body.String())
		}
		for _, header := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods"} {
			if got := out.Header().Get(header); got != "" {
				t.Fatalf("%s %s: expected no %s header, got %q", tc.method, tc.path, header, got)
			}
		}
		if strings.Contains(out.Body.String(), "plaintext") || strings.Contains(out.Body.String(), "secret-cookie-secret") {
			t.Fatalf("%s %s: CORS denial path should remain value-free: %s", tc.method, tc.path, out.Body.String())
		}
	}
}

func TestAPIPreflightUsesSafeMethodBoundary(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodOptions, "/api/posture", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("X-Request-Id", "cors-preflight-1")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("expected Allow GET, HEAD, got %q", got)
	}
	body := out.Body.String()
	for _, want := range []string{`"error":"method_not_allowed"`, `"request_id":"cors-preflight-1"`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("preflight denial should include %s: %s", want, body)
		}
	}
	if out.Header().Get("Access-Control-Allow-Origin") != "" || strings.Contains(body, "plaintext") {
		t.Fatalf("preflight denial should not open CORS or leak values: headers=%#v body=%s", out.Header(), body)
	}
}

func TestRouteValueLeakSentinelCoversPublicAPIAndUI(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.oauth = testOAuthConfig()
	app.verifier = &oidc.IDTokenVerifier{}

	cases := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
		status      int
		setup       func(*http.Request)
	}{
		{name: "health", method: http.MethodGet, path: "/healthz", status: http.StatusOK},
		{name: "ready", method: http.MethodGet, path: "/readyz", status: http.StatusOK},
		{name: "favicon", method: http.MethodGet, path: "/favicon.ico", status: http.StatusNoContent},
		{name: "login", method: http.MethodGet, path: "/login", status: http.StatusFound},
		{
			name:   "bad callback",
			method: http.MethodGet,
			path:   "/oidc/callback?state=wrong&code=raw-secret-value",
			status: http.StatusBadRequest,
			setup: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "state-cookie-secret"})
				req.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: "nonce-cookie-secret"})
				req.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: "pkce-cookie-secret"})
			},
		},
		{name: "browser missing", method: http.MethodGet, path: "/missing?ref=secret-cookie-secret", status: http.StatusNotFound},
		{name: "api missing", method: http.MethodGet, path: "/api/missing?ref=raw-secret-value", status: http.StatusNotFound},
		{name: "api method", method: http.MethodDelete, path: "/api/posture", status: http.StatusMethodNotAllowed},
		{name: "posture", method: http.MethodGet, path: "/api/posture", status: http.StatusOK},
		{name: "descriptors", method: http.MethodGet, path: "/api/warden/descriptors", status: http.StatusOK},
		{name: "audit", method: http.MethodGet, path: "/api/audit/recent", status: http.StatusOK},
		{name: "evidence", method: http.MethodGet, path: "/api/evidence", status: http.StatusOK},
		{name: "resolve", method: http.MethodPost, path: "/api/warden/resolve", body: `{"ref":"zitadel-janus-oidc","reason":"local smoke"}`, contentType: "application/json", status: http.StatusOK},
		{name: "resolve bad json", method: http.MethodPost, path: "/api/warden/resolve", body: `{"ref":"raw-secret-value"`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "permit", method: http.MethodPost, path: "/api/permits", body: `{"ref":"zitadel-janus-oidc","action":"metadata_use","destination":"dashboard","reason":"local smoke"}`, contentType: "application/json", status: http.StatusCreated},
		{name: "permit missing run", method: http.MethodPost, path: "/api/permits/missing/run", status: http.StatusNotFound},
		{name: "dashboard", method: http.MethodGet, path: "/", status: http.StatusOK},
		{name: "ui resolve", method: http.MethodPost, path: "/ui/warden/resolve", body: "ref=zitadel-janus-oidc&reason=local+smoke", contentType: "application/x-www-form-urlencoded", status: http.StatusOK},
		{name: "ui permit", method: http.MethodPost, path: "/ui/permits", body: "ref=zitadel-janus-oidc&action=metadata_use&destination=dashboard&reason=local+smoke", contentType: "application/x-www-form-urlencoded", status: http.StatusOK},
		{name: "ui permit missing run", method: http.MethodPost, path: "/ui/permits/missing/run", status: http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqID := "route-sentinel-" + strings.NewReplacer(" ", "-", "/", "-").Replace(tc.name)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("X-Request-Id", reqID)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.setup != nil {
				tc.setup(req)
			}
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%s", tc.status, out.Code, out.Body.String())
			}
			assertRouteResponseValueFree(t, tc.name, out)
			assertJSONErrorRequestCorrelated(t, tc.name, reqID, out)
		})
	}
}

func TestJSONErrorResponsesAreRequestCorrelated(t *testing.T) {
	app := newTestApp(t)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		status int
	}{
		{name: "auth required posture", method: http.MethodGet, path: "/api/posture", status: http.StatusUnauthorized},
		{name: "auth required resolve", method: http.MethodPost, path: "/api/warden/resolve", status: http.StatusUnauthorized},
		{name: "auth required evidence", method: http.MethodGet, path: "/api/evidence", status: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqID := "json-error-" + strings.NewReplacer(" ", "-", "/", "-").Replace(tc.name)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("X-Request-Id", reqID)
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%s", tc.status, out.Code, out.Body.String())
			}
			assertRouteResponseValueFree(t, tc.name, out)
			assertJSONErrorRequestCorrelated(t, tc.name, reqID, out)
		})
	}

	setupApp := newTestApp(t)
	setupApp.cfg.OIDCSecret = ""
	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	req.Header.Set("X-Request-Id", "json-error-setup")
	out := httptest.NewRecorder()
	setupApp.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	assertRouteResponseValueFree(t, "auth setup", out)
	assertJSONErrorRequestCorrelated(t, "auth setup", "json-error-setup", out)
}

func assertRouteResponseValueFree(t *testing.T, name string, out *httptest.ResponseRecorder) {
	t.Helper()
	var haystack strings.Builder
	haystack.WriteString(out.Body.String())
	for key, values := range out.Result().Header {
		haystack.WriteString("\n")
		haystack.WriteString(key)
		haystack.WriteString(":")
		haystack.WriteString(strings.Join(values, "\n"))
	}
	body := strings.ToLower(haystack.String())
	for _, marker := range []string{
		"plaintext",
		"raw-secret-value",
		"state-cookie-secret",
		"nonce-cookie-secret",
		"pkce-cookie-secret",
		"secret-cookie-secret",
		"cookie_key",
		"oidc_secret",
		"oidcsecret",
		"client_secret",
		"/run/agenix",
		"secrets/",
		".age\"",
		"\"source\"",
		"\"value_returned\":true",
		"value_returned=true",
	} {
		if strings.Contains(body, marker) {
			t.Fatalf("%s response leaked marker %q: headers=%#v body=%s", name, marker, out.Result().Header, out.Body.String())
		}
	}
}

func assertJSONErrorRequestCorrelated(t *testing.T, name, reqID string, out *httptest.ResponseRecorder) {
	t.Helper()
	if out.Code < http.StatusBadRequest || !strings.Contains(out.Header().Get("Content-Type"), "application/json") {
		return
	}
	body := out.Body.String()
	for _, want := range []string{`"request_id":"` + reqID + `"`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("%s JSON error should include %s: %s", name, want, body)
		}
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

func TestDashboardRoleAvailabilityStripByRole(t *testing.T) {
	cases := []struct {
		name      string
		roles     []string
		want      []string
		forbidden []string
	}{
		{
			name:  "viewer",
			roles: []string{RoleViewer},
			want: []string{
				"Available to you",
				"Safe posture and descriptor views are available.",
				"Operator role required.",
				"Auditor role required.",
				"Admin role required.",
			},
			forbidden: []string{
				"Handle and permit controls are available.",
				"Audit rows and evidence export are available.",
				"Admin policy review is available.",
			},
		},
		{
			name:  "auditor",
			roles: []string{RoleViewer, RoleAuditor},
			want: []string{
				"Available to you",
				"Audit rows and evidence export are available.",
				"Operator role required.",
				"Admin role required.",
			},
			forbidden: []string{
				"Handle and permit controls are available.",
				"Admin policy review is available.",
			},
		},
		{
			name:  "operator",
			roles: []string{RoleViewer, RoleOperator},
			want: []string{
				"Available to you",
				"Handle and permit controls are available.",
				"Auditor role required.",
				"Admin role required.",
			},
			forbidden: []string{
				"Audit rows and evidence export are available.",
				"Admin policy review is available.",
			},
		},
		{
			name:  "all roles",
			roles: []string{RoleViewer, RoleOperator, RoleAuditor, RoleAdmin},
			want: []string{
				"Available to you",
				"Handle and permit controls are available.",
				"Audit rows and evidence export are available.",
				"Admin policy review is available.",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newTestApp(t)
			session := Session{Subject: tc.name, Roles: tc.roles, Expiry: time.Now().UTC().Add(time.Hour)}
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
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("%s dashboard should render %q: %s", tc.name, want, body)
				}
			}
			for _, forbidden := range tc.forbidden {
				if strings.Contains(body, forbidden) {
					t.Fatalf("%s dashboard should not render %q: %s", tc.name, forbidden, body)
				}
			}
			for _, marker := range []string{"plaintext", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
				if strings.Contains(body, marker) {
					t.Fatalf("%s dashboard leaked %q: %s", tc.name, marker, body)
				}
			}
		})
	}
}

func TestActionReadinessDistinguishesRoleAndReadinessGates(t *testing.T) {
	viewer := ActionReadinessFor(Session{Roles: []string{RoleViewer}}, true)
	if viewer.ValueReturned || viewer.Available != 1 || viewer.Gated != 5 || viewer.Blocked != 0 {
		t.Fatalf("viewer readiness should show one safe action and role gates: %#v", viewer)
	}
	for _, key := range []string{"evidence_export", "handle_issue", "permit_create", "permit_run_check", "admin_policy_review"} {
		if !actionReadinessHasState(viewer.Actions, key, "role_gated") {
			t.Fatalf("viewer readiness should role-gate %s: %#v", key, viewer)
		}
	}

	allRoles := ActionReadinessFor(Session{Roles: AllRoles()}, true)
	if allRoles.Available != 6 || allRoles.Gated != 0 || allRoles.Blocked != 0 || allRoles.ValueReturned {
		t.Fatalf("full-role readiness should make all actions available: %#v", allRoles)
	}
	for _, key := range []string{"evidence_export", "handle_issue", "permit_create", "permit_run_check", "admin_policy_review"} {
		if !actionReadinessHasState(allRoles.Actions, key, "available") {
			t.Fatalf("full-role readiness should allow %s: %#v", key, allRoles)
		}
	}

	degraded := ActionReadinessFor(Session{Roles: AllRoles()}, false)
	if degraded.Available != 2 || degraded.Blocked != 4 || degraded.Gated != 0 {
		t.Fatalf("degraded readiness should block sensitive actions while leaving safe views: %#v", degraded)
	}
	for _, key := range []string{"evidence_export", "handle_issue", "permit_create", "permit_run_check"} {
		if !actionReadinessHasState(degraded.Actions, key, "readiness_blocked") {
			t.Fatalf("degraded readiness should block %s: %#v", key, degraded)
		}
	}
	if !actionReadinessHasState(degraded.Actions, "posture_view", "available") || !actionReadinessHasState(degraded.Actions, "admin_policy_review", "available") {
		t.Fatalf("degraded readiness should leave safe review actions available: %#v", degraded)
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
	if !strings.Contains(viewerBody, "Auditor role required") || !strings.Contains(viewerBody, "restricted") || !strings.Contains(viewerBody, "auditor_required") || !strings.Contains(viewerBody, "Evidence JSON is gated") || !strings.Contains(viewerBody, "exact receipt") || !strings.Contains(viewerBody, "Use an auditor session to download evidence") {
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
	if !strings.Contains(auditorBody, "private-ref") || !strings.Contains(auditorBody, "<th>Severity</th>") || !strings.Contains(auditorBody, ">info<") || !strings.Contains(auditorBody, "export_ready") || !strings.Contains(auditorBody, "hash ready") {
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
	for _, want := range []string{"Handle ready", "Action receipt", "Role", "CSRF", "Readiness", "Audit", "request_id=", "metadata_only", "secret_value_returned=false", "request_body_returned=false", "value_returned=false", "zitadel-janus-oidc"} {
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
	for _, want := range []string{"Permit recorded", "Action receipt", "Role", "CSRF", "Readiness", "Audit", "request_id=", "metadata_only", "secret_value_returned=false", "request_body_returned=false", "Permit safety verdict", "Metadata only", "No connector", "Audited", "approved_metadata_only", "Run safety check", "value_returned=false"} {
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
	for _, want := range []string{"Safety check complete", "Action receipt", "Role", "CSRF", "Readiness", "Audit", "request_id=", "metadata_only", "secret_value_returned=false", "request_body_returned=false", "Permit safety verdict", "Metadata only", "No connector", "Scrubbed output", "not_executed", "output_scrubbed=true", "value_returned=false"} {
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
	pack := app.evidencePack(Session{Roles: AllRoles()})
	if pack.Integrity == nil {
		t.Fatal("expected evidence integrity metadata")
	}
	if pack.Integrity.Algorithm != "sha256-json-v1" || len(pack.Integrity.PackHash) != 64 {
		t.Fatalf("unexpected integrity metadata: %#v", pack.Integrity)
	}
	if pack.Integrity.ValueReturned || pack.Integrity.GeneratedAt.IsZero() {
		t.Fatalf("integrity metadata should be value-free and timestamped: %#v", pack.Integrity)
	}
	if pack.Receipt == nil || pack.Receipt.PackHash != pack.Integrity.PackHash || !pack.Receipt.HashAvailable || pack.Receipt.HashHeader != "X-Janus-Evidence-Hash" || pack.Receipt.BodyField != "integrity.pack_hash" || pack.Receipt.ValueReturned {
		t.Fatalf("receipt should mirror integrity hash without values: %#v", pack.Receipt)
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
	for _, spec := range enterpriseValidationSpecs() {
		t.Setenv(spec.EnvKey, "")
	}
	issues := enterpriseChecks(Config{
		ProductMode:  "enterprise",
		RequireAuth:  true,
		OIDCIssuer:   "https://auth.inspr.at",
		OIDCClientID: "client",
		OIDCSecret:   "secret",
		CookieKey:    []byte("0123456789abcdef0123456789abcdef"),
	})
	if len(issues) != 7 {
		t.Fatalf("expected seven enterprise gates, got %d: %#v", len(issues), issues)
	}
	for _, want := range []string{"remote audit", "break-glass", "restore drill", "integration conformance", "release provenance", "privacy and retention", "Explicit Janus role bindings"} {
		if !issueContains(issues, want) {
			t.Fatalf("enterprise gates should include %q: %#v", want, issues)
		}
	}
}
