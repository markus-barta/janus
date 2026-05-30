package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	return &App{
		cfg:       testConfig(),
		store:     store,
		broker:    NewBroker(store),
		permits:   NewPermitStore(),
		templates: mustTemplates(),
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
	if descriptors[0].Scope != "csb1" || descriptors[0].EgressMode != "none" {
		t.Fatalf("expected normalized safe metadata: %#v", descriptors[0])
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
	recent := store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Action != "two" || recent[0].PrevHash == "" || recent[0].EventHash == "" {
		t.Fatalf("unexpected recent audit: %#v", recent)
	}
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

func TestSessionCookieIsOIDCRedirectCompatible(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie must be Lax for OIDC redirects, got %v", cookies[0].SameSite)
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("session cookie must be secure and httponly: %#v", cookies[0])
	}
}

func TestLogoutRequiresCSRF(t *testing.T) {
	app := newTestApp(t)
	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(rr.Result().Cookies()[0])

	out := httptest.NewRecorder()
	app.withAuth(app.handleLogout)(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected CSRF denial, got %d", out.Code)
	}
}

func TestWardenResolveReturnsHandleOnly(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
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
	if !strings.Contains(body, `"scope"`) || !strings.Contains(body, `"scope_bound_metadata"`) {
		t.Fatalf("posture response should include scope policy: %s", body)
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
	for _, want := range []string{"Live posture", "Evidence JSON", "Request metadata handle", "Request permit", "Access policy", "bootstrap owner", "Scope boundary"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") {
		t.Fatalf("dashboard should remain value-free: %s", body)
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
	for _, want := range []string{"Permit recorded", "approved_metadata_only", "Run safety check", "value_returned=false"} {
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
	app.permits.Put(permit)

	req := httptest.NewRequest(http.MethodPost, "/ui/permits/"+permit.ID+"/run", nil)
	req.SetPathValue("permitID", permit.ID)
	out := httptest.NewRecorder()
	app.withAuth(app.handleRunPermitUI)(out, req)
	if out.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Safety check complete", "not_executed", "output_scrubbed=true", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("permit run UI response should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") {
		t.Fatalf("permit run UI response should remain value-free: %s", body)
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
