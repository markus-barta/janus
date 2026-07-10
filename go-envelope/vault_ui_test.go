package main

// JANUS-271: invariants of the doorkeeper vault page (the new "/" dashboard).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVaultPageRendersCardsTilesAndBrand(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"JANUS", "every secret, accounted for", "/static/janus.css", "brand-full", "/static/janus-logo-full.png", "Signed in", "3 elevated roles", "Secrets", "Need attention", "value_returned=false", "rotates every"} {
		if !strings.Contains(body, want) {
			t.Fatalf("vault page should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "/static/janus-logo.svg") {
		t.Fatalf("vault page returned to the synthetic logo: %s", body)
	}
	assertRouteResponseValueFree(t, "vault page", out)
}

func TestVaultPageRendersFocusWithOperatorActions(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/?ref=csb1-age-identity", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"csb1-age-identity", `action="/ui/warden/resolve"`, `action="/ui/permits"`, "Create temporary metadata reference", "Record metadata authorization"} {
		if !strings.Contains(body, want) {
			t.Fatalf("vault focus should render %q: %s", want, body)
		}
	}
}

func TestVaultPageHidesOperatorFormsForViewer(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/?ref=csb1-age-identity", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, "Metadata controls are role-gated") {
		t.Fatalf("viewer should get the friendly role-gated state: %s", body)
	}
	for _, forbidden := range []string{`action="/ui/warden/resolve"`, `action="/ui/permits"`, "Create temporary metadata reference", "Record authorization"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("viewer vault page rendered operator form %q: %s", forbidden, body)
		}
	}
}

func TestVaultPageGatesLedgerByRole(t *testing.T) {
	app := newTestApp(t)
	app.store.AppendAudit(AuditEntry{
		Action:    "secret.review",
		Outcome:   "allowed",
		Method:    http.MethodPost,
		Path:      "/api/example",
		SecretRef: "private-ref",
	})

	viewer := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	viewerCookie := httptest.NewRecorder()
	app.writeSession(viewerCookie, viewer)
	req := httptest.NewRequest(http.MethodGet, "/ledger", nil)
	req.AddCookie(viewerCookie.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	viewerBody := out.Body.String()
	if !strings.Contains(viewerBody, "Audit needs the auditor role") {
		t.Fatalf("viewer should see the ledger role gate: %s", viewerBody)
	}
	if strings.Contains(viewerBody, "private-ref") {
		t.Fatalf("viewer ledger page leaked audit ref: %s", viewerBody)
	}

	auditor := Session{Subject: "auditor", Roles: []string{RoleAuditor, RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	auditorCookie := httptest.NewRecorder()
	app.writeSession(auditorCookie, auditor)
	req = httptest.NewRequest(http.MethodGet, "/ledger", nil)
	req.AddCookie(auditorCookie.Result().Cookies()[0])
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	auditorBody := out.Body.String()
	if !strings.Contains(auditorBody, "private-ref") || !strings.Contains(auditorBody, "secret.review") {
		t.Fatalf("auditor should see ledger rows: %s", auditorBody)
	}
	if !strings.Contains(auditorBody, "hash chain") {
		t.Fatalf("auditor ledger should show the chain panel: %s", auditorBody)
	}
}

func TestRequestsAndAssurancePagesRender(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/requests", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("requests page: expected 200, got %d", out.Code)
	}
	for _, want := range []string{"Permits", "short-lived metadata authorizations", "Active records", "Expired records", "No active metadata authorizations", "What is a permit?", "value_returned=false"} {
		if !strings.Contains(out.Body.String(), want) {
			t.Fatalf("permits page should render %q: %s", want, out.Body.String())
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/assurance", nil)
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("assurance page: expected 200, got %d", out.Code)
	}
	for _, want := range []string{"fail closed by design", "Readiness", "Lifecycle", "Settings", "value_returned=false"} {
		if !strings.Contains(out.Body.String(), want) {
			t.Fatalf("health page should render %q: %s", want, out.Body.String())
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/settings", nil)
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("settings page: expected 200, got %d", out.Code)
	}
	for _, want := range []string{"configuration posture", "Product mode", "Role policy", "Evidence boundary", "Presence-only workflow", "value_returned=false"} {
		if !strings.Contains(out.Body.String(), want) {
			t.Fatalf("settings page should render %q: %s", want, out.Body.String())
		}
	}
}

func TestRequestsPageUsesPlainLanguageForInternalCodes(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	permit, err := app.broker.CreatePermit(PrincipalChain{HumanSubject: "operator"}, PermitRequest{
		Ref:         "zitadel-janus-oidc",
		Action:      "metadata_use",
		Destination: "dashboard",
		Reason:      "ticket 123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.permits.Put(permit); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/requests", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	body := out.Body.String()
	for _, want := range []string{"Review metadata", "Recorded · metadata only", "Verify that execution is disabled", "What is a permit?"} {
		if !strings.Contains(body, want) {
			t.Fatalf("requests page should explain internal state as %q: %s", want, body)
		}
	}
	for _, rawCode := range []string{"metadata_use", "approved_metadata_only", "not_executed"} {
		if strings.Contains(body, rawCode) {
			t.Fatalf("requests page exposed internal code %q instead of plain language: %s", rawCode, body)
		}
	}
}

func TestNewSecretInputsAutoNormalize(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/vault/new?service=Home+Assistant&host=hsb1&env=HOME_ASSISTANT_TOKEN", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	body := out.Body.String()
	if !strings.Contains(body, "hsb1-home-assistant-env") {
		t.Fatalf("inputs should normalize into a usable name: %s", body)
	}
	if !strings.Contains(body, "Tidied up safely") {
		t.Fatalf("normalization should be surfaced as a friendly note: %s", body)
	}
	if strings.Contains(body, "Plan not ready") || strings.Contains(body, "not usable yet") {
		t.Fatalf("normalizable input must not produce an error: %s", body)
	}
}

func TestAccessPageRendersLanesWithoutIdentityValues(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.cfg.RolePolicy = RolePolicy{
		AdminSubjects:    map[string]bool{"markus@barta.com": true},
		AuditorSubjects:  map[string]bool{"markus@barta.com": true},
		OperatorSubjects: map[string]bool{"markus@barta.com": true},
		AdminGroups:      map[string]bool{"janus-admins": true},
	}

	req := httptest.NewRequest(http.MethodGet, "/access", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"who may open which door", "identity values withheld", "Available now", "action readiness", "Role lanes", "Admin", "Auditor", "Operator", "Policy and ownership", "GET /api/audit/recent", "GET /vault/new/plan.sh", "Local development", "Baseline", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("access page should render %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"markus@barta.com", "janus-admins", "dev-local", "Local Dev", "Zitadel + Janus", "signed_session_browser_proof"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("access page leaked binding identity %q: %s", forbidden, body)
		}
	}
}

func TestAccessPageDistinguishesAuthenticatedBrowserProof(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RolePolicy = RolePolicy{
		AdminSubjects:    map[string]bool{"subject-secret-sentinel": true},
		AuditorSubjects:  map[string]bool{"subject-secret-sentinel": true},
		OperatorSubjects: map[string]bool{"subject-secret-sentinel": true},
	}
	session := Session{Subject: "subject-secret-sentinel", Roles: AllRoles(), Expiry: time.Now().UTC().Add(time.Hour)}
	cookieWriter := httptest.NewRecorder()
	app.writeSession(cookieWriter, session)

	req := httptest.NewRequest(http.MethodGet, "/access", nil)
	req.AddCookie(cookieWriter.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Zitadel + Janus", "signed_session_browser_proof", "Browser proof", "Explicit", "GET /vault/new/plan.sh"} {
		if !strings.Contains(body, want) {
			t.Fatalf("authenticated access page should render %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"subject-secret-sentinel", "local_development_session", "Local development"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("authenticated access page leaked or mislabeled %q: %s", forbidden, body)
		}
	}
}

func TestVaultSidebarLinksAccessPage(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	for _, want := range []string{`href="/access"`, `href="/requests"`, `href="/ledger"`, `href="/assurance"`, `href="/settings"`, "Permits", "Audit", "Health", "Settings"} {
		if !strings.Contains(out.Body.String(), want) {
			t.Fatalf("vault sidebar should render %q: %s", want, out.Body.String())
		}
	}
}

func TestVaultFiltersNarrowCardsButKeepTiles(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/?q=zitadel", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	body := out.Body.String()
	if !strings.Contains(body, "zitadel-janus-oidc") {
		t.Fatalf("filtered vault should keep matching secret: %s", body)
	}
	if strings.Contains(body, `href="/?ref=csb1-age-identity#focus"`) {
		t.Fatalf("filtered vault should hide non-matching secret: %s", body)
	}
	if !strings.Contains(body, "1 of 2 secrets shown") {
		t.Fatalf("filtered vault should show the filter note: %s", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/?q=no-such-thing", nil)
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if !strings.Contains(out.Body.String(), "Nothing matches these filters") {
		t.Fatalf("empty filter result should render the friendly state: %s", out.Body.String())
	}
}

func TestVaultListViewRendersTable(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/?view=list", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	body := out.Body.String()
	for _, want := range []string{"<table class=\"ledger\">", "last checked", "csb1-age-identity", "zitadel-janus-oidc"} {
		if !strings.Contains(body, want) {
			t.Fatalf("list view should render %q: %s", want, body)
		}
	}
}

func TestNewSecretPlanGeneratesDeclarativeSteps(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/vault/new?service=xyz&host=csb1&env=XYZ_TOKEN&rotation=90&tags=app-env", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"csb1-xyz-env", "agenix -e secrets/csb1-xyz-env.age", "publicKeys = markus &#43;&#43; csb1", "age.secrets.csb1-xyz-env", "/run/agenix/csb1-xyz-env", "agenix-catalog.json", "1Password", "value never enters Janus", "rotation_days&#34;: 90"} {
		if !strings.Contains(body, want) {
			t.Fatalf("new-secret plan should include %q: %s", want, body)
		}
	}
	if strings.Contains(body, `name="value"`) || strings.Contains(body, "type=\"password\"") {
		t.Fatalf("new-secret flow must never ask for the secret value: %s", body)
	}
}

func TestNewSecretScriptDownloadIsGatedAndValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/vault/new/plan.sh?service=xyz&host=csb1&env=XYZ_TOKEN", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Content-Type"); !strings.Contains(got, "shellscript") {
		t.Fatalf("expected shellscript content type, got %q", got)
	}
	body := out.Body.String()
	for _, want := range []string{"set -euo pipefail", "agenix -e secrets/csb1-xyz-env.age", "idempotent", "1Password"} {
		if !strings.Contains(body, want) {
			t.Fatalf("plan script should contain %q: %s", want, body)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/vault/new/plan.sh?service=!!!", nil)
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("underivable plan should 400, got %d", out.Code)
	}
}

func TestNewSecretScriptAppliesToNixcfgFixtureIdempotently(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}

	dir := t.TempDir()
	mustWrite := func(rel, content string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("secrets/secrets.nix", `let
  markus = [ "ssh-ed25519 AAA" ];
  csb1 = [ "ssh-ed25519 BBB" ];
in
{
  "existing.age".publicKeys = markus ++ csb1;
}
`)
	mustWrite("hosts/csb1/configuration.nix", `{ config, ... }:
{
  networking.hostName = "csb1";
  age.secrets.csb1-xyz-env-old = {};
}
`)
	mustWrite("hosts/csb1/docker/janus/catalog/agenix-catalog.json", "[]\n")

	maliciousDisplay := `xyz '''; open('pwned', 'w').write('yes'); #`
	plan := newSecretPlanFromQuery(url.Values{"service": {"xyz"}, "host": {"csb1"}, "env": {"XYZ_TOKEN"}, "display": {maliciousDisplay}, "rotation": {"90"}})
	if plan == nil || len(plan.Problems) > 0 {
		t.Fatalf("plan should be valid: %+v", plan)
	}
	scriptPath := filepath.Join(dir, "plan.sh")
	if err := os.WriteFile(scriptPath, []byte(newSecretScript(plan)), 0o755); err != nil {
		t.Fatal(err)
	}

	runScript := func(pass int) string {
		t.Helper()
		cmd := exec.Command("bash", scriptPath)
		cmd.Dir = dir
		outBytes, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pass %d: script failed: %v\n%s", pass, err, outBytes)
		}
		return string(outBytes)
	}

	first := runScript(1)
	for _, want := range []string{"+ secrets/secrets.nix", "age.secrets.csb1-xyz-env wired", "descriptor added"} {
		if !strings.Contains(first, want) {
			t.Fatalf("first run should report %q: %s", want, first)
		}
	}

	second := runScript(2)
	for _, want := range []string{"= secrets/secrets.nix already declares", "already wires", "catalog already lists"} {
		if !strings.Contains(second, want) {
			t.Fatalf("second run should be a no-op reporting %q: %s", want, second)
		}
	}

	secretsNix, _ := os.ReadFile(filepath.Join(dir, "secrets/secrets.nix"))
	if got := strings.Count(string(secretsNix), `"csb1-xyz-env.age".publicKeys = markus ++ csb1;`); got != 1 {
		t.Fatalf("secrets.nix should declare the recipient exactly once, got %d:\n%s", got, secretsNix)
	}
	conf, _ := os.ReadFile(filepath.Join(dir, "hosts/csb1/configuration.nix"))
	if got := strings.Count(string(conf), "age.secrets.csb1-xyz-env = {"); got != 1 {
		t.Fatalf("configuration.nix should wire the secret exactly once, got %d:\n%s", got, conf)
	}
	if !strings.Contains(string(conf), `path = "/run/agenix/csb1-xyz-env";`) {
		t.Fatalf("configuration.nix missing materialization path:\n%s", conf)
	}
	catalog, _ := os.ReadFile(filepath.Join(dir, "hosts/csb1/docker/janus/catalog/agenix-catalog.json"))
	if got := strings.Count(string(catalog), `"id": "csb1-xyz-env"`); got != 1 {
		t.Fatalf("catalog should list the descriptor exactly once, got %d:\n%s", got, catalog)
	}
	if strings.Contains(string(catalog), "rotation_days\": 90") == false {
		t.Fatalf("catalog should carry rotation_days 90:\n%s", catalog)
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); !os.IsNotExist(err) {
		t.Fatalf("display text escaped the catalog and executed code: %v", err)
	}
	var descriptors []newSecretCatalogDescriptor
	if err := json.Unmarshal(catalog, &descriptors); err != nil {
		t.Fatalf("catalog should remain valid JSON: %v\n%s", err, catalog)
	}
	if len(descriptors) != 1 || descriptors[0].DisplayName != maliciousDisplay {
		t.Fatalf("catalog should preserve the display label as data, not code: %#v", descriptors)
	}
}

func TestNewSecretPlanRejectsUnderivableNames(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/vault/new?service=!!!&host=csb1&env=XYZ_TOKEN", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if !strings.Contains(out.Body.String(), "could not turn that service name into a safe configuration name") {
		t.Fatalf("underivable service name should block the plan: %s", out.Body.String())
	}
	if strings.Contains(out.Body.String(), "agenix -e secrets/") {
		t.Fatalf("blocked plan should not emit commands: %s", out.Body.String())
	}
}

func TestNewSecretPlanPreservesExactEnvironmentNameAndRejectsHostMutation(t *testing.T) {
	plan := newSecretPlanFromQuery(url.Values{
		"service": {"Example API"},
		"host":    {"csb1"},
		"env":     {"apiKey"},
	})
	if plan == nil || len(plan.Problems) != 0 {
		t.Fatalf("mixed-case environment name should be valid: %#v", plan)
	}
	if plan.EnvName != "apiKey" || !strings.Contains(plan.AgenixEdit, "apiKey=<value>") {
		t.Fatalf("environment name is case-sensitive and must be preserved: %#v", plan)
	}

	for _, hostileHost := range []string{"csb!", "csb1/../../hsb1", "1server", "csb1\thsb1", "prod_db", "prod db", "CSB1"} {
		blocked := newSecretPlanFromQuery(url.Values{
			"service": {"Example API"},
			"host":    {hostileHost},
			"env":     {"API_KEY"},
		})
		if blocked == nil || len(blocked.Problems) == 0 || blocked.AgenixEdit != "" || blocked.Catalog != "" {
			t.Fatalf("host %q must be rejected rather than changed into another machine: %#v", hostileHost, blocked)
		}
	}
}

func TestNewSecretInvalidOptionalFieldsStayVisible(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/vault/new?service=Example+API&host=csb1&env=API_KEY&display=Friendly&classification=unexpected&rotation=0&tags=one%2Ctwo", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected validation page, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`class="optional-settings" open`, `value="Friendly"`, `value="0"`, `value="one,two"`, "Choose Standard, High, or Critical sensitivity", "Enter a review interval from 1 to 3650 days", "Nothing has changed"} {
		if !strings.Contains(body, want) {
			t.Fatalf("invalid optional settings should preserve and explain %q: %s", want, body)
		}
	}
	if strings.Contains(body, "Download setup script") || strings.Contains(body, "agenix -e secrets/") {
		t.Fatalf("invalid optional settings must not generate an executable guide: %s", body)
	}
}

func TestNewSecretViewerCanPreviewButCannotDownload(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer-subject-secret", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookieWriter := httptest.NewRecorder()
	app.writeSession(cookieWriter, session)
	sessionCookie := cookieWriter.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/vault/new?service=Example+API&host=csb1&env=API_KEY", nil)
	req.AddCookie(sessionCookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("viewer preview: expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, "Operator required to download") || !strings.Contains(body, "Setup guide") {
		t.Fatalf("viewer should see a useful preview and a clear role gate: %s", body)
	}
	if strings.Contains(body, `href="/vault/new/plan.sh`) || strings.Contains(body, "viewer-subject-secret") {
		t.Fatalf("viewer preview exposed a download or identity value: %s", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/vault/new/plan.sh?service=Example+API&host=csb1&env=API_KEY", nil)
	req.AddCookie(sessionCookie)
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("viewer download: expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if strings.Contains(out.Body.String(), "#!/usr/bin/env bash") || strings.Contains(out.Body.String(), "viewer-subject-secret") {
		t.Fatalf("viewer denial must not contain script bytes or identity values: %s", out.Body.String())
	}
}

func TestVaultDoesNotAutoSelectAndUnknownRefCannotRenderActions(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	for _, path := range []string{"/", "/?ref=not-a-real-secret"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, out.Code)
		}
		body := out.Body.String()
		if strings.Contains(body, `action="/ui/warden/resolve"`) || strings.Contains(body, `action="/ui/permits"`) || strings.Contains(body, `name="ref" value=`) {
			t.Fatalf("%s selected a mutation target without an exact known reference: %s", path, body)
		}
		if path != "/" && !strings.Contains(body, "Secret not found") {
			t.Fatalf("unknown reference should render a safe not-found panel: %s", body)
		}
	}
}

func TestNewSecretScriptPreflightLeavesFilesUnchanged(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "hosts", "csb1"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("let\n  markus = [];\n  csb1 = [];\nin\n{\n}\n")
	secretsPath := filepath.Join(dir, "secrets", "secrets.nix")
	if err := os.WriteFile(secretsPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	plan := newSecretPlanFromQuery(url.Values{"service": {"xyz"}, "host": {"csb1"}, "env": {"XYZ_TOKEN"}})
	if plan == nil || len(plan.Problems) != 0 {
		t.Fatalf("expected valid plan: %#v", plan)
	}
	scriptPath := filepath.Join(dir, "plan.sh")
	if err := os.WriteFile(scriptPath, []byte(newSecretScript(plan)), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "configuration.nix") {
		t.Fatalf("missing target must fail during preflight: err=%v output=%s", err, output)
	}
	after, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatalf("preflight failure partially changed secrets.nix:\n%s", after)
	}
}

func TestBrokerRejectsUnsafeMetadataText(t *testing.T) {
	app := newTestApp(t)
	principal := PrincipalChain{HumanSubject: "operator"}

	if _, err := app.broker.ResolveHandle(principal, HandleRequest{Ref: "zitadel-janus-oidc"}); err == nil {
		t.Fatal("handle reason should be required at the broker boundary")
	}
	if _, err := app.broker.ResolveHandle(principal, HandleRequest{Ref: "zitadel-janus-oidc", Reason: strings.Repeat("x", 161)}); err == nil {
		t.Fatal("overlong handle reason should be rejected")
	}
	if _, err := app.broker.CreatePermit(principal, PermitRequest{Ref: "zitadel-janus-oidc", Action: "metadata_use", Reason: "ticket", Destination: "dashboard\nsecret"}); err == nil {
		t.Fatal("control characters in persisted destination should be rejected")
	}
	if _, err := app.broker.CreatePermit(principal, PermitRequest{Ref: "zitadel-janus-oidc", Action: "metadata_use", Reason: strings.Repeat("x", 161)}); err == nil {
		t.Fatal("overlong persisted reason should be rejected")
	}
}

func TestVaultStaticAssetsServed(t *testing.T) {
	app := newTestApp(t)
	cases := []struct {
		path        string
		contentType string
	}{
		{path: "/static/janus.css", contentType: "text/css; charset=utf-8"},
		{path: "/static/janus-logo.svg", contentType: "image/svg+xml"},
		{path: "/static/janus-logo-full.png", contentType: "image/png"},
		{path: "/static/janus-login-hero.png", contentType: "image/png"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", tc.path, out.Code)
		}
		if got := out.Header().Get("Content-Type"); got != tc.contentType {
			t.Fatalf("%s: expected content type %q, got %q", tc.path, tc.contentType, got)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/static/nope.js", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("unknown static asset should 404, got %d", out.Code)
	}
}

func TestBrandArtworkUsesIntendedScaleAlignmentAndSuppliedLogo(t *testing.T) {
	cssBytes, err := uiStaticFS.ReadFile("ui/janus.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssBytes)
	if strings.Count(css, "{") != strings.Count(css, "}") {
		t.Fatalf("janus.css has unbalanced blocks: opens=%d closes=%d", strings.Count(css, "{"), strings.Count(css, "}"))
	}
	for _, want := range []string{
		`url("/static/janus-header-bg.png") right center / contain no-repeat`,
		`width: min(700px, calc(100% + 48px))`,
		`url("/static/janus-side-bg.png") center / contain no-repeat`,
		`height: min(390px, 100%)`,
		`mask-composite: intersect`,
		`transparent 0`,
		`object-fit: contain`,
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("artwork CSS should preserve each asset's scale, alignment, and edge fade via %q", want)
		}
	}
	for _, forbidden := range []string{
		`url("/static/janus-header-bg.png") center / cover no-repeat`,
		`url("/static/janus-side-bg.png") center bottom / cover no-repeat`,
		`mask-image: radial-gradient`,
	} {
		if strings.Contains(css, forbidden) {
			t.Fatalf("artwork CSS returned to cropped or radial treatment %q", forbidden)
		}
	}
	assetHashes := map[string]string{
		"janus-logo-full.png": "2bb27f067c38c25d8e463ffc542cbc3653d3aa1b465accc212308b6f3c5f89dd",
		"janus-header-bg.png": "d1047ff0489162ab2669fe9a1ef6bbbf1af1e50304005240f9bd25aa1783df01",
		"janus-side-bg.png":   "b2ef2ccba869a4e075a3cb34c32ebd8c584f04d13fb46c40239ef824c651815b",
	}
	for name, want := range assetHashes {
		assetBytes, err := uiStaticFS.ReadFile("ui/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(assetBytes)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("Janus brand asset %s changed: got sha256 %s want %s", name, got, want)
		}
	}
}
