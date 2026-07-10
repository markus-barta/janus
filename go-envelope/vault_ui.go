package main

// JANUS-271: doorkeeper vault UI — first strangler slice. The embedded
// "dashboard" template (ui/vault.html) replaced the inline legacy page at /;
// the legacy console was removed in the JANUS-269 cull.

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed ui/janus.css ui/janus-logo.svg ui/janus-logo-full.png ui/janus-header-bg.png ui/janus-side-bg.png ui/janus-login-hero.png
var uiStaticFS embed.FS

//go:embed ui/*.html
var vaultTemplateFS embed.FS

type VaultTiles struct {
	Secrets   int
	Active    int
	Attention int
	Permits   int
}

func vaultTilesFor(descriptors []SecretDescriptor, lifecycle LifecyclePosture, permits PermitPosture) VaultTiles {
	return VaultTiles{
		Secrets:   len(descriptors),
		Active:    lifecycle.ActiveCount,
		Attention: lifecycle.BlockedCount + lifecycle.StaleCount,
		Permits:   permits.Count,
	}
}

func descriptorProviders(descriptors []SecretDescriptor) []string {
	seen := map[string]bool{}
	for _, d := range descriptors {
		if d.Provider != "" {
			seen[d.Provider] = true
		}
	}
	providers := make([]string, 0, len(seen))
	for p := range seen {
		providers = append(providers, p)
	}
	sort.Strings(providers)
	return providers
}

func humanSince(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Until(t)
	future := d > 0
	if !future {
		d = -d
	}
	var span string
	switch {
	case d < time.Minute:
		span = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		span = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		span = fmt.Sprintf("%dh", int(d.Hours()))
	default:
		span = fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if future {
		return "in " + span
	}
	return span + " ago"
}

func (app *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	var contentType string
	switch name {
	case "janus.css":
		contentType = "text/css; charset=utf-8"
	case "janus-logo.svg":
		contentType = "image/svg+xml"
	case "janus-logo-full.png", "janus-header-bg.png", "janus-side-bg.png", "janus-login-hero.png":
		contentType = "image/png"
	default:
		app.renderSafeFailure(w, r, http.StatusNotFound, "route_not_found", "Janus does not expose that route.", nil)
		return
	}
	data, err := uiStaticFS.ReadFile("ui/" + name)
	if err != nil {
		app.renderSafeFailure(w, r, http.StatusNotFound, "route_not_found", "Janus does not expose that route.", nil)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(data)
}

// applyVaultFilters narrows the descriptor list for GET / according to the
// filter bar (q, provider, state, view). Tiles keep global counts; only the
// card/list rendering shrinks. Action re-renders never pass filters.
func applyVaultFilters(data map[string]any, r *http.Request) {
	query := r.URL.Query()
	q := strings.ToLower(strings.TrimSpace(query.Get("q")))
	provider := strings.TrimSpace(query.Get("provider"))
	state := strings.TrimSpace(query.Get("state"))
	if view := query.Get("view"); view == "list" {
		data["View"] = "list"
	}
	descriptors, _ := data["Descriptors"].([]SecretDescriptor)
	filtered := make([]SecretDescriptor, 0, len(descriptors))
	for _, d := range descriptors {
		if provider != "" && d.Provider != provider {
			continue
		}
		lifecycle := DescriptorLifecycle(d)
		if state == "active" && lifecycle != LifecycleActive {
			continue
		}
		if state == "attention" && lifecycle == LifecycleActive {
			continue
		}
		if q != "" {
			haystack := strings.ToLower(d.ID + " " + d.DisplayName + " " + d.Owner + " " + d.Scope + " " + strings.Join(d.Tags, " "))
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		filtered = append(filtered, d)
	}
	data["Descriptors"] = filtered
	data["Query"] = query.Get("q")
	data["FilterProvider"] = provider
	data["FilterState"] = state
}

var secretNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

var (
	slugInvalidChars = regexp.MustCompile(`[^a-z0-9-]+`)
	slugDashRuns     = regexp.MustCompile(`-{2,}`)
	envNamePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	slugInputPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _-]*$`)
	hostNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

func normalizeEnvName(value string) string {
	return strings.TrimSpace(value)
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// normalizeSlug turns free-form input into a usable name part instead of
// rejecting it: "Home Assistant" → "home-assistant".
func normalizeSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	s = slugInvalidChars.ReplaceAllString(s, "")
	s = slugDashRuns.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// NewSecretPlan is the guided "server needs a new secret" flow: Janus never
// touches the value — it generates the declarative steps (1Password → agenix
// → nixcfg wiring → catalog descriptor) as copy-paste artifacts.
type NewSecretPlan struct {
	Name           string
	DisplayName    string
	Host           string
	HostInput      string
	Service        string
	ServiceLabel   string
	EnvName        string
	EnvInput       string
	TagsInput      string
	RotationInput  string
	NormalizedNote string
	Classification string
	OpenOptional   bool
	RotationDays   int
	Tags           []string
	Problems       []string
	AgenixEdit     string
	SecretsNix     string
	HostNix        string
	Compose        string
	Catalog        string
}

type newSecretCatalogDescriptor struct {
	ID             string   `json:"id"`
	DisplayName    string   `json:"display_name"`
	Provider       string   `json:"provider"`
	Classification string   `json:"classification"`
	Owner          string   `json:"owner"`
	Scope          string   `json:"scope"`
	Source         string   `json:"source"`
	RotationDays   int      `json:"rotation_days"`
	Lifecycle      string   `json:"lifecycle"`
	Status         string   `json:"status"`
	UseEnabled     bool     `json:"use_enabled"`
	ConsumerCount  int      `json:"consumer_count"`
	EgressMode     string   `json:"egress_mode"`
	Tags           []string `json:"tags"`
}

func newSecretPlanFromQuery(query url.Values) *NewSecretPlan {
	submitted := false
	for _, key := range []string{"service", "host", "env", "display", "classification", "rotation", "tags"} {
		if _, ok := query[key]; ok {
			submitted = true
			break
		}
	}
	if !submitted {
		return nil
	}
	rawService := strings.TrimSpace(query.Get("service"))
	rawHost := strings.TrimSpace(query.Get("host"))
	rawEnvName := strings.TrimSpace(query.Get("env"))
	rawClassification := strings.TrimSpace(query.Get("classification"))
	rawRotation := strings.TrimSpace(query.Get("rotation"))
	rawTags := query.Get("tags")
	service := normalizeSlug(rawService)
	host := rawHost
	envName := normalizeEnvName(rawEnvName)
	plan := &NewSecretPlan{
		Service:        service,
		ServiceLabel:   rawService,
		Host:           host,
		HostInput:      rawHost,
		EnvName:        envName,
		EnvInput:       rawEnvName,
		TagsInput:      rawTags,
		RotationInput:  rawRotation,
		Classification: "high",
		RotationDays:   180,
	}
	if plan.RotationInput == "" {
		plan.RotationInput = "180"
	}
	switch rawClassification {
	case "":
	case "medium", "high", "critical":
		plan.Classification = rawClassification
	default:
		plan.Classification = ""
		plan.OpenOptional = true
		plan.Problems = append(plan.Problems, "Choose Standard, High, or Critical sensitivity.")
	}
	if rawRotation != "" {
		if rotation, err := strconv.Atoi(rawRotation); err == nil && rotation >= 1 && rotation <= 3650 {
			plan.RotationDays = rotation
		} else {
			plan.OpenOptional = true
			plan.Problems = append(plan.Problems, "Enter a review interval from 1 to 3650 days.")
		}
	}
	plan.DisplayName = strings.TrimSpace(query.Get("display"))
	if plan.DisplayName == "" && host != "" {
		plan.DisplayName = rawService + " on " + host
	}
	if len(plan.DisplayName) > 120 || containsControl(plan.DisplayName) {
		plan.OpenOptional = true
		plan.Problems = append(plan.Problems, "Keep the display name under 120 characters and on one line.")
	}
	if len(rawTags) > 512 {
		plan.OpenOptional = true
		plan.Problems = append(plan.Problems, "Keep the complete tag list under 512 characters.")
		rawTags = ""
		plan.TagsInput = ""
	}
	for _, tag := range strings.Split(rawTags, ",") {
		if tag = normalizeSlug(tag); tag != "" {
			if len(tag) > 32 {
				plan.OpenOptional = true
				plan.Problems = append(plan.Problems, "Keep each tag under 32 characters.")
				continue
			}
			if len(plan.Tags) < 8 {
				plan.Tags = append(plan.Tags, tag)
			} else {
				plan.OpenOptional = true
				plan.Problems = append(plan.Problems, "Use at most 8 tags.")
				break
			}
		}
	}
	if len(plan.Tags) == 0 && service != "" {
		plan.Tags = []string{service}
	}
	if rawService == "" {
		plan.Problems = append(plan.Problems, "Enter the service that needs the secret, for example Home Assistant.")
	} else if len(rawService) > 80 {
		plan.Problems = append(plan.Problems, "Keep the service name under 80 characters.")
	} else if !slugInputPattern.MatchString(rawService) || service == "" {
		plan.Problems = append(plan.Problems, "We could not turn that service name into a safe configuration name. Use letters, numbers, spaces, or dashes.")
	}
	if rawHost == "" {
		plan.Problems = append(plan.Problems, "Enter the machine where the service runs, for example csb1.")
	} else if !hostNamePattern.MatchString(host) {
		plan.Problems = append(plan.Problems, "Use the exact machine name: lowercase letters, numbers, and dashes, starting with a letter (for example csb1).")
	}
	if rawEnvName == "" {
		plan.Problems = append(plan.Problems, "Enter the environment variable name the service expects. Do not enter its value.")
	} else if !envNamePattern.MatchString(envName) {
		plan.Problems = append(plan.Problems, "Use the exact environment variable name the service expects, such as HOME_ASSISTANT_TOKEN (letters, numbers, and underscores only).")
	}
	if len(plan.Problems) > 0 {
		return plan
	}
	var normalizedNote string
	if service != strings.ToLower(rawService) || host != strings.ToLower(rawHost) || envName != rawEnvName {
		normalizedNote = rawService
		normalizedNote += " on " + rawHost + " → " + host + "-" + service + "-env / " + envName
	}
	plan.Name = host + "-" + service + "-env"
	plan.NormalizedNote = normalizedNote
	if !secretNamePattern.MatchString(plan.Name) {
		plan.Problems = append(plan.Problems, "The service and machine names do not form a usable configuration name yet.")
		return plan
	}
	plan.AgenixEdit = fmt.Sprintf(`cd ~/Code/nixcfg
agenix -e secrets/%s.age
# enter %s=<value> when the encrypted editor opens; take the value from 1Password`, plan.Name, plan.EnvName)
	plan.SecretsNix = fmt.Sprintf(`  # %s env for %s.
  # Contains %s=<value>; the value never enters Janus.
  # Edit: agenix -e secrets/%s.age
  "%s.age".publicKeys = markus ++ %s;`, plan.Service, plan.Host, plan.EnvName, plan.Name, plan.Name, plan.Host)
	plan.HostNix = fmt.Sprintf(`  age.secrets.%s = {
    file = ../../secrets/%s.age;
    path = "/run/agenix/%s";
  };`, plan.Name, plan.Name, plan.Name)
	plan.Compose = fmt.Sprintf(`  %s:
    # ...
    env_file:
      - /run/agenix/%s`, plan.Service, plan.Name)
	descriptor := newSecretCatalogDescriptor{
		ID:             plan.Name,
		DisplayName:    plan.DisplayName,
		Provider:       "agenix",
		Classification: plan.Classification,
		Owner:          "platform",
		Scope:          plan.Host,
		Source:         "secrets/" + plan.Name + ".age",
		RotationDays:   plan.RotationDays,
		Lifecycle:      "active",
		Status:         "managed",
		UseEnabled:     true,
		ConsumerCount:  1,
		EgressMode:     "none",
		Tags:           append([]string(nil), plan.Tags...),
	}
	catalog, err := json.MarshalIndent(descriptor, " ", " ")
	if err != nil {
		plan.Problems = append(plan.Problems, "Janus could not build the metadata-only catalog entry.")
		return plan
	}
	plan.Catalog = string(catalog)
	return plan
}

// newSecretScript renders the plan as an executable, additive-only,
// idempotent bash script (JANUS-273). It performs the repo edits that are
// safe to automate and prints the ones that are not; the secret VALUE never
// appears — encrypting it stays a human step (agenix -e).
func newSecretScript(plan *NewSecretPlan) string {
	catalogBase64 := base64.StdEncoding.EncodeToString([]byte(plan.Catalog))
	return fmt.Sprintf(`#!/usr/bin/env bash
# janus apply-plan for %[1]s — generated by the Janus vault (JANUS-273).
# Run from the root of your nixcfg checkout. Additive and idempotent; review
# with git diff afterwards. The secret VALUE is never part of this file.
set -euo pipefail

NAME=%[1]s
HOST=%[2]s
CONF="hosts/$HOST/configuration.nix"
CATALOG="hosts/$HOST/docker/janus/catalog/agenix-catalog.json"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required before this setup can be applied" >&2
  exit 1
fi
if [ ! -f secrets/secrets.nix ] || [ ! -d "hosts/$HOST" ] || [ ! -f "$CONF" ]; then
  echo "error: run this from the nixcfg repo root (needs secrets/secrets.nix, hosts/$HOST, and $CONF)" >&2
  exit 1
fi
if [ ! -w secrets/secrets.nix ] || [ ! -w "$CONF" ]; then
  echo "error: target Nix files are not writable; no files were changed" >&2
  exit 1
fi
if ! grep -Eq "^[[:space:]]*${HOST}[[:space:]]*=" secrets/secrets.nix; then
  echo "error: secrets/secrets.nix does not define a recipient variable for $HOST" >&2
  exit 1
fi
if ! grep -Eq '^[[:space:]]*}[[:space:]]*$' secrets/secrets.nix || ! grep -Eq '^[[:space:]]*}[[:space:]]*$' "$CONF"; then
  echo "error: a target Nix file has no closing attribute-set brace; no files were changed" >&2
  exit 1
fi
if [ -f "$CATALOG" ]; then
  if [ ! -w "$CATALOG" ]; then
    echo "error: $CATALOG is not writable; no files were changed" >&2
    exit 1
  fi
  python3 - "$CATALOG" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
    raise SystemExit('janus catalog must contain a JSON list of descriptors; no files were changed')
PY
fi

# --- 1) recipients in secrets/secrets.nix ------------------------------------
if grep -Fq "\"$NAME.age\"" secrets/secrets.nix; then
  echo "= secrets/secrets.nix already declares $NAME.age"
else
  python3 - secrets/secrets.nix <<'PY'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines(keepends=True)
block = '''
  # %[3]s env for %[2]s.
  # Contains %[6]s=<value>; the value never enters Janus.
  # Edit: agenix -e secrets/%[1]s.age
  "%[1]s.age".publicKeys = markus ++ %[2]s;
'''
for i in range(len(lines) - 1, -1, -1):
    if lines[i].strip() == '}':
        lines.insert(i, block)
        break
else:
    sys.exit('could not find a closing brace in ' + path)
open(path, 'w').write(''.join(lines))
PY
  echo "+ secrets/secrets.nix: recipients declared for $NAME.age"
fi

# --- 2) materialization in hosts/$HOST/configuration.nix ---------------------
if grep -Fq "age.secrets.$NAME = {" "$CONF"; then
  echo "= $CONF already wires $NAME"
else
  python3 - "$CONF" <<'PY'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines(keepends=True)
block = '''
  age.secrets.%[1]s = {
    file = ../../secrets/%[1]s.age;
    path = "/run/agenix/%[1]s";
  };
'''
for i in range(len(lines) - 1, -1, -1):
    if lines[i].strip() == '}':
        lines.insert(i, block)
        break
else:
    sys.exit('could not find a closing brace in ' + path)
open(path, 'w').write(''.join(lines))
PY
  echo "+ $CONF: age.secrets.$NAME wired"
fi

# --- 3) janus catalog descriptor ---------------------------------------------
if [ ! -f "$CATALOG" ]; then
  echo "! no janus catalog at $CATALOG — skipped (this host runs no janus)"
else
  python3 - "$CATALOG" <<'PY'
import base64, json, sys
path = sys.argv[1]
data = json.load(open(path))
if any(d.get('id') == '%[1]s' for d in data):
    print('= catalog already lists %[1]s')
else:
    data.append(json.loads(base64.b64decode('%[4]s').decode('utf-8')))
    open(path, 'w').write(json.dumps(data, indent=1) + '\n')
    print('+ catalog: descriptor added for %[1]s')
PY
fi

# --- what stays human ---------------------------------------------------------
cat <<'HUMAN'

next steps (manual, in order):
1) point the service at the encrypted env file in hosts/%[2]s/docker/docker-compose.yml:
%[5]s

2) open the encrypted editor and enter %[6]s=<value> — take the value from 1Password:
   agenix -e secrets/%[1]s.age

3) review and commit:
   git diff
4) deploy the host as usual. If this host has a Janus catalog, recreate its
   Janus container so the new metadata appears in the Vault.
HUMAN
git status --short || true
`, plan.Name, plan.Host, plan.Service, catalogBase64, plan.Compose, plan.EnvName)
}

func (app *App) handleNewSecretScript(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !HasRole(session, RoleOperator) {
		app.audit(r, "vault.new.plan", "denied", actorFromContext(r.Context()), "operator role required")
		app.renderSafeFailure(w, r, http.StatusForbidden, "role_denied", "An operator must download and apply service configuration. You can still preview the setup guide.", nil)
		return
	}
	plan := newSecretPlanFromQuery(r.URL.Query())
	if plan == nil || len(plan.Problems) > 0 {
		app.audit(r, "vault.new.plan", "denied", actorFromContext(r.Context()), "invalid plan")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "plan_invalid", "The plan parameters are incomplete or unusable; generate the plan in the vault first.", nil)
		return
	}
	app.audit(r, "vault.new.plan", "allowed", actorFromContext(r.Context()), "")
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=janus-plan-"+plan.Name+".sh")
	_, _ = w.Write([]byte(newSecretScript(plan)))
}

func (app *App) handleNewSecretPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "vault.new.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "vault"
	data["Plan"] = newSecretPlanFromQuery(r.URL.Query())
	renderTemplate(w, app.templates, "new_secret_page", data)
}

func (app *App) handleAccessPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "access.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "access"
	renderTemplate(w, app.templates, "access_page", data)
}

func splitPermits(permits []Permit, now time.Time) (pending, past []Permit) {
	for _, p := range permits {
		if p.ExpiresAt.After(now) {
			pending = append(pending, p)
		} else {
			past = append(past, p)
		}
	}
	return pending, past
}

func permitActionLabel(action string) string {
	switch action {
	case "metadata_use":
		return "Review metadata"
	case "resolve_handle":
		return "Create temporary metadata reference"
	default:
		return "Metadata action"
	}
}

func permitStatusLabel(status string) string {
	switch status {
	case "approved_metadata_only", "approved":
		return "Recorded · metadata only"
	case "not_executed":
		return "Execution disabled"
	case "denied":
		return "Denied"
	default:
		return "Review required"
	}
}

func permitStatusTone(status string) string {
	switch status {
	case "approved_metadata_only", "approved", "not_executed":
		return "ok"
	case "denied":
		return "bad"
	default:
		return "warn"
	}
}

func (app *App) handleRequestsPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "requests.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "requests"
	permits, _ := data["Permits"].([]Permit)
	pending, past := splitPermits(permits, time.Now().UTC())
	data["PendingPermits"] = pending
	data["PastPermits"] = past
	renderTemplate(w, app.templates, "requests_page", data)
}

func (app *App) handleLedgerPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "ledger.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "ledger"
	if canView, _ := data["CanViewAudit"].(bool); canView {
		data["Audit"] = app.store.RecentAudit(50)
	}
	renderTemplate(w, app.templates, "ledger_page", data)
}

func (app *App) handleAssurancePage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "assurance.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "assurance"
	renderTemplate(w, app.templates, "assurance_page", data)
}

func (app *App) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "settings.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "settings"
	renderTemplate(w, app.templates, "settings_page", data)
}
