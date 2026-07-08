package main

// JANUS-271: doorkeeper vault UI — first strangler slice. The embedded
// "dashboard" template (ui/vault.html) replaced the inline legacy page at /;
// the legacy console stays reachable at /legacy until the JANUS-269 cull.

import (
	"embed"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed ui/janus.css ui/janus-logo.svg
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

// NewSecretPlan is the guided "server needs a new secret" flow: Janus never
// touches the value — it generates the declarative steps (1Password → agenix
// → nixcfg wiring → catalog descriptor) as copy-paste artifacts.
type NewSecretPlan struct {
	Name           string
	DisplayName    string
	Host           string
	Service        string
	Classification string
	RotationDays   int
	Tags           []string
	Problems       []string
	AgenixEdit     string
	SecretsNix     string
	HostNix        string
	Compose        string
	Catalog        string
}

func newSecretPlanFromQuery(query url.Values) *NewSecretPlan {
	service := strings.ToLower(strings.TrimSpace(query.Get("service")))
	if service == "" {
		return nil
	}
	host := strings.ToLower(strings.TrimSpace(query.Get("host")))
	if host == "" {
		host = "csb1"
	}
	classification := query.Get("classification")
	switch classification {
	case "medium", "high", "critical":
	default:
		classification = "high"
	}
	rotation, err := strconv.Atoi(query.Get("rotation"))
	if err != nil || rotation < 1 || rotation > 3650 {
		rotation = 180
	}
	display := strings.TrimSpace(query.Get("display"))
	if display == "" {
		display = strings.ToUpper(service[:1]) + service[1:] + " environment"
	}
	var tags []string
	for _, tag := range strings.Split(query.Get("tags"), ",") {
		if tag = strings.ToLower(strings.TrimSpace(tag)); tag != "" {
			tags = append(tags, tag)
		}
	}
	if len(tags) == 0 {
		tags = []string{service}
	}
	plan := &NewSecretPlan{
		Name:           host + "-" + service + "-env",
		DisplayName:    display,
		Host:           host,
		Service:        service,
		Classification: classification,
		RotationDays:   rotation,
		Tags:           tags,
	}
	if !secretNamePattern.MatchString(plan.Name) {
		plan.Problems = append(plan.Problems, "service and host must be lowercase letters, digits, or dashes — the derived name '"+plan.Name+"' is not usable yet.")
		return plan
	}
	tagList := `"` + strings.Join(plan.Tags, `", "`) + `"`
	plan.AgenixEdit = fmt.Sprintf(`cd ~/Code/nixcfg
agenix -e secrets/%s.age
# paste KEY=VALUE lines — take the values from 1Password (canonical store)`, plan.Name)
	plan.SecretsNix = fmt.Sprintf(`  # %s env for %s.
  # Format: KEY=VALUE lines
  # Edit: agenix -e secrets/%s.age
  "%s.age".publicKeys = markus ++ %s;`, plan.Service, plan.Host, plan.Name, plan.Name, plan.Host)
	plan.HostNix = fmt.Sprintf(`  age.secrets.%s = {
    file = ../../secrets/%s.age;
    path = "/run/agenix/%s";
  };`, plan.Name, plan.Name, plan.Name)
	plan.Compose = fmt.Sprintf(`  %s:
    # ...
    env_file:
      - /run/agenix/%s`, plan.Service, plan.Name)
	plan.Catalog = fmt.Sprintf(` {
  "id": "%s",
  "display_name": "%s",
  "provider": "agenix",
  "classification": "%s",
  "owner": "platform",
  "scope": "%s",
  "source": "secrets/%s.age",
  "rotation_days": %d,
  "lifecycle": "active",
  "status": "managed",
  "use_enabled": true,
  "consumer_count": 1,
  "egress_mode": "none",
  "tags": [%s]
 }`, plan.Name, plan.DisplayName, plan.Classification, plan.Host, plan.Name, plan.RotationDays, tagList)
	return plan
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

func (app *App) handleLegacyDashboard(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "dashboard.view", "allowed", actorFromContext(r.Context()), "legacy console")
	session := currentSession(r.Context())
	renderTemplate(w, app.templates, "legacy_dashboard", app.dashboardData(r, session, nil, r.URL.Query().Get("ref")))
}
