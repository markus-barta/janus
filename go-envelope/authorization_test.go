package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type canonicalRoleMatrix struct {
	SchemaVersion int    `json:"schema_version"`
	PolicyID      string `json:"policy_id"`
	Roles         []struct {
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	} `json:"roles"`
}

func TestAuthorizationVocabularyMatchesCanonicalSnapshot(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "config", "authorization", "role-matrix-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot canonicalRoleMatrix
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.PolicyID != "janus-role-matrix-v1" {
		t.Fatalf("unexpected canonical authorization snapshot: %#v", snapshot)
	}

	got := make(map[string]map[string]bool, len(snapshot.Roles))
	for _, role := range snapshot.Roles {
		if role.Role == "admin" || role.Role == "" || got[role.Role] != nil {
			t.Fatalf("invalid or duplicate canonical role %q", role.Role)
		}
		permissions := make(map[string]bool, len(role.Permissions))
		for _, permission := range role.Permissions {
			if permission == "" || permissions[permission] {
				t.Fatalf("invalid or duplicate permission for role %q", role.Role)
			}
			permissions[permission] = true
		}
		got[role.Role] = permissions
	}
	if !reflect.DeepEqual(got, rolePermissionCeilings) {
		t.Fatalf("Go authorization vocabulary drifted from canonical snapshot\ncanonical=%#v\ngo=%#v", got, rolePermissionCeilings)
	}
	if !reflect.DeepEqual(AllRoles(), []string{RoleViewer, RoleOperator, RoleOwner, RoleApprover, RoleAuditor, RoleSecurityAdmin, RoleBreakGlassAdmin, RoleServiceAdmin, RoleWorkloadAdmin}) {
		t.Fatalf("Go role order drifted: %#v", AllRoles())
	}
}

func TestEveryRouteUsesKnownCanonicalPermission(t *testing.T) {
	app := newTestApp(t)
	seen := map[string]bool{}
	for _, route := range app.routeSpecs() {
		if route.pattern == "" || seen[route.pattern] {
			t.Fatalf("missing or duplicate route pattern %q", route.pattern)
		}
		seen[route.pattern] = true
		if route.permission == "" || !knownPermission(route.permission) {
			t.Fatalf("route %q has unknown permission %q", route.pattern, route.permission)
		}
		if len(rolesForPermission(route.permission)) == 0 {
			t.Fatalf("route %q permission %q has no canonical role", route.pattern, route.permission)
		}
	}
	if len(seen) == 0 {
		t.Fatal("route inventory is empty")
	}
}

func TestAuthorizationNegativeRoleBoundaries(t *testing.T) {
	tests := []struct {
		role       string
		permission string
	}{
		{role: RoleAuditor, permission: PermissionSecretUse},
		{role: RoleOwner, permission: PermissionSecretUse},
		{role: RoleSecurityAdmin, permission: PermissionSecretUse},
		{role: RoleOperator, permission: PermissionApprovalIssue},
		{role: RoleOperator, permission: PermissionRoleBindingIssue},
		{role: RoleApprover, permission: PermissionSecretUse},
		{role: RoleServiceAdmin, permission: PermissionSecretUse},
		{role: RoleWorkloadAdmin, permission: PermissionSecretUse},
	}
	for _, tc := range tests {
		t.Run(tc.role+"_cannot_"+tc.permission, func(t *testing.T) {
			if SessionHasPermission(Session{Roles: []string{RoleViewer, tc.role}}, tc.permission) {
				t.Fatalf("role %q unexpectedly has %q", tc.role, tc.permission)
			}
		})
	}
	if len(rolePermissionCeilings[RoleBreakGlassAdmin]) != 0 {
		t.Fatalf("break-glass eligibility ceiling must be empty: %#v", rolePermissionCeilings[RoleBreakGlassAdmin])
	}
	for permission := range allCanonicalPermissions() {
		withEligibility := SessionHasPermission(Session{Roles: []string{RoleViewer, RoleBreakGlassAdmin}}, permission)
		viewerOnly := SessionHasPermission(Session{Roles: []string{RoleViewer}}, permission)
		if withEligibility != viewerOnly {
			t.Fatalf("break-glass eligibility role changed authority for %q", permission)
		}
	}
}

func TestOIDCRoleProjectionIsExactAndRejectsAmbiguity(t *testing.T) {
	policy := RolePolicy{
		ViewerSubjects:        map[string]bool{"viewer-subject": true},
		OwnerSubjects:         map[string]bool{"owner-subject": true},
		OperatorGroups:        map[string]bool{"operator-group": true},
		SecurityAdminSubjects: map[string]bool{"security-subject": true},
	}
	roles, err := DeriveRolesChecked("owner-subject", "", []string{"operator-group"}, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{RoleViewer, RoleOwner, RoleOperator} {
		if !HasRole(Session{Roles: roles}, role) {
			t.Fatalf("exact mapping omitted %q from %#v", role, roles)
		}
	}
	if roles, err := DeriveRolesChecked("viewer-subject", "", nil, policy); err != nil || !reflect.DeepEqual(roles, []string{RoleViewer}) {
		t.Fatalf("explicit viewer binding should grant only viewer, roles=%#v err=%v", roles, err)
	}
	if roles, err := DeriveRolesChecked("unknown-subject", "", []string{"unknown-group"}, policy); err != nil || len(roles) != 0 {
		t.Fatalf("unknown exact values should receive no role, roles=%#v err=%v", roles, err)
	}

	canary := "identity-claim-canary-309"
	for name, ambiguous := range map[string]RolePolicy{
		"subject": {OwnerSubjects: map[string]bool{canary: true}, ApproverSubjects: map[string]bool{canary: true}},
		"group":   {OperatorGroups: map[string]bool{canary: true}, AuditorGroups: map[string]bool{canary: true}},
	} {
		t.Run(name, func(t *testing.T) {
			claims := []string(nil)
			subject := canary
			if name == "group" {
				subject = "safe-subject"
				claims = []string{canary}
			}
			roles, err := DeriveRolesChecked(subject, "", claims, ambiguous)
			if err == nil || len(roles) != 0 || strings.Contains(err.Error(), canary) {
				t.Fatalf("ambiguous mapping must fail closed without values, roles=%#v err=%v", roles, err)
			}
		})
	}
	roles, err = DeriveRolesChecked("safe-subject", "", []string{canary, canary}, RolePolicy{OperatorGroups: map[string]bool{canary: true}})
	if err == nil || len(roles) != 0 || strings.Contains(err.Error(), canary) {
		t.Fatalf("duplicate claims must fail closed without values, roles=%#v err=%v", roles, err)
	}
}

func TestZitadelProjectRolesPreferConfiguredProjectAndIgnoreMetadata(t *testing.T) {
	const projectID = "375139131258306571"
	raw := map[string]json.RawMessage{
		zitadelProjectRolesClaim: json.RawMessage(`{"janus:legacy":{"org-id":"org.example"}}`),
		zitadelProjectRolesClaimPrefix + projectID + zitadelProjectRolesClaimSuffix: json.RawMessage(
			`{"janus:viewer":{"org-id":"org.example"},"janus:operator":{"org-id":"org.example"}}`,
		),
		zitadelProjectRolesClaimPrefix + "999" + zitadelProjectRolesClaimSuffix: json.RawMessage(
			`{"foreign-role":{"org-id":"foreign.example"}}`,
		),
	}
	projectRoles, err := ZitadelProjectRoles(raw, projectID)
	if err != nil {
		t.Fatal(err)
	}
	inputs := ClaimRoleInputs(nil, nil, projectRoles)
	sort.Strings(inputs)
	if !reflect.DeepEqual(inputs, []string{"janus:operator", "janus:viewer"}) {
		t.Fatalf("project role projection should return only exact role keys: %#v", inputs)
	}
	if roles, err := ZitadelProjectRoles(
		map[string]json.RawMessage{
			zitadelProjectRolesClaim: json.RawMessage(`{"janus:operator":{}}`),
		},
		projectID,
	); err != nil || roles != nil {
		t.Fatalf("configured project must not fall back to an unscoped claim, roles=%#v err=%v", roles, err)
	}
}

func TestZitadelProjectRolesLegacyFallbackAndAmbiguityFailClosed(t *testing.T) {
	legacy := map[string]json.RawMessage{
		zitadelProjectRolesClaim: json.RawMessage(`{"janus:auditor":{"org-id":"org.example"}}`),
	}
	projectRoles, err := ZitadelProjectRoles(legacy, "")
	if err != nil || !reflect.DeepEqual(ClaimRoleInputs(nil, nil, projectRoles), []string{"janus:auditor"}) {
		t.Fatalf("legacy role claim should remain supported, roles=%#v err=%v", projectRoles, err)
	}

	canary := "role-claim-canary-267"
	for name, claims := range map[string]map[string]json.RawMessage{
		"multiple projects": {
			zitadelProjectRolesClaimPrefix + "111" + zitadelProjectRolesClaimSuffix: json.RawMessage(`{"viewer":{}}`),
			zitadelProjectRolesClaimPrefix + "222" + zitadelProjectRolesClaimSuffix: json.RawMessage(`{"operator":{}}`),
		},
		"malformed": {
			zitadelProjectRolesClaim: json.RawMessage(`"` + canary + `"`),
		},
	} {
		t.Run(name, func(t *testing.T) {
			roles, err := ZitadelProjectRoles(claims, "")
			if err == nil || roles != nil || strings.Contains(err.Error(), canary) {
				t.Fatalf("invalid project role claims must fail closed without values, roles=%#v err=%v", roles, err)
			}
		})
	}
	if roles, err := ZitadelProjectRoles(legacy, "not-a-project-id"); err == nil || roles != nil {
		t.Fatalf("invalid configured project id must fail closed, roles=%#v err=%v", roles, err)
	}
}

func TestSessionRoleValidationRejectsLegacyUnknownAndDuplicateRoles(t *testing.T) {
	if !validateSessionRoles([]string{RoleViewer, RoleOperator}) {
		t.Fatal("known unique roles should validate")
	}
	for _, roles := range [][]string{
		nil,
		{RoleOperator},
		{RoleViewer, RoleViewer},
		{RoleViewer, "admin"},
		{RoleViewer, "unknown"},
	} {
		if validateSessionRoles(roles) {
			t.Fatalf("invalid session roles accepted: %#v", roles)
		}
	}
}

func TestPermissionDenialIsValueFreeInResponseAndAudit(t *testing.T) {
	app := newTestApp(t)
	canary := "subject-canary-309"
	session := Session{Subject: canary, Roles: []string{RoleViewer}}
	req := httptest.NewRequest(http.MethodPost, "/api/permits", nil)
	req = req.WithContext(context.WithValue(req.Context(), sessionKey{}, session))
	out := httptest.NewRecorder()
	app.requirePermission(PermissionSecretUse, "POST /api/permits", func(http.ResponseWriter, *http.Request) {
		t.Fatal("denied route handler ran")
	})(out, req)
	if out.Code != http.StatusForbidden || strings.Contains(out.Body.String(), canary) || strings.Contains(out.Body.String(), PermissionSecretUse) {
		t.Fatalf("permission denial leaked detail: status=%d body=%s", out.Code, out.Body.String())
	}
	entries := app.store.RecentAudit(1)
	if len(entries) != 1 {
		t.Fatalf("expected one denial audit, got %d", len(entries))
	}
	raw, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) || entries[0].ActorHash == "" || entries[0].Outcome != "denied" {
		t.Fatalf("denial audit must use only a principal hash: %s", raw)
	}
}

func allCanonicalPermissions() map[string]bool {
	permissions := map[string]bool{}
	for _, ceiling := range rolePermissionCeilings {
		for permission := range ceiling {
			permissions[permission] = true
		}
	}
	return permissions
}
