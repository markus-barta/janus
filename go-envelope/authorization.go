package main

import "sort"

const (
	PermissionDescriptorList          = "descriptor.list"
	PermissionDescriptorRead          = "descriptor.read"
	PermissionHealthRead              = "health.read"
	PermissionSecretUse               = "secret.use"
	PermissionManagedRun              = "managed_run.use"
	PermissionEnvFile                 = "env_file.use"
	PermissionApprovalIssue           = "approval.issue"
	PermissionApprovalPermit          = "approval.permit"
	PermissionApprovalRead            = "approval.read"
	PermissionApprovalRevoke          = "approval.revoke"
	PermissionDelegationIssue         = "delegation.issue"
	PermissionDelegationRead          = "delegation.read"
	PermissionDelegationRevoke        = "delegation.revoke"
	PermissionLifecycleTransition     = "lifecycle.transition"
	PermissionLifecycleRead           = "lifecycle.read"
	PermissionDestroyRecord           = "destroy.record"
	PermissionDestroyFinalize         = "destroy.finalize"
	PermissionDestroyReconcile        = "destroy.reconcile"
	PermissionRotationManage          = "rotation.manage"
	PermissionLifecycleEntry          = "lifecycle.entry"
	PermissionMigrationManage         = "migration.manage"
	PermissionScopeTransferManage     = "scope_transfer.manage"
	PermissionRecoveryDrill           = "recovery.drill"
	PermissionRetentionManage         = "retention.manage"
	PermissionPharosRetire            = "pharos.retire"
	PermissionPharosReconcile         = "pharos.reconcile"
	PermissionRoleBindingIssue        = "role_binding.issue"
	PermissionRoleBindingRead         = "role_binding.read"
	PermissionRoleBindingRevoke       = "role_binding.revoke"
	PermissionRoleBindingStatus       = "role_binding.status"
	PermissionAuthorizationPolicyRead = "authorization_policy.read"
	PermissionAuthorizationPolicyEdit = "authorization_policy.manage"
	PermissionBreakGlassActivate      = "break_glass.activate"
	PermissionBreakGlassRead          = "break_glass.read"
	PermissionBreakGlassRevoke        = "break_glass.revoke"
	PermissionBreakGlassReview        = "break_glass.review"
)

// This code ceiling is checked byte-for-vocabulary parity against the shared
// config/authorization/role-matrix-v1.json snapshot in tests. Runtime policy
// can remove permissions but cannot invent a permission or role.
var rolePermissionCeilings = map[string]map[string]bool{
	RoleViewer:          permissionSet(PermissionDescriptorList, PermissionDescriptorRead, PermissionHealthRead, PermissionLifecycleRead),
	RoleOperator:        permissionSet(PermissionDescriptorList, PermissionDescriptorRead, PermissionHealthRead, PermissionSecretUse, PermissionManagedRun, PermissionEnvFile, PermissionApprovalRead, PermissionLifecycleRead),
	RoleOwner:           permissionSet(PermissionDescriptorList, PermissionDescriptorRead, PermissionHealthRead, PermissionApprovalRead, PermissionDelegationIssue, PermissionDelegationRead, PermissionDelegationRevoke, PermissionLifecycleTransition, PermissionLifecycleRead, PermissionDestroyRecord, PermissionDestroyFinalize, PermissionDestroyReconcile, PermissionRotationManage, PermissionLifecycleEntry, PermissionMigrationManage, PermissionScopeTransferManage, PermissionRecoveryDrill, PermissionRetentionManage, PermissionPharosRetire, PermissionPharosReconcile, PermissionAuthorizationPolicyRead),
	RoleApprover:        permissionSet(PermissionDescriptorList, PermissionDescriptorRead, PermissionHealthRead, PermissionApprovalIssue, PermissionApprovalPermit, PermissionApprovalRead, PermissionApprovalRevoke, PermissionDelegationRead, PermissionLifecycleRead),
	RoleAuditor:         permissionSet(PermissionDescriptorList, PermissionDescriptorRead, PermissionHealthRead, PermissionApprovalRead, PermissionDelegationRead, PermissionLifecycleRead, PermissionRoleBindingRead, PermissionRoleBindingStatus, PermissionAuthorizationPolicyRead, PermissionBreakGlassRead, PermissionBreakGlassReview),
	RoleSecurityAdmin:   permissionSet(PermissionHealthRead, PermissionRoleBindingIssue, PermissionRoleBindingRead, PermissionRoleBindingRevoke, PermissionRoleBindingStatus, PermissionAuthorizationPolicyRead, PermissionAuthorizationPolicyEdit, PermissionBreakGlassActivate, PermissionBreakGlassRead, PermissionBreakGlassRevoke, PermissionBreakGlassReview),
	RoleBreakGlassAdmin: permissionSet(),
	RoleServiceAdmin:    permissionSet(PermissionDescriptorList, PermissionDescriptorRead, PermissionHealthRead, PermissionLifecycleTransition, PermissionLifecycleRead, PermissionRotationManage, PermissionLifecycleEntry),
	RoleWorkloadAdmin:   permissionSet(PermissionDescriptorList, PermissionDescriptorRead, PermissionHealthRead, PermissionLifecycleTransition, PermissionLifecycleRead),
}

func permissionSet(permissions ...string) map[string]bool {
	set := make(map[string]bool, len(permissions))
	for _, permission := range permissions {
		set[permission] = true
	}
	return set
}

func SessionHasPermission(session Session, permission string) bool {
	for _, role := range session.Roles {
		if rolePermissionCeilings[role][permission] {
			return true
		}
	}
	return false
}

func knownPermission(permission string) bool {
	for _, ceiling := range rolePermissionCeilings {
		if ceiling[permission] {
			return true
		}
	}
	return false
}

func rolesForPermission(permission string) []string {
	roles := []string{}
	for role, ceiling := range rolePermissionCeilings {
		if ceiling[permission] {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	return roles
}

func validateSessionRoles(roles []string) bool {
	if len(roles) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if seen[role] {
			return false
		}
		seen[role] = true
		if _, known := rolePermissionCeilings[role]; !known {
			return false
		}
	}
	return seen[RoleViewer]
}
