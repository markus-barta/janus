//! Principal-chain identity model.

use crate::{JanusError, JanusResult};

fn non_empty(kind: &'static str, value: impl Into<String>) -> JanusResult<String> {
    let value = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() != value.len() {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(value)
}

/// Kind of actor participating in a Janus decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrincipalKind {
    /// Real human, usually SSO/passkey authenticated.
    Human,
    /// AI/agent session operating under a scoped task.
    AgentSession,
    /// Local runner, connector, or managed command executor.
    Executor,
    /// CI/service workload identity.
    Workload,
    /// Admin or break-glass principal.
    Admin,
}

/// Opaque principal identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Construct a non-empty principal id.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        Ok(Self(non_empty("principal_id", value)?))
    }

    /// Safe string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A single actor in the decision chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// Actor kind.
    pub kind: PrincipalKind,
    /// Opaque actor id.
    pub id: PrincipalId,
}

impl Principal {
    /// Construct a principal.
    pub fn new(kind: PrincipalKind, id: PrincipalId) -> Self {
        Self { kind, id }
    }
}

/// Scope boundary carried by refs, permits, policies, and audit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScopeRef(String);

impl ScopeRef {
    /// Construct a non-empty scope reference.
    pub fn new(value: impl Into<String>) -> JanusResult<Self> {
        Ok(Self(non_empty("scope_ref", value)?))
    }

    /// Safe string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Full principal chain for a decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalChain {
    /// Optional human on whose behalf work is happening.
    pub human: Option<Principal>,
    /// Optional agent session.
    pub agent: Option<Principal>,
    /// Executor expected to consume a permit.
    pub executor: Principal,
    /// Optional service/workload identity.
    pub workload: Option<Principal>,
    /// Optional admin/break-glass identity.
    pub admin: Option<Principal>,
    /// Project/repo/environment/host boundary.
    pub scope: ScopeRef,
}

impl PrincipalChain {
    /// Construct the smallest valid chain: executor + scope.
    pub fn new(executor: Principal, scope: ScopeRef) -> Self {
        Self {
            human: None,
            agent: None,
            executor,
            workload: None,
            admin: None,
            scope,
        }
    }

    /// A stable, value-free binding string for policy/audit comparisons.
    pub fn binding_key(&self) -> String {
        let mut parts = vec![
            format!("executor:{}", self.executor.id.as_str()),
            format!("scope:{}", self.scope.as_str()),
        ];
        if let Some(human) = &self.human {
            parts.push(format!("human:{}", human.id.as_str()));
        }
        if let Some(agent) = &self.agent {
            parts.push(format!("agent:{}", agent.id.as_str()));
        }
        if let Some(workload) = &self.workload {
            parts.push(format!("workload:{}", workload.id.as_str()));
        }
        if let Some(admin) = &self.admin {
            parts.push(format!("admin:{}", admin.id.as_str()));
        }
        parts.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_key_is_value_free_and_stable() {
        let chain = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("runner-a").unwrap(),
            ),
            ScopeRef::new("proj/dev").unwrap(),
        );
        assert_eq!(chain.binding_key(), "executor:runner-a|scope:proj/dev");
    }
}
