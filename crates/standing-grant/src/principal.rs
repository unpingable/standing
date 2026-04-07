use serde::{Deserialize, Serialize};

/// A principal: a stable, opaque identity for authorization.
///
/// Display labels are for humans and receipts. Authorization uses `id` only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Principal {
    /// Stable opaque identifier (e.g., "wl:deploy-bot:host-abc", "admin:jbeck")
    pub id: String,
    /// Human-readable label for receipts (never used for authorization)
    pub label: String,
}

impl Principal {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
        }
    }

    /// System principal for automated transitions (expiry, reaping).
    pub fn system() -> Self {
        Self {
            id: "system".to_string(),
            label: "system".to_string(),
        }
    }
}

/// The role a principal plays in a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    /// The workload the grant is for
    Subject,
    /// An administrator or the original issuer
    Admin,
    /// The system itself (automated expiry, reaping)
    System,
}

/// Who is attempting a transition, and in what capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorContext {
    /// The principal performing the action
    pub principal: Principal,
    /// The role they're claiming for this transition
    pub role: PrincipalRole,
}

impl ActorContext {
    pub fn subject(principal: Principal) -> Self {
        Self {
            principal,
            role: PrincipalRole::Subject,
        }
    }

    pub fn admin(principal: Principal) -> Self {
        Self {
            principal,
            role: PrincipalRole::Admin,
        }
    }

    pub fn system() -> Self {
        Self {
            principal: Principal::system(),
            role: PrincipalRole::System,
        }
    }
}
