use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::principal::Principal;

/// What the grant permits: action × target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantScope {
    /// The action being permitted (e.g., "deploy", "rotate-secret", "scale")
    pub action: String,
    /// The target of the action (e.g., "prod/web-api", "staging/db")
    pub target: String,
}

/// A request to create a grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequest {
    /// Who is requesting the grant (stable principal)
    pub subject: Principal,
    /// What the grant would permit
    pub scope: GrantScope,
    /// Requested duration in seconds
    pub duration_secs: u64,
    /// Optional front of the validity window. `None` = valid immediately on
    /// issue. When set, the grant cannot activate or be used before this time.
    #[serde(default)]
    pub not_before: Option<DateTime<Utc>>,
    /// Arbitrary context for the policy engine
    pub context: serde_json::Value,
}

/// A grant: a scoped, time-limited entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Unique grant ID
    pub id: Uuid,
    /// The principal this grant is bound to (stable identity)
    pub subject: Principal,
    /// What it permits
    pub scope: GrantScope,
    /// Optional front of the validity window (`None` = valid on issue).
    #[serde(default)]
    pub not_before: Option<DateTime<Utc>>,
    /// When the grant was issued
    pub issued_at: DateTime<Utc>,
    /// When the grant expires (lease boundary)
    pub expires_at: DateTime<Utc>,
}

impl Grant {
    /// Is this grant expired as of the given time?
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Is this grant not-yet-valid as of the given time (before `not_before`)?
    pub fn is_not_yet_valid_at(&self, now: DateTime<Utc>) -> bool {
        matches!(self.not_before, Some(nb) if now < nb)
    }
}
