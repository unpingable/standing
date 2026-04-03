use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What the grant permits: actor × action × target.
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
    /// Who is requesting the grant
    pub actor: String,
    /// What the grant would permit
    pub scope: GrantScope,
    /// Requested duration in seconds
    pub duration_secs: u64,
    /// Arbitrary context for the policy engine
    pub context: serde_json::Value,
}

/// A grant: a scoped, time-limited entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Unique grant ID
    pub id: Uuid,
    /// Who holds this grant
    pub actor: String,
    /// What it permits
    pub scope: GrantScope,
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
}
