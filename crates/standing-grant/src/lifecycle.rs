use chrono::{Duration, Utc};
use uuid::Uuid;

use standing_receipt::{Receipt, ReceiptBuilder, ReceiptChain, ReceiptKind};

use crate::error::GrantError;
use crate::grant::{Grant, GrantRequest, GrantScope};

/// The state of a grant in its lifecycle.
///
/// Terminal states: Used, Expired, Revoked, Denied, Abandoned.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// Grant has been requested, awaiting policy decision
    Requested,
    /// Policy approved, grant is live
    Issued,
    /// Workload has begun using the grant
    Active,
    /// Grant was used to perform the action (terminal)
    Used,
    /// Grant expired before use (terminal)
    Expired,
    /// Grant was explicitly revoked (terminal)
    Revoked,
    /// Policy denied the grant request (terminal)
    Denied,
    /// Workload disappeared mid-lease (terminal)
    Abandoned,
}

impl GrantState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            GrantState::Used
                | GrantState::Expired
                | GrantState::Revoked
                | GrantState::Denied
                | GrantState::Abandoned
        )
    }

    /// The allowed transitions from this state.
    pub fn allowed_transitions(&self) -> &[GrantState] {
        match self {
            GrantState::Requested => &[GrantState::Issued, GrantState::Denied],
            GrantState::Issued => &[
                GrantState::Active,
                GrantState::Expired,
                GrantState::Revoked,
                GrantState::Abandoned,
            ],
            GrantState::Active => &[
                GrantState::Used,
                GrantState::Expired,
                GrantState::Revoked,
                GrantState::Abandoned,
            ],
            // Terminal states allow no transitions
            GrantState::Used
            | GrantState::Expired
            | GrantState::Revoked
            | GrantState::Denied
            | GrantState::Abandoned => &[],
        }
    }

    /// Can this state transition to `target`?
    pub fn can_transition_to(&self, target: &GrantState) -> bool {
        self.allowed_transitions().contains(target)
    }

    /// Parse from the string form used in storage.
    pub fn from_str(s: &str) -> Option<GrantState> {
        match s {
            "requested" => Some(GrantState::Requested),
            "issued" => Some(GrantState::Issued),
            "active" => Some(GrantState::Active),
            "used" => Some(GrantState::Used),
            "expired" => Some(GrantState::Expired),
            "revoked" => Some(GrantState::Revoked),
            "denied" => Some(GrantState::Denied),
            "abandoned" => Some(GrantState::Abandoned),
            _ => None,
        }
    }
}

impl std::fmt::Display for GrantState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", self));
        f.write_str(&s)
    }
}

/// State machine for a single grant's lifecycle.
/// Every transition emits a receipt; the receipt chain is the ground truth.
pub struct GrantMachine {
    pub grant: Option<Grant>,
    pub state: GrantState,
    pub chain: ReceiptChain,
    grant_id: Uuid,
}

impl GrantMachine {
    /// Start a new grant lifecycle from a request.
    /// Emits a GrantRequested receipt.
    pub fn request(req: &GrantRequest) -> Result<Self, GrantError> {
        let grant_id = Uuid::new_v4();
        let subject = grant_id.to_string();

        let receipt = ReceiptBuilder::new(ReceiptKind::GrantRequested, &req.actor, &subject)
            .evidence(serde_json::json!({
                "scope": {
                    "action": req.scope.action,
                    "target": req.scope.target,
                },
                "duration_secs": req.duration_secs,
                "context": req.context,
            }))
            .build()
            .map_err(GrantError::Receipt)?;

        let chain = ReceiptChain::new(receipt);

        Ok(Self {
            grant: None,
            state: GrantState::Requested,
            chain,
            grant_id,
        })
    }

    /// Issue the grant (policy approved). Transitions Requested → Issued.
    pub fn issue(
        &mut self,
        duration_secs: u64,
        policy_hash: &str,
        evidence: serde_json::Value,
    ) -> Result<&Receipt, GrantError> {
        self.require_state(&GrantState::Requested)?;

        let now = Utc::now();
        let grant = Grant {
            id: self.grant_id,
            actor: self.actor().to_string(),
            scope: self.scope_from_chain(),
            issued_at: now,
            expires_at: now + Duration::seconds(duration_secs as i64),
        };

        let receipt = ReceiptBuilder::new(
            ReceiptKind::GrantIssued,
            &grant.actor,
            &self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .policy_hash(policy_hash)
        .evidence(evidence)
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.grant = Some(grant);
        self.state = GrantState::Issued;
        Ok(self.chain.tip())
    }

    /// Deny the grant (policy rejected). Transitions Requested → Denied.
    pub fn deny(
        &mut self,
        policy_hash: &str,
        evidence: serde_json::Value,
    ) -> Result<&Receipt, GrantError> {
        self.require_state(&GrantState::Requested)?;

        let receipt = ReceiptBuilder::new(
            ReceiptKind::GrantDenied,
            self.actor(),
            &self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .policy_hash(policy_hash)
        .evidence(evidence)
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = GrantState::Denied;
        Ok(self.chain.tip())
    }

    /// Activate the grant (workload begins using it). Transitions Issued → Active.
    pub fn activate(&mut self) -> Result<&Receipt, GrantError> {
        self.require_state(&GrantState::Issued)?;
        self.check_not_expired()?;

        let receipt = ReceiptBuilder::new(
            ReceiptKind::GrantActivated,
            self.actor(),
            &self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = GrantState::Active;
        Ok(self.chain.tip())
    }

    /// Record that the grant was used. Transitions Active → Used.
    pub fn record_use(&mut self, evidence: serde_json::Value) -> Result<&Receipt, GrantError> {
        self.require_state(&GrantState::Active)?;
        self.check_not_expired()?;

        let receipt = ReceiptBuilder::new(
            ReceiptKind::GrantUsed,
            self.actor(),
            &self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .evidence(evidence)
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = GrantState::Used;
        Ok(self.chain.tip())
    }

    /// Expire the grant. Transitions Issued|Active → Expired.
    pub fn expire(&mut self) -> Result<&Receipt, GrantError> {
        if self.state != GrantState::Issued && self.state != GrantState::Active {
            return Err(GrantError::InvalidTransition {
                from: self.state.to_string(),
                to: "expired".to_string(),
            });
        }

        let receipt = ReceiptBuilder::new(
            ReceiptKind::GrantExpired,
            self.actor(),
            &self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = GrantState::Expired;
        Ok(self.chain.tip())
    }

    /// Revoke the grant. Transitions Issued|Active → Revoked.
    pub fn revoke(&mut self, reason: &str) -> Result<&Receipt, GrantError> {
        if self.state != GrantState::Issued && self.state != GrantState::Active {
            return Err(GrantError::InvalidTransition {
                from: self.state.to_string(),
                to: "revoked".to_string(),
            });
        }

        let receipt = ReceiptBuilder::new(
            ReceiptKind::GrantRevoked,
            self.actor(),
            &self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .evidence(serde_json::json!({"reason": reason}))
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = GrantState::Revoked;
        Ok(self.chain.tip())
    }

    /// Mark as abandoned (workload vanished). Transitions Issued|Active → Abandoned.
    pub fn abandon(&mut self) -> Result<&Receipt, GrantError> {
        if self.state != GrantState::Issued && self.state != GrantState::Active {
            return Err(GrantError::InvalidTransition {
                from: self.state.to_string(),
                to: "abandoned".to_string(),
            });
        }

        let receipt = ReceiptBuilder::new(
            ReceiptKind::GrantAbandoned,
            self.actor(),
            &self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = GrantState::Abandoned;
        Ok(self.chain.tip())
    }

    /// The grant ID for this lifecycle.
    pub fn grant_id(&self) -> Uuid {
        self.grant_id
    }

    fn actor(&self) -> &str {
        // Actor is on the first receipt in the chain
        &self.chain.receipts()[0].actor
    }

    fn scope_from_chain(&self) -> GrantScope {
        // Scope is in the evidence of the first (GrantRequested) receipt
        let evidence = &self.chain.receipts()[0].evidence;
        GrantScope {
            action: evidence["scope"]["action"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            target: evidence["scope"]["target"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
        }
    }

    fn require_state(&self, expected: &GrantState) -> Result<(), GrantError> {
        if self.state.is_terminal() {
            return Err(GrantError::Terminal(self.state.to_string()));
        }
        if &self.state != expected {
            return Err(GrantError::InvalidTransition {
                from: self.state.to_string(),
                to: format!("(from {})", expected),
            });
        }
        Ok(())
    }

    fn check_not_expired(&self) -> Result<(), GrantError> {
        if let Some(grant) = &self.grant {
            if grant.is_expired_at(Utc::now()) {
                return Err(GrantError::Expired {
                    expired_at: grant.expires_at.to_rfc3339(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::GrantRequest;

    fn test_request() -> GrantRequest {
        GrantRequest {
            actor: "deploy-bot".to_string(),
            scope: GrantScope {
                action: "deploy".to_string(),
                target: "prod/web-api".to_string(),
            },
            duration_secs: 300,
            context: serde_json::json!({"ticket": "DEPLOY-1234"}),
        }
    }

    #[test]
    fn happy_path_lifecycle() {
        let req = test_request();
        let mut m = GrantMachine::request(&req).unwrap();
        assert_eq!(m.state, GrantState::Requested);
        assert_eq!(m.chain.len(), 1);

        m.issue(300, "policy-sha256-abc", serde_json::json!({"allowed": true}))
            .unwrap();
        assert_eq!(m.state, GrantState::Issued);
        assert_eq!(m.chain.len(), 2);

        m.activate().unwrap();
        assert_eq!(m.state, GrantState::Active);
        assert_eq!(m.chain.len(), 3);

        m.record_use(serde_json::json!({"deployed": "v1.2.3"}))
            .unwrap();
        assert_eq!(m.state, GrantState::Used);
        assert_eq!(m.chain.len(), 4);

        // Chain is valid
        m.chain.verify().unwrap();
    }

    #[test]
    fn denied_grant() {
        let req = test_request();
        let mut m = GrantMachine::request(&req).unwrap();

        m.deny("policy-sha256-abc", serde_json::json!({"reason": "scope too broad"}))
            .unwrap();
        assert_eq!(m.state, GrantState::Denied);
        assert!(m.state.is_terminal());

        // Can't issue after deny
        assert!(m
            .issue(300, "x", serde_json::json!(null))
            .is_err());
    }

    #[test]
    fn revocation() {
        let req = test_request();
        let mut m = GrantMachine::request(&req).unwrap();
        m.issue(300, "p", serde_json::json!(null)).unwrap();
        m.activate().unwrap();

        m.revoke("security incident").unwrap();
        assert_eq!(m.state, GrantState::Revoked);

        // Can't use after revoke
        assert!(m.record_use(serde_json::json!(null)).is_err());
    }

    #[test]
    fn abandonment() {
        let req = test_request();
        let mut m = GrantMachine::request(&req).unwrap();
        m.issue(300, "p", serde_json::json!(null)).unwrap();

        m.abandon().unwrap();
        assert_eq!(m.state, GrantState::Abandoned);
        assert!(m.state.is_terminal());
    }

    #[test]
    fn cannot_skip_states() {
        let req = test_request();
        let mut m = GrantMachine::request(&req).unwrap();

        // Can't activate before issued
        assert!(m.activate().is_err());

        // Can't use before active
        m.issue(300, "p", serde_json::json!(null)).unwrap();
        assert!(m.record_use(serde_json::json!(null)).is_err());
    }
}
