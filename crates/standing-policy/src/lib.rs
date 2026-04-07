//! Policy engine for standing.
//!
//! Evaluates grant requests against policy and emits decision receipts.
//! Hardcoded policy for slice 1; trait-based for future pluggability.

use sha2::{Digest, Sha256};
use standing_grant::GrantRequest;
use standing_receipt::{ReceiptBuilder, ReceiptKind, Receipt, ReceiptError};

/// The verdict of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

/// A policy decision: verdict + evidence + receipt.
#[derive(Debug)]
pub struct PolicyDecision {
    pub verdict: Verdict,
    pub reason: String,
    pub policy_hash: String,
    pub receipt: Receipt,
}

/// Policy evaluator trait.
pub trait PolicyEvaluator {
    fn evaluate(
        &self,
        request: &GrantRequest,
        subject: &str,
        parent_digest: &str,
    ) -> Result<PolicyDecision, PolicyError>;

    /// Hash of the policy definition, for pinning in receipts.
    fn policy_hash(&self) -> String;
}

/// Errors from policy evaluation.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("receipt error: {0}")]
    Receipt(#[from] ReceiptError),
}

/// Hardcoded policy for slice 1.
///
/// Rules:
/// - Max duration: 3600 seconds (1 hour)
/// - Action must not be empty
/// - Target must not be empty
/// - Actor must not be empty
///
/// That's it. This is a placeholder, not a cathedral.
pub struct HardcodedPolicy;

impl HardcodedPolicy {
    const POLICY_DEFINITION: &str = "max_duration=3600;require_non_empty_fields";
}

impl PolicyEvaluator for HardcodedPolicy {
    fn evaluate(
        &self,
        request: &GrantRequest,
        subject: &str,
        parent_digest: &str,
    ) -> Result<PolicyDecision, PolicyError> {
        let policy_hash = self.policy_hash();

        // Evaluate
        let (verdict, reason) = if request.subject.id.is_empty() {
            (Verdict::Deny, "subject identity is empty".to_string())
        } else if request.scope.action.is_empty() {
            (Verdict::Deny, "action is empty".to_string())
        } else if request.scope.target.is_empty() {
            (Verdict::Deny, "target is empty".to_string())
        } else if request.duration_secs > 3600 {
            (
                Verdict::Deny,
                format!(
                    "duration {}s exceeds max 3600s",
                    request.duration_secs
                ),
            )
        } else {
            (Verdict::Allow, "all checks passed".to_string())
        };

        let receipt_kind = match verdict {
            Verdict::Allow => ReceiptKind::PolicyDecision,
            Verdict::Deny => ReceiptKind::PolicyDecision,
        };

        let receipt = ReceiptBuilder::new(receipt_kind, "policy-engine", subject)
            .parent_digest(parent_digest)
            .policy_hash(&policy_hash)
            .evidence(serde_json::json!({
                "verdict": verdict,
                "reason": reason,
                "request": {
                    "subject": request.subject,
                    "action": request.scope.action,
                    "target": request.scope.target,
                    "duration_secs": request.duration_secs,
                },
            }))
            .build()?;

        Ok(PolicyDecision {
            verdict,
            reason,
            policy_hash,
            receipt,
        })
    }

    fn policy_hash(&self) -> String {
        let hash = Sha256::digest(Self::POLICY_DEFINITION.as_bytes());
        hex::encode(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use standing_grant::{GrantRequest, GrantScope, Principal};

    fn make_request(subject_id: &str, action: &str, target: &str, duration: u64) -> GrantRequest {
        GrantRequest {
            subject: Principal::new(subject_id, subject_id),
            scope: GrantScope {
                action: action.to_string(),
                target: target.to_string(),
            },
            duration_secs: duration,
            context: serde_json::json!({}),
        }
    }

    // Fake parent digest for testing
    fn fake_parent() -> String {
        "a".repeat(64)
    }

    #[test]
    fn allows_valid_request() {
        let policy = HardcodedPolicy;
        let req = make_request("deploy-bot", "deploy", "prod/web", 300);
        let decision = policy.evaluate(&req, "test-grant-id", &fake_parent()).unwrap();
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[test]
    fn denies_excessive_duration() {
        let policy = HardcodedPolicy;
        let req = make_request("bot", "deploy", "prod", 7200);
        let decision = policy.evaluate(&req, "test-grant-id", &fake_parent()).unwrap();
        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("exceeds max"));
    }

    #[test]
    fn denies_empty_subject() {
        let policy = HardcodedPolicy;
        let req = make_request("", "deploy", "prod", 300);
        let decision = policy.evaluate(&req, "test-grant-id", &fake_parent()).unwrap();
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    #[test]
    fn policy_hash_is_stable() {
        let p = HardcodedPolicy;
        assert_eq!(p.policy_hash(), p.policy_hash());
        assert!(!p.policy_hash().is_empty());
    }
}
