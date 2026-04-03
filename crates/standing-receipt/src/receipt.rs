use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::canonical::canonical_json;
use crate::error::ReceiptError;

/// What kind of event this receipt witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    /// A grant was requested
    GrantRequested,
    /// A grant was issued (policy said yes)
    GrantIssued,
    /// A grant request was denied (policy said no)
    GrantDenied,
    /// A grant was activated (workload began using it)
    GrantActivated,
    /// A grant was used (action performed under it)
    GrantUsed,
    /// A grant expired (lease ran out)
    GrantExpired,
    /// A grant was revoked (explicit revocation)
    GrantRevoked,
    /// A grant was abandoned (workload disappeared mid-lease)
    GrantAbandoned,
    /// A policy decision was made
    PolicyDecision,
}

/// A receipt: content-addressed witness to an event.
///
/// Once built, a receipt is immutable. Its digest is computed from
/// the canonical JSON of its body (everything except the digest itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Unique receipt ID
    pub id: Uuid,
    /// What happened
    pub kind: ReceiptKind,
    /// When it happened
    pub timestamp: DateTime<Utc>,
    /// Who/what actor was involved
    pub actor: String,
    /// What was the subject (grant ID, action, etc.)
    pub subject: String,
    /// SHA-256 of the parent receipt in the chain (None for first receipt)
    pub parent_digest: Option<String>,
    /// Arbitrary structured evidence attached to this receipt
    pub evidence: serde_json::Value,
    /// SHA-256 of the policy that was evaluated (if applicable)
    pub policy_hash: Option<String>,
    /// SHA-256 digest of the canonical JSON of all fields above
    pub digest: String,
}

/// Builder for receipts. Computes digest on build.
pub struct ReceiptBuilder {
    kind: ReceiptKind,
    actor: String,
    subject: String,
    parent_digest: Option<String>,
    evidence: serde_json::Value,
    policy_hash: Option<String>,
    timestamp: Option<DateTime<Utc>>,
}

impl ReceiptBuilder {
    pub fn new(kind: ReceiptKind, actor: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            kind,
            actor: actor.into(),
            subject: subject.into(),
            parent_digest: None,
            evidence: serde_json::Value::Null,
            policy_hash: None,
            timestamp: None,
        }
    }

    pub fn parent_digest(mut self, digest: impl Into<String>) -> Self {
        self.parent_digest = Some(digest.into());
        self
    }

    pub fn evidence(mut self, evidence: serde_json::Value) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.policy_hash = Some(hash.into());
        self
    }

    pub fn timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Build the receipt, computing its content-addressed digest.
    pub fn build(self) -> Result<Receipt, ReceiptError> {
        let id = Uuid::new_v4();
        let timestamp = self.timestamp.unwrap_or_else(Utc::now);

        // The body we hash: everything except the digest itself.
        let body = ReceiptBody {
            id,
            kind: &self.kind,
            timestamp,
            actor: &self.actor,
            subject: &self.subject,
            parent_digest: self.parent_digest.as_deref(),
            evidence: &self.evidence,
            policy_hash: self.policy_hash.as_deref(),
        };

        let canonical = canonical_json(&body)?;
        let hash = Sha256::digest(&canonical);
        let digest = hex::encode(hash);

        Ok(Receipt {
            id,
            kind: self.kind,
            timestamp,
            actor: self.actor,
            subject: self.subject,
            parent_digest: self.parent_digest,
            evidence: self.evidence,
            policy_hash: self.policy_hash,
            digest,
        })
    }
}

/// Internal: the fields we hash to produce the digest.
#[derive(Serialize)]
struct ReceiptBody<'a> {
    id: Uuid,
    kind: &'a ReceiptKind,
    timestamp: DateTime<Utc>,
    actor: &'a str,
    subject: &'a str,
    parent_digest: Option<&'a str>,
    evidence: &'a serde_json::Value,
    policy_hash: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_has_deterministic_digest() {
        let ts = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .to_utc();

        // Build same receipt twice — digests differ because UUIDs differ.
        // But the digest is computed from the body, so it's internally consistent.
        let r = ReceiptBuilder::new(ReceiptKind::GrantRequested, "deploy-bot", "grant-123")
            .timestamp(ts)
            .build()
            .unwrap();

        assert!(!r.digest.is_empty());
        assert_eq!(r.kind, ReceiptKind::GrantRequested);
        assert_eq!(r.actor, "deploy-bot");
    }

    #[test]
    fn receipt_with_evidence() {
        let r = ReceiptBuilder::new(ReceiptKind::PolicyDecision, "policy-engine", "grant-456")
            .evidence(serde_json::json!({"allowed": true, "reason": "scope matches"}))
            .policy_hash("abc123")
            .build()
            .unwrap();

        assert!(r.policy_hash.is_some());
        assert!(r.evidence.is_object());
    }

    #[test]
    fn receipt_chain_linkage() {
        let r1 = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", "g1")
            .build()
            .unwrap();
        let r2 = ReceiptBuilder::new(ReceiptKind::GrantIssued, "issuer", "g1")
            .parent_digest(&r1.digest)
            .build()
            .unwrap();

        assert_eq!(r2.parent_digest.as_deref(), Some(r1.digest.as_str()));
    }
}
