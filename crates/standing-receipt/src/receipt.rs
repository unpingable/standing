use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::canonical::canonical_json;
use crate::error::ReceiptError;

/// Schema version of the receipt envelope. Folded into the content-address, so
/// a version bump changes every receipt's digest — a deliberate rebase, not a
/// silent migration. Mirrors the identity-claim precedent
/// (`standing_identity::SCHEMA_VERSION`). Unknown versions are refused by
/// [`Receipt::verify_integrity`].
pub const SCHEMA_VERSION: u32 = 1;

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
    /// An assertion lease was requested (entitlement-to-assert, Phase 4b)
    AssertionGrantRequested,
    /// An assertion lease was issued (policy said yes)
    AssertionGrantIssued,
    /// An assertion lease request was denied (policy said no)
    AssertionGrantDenied,
    /// An assertion lease was activated (first spend, or explicit activate)
    AssertionGrantActivated,
    /// An assertion lease expired (window closed)
    AssertionGrantExpired,
    /// An assertion lease was revoked (explicit revocation)
    AssertionGrantRevoked,
    /// An assertion lease hit its use budget (`spend_count == max_uses`), L1
    AssertionGrantExhausted,
    /// A single assertion was made under a lease (per-spend accounting residue).
    /// NOT the lease's witness — it cites the prior `AssertionGrantIssued`
    /// receipt as authority (L3: no retroactive standing).
    AssertionMade,
    /// A policy decision was made
    PolicyDecision,
    /// A policy-level freeze was installed over a grant class (incident mode).
    /// A deny-overlay, not a grant-record change. See docs/lifecycle-freeze.md.
    PolicyFrozen,
    /// A policy-level freeze was lifted (explicit thaw).
    PolicyThawed,
    /// The root of this Standing instance's receipt chain: the operator's
    /// citable fiat establishing initial policy. Exactly one per instance.
    /// `parent_digest` is always None; this is the named genesis the chain
    /// terminates at. See `docs/genesis-receipt.md`.
    GenesisInstall,
}

/// A receipt: content-addressed witness to an event.
///
/// Once built, a receipt is immutable. Its digest is computed from
/// the canonical JSON of its body (everything except the digest itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Envelope schema version. Folded into the digest; see [`SCHEMA_VERSION`].
    pub schema_version: u32,
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
            schema_version: SCHEMA_VERSION,
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
            schema_version: SCHEMA_VERSION,
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

impl Receipt {
    /// Recompute this receipt's content-address from its current field values.
    /// A tamper-evident check: if any hashed field was altered after `build`,
    /// this diverges from the stored `digest`.
    pub fn recompute_digest(&self) -> Result<String, ReceiptError> {
        let body = ReceiptBody {
            schema_version: self.schema_version,
            id: self.id,
            kind: &self.kind,
            timestamp: self.timestamp,
            actor: &self.actor,
            subject: &self.subject,
            parent_digest: self.parent_digest.as_deref(),
            evidence: &self.evidence,
            policy_hash: self.policy_hash.as_deref(),
        };
        let canonical = canonical_json(&body)?;
        Ok(hex::encode(Sha256::digest(&canonical)))
    }

    /// Verify integrity: the schema version is one this build understands, and
    /// the stored digest matches a fresh hash of the body. Fail-closed on an
    /// unknown version — an envelope we cannot re-hash faithfully is refused,
    /// not trusted.
    pub fn verify_integrity(&self) -> Result<(), ReceiptError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReceiptError::UnsupportedSchemaVersion {
                got: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        let recomputed = self.recompute_digest()?;
        if recomputed != self.digest {
            return Err(ReceiptError::DigestMismatch {
                expected: self.digest.clone(),
                actual: recomputed,
            });
        }
        Ok(())
    }
}

/// Internal: the fields we hash to produce the digest.
#[derive(Serialize)]
struct ReceiptBody<'a> {
    schema_version: u32,
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
    fn receipt_carries_schema_version_and_verifies_integrity() {
        let r = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", "g1")
            .build()
            .unwrap();
        assert_eq!(r.schema_version, SCHEMA_VERSION);
        // A freshly built receipt re-hashes to its stored digest.
        r.verify_integrity().unwrap();
        assert_eq!(r.recompute_digest().unwrap(), r.digest);
    }

    #[test]
    fn unknown_schema_version_refused() {
        let mut r = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", "g1")
            .build()
            .unwrap();
        r.schema_version = 999;
        assert!(matches!(
            r.verify_integrity(),
            Err(ReceiptError::UnsupportedSchemaVersion { got: 999, .. })
        ));
    }

    #[test]
    fn tampered_evidence_breaks_digest() {
        let mut r = ReceiptBuilder::new(ReceiptKind::PolicyDecision, "bot", "g1")
            .evidence(serde_json::json!({"allowed": true}))
            .build()
            .unwrap();
        // Mutate a hashed field without rebuilding — digest no longer matches.
        r.evidence = serde_json::json!({"allowed": false});
        assert!(matches!(
            r.verify_integrity(),
            Err(ReceiptError::DigestMismatch { .. })
        ));
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
