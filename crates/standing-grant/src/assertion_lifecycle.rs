//! Assertion-grant lease state machine (Phase 4b).
//!
//! Mirrors [`crate::lifecycle::GrantMachine`] one-for-one, plus a repeatable
//! `spend` verb the single-use act machine has no analog for. Every verb emits a
//! receipt onto the chain; the chain is the ground truth. This is the in-process
//! constructor for the request→issue flow — the persistence + concurrency path
//! lives in `standing-store` (`spend_assertion`/`transition_assertion`), which
//! shares the same predicate helpers in [`crate::assertion`] so the two can
//! never diverge.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use standing_receipt::{Receipt, ReceiptBuilder, ReceiptChain, ReceiptKind};

use crate::assertion::{
    ASSERTION_MADE_VERSION, AssertCoverage, AssertionGrant, AssertionGrantRequest,
    AssertionGrantState, AssertionScope, RequestProof, WindowState, assertion_covers,
};
use crate::error::GrantError;
use crate::principal::Principal;

/// State machine for a single assertion lease's lifecycle.
pub struct AssertionGrantMachine {
    pub grant: Option<AssertionGrant>,
    pub state: AssertionGrantState,
    pub chain: ReceiptChain,
    grant_id: Uuid,
}

impl AssertionGrantMachine {
    /// Start a new lease lifecycle from a request. Emits `AssertionGrantRequested`.
    pub fn request(req: &AssertionGrantRequest) -> Result<Self, GrantError> {
        Self::request_rooted(req, None)
    }

    /// Like [`AssertionGrantMachine::request`], but cryptographically roots the
    /// chain's first receipt at the instance genesis (see
    /// `GrantMachine::request_rooted`). Assertion issuance already *cites* the
    /// genesis as `settlement_witness`; this makes the request receipt a real
    /// `parent_digest` link so the chain walk terminates AT genesis.
    pub fn request_rooted(
        req: &AssertionGrantRequest,
        genesis_digest: Option<&str>,
    ) -> Result<Self, GrantError> {
        let grant_id = Uuid::new_v4();
        let subject = grant_id.to_string();

        let mut builder = ReceiptBuilder::new(
            ReceiptKind::AssertionGrantRequested,
            &req.actor.id,
            &subject,
        )
        .evidence(serde_json::json!({
            "actor": { "id": req.actor.id, "label": req.actor.label },
            "scope": {
                "claim_kind": req.scope.claim_kind,
                "subject_scope": req.scope.subject_scope,
                "audience": req.scope.audience,
            },
            "not_before": req.not_before.to_rfc3339(),
            "duration_secs": req.duration_secs,
            "max_uses": req.max_uses,
            "context": req.context,
        }));
        if let Some(g) = genesis_digest {
            builder = builder.parent_digest(g);
        }
        let receipt = builder.build().map_err(GrantError::Receipt)?;

        let chain = ReceiptChain::new(receipt);
        Ok(Self {
            grant: None,
            state: AssertionGrantState::Requested,
            chain,
            grant_id,
        })
    }

    /// Issue the lease (policy approved). Transitions Requested → Issued.
    ///
    /// `genesis_digest` is the instance's genesis receipt digest — the prior
    /// settlement-witness (Lean L4). It is required and must be non-empty:
    /// no lease minting without a witnessed root. The `AssertionGrantIssued`
    /// evidence binds the FULL terms so scope cannot be widened later (L3/L4).
    pub fn issue(
        &mut self,
        issuer: &Principal,
        genesis_digest: &str,
        policy_hash: &str,
        evidence: serde_json::Value,
    ) -> Result<&Receipt, GrantError> {
        self.require_state(&AssertionGrantState::Requested)?;
        if genesis_digest.is_empty() {
            return Err(GrantError::NoGenesis);
        }
        if issuer.id == self.actor_id() {
            return Err(GrantError::AssertionSelfGrant(issuer.id.clone()));
        }

        let req = self.request_from_chain();
        let issued_at = Utc::now();
        let expires_at = req.not_before + Duration::seconds(req.duration_secs as i64);

        let grant = AssertionGrant {
            id: self.grant_id,
            actor: req.actor.clone(),
            scope: req.scope.clone(),
            not_before: req.not_before,
            issued_at,
            expires_at,
            max_uses: req.max_uses,
            spend_count: 0,
        };

        let receipt = ReceiptBuilder::new(
            ReceiptKind::AssertionGrantIssued,
            &issuer.id,
            self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .policy_hash(policy_hash)
        .evidence(serde_json::json!({
            // Full terms, content-addressed — scope cannot be widened under
            // this digest later (L4 mutated_terms_rejected).
            "terms": {
                "claim_kind": grant.scope.claim_kind,
                "subject_scope": grant.scope.subject_scope,
                "audience": grant.scope.audience,
                "not_before": grant.not_before.to_rfc3339(),
                "expires_at": grant.expires_at.to_rfc3339(),
                "max_uses": grant.max_uses,
            },
            "settlement_witness": genesis_digest,  // prior witness (L4)
            "operator_id": issuer.id,
            "detail": evidence,
        }))
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.grant = Some(grant);
        self.state = AssertionGrantState::Issued;
        Ok(self.chain.tip())
    }

    /// Deny the lease (policy rejected). Transitions Requested → Denied.
    pub fn deny(
        &mut self,
        policy_hash: &str,
        evidence: serde_json::Value,
    ) -> Result<&Receipt, GrantError> {
        self.require_state(&AssertionGrantState::Requested)?;
        let receipt = ReceiptBuilder::new(
            ReceiptKind::AssertionGrantDenied,
            self.actor_id(),
            self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .policy_hash(policy_hash)
        .evidence(evidence)
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = AssertionGrantState::Denied;
        Ok(self.chain.tip())
    }

    /// Activate the lease. Transitions Issued → Active.
    pub fn activate(&mut self, now: DateTime<Utc>) -> Result<&Receipt, GrantError> {
        self.require_state(&AssertionGrantState::Issued)?;
        self.check_window(now)?;

        let receipt = ReceiptBuilder::new(
            ReceiptKind::AssertionGrantActivated,
            self.actor_id(),
            self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = AssertionGrantState::Active;
        Ok(self.chain.tip())
    }

    /// Spend the lease once (the `Active → Active` self-loop). Checks window +
    /// coverage + budget (all via the shared [`crate::assertion`] predicates),
    /// then emits an `AssertionMade` receipt that CITES the issuance receipt as
    /// its authority (L3 — it is spend-accounting residue, not a fresh witness).
    ///
    /// Replay defense is NOT here — the single-use `jti` ledger needs the store.
    /// The store's `spend_assertion` runs this same check set plus replay + CAS.
    pub fn spend(
        &mut self,
        proof: &RequestProof,
        now: DateTime<Utc>,
    ) -> Result<&Receipt, GrantError> {
        self.require_state(&AssertionGrantState::Active)?;
        let grant = self
            .grant
            .as_ref()
            .expect("Active lease has a grant")
            .clone();

        // Coverage (names the failing axis for the basis).
        if proof.actor != grant.actor.id {
            return Err(GrantError::OutOfScope {
                axis: "actor_mismatch".into(),
            });
        }
        match assertion_covers(
            &grant.scope,
            &proof.claim_kind,
            &proof.subject_id,
            &proof.audience,
        ) {
            AssertCoverage::Covered => {}
            AssertCoverage::ClaimKindMismatch => {
                return Err(GrantError::OutOfScope {
                    axis: "claim_kind_out_of_scope".into(),
                });
            }
            AssertCoverage::SubjectMismatch => {
                return Err(GrantError::OutOfScope {
                    axis: "subject_out_of_scope".into(),
                });
            }
            AssertCoverage::AudienceMismatch => {
                return Err(GrantError::OutOfScope {
                    axis: "audience_mismatch".into(),
                });
            }
        }

        // Window (checked at spend time — L2).
        self.check_window(now)?;

        // Budget (L1). An exhausted lease refuses; the caller drives it to the
        // terminal Exhausted state via `exhaust()`.
        if grant.is_exhausted() {
            return Err(GrantError::BudgetExhausted {
                max_uses: grant.max_uses.unwrap_or(0),
            });
        }

        let issuance_digest = self.issuance_digest().unwrap_or_default();
        let new_seq = grant.spend_count + 1;

        let receipt = ReceiptBuilder::new(
            ReceiptKind::AssertionMade,
            &grant.actor.id,
            self.grant_id.to_string(),
        )
        .parent_digest(self.chain.tip().digest.clone())
        .evidence(serde_json::json!({
            "version": ASSERTION_MADE_VERSION,
            "proof": proof.canonical_body(),   // the fixed signed body (amendment #4)
            "spend_seq": new_seq,
            "authority": issuance_digest,        // cites the prior witness (L3)
        }))
        .build()
        .map_err(GrantError::Receipt)?;

        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        if let Some(g) = self.grant.as_mut() {
            g.spend_count = new_seq;
        }
        Ok(self.chain.tip())
    }

    /// Revoke the lease. Transitions Issued|Active → Revoked.
    pub fn revoke(&mut self, reason: &str) -> Result<&Receipt, GrantError> {
        self.require_non_terminal_lease()?;
        self.emit_terminal(
            AssertionGrantState::Revoked,
            ReceiptKind::AssertionGrantRevoked,
            serde_json::json!({ "reason": reason }),
        )
    }

    /// Expire the lease. Transitions Issued|Active → Expired.
    pub fn expire(&mut self) -> Result<&Receipt, GrantError> {
        self.require_non_terminal_lease()?;
        self.emit_terminal(
            AssertionGrantState::Expired,
            ReceiptKind::AssertionGrantExpired,
            serde_json::Value::Null,
        )
    }

    /// Mark the lease exhausted (use budget hit). Transitions Active → Exhausted.
    pub fn exhaust(&mut self) -> Result<&Receipt, GrantError> {
        if self.state != AssertionGrantState::Active {
            return Err(GrantError::InvalidTransition {
                from: self.state.to_string(),
                to: "exhausted".to_string(),
            });
        }
        let max_uses = self.grant.as_ref().and_then(|g| g.max_uses).unwrap_or(0);
        self.emit_terminal(
            AssertionGrantState::Exhausted,
            ReceiptKind::AssertionGrantExhausted,
            serde_json::json!({ "max_uses": max_uses }),
        )
    }

    pub fn grant_id(&self) -> Uuid {
        self.grant_id
    }

    // -- helpers ---------------------------------------------------------

    fn emit_terminal(
        &mut self,
        target: AssertionGrantState,
        kind: ReceiptKind,
        evidence: serde_json::Value,
    ) -> Result<&Receipt, GrantError> {
        let receipt = ReceiptBuilder::new(kind, self.actor_id(), self.grant_id.to_string())
            .parent_digest(self.chain.tip().digest.clone())
            .evidence(evidence)
            .build()
            .map_err(GrantError::Receipt)?;
        self.chain.append(receipt).map_err(GrantError::Receipt)?;
        self.state = target;
        Ok(self.chain.tip())
    }

    fn check_window(&self, now: DateTime<Utc>) -> Result<(), GrantError> {
        if let Some(grant) = &self.grant {
            match grant.window_state(now, Duration::zero()) {
                WindowState::Within => Ok(()),
                WindowState::NotYetValid => Err(GrantError::NotYetValid {
                    not_before: grant.not_before.to_rfc3339(),
                }),
                WindowState::Expired => Err(GrantError::Expired {
                    expired_at: grant.expires_at.to_rfc3339(),
                }),
                WindowState::Incoherent => Err(GrantError::WindowIncoherent),
            }
        } else {
            Ok(())
        }
    }

    fn actor_id(&self) -> &str {
        &self.chain.receipts()[0].actor
    }

    fn issuance_digest(&self) -> Option<String> {
        self.chain
            .receipts()
            .iter()
            .find(|r| r.kind == ReceiptKind::AssertionGrantIssued)
            .map(|r| r.digest.clone())
    }

    /// Reconstruct the request from the first receipt's evidence (mirrors the
    /// act-grant `subject_from_chain`/`scope_from_chain` idiom).
    fn request_from_chain(&self) -> AssertionGrantRequest {
        let e = &self.chain.receipts()[0].evidence;
        let actor = Principal {
            id: e["actor"]["id"]
                .as_str()
                .unwrap_or(self.actor_id())
                .to_string(),
            label: e["actor"]["label"].as_str().unwrap_or("").to_string(),
        };
        let scope = AssertionScope {
            claim_kind: e["scope"]["claim_kind"].as_str().unwrap_or("").to_string(),
            subject_scope: e["scope"]["subject_scope"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            audience: e["scope"]["audience"].as_str().unwrap_or("").to_string(),
        };
        let not_before = e["not_before"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.to_utc())
            .unwrap_or_else(Utc::now);
        let duration_secs = e["duration_secs"].as_u64().unwrap_or(0);
        let max_uses = e["max_uses"].as_u64();
        AssertionGrantRequest {
            actor,
            scope,
            not_before,
            duration_secs,
            max_uses,
            context: e["context"].clone(),
        }
    }

    fn require_state(&self, expected: &AssertionGrantState) -> Result<(), GrantError> {
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

    fn require_non_terminal_lease(&self) -> Result<(), GrantError> {
        if self.state != AssertionGrantState::Issued && self.state != AssertionGrantState::Active {
            return Err(GrantError::InvalidTransition {
                from: self.state.to_string(),
                to: "(revoke/expire requires issued or active)".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assertion::AssertionScope;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().to_utc()
    }

    fn req(max_uses: Option<u64>) -> AssertionGrantRequest {
        AssertionGrantRequest {
            actor: Principal::new("component:nq:linode", "nq@linode"),
            scope: AssertionScope {
                claim_kind: "sqlite_wal_state".into(),
                subject_scope: "labelwatch/*".into(),
                audience: "nq:main".into(),
            },
            // Wide-open past→future window so `Utc::now()` at spend is Within.
            not_before: t("2000-01-01T00:00:00Z"),
            duration_secs: 100 * 365 * 24 * 3600,
            max_uses,
            context: serde_json::json!({}),
        }
    }

    fn proof(grant_id: Uuid, jti: &str, subject_id: &str) -> RequestProof {
        RequestProof {
            grant_id,
            actor: "component:nq:linode".into(),
            claim_kind: "sqlite_wal_state".into(),
            subject_id: subject_id.into(),
            audience: "nq:main".into(),
            jti: jti.into(),
            body_digest: Some("deadbeef".into()),
            issued_at: Utc::now(),
        }
    }

    fn operator() -> Principal {
        Principal::new("wl:operator:laptop", "operator")
    }

    #[test]
    fn happy_path_lease_with_reuse() {
        let mut m = AssertionGrantMachine::request(&req(Some(3))).unwrap();
        assert_eq!(m.state, AssertionGrantState::Requested);
        m.issue(
            &operator(),
            "genesis-digest",
            "policy-hash",
            serde_json::json!({"ok": true}),
        )
        .unwrap();
        assert_eq!(m.state, AssertionGrantState::Issued);
        let issued = m.chain.tip();
        assert_eq!(issued.actor, "wl:operator:laptop");
        assert_eq!(issued.evidence["operator_id"], "wl:operator:laptop");
        m.activate(Utc::now()).unwrap();
        assert_eq!(m.state, AssertionGrantState::Active);

        // Spend three times — the lease stays Active (reuse).
        let gid = m.grant_id();
        for i in 0..3 {
            m.spend(
                &proof(gid, &format!("jti-{i}"), "labelwatch/foo"),
                Utc::now(),
            )
            .unwrap();
            assert_eq!(m.state, AssertionGrantState::Active);
        }
        assert_eq!(m.grant.as_ref().unwrap().spend_count, 3);
        m.chain.verify().unwrap();
    }

    #[test]
    fn issue_without_genesis_fails_closed() {
        let mut m = AssertionGrantMachine::request(&req(None)).unwrap();
        assert!(matches!(
            m.issue(&operator(), "", "p", serde_json::json!(null)),
            Err(GrantError::NoGenesis)
        ));
    }

    #[test]
    fn speaker_cannot_issue_its_own_lease() {
        let mut m = AssertionGrantMachine::request(&req(None)).unwrap();
        let speaker = Principal::new("component:nq:linode", "nq@linode");
        assert!(matches!(
            m.issue(&speaker, "g", "p", serde_json::json!(null)),
            Err(GrantError::AssertionSelfGrant(_))
        ));
        assert_eq!(m.state, AssertionGrantState::Requested);
        assert_eq!(m.chain.len(), 1, "refused self-grant must emit no receipt");
    }

    #[test]
    fn budget_exhaustion_refuses_then_exhausts() {
        let mut m = AssertionGrantMachine::request(&req(Some(1))).unwrap();
        m.issue(&operator(), "g", "p", serde_json::json!(null))
            .unwrap();
        m.activate(Utc::now()).unwrap();
        let gid = m.grant_id();
        m.spend(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now())
            .unwrap();
        // Budget of 1 is now spent — next spend refuses.
        assert!(matches!(
            m.spend(&proof(gid, "jti-1", "labelwatch/foo"), Utc::now()),
            Err(GrantError::BudgetExhausted { max_uses: 1 })
        ));
        m.exhaust().unwrap();
        assert_eq!(m.state, AssertionGrantState::Exhausted);
        assert!(m.state.is_terminal());
    }

    #[test]
    fn out_of_scope_subject_refused() {
        let mut m = AssertionGrantMachine::request(&req(None)).unwrap();
        m.issue(&operator(), "g", "p", serde_json::json!(null))
            .unwrap();
        m.activate(Utc::now()).unwrap();
        let gid = m.grant_id();
        assert!(matches!(
            m.spend(&proof(gid, "jti-0", "other/foo"), Utc::now()),
            Err(GrantError::OutOfScope { .. })
        ));
    }

    #[test]
    fn cannot_spend_before_active() {
        let mut m = AssertionGrantMachine::request(&req(None)).unwrap();
        m.issue(&operator(), "g", "p", serde_json::json!(null))
            .unwrap();
        let gid = m.grant_id();
        assert!(
            m.spend(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now())
                .is_err()
        );
    }

    #[test]
    fn revoke_is_terminal() {
        let mut m = AssertionGrantMachine::request(&req(None)).unwrap();
        m.issue(&operator(), "g", "p", serde_json::json!(null))
            .unwrap();
        m.activate(Utc::now()).unwrap();
        m.revoke("incident").unwrap();
        assert_eq!(m.state, AssertionGrantState::Revoked);
        let gid = m.grant_id();
        assert!(
            m.spend(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now())
                .is_err()
        );
    }

    #[test]
    fn not_yet_valid_window_refused_at_activate() {
        let mut r = req(None);
        r.not_before = t("2099-01-01T00:00:00Z");
        r.duration_secs = 3600;
        let mut m = AssertionGrantMachine::request(&r).unwrap();
        m.issue(&operator(), "g", "p", serde_json::json!(null))
            .unwrap();
        assert!(matches!(
            m.activate(Utc::now()),
            Err(GrantError::NotYetValid { .. })
        ));
    }
}
