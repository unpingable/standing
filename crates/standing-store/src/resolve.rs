//! Store-backed resolution of the assertion-standing preflight (Phase 4b).
//!
//! The pure door `standing_policy::preflight::check_assert` answers only the
//! *effect gate* — "does this effect need assert-standing at all?" — and, for
//! binding/mutating effects, returns `RequiredNotImplemented`. This module fills
//! that hole with a store lookup, upgrading the decision to
//! `RequiredAndAvailable` / `RequiredButDenied`. The pure door is untouched.
//!
//! ## Preview vs spend (amendment #2 — the anti-laundering seam)
//!
//! [`Store::resolve_assert_preview`] is a **dry run**: it checks scope + window +
//! budget WITHOUT recording a replay nonce or emitting a receipt. It returns
//! `authorizes_effect = false` — "would be available," never "is granted."
//! [`Store::resolve_assert_spend`] is the **real** path: it runs
//! `spend_assertion` (recording the `jti`, emitting an `AssertionMade`) and only
//! then returns `authorizes_effect = true` with the receipt digest. A consumer
//! about to bind/mutate MUST use the spend path.

use chrono::{DateTime, Duration, Utc};

use standing_grant::{
    assertion_covers, AssertCoverage, AssertionGrant, AssertionGrantState, AssertionScope,
    Principal, RequestProof, WindowState,
};
use standing_policy::preflight::{
    assert_basis, check_assert, AssertCheckDecision, AssertCheckRequest, AssertCheckResult,
};
use standing_policy::resolver::basis;

use crate::{AssertionGrantRow, Store, StoreError};

impl Store {
    /// Dry-run resolution: check whether a lease *would* cover this request,
    /// without consuming anything. `authorizes_effect` is always `false`.
    pub fn resolve_assert_preview(
        &self,
        request: &AssertCheckRequest,
        proof: &RequestProof,
        now: DateTime<Utc>,
    ) -> Result<AssertCheckResult, StoreError> {
        let door = self.door(request)?;
        if !matches!(door.decision, AssertCheckDecision::RequiredNotImplemented) {
            // NotRequired (or any non-refusal) passes through verbatim.
            return Ok(door);
        }
        match self.dry_check_assertion(proof, now) {
            Ok(row) => Ok(self.available(door, &row, "preview", false, None)),
            Err(e) => Ok(self.denied(door, &e)),
        }
    }

    /// Real resolution: spend the lease (record replay nonce, emit
    /// `AssertionMade`). Only this path returns an authorizing decision.
    pub fn resolve_assert_spend(
        &mut self,
        request: &AssertCheckRequest,
        proof: &RequestProof,
        now: DateTime<Utc>,
    ) -> Result<AssertCheckResult, StoreError> {
        let door = self.door(request)?;
        if !matches!(door.decision, AssertCheckDecision::RequiredNotImplemented) {
            return Ok(door);
        }
        // Read the lease first so we can report its reuse posture even if the
        // spend then refuses for another reason.
        let row = self.get_assertion_grant(&proof.grant_id.to_string())?;
        match self.spend_assertion(proof, now) {
            Ok(result) => {
                let row = row.ok_or_else(|| {
                    StoreError::AssertionGrantNotFound(proof.grant_id.to_string())
                })?;
                Ok(self.available(door, &row, "spend", true, Some(result.receipt_digest)))
            }
            Err(e) => Ok(self.denied(door, &e)),
        }
    }

    /// Run the pure door with this instance's genesis + policy hash cited.
    fn door(&self, request: &AssertCheckRequest) -> Result<AssertCheckResult, StoreError> {
        let genesis = self.get_genesis()?;
        let (gen_digest, policy_hash) = match genesis {
            Some(g) => (Some(g.digest), g.policy_hash),
            None => (None, None),
        };
        Ok(check_assert(request, gen_digest.as_deref(), policy_hash.as_deref()))
    }

    /// Build a `RequiredAndAvailable` result from the door template.
    fn available(
        &self,
        door: AssertCheckResult,
        row: &AssertionGrantRow,
        mode: &str,
        authorizes: bool,
        receipt_digest: Option<String>,
    ) -> AssertCheckResult {
        // Reuse posture (L1): an unbounded lease is honestly stamped.
        let (reuse_bound, certified_sound) = match row.max_uses {
            None => (Some("unbounded_kind_scope".to_string()), Some(false)),
            Some(_) => (None, Some(true)),
        };
        let mut why = door.why;
        why.note = if authorizes {
            "Lease covers this request and it is fresh (scope + within-validity + \
             not-replayed + budget). Effect AUTHORIZED under a recorded AssertionMade \
             receipt. NOTE: freshness is within_validity only — no per-request MAC or \
             clock-divergence check yet (Phase 5); binding mode trusts the transport."
                .to_string()
        } else {
            "Lease WOULD cover this request (scope + within-validity + budget). This is a \
             PREVIEW — nothing was recorded and no effect is authorized. Call the spend \
             path to actually assert."
                .to_string()
        };
        AssertCheckResult {
            decision: AssertCheckDecision::RequiredAndAvailable,
            reason: assert_basis::ASSERTION_AVAILABLE.to_string(),
            authorizes_effect: authorizes,
            decision_mode: Some(mode.to_string()),
            emitted_receipt_digest: receipt_digest,
            reuse_bound,
            certified_sound,
            freshness: Some("within_validity".to_string()),
            why,
            ..door
        }
    }

    /// Build a `RequiredButDenied` result from a refusal.
    fn denied(&self, door: AssertCheckResult, err: &StoreError) -> AssertCheckResult {
        let (basis_str, note) = refusal_basis(err);
        let mut why = door.why;
        why.note = note;
        AssertCheckResult {
            decision: AssertCheckDecision::RequiredButDenied,
            reason: basis_str,
            authorizes_effect: false,
            decision_mode: Some("resolved".to_string()),
            emitted_receipt_digest: None,
            reuse_bound: None,
            certified_sound: None,
            freshness: None,
            why,
            ..door
        }
    }

    /// Find an active, in-window, budget-remaining, unfrozen lease for this
    /// actor+audience whose scope covers `(claim_kind, subject_id)`. The
    /// by-coordinates lookup a `StandingResolver` needs (its `StandingRequest`
    /// carries no grant id). Returns the first match.
    pub fn find_active_assertion_lease(
        &self,
        actor: &str,
        audience: &str,
        claim_kind: &str,
        subject_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AssertionGrantRow>, StoreError> {
        // A freeze over the class means no lease is usable — respect it here too.
        if self.active_freeze_for(claim_kind, actor, audience, now)?.is_some() {
            return Ok(None);
        }
        for row in self.list_assertion_grants(None, Some(audience))? {
            if !matches!(row.state.as_str(), "active" | "issued") {
                continue;
            }
            if row.actor != actor {
                continue;
            }
            let grant = match row_to_grant(&row) {
                Ok(g) => g,
                Err(_) => continue,
            };
            if !matches!(
                assertion_covers(&grant.scope, claim_kind, subject_id, audience),
                AssertCoverage::Covered
            ) {
                continue;
            }
            if !matches!(grant.window_state(now, Duration::zero()), WindowState::Within) {
                continue;
            }
            if grant.is_exhausted() {
                continue;
            }
            return Ok(Some(row));
        }
        Ok(None)
    }

    /// Read-only coverage/window/budget check — the preview's engine. Runs the
    /// same predicates as `spend_assertion` but touches nothing (no replay, no
    /// receipt). Cannot promise not-replayed; that's the spend path's job.
    fn dry_check_assertion(
        &self,
        proof: &RequestProof,
        now: DateTime<Utc>,
    ) -> Result<AssertionGrantRow, StoreError> {
        // Policy freeze applies to preview too, so a dry run reflects it.
        if let Some(f) = self.active_freeze_for(&proof.claim_kind, &proof.actor, &proof.audience, now)? {
            return Err(StoreError::ClassFrozen { handle: f.handle, reason: f.reason });
        }

        let row = self
            .get_assertion_grant(&proof.grant_id.to_string())?
            .ok_or_else(|| StoreError::AssertionGrantNotFound(proof.grant_id.to_string()))?;

        let state = AssertionGrantState::from_str(&row.state).ok_or_else(|| {
            StoreError::InvalidTransition { from: row.state.clone(), to: "active".into() }
        })?;
        match state {
            AssertionGrantState::Active | AssertionGrantState::Issued => {}
            AssertionGrantState::Exhausted => {
                return Err(StoreError::AssertionBudgetExhausted {
                    max_uses: row.max_uses.unwrap_or(0),
                })
            }
            other => {
                return Err(StoreError::InvalidTransition {
                    from: other.to_string(),
                    to: "active (spend)".into(),
                })
            }
        }

        let grant = row_to_grant(&row)?;
        if proof.actor != grant.actor.id {
            return Err(StoreError::AssertionOutOfScope { axis: "actor_mismatch".into() });
        }
        match assertion_covers(&grant.scope, &proof.claim_kind, &proof.subject_id, &proof.audience) {
            AssertCoverage::Covered => {}
            AssertCoverage::ClaimKindMismatch => {
                return Err(StoreError::AssertionOutOfScope { axis: "claim_kind_out_of_scope".into() })
            }
            AssertCoverage::SubjectMismatch => {
                return Err(StoreError::AssertionOutOfScope { axis: "subject_out_of_scope".into() })
            }
            AssertCoverage::AudienceMismatch => {
                return Err(StoreError::AssertionOutOfScope { axis: "audience_mismatch".into() })
            }
        }
        match grant.window_state(now, Duration::zero()) {
            WindowState::Within => {}
            WindowState::NotYetValid => {
                return Err(StoreError::AssertionNotYetValid(grant.not_before.to_rfc3339()))
            }
            WindowState::Expired => {
                return Err(StoreError::AssertionWindowClosed(grant.expires_at.to_rfc3339()))
            }
            WindowState::Incoherent => return Err(StoreError::AssertionWindowIncoherent),
        }
        if grant.is_exhausted() {
            return Err(StoreError::AssertionBudgetExhausted { max_uses: grant.max_uses.unwrap_or(0) });
        }
        Ok(row)
    }
}

/// Rebuild an [`AssertionGrant`] from a returned row. Fail-closed on
/// missing/unparseable window bounds (L2), same discipline as the tx path.
fn row_to_grant(row: &AssertionGrantRow) -> Result<AssertionGrant, StoreError> {
    let parse = |o: &Option<String>| -> Result<DateTime<Utc>, StoreError> {
        o.as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.to_utc())
            .ok_or(StoreError::AssertionWindowIncoherent)
    };
    let not_before = parse(&row.not_before)?;
    let expires_at = parse(&row.expires_at)?;
    let issued_at = parse(&row.issued_at).unwrap_or(not_before);
    Ok(AssertionGrant {
        id: uuid::Uuid::parse_str(&row.id).unwrap_or_else(|_| uuid::Uuid::nil()),
        actor: Principal::new(row.actor.clone(), row.actor.clone()),
        scope: AssertionScope {
            claim_kind: row.claim_kind.clone(),
            subject_scope: row.subject_scope.clone(),
            audience: row.audience.clone(),
        },
        not_before,
        issued_at,
        expires_at,
        max_uses: row.max_uses,
        spend_count: row.spend_count,
    })
}

/// Map a store refusal to a `(standing_basis, operator note)` pair. Basis
/// strings come from the shared refusal vocabulary in
/// `standing_policy::resolver::basis` where one exists.
fn refusal_basis(err: &StoreError) -> (String, String) {
    match err {
        StoreError::AssertionGrantNotFound(_) => (
            assert_basis::NO_COVERING_LEASE.to_string(),
            "No assertion lease covers this actor for this request.".to_string(),
        ),
        StoreError::AssertionOutOfScope { axis } => {
            (axis.clone(), format!("Request falls outside the lease scope: {axis}."))
        }
        StoreError::AssertionWindowClosed(at) => (
            basis::STANDING_EXPIRED.to_string(),
            format!("Lease window closed (expired at {at})."),
        ),
        StoreError::AssertionNotYetValid(nb) => (
            basis::GRANT_NOT_YET_VALID.to_string(),
            format!("Lease not yet valid (not_before {nb})."),
        ),
        StoreError::AssertionWindowIncoherent => (
            "window_incoherent".to_string(),
            "Lease window is incoherent or its stored timestamps are unparseable; refused."
                .to_string(),
        ),
        StoreError::AssertionBudgetExhausted { max_uses } => (
            "use_budget_exhausted".to_string(),
            format!("Lease use budget exhausted (max_uses {max_uses}); re-witness required."),
        ),
        StoreError::ReplayDetected { jti, .. } => (
            basis::REPLAY_DETECTED.to_string(),
            format!("Replay detected: jti {jti} already seen for this audience."),
        ),
        StoreError::ClassFrozen { handle, reason } => (
            format!("class_frozen:{handle}"),
            format!("Class frozen by policy: {reason} (freeze {handle})."),
        ),
        StoreError::AssertionMacInvalid => (
            "assertion_mac_invalid".to_string(),
            "Per-request proof MAC is invalid or missing.".to_string(),
        ),
        StoreError::ClockSkewExceeded(s) => (
            basis::CLOCK_SKEW_EXCEEDED.to_string(),
            format!("Proof issued_at is {s}s in the future beyond tolerance."),
        ),
        StoreError::RequestTimestampOutOfWindow(s) => (
            basis::REQUEST_TIMESTAMP_OUT_OF_WINDOW.to_string(),
            format!("Proof timestamp is {s}s old, beyond the freshness window."),
        ),
        other => (
            basis::DENY_DEFAULT.to_string(),
            format!("Assertion refused: {other}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use standing_grant::AssertionGrantState;
    use standing_policy::preflight::EffectClass;
    use standing_receipt::{ReceiptBuilder, ReceiptKind};
    use uuid::Uuid;

    use crate::AssertionGrantMeta;

    const ACTOR: &str = "component:nq:linode";

    fn issued_lease(store: &mut Store, max_uses: Option<u64>) -> Uuid {
        let gid = Uuid::new_v4();
        let subject = gid.to_string();
        let nb = Utc::now() - Duration::days(1);
        let exp = Utc::now() + Duration::days(365);
        let m = |issued: bool| AssertionGrantMeta {
            actor: ACTOR.into(),
            claim_kind: "sqlite_wal_state".into(),
            subject_scope: "labelwatch/*".into(),
            audience: "nq:main".into(),
            not_before: Some(nb),
            issued_at: Some(nb),
            expires_at: if issued { Some(exp) } else { None },
            max_uses,
        };
        let r1 = ReceiptBuilder::new(ReceiptKind::AssertionGrantRequested, ACTOR, &subject)
            .evidence(serde_json::json!({})).build().unwrap();
        store.record_assertion_transition(gid, &AssertionGrantState::Requested, &r1, Some(m(false))).unwrap();
        let r2 = ReceiptBuilder::new(ReceiptKind::AssertionGrantIssued, ACTOR, &subject)
            .parent_digest(r1.digest.clone()).evidence(serde_json::json!({})).build().unwrap();
        store.record_assertion_transition(gid, &AssertionGrantState::Issued, &r2, Some(m(true))).unwrap();
        gid
    }

    fn request() -> AssertCheckRequest {
        AssertCheckRequest::new(ACTOR, "nq:main", "sqlite_wal_state", "labelwatch/foo", EffectClass::Binding).unwrap()
    }

    fn proof(gid: Uuid, jti: &str) -> RequestProof {
        RequestProof {
            grant_id: gid,
            actor: ACTOR.into(),
            claim_kind: "sqlite_wal_state".into(),
            subject_id: "labelwatch/foo".into(),
            audience: "nq:main".into(),
            jti: jti.into(),
            body_digest: Some("dead".into()),
            issued_at: Utc::now(),
        }
    }

    #[test]
    fn preview_never_authorizes_and_never_consumes() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, Some(5));
        let r = store.resolve_assert_preview(&request(), &proof(gid, "jti-preview"), Utc::now()).unwrap();
        assert_eq!(r.decision, AssertCheckDecision::RequiredAndAvailable);
        assert!(!r.authorizes_effect, "preview MUST NOT authorize");
        assert_eq!(r.decision_mode.as_deref(), Some("preview"));
        assert!(r.emitted_receipt_digest.is_none());
        // Nothing consumed.
        assert_eq!(store.get_assertion_grant(&gid.to_string()).unwrap().unwrap().spend_count, 0);
    }

    #[test]
    fn spend_authorizes_and_emits_receipt() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, Some(5));
        let r = store.resolve_assert_spend(&request(), &proof(gid, "jti-spend"), Utc::now()).unwrap();
        assert_eq!(r.decision, AssertCheckDecision::RequiredAndAvailable);
        assert!(r.authorizes_effect, "spend authorizes");
        assert_eq!(r.decision_mode.as_deref(), Some("spend"));
        assert!(r.emitted_receipt_digest.is_some());
        assert_eq!(store.get_assertion_grant(&gid.to_string()).unwrap().unwrap().spend_count, 1);
    }

    #[test]
    fn unbounded_lease_is_stamped_not_certified_sound() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, None); // unbounded
        let r = store.resolve_assert_spend(&request(), &proof(gid, "jti-u"), Utc::now()).unwrap();
        assert!(r.authorizes_effect);
        assert_eq!(r.reuse_bound.as_deref(), Some("unbounded_kind_scope"));
        assert_eq!(r.certified_sound, Some(false));
    }

    #[test]
    fn replay_via_spend_is_denied() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, None);
        store.resolve_assert_spend(&request(), &proof(gid, "dup"), Utc::now()).unwrap();
        let r = store.resolve_assert_spend(&request(), &proof(gid, "dup"), Utc::now()).unwrap();
        assert_eq!(r.decision, AssertCheckDecision::RequiredButDenied);
        assert!(!r.authorizes_effect);
        assert_eq!(r.reason, basis::REPLAY_DETECTED);
    }

    #[test]
    fn descriptive_effect_passes_through_not_required() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, None);
        let req = AssertCheckRequest::new(ACTOR, "nq:main", "sqlite_wal_state", "labelwatch/foo", EffectClass::Descriptive).unwrap();
        let r = store.resolve_assert_spend(&req, &proof(gid, "jti-d"), Utc::now()).unwrap();
        assert_eq!(r.decision, AssertCheckDecision::NotRequired);
        assert!(!r.authorizes_effect);
        // Descriptive never touches the lease.
        assert_eq!(store.get_assertion_grant(&gid.to_string()).unwrap().unwrap().spend_count, 0);
    }
}
