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
    AssertCoverage, AssertionGrant, AssertionGrantState, AssertionScope, Principal, RequestProof,
    WindowState, assertion_covers,
};
use standing_policy::preflight::{
    AssertCheckDecision, AssertCheckRequest, AssertCheckResult, assert_basis, check_assert,
};
use standing_policy::resolver::basis;

use crate::{AssertionGrantRow, Store, StoreError};

fn with_proof_echo(mut result: AssertCheckResult, proof: &RequestProof) -> AssertCheckResult {
    result.grant_id = Some(proof.grant_id.to_string());
    result.jti = Some(proof.jti.clone());
    result.body_digest = proof.body_digest.clone();
    result
}

fn request_proof_mismatch(
    request: &AssertCheckRequest,
    proof: &RequestProof,
) -> Option<&'static str> {
    if request.principal != proof.actor {
        Some("principal_actor")
    } else if request.consumer != proof.audience {
        Some("consumer_audience")
    } else if request.claim_kind != proof.claim_kind {
        Some("claim_kind")
    } else if request.target != proof.subject_id {
        Some("target_subject")
    } else {
        None
    }
}

fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl Store {
    /// Dry-run resolution: check whether a lease *would* cover this request,
    /// without consuming anything. `authorizes_effect` is always `false`.
    pub fn resolve_assert_preview(
        &self,
        request: &AssertCheckRequest,
        proof: &RequestProof,
        now: DateTime<Utc>,
    ) -> Result<AssertCheckResult, StoreError> {
        let door = with_proof_echo(self.door(request)?, proof);
        if !matches!(door.decision, AssertCheckDecision::RequiredNotImplemented) {
            // NotRequired (or any non-refusal) passes through verbatim.
            return Ok(door);
        }
        if let Some(axis) = request_proof_mismatch(request, proof) {
            return Ok(self.denied_with_basis(
                door,
                format!("{}:{axis}", assert_basis::REQUEST_PROOF_MISMATCH),
                format!(
                    "Preflight request and proof disagree on {axis}; refused before lease lookup."
                ),
                "preview",
            ));
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
        let door = with_proof_echo(self.door(request)?, proof);
        if !matches!(door.decision, AssertCheckDecision::RequiredNotImplemented) {
            return Ok(door);
        }
        if let Some(axis) = request_proof_mismatch(request, proof) {
            return Ok(self.denied_with_basis(
                door,
                format!("{}:{axis}", assert_basis::REQUEST_PROOF_MISMATCH),
                format!(
                    "Preflight request and proof disagree on {axis}; refused before replay or budget mutation."
                ),
                "spend",
            ));
        }
        match proof.body_digest.as_deref() {
            Some(digest) if is_sha256_hex(digest) => {}
            None => {
                return Ok(self.denied_with_basis(
                    door,
                    basis::BODY_DIGEST_REQUIRED.to_string(),
                    "Authorizing spend requires a body_digest.".to_string(),
                    "spend",
                ));
            }
            Some(_) => {
                return Ok(self.denied_with_basis(
                    door,
                    basis::BODY_DIGEST_INVALID.to_string(),
                    "Authorizing spend requires body_digest as 64 hexadecimal SHA-256 characters."
                        .to_string(),
                    "spend",
                ));
            }
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
        Ok(check_assert(
            request,
            gen_digest.as_deref(),
            policy_hash.as_deref(),
        ))
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
        self.denied_with_basis(door, basis_str, note, "resolved")
    }

    fn denied_with_basis(
        &self,
        door: AssertCheckResult,
        basis_str: String,
        note: String,
        mode: &str,
    ) -> AssertCheckResult {
        let mut why = door.why;
        why.note = note;
        AssertCheckResult {
            decision: AssertCheckDecision::RequiredButDenied,
            reason: basis_str,
            authorizes_effect: false,
            decision_mode: Some(mode.to_string()),
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
    /// carries no grant id). Returns the first usable match. If leases cover
    /// the coordinates but none is usable, returns a specific refusal rather
    /// than erasing it into `Ok(None)`.
    pub fn find_active_assertion_lease(
        &self,
        actor: &str,
        audience: &str,
        claim_kind: &str,
        subject_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AssertionGrantRow>, StoreError> {
        // A freeze over the class means no lease is usable — respect it here too.
        if let Some(freeze) = self.active_freeze_for(claim_kind, actor, audience, now)? {
            return Err(StoreError::ClassFrozen {
                handle: freeze.handle,
                reason: freeze.reason,
            });
        }
        let mut covering_refusal = None;
        for row in self.list_assertion_grants(None, Some(audience))? {
            if row.actor != actor {
                continue;
            }

            // Establish coordinate coverage without parsing the validity
            // window first. That lets a malformed *covering* lease retain its
            // specific refusal instead of becoming indistinguishable from no
            // lease at all.
            let scope = AssertionScope {
                claim_kind: row.claim_kind.clone(),
                subject_scope: row.subject_scope.clone(),
                audience: row.audience.clone(),
            };
            if !matches!(
                assertion_covers(&scope, claim_kind, subject_id, audience),
                AssertCoverage::Covered
            ) {
                continue;
            }

            let state = match row.state.parse::<AssertionGrantState>() {
                Ok(
                    state @ (AssertionGrantState::Issued
                    | AssertionGrantState::Active
                    | AssertionGrantState::Expired
                    | AssertionGrantState::Exhausted),
                ) => state,
                Ok(_) => continue,
                Err(_) => {
                    covering_refusal.get_or_insert(StoreError::InvalidTransition {
                        from: row.state.clone(),
                        to: "active (resolve)".to_string(),
                    });
                    continue;
                }
            };

            let grant = match row_to_grant(&row) {
                Ok(g) => g,
                Err(err) => {
                    covering_refusal.get_or_insert(err);
                    continue;
                }
            };
            match state {
                AssertionGrantState::Expired => {
                    covering_refusal.get_or_insert(StoreError::AssertionWindowClosed(
                        grant.expires_at.to_rfc3339(),
                    ));
                    continue;
                }
                AssertionGrantState::Exhausted => {
                    covering_refusal.get_or_insert(StoreError::AssertionBudgetExhausted {
                        max_uses: grant.max_uses.unwrap_or(0),
                    });
                    continue;
                }
                AssertionGrantState::Issued | AssertionGrantState::Active => {}
                _ => continue,
            }
            match grant.window_state(now, Duration::zero()) {
                WindowState::Within if !grant.is_exhausted() => return Ok(Some(row)),
                WindowState::Within => {
                    covering_refusal.get_or_insert(StoreError::AssertionBudgetExhausted {
                        max_uses: grant.max_uses.unwrap_or(0),
                    });
                }
                WindowState::NotYetValid => {
                    covering_refusal.get_or_insert(StoreError::AssertionNotYetValid(
                        grant.not_before.to_rfc3339(),
                    ));
                }
                WindowState::Expired => {
                    covering_refusal.get_or_insert(StoreError::AssertionWindowClosed(
                        grant.expires_at.to_rfc3339(),
                    ));
                }
                WindowState::Incoherent => {
                    covering_refusal.get_or_insert(StoreError::AssertionWindowIncoherent);
                }
            }
        }
        match covering_refusal {
            Some(err) => Err(err),
            None => Ok(None),
        }
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
        if let Some(f) =
            self.active_freeze_for(&proof.claim_kind, &proof.actor, &proof.audience, now)?
        {
            return Err(StoreError::ClassFrozen {
                handle: f.handle,
                reason: f.reason,
            });
        }

        let row = self
            .get_assertion_grant(&proof.grant_id.to_string())?
            .ok_or_else(|| StoreError::AssertionGrantNotFound(proof.grant_id.to_string()))?;

        let state = row.state.parse::<AssertionGrantState>().map_err(|_| {
            StoreError::InvalidTransition {
                from: row.state.clone(),
                to: "active".into(),
            }
        })?;
        match state {
            AssertionGrantState::Active | AssertionGrantState::Issued => {}
            AssertionGrantState::Exhausted => {
                return Err(StoreError::AssertionBudgetExhausted {
                    max_uses: row.max_uses.unwrap_or(0),
                });
            }
            other => {
                return Err(StoreError::InvalidTransition {
                    from: other.to_string(),
                    to: "active (spend)".into(),
                });
            }
        }

        let grant = row_to_grant(&row)?;
        if proof.actor != grant.actor.id {
            return Err(StoreError::AssertionOutOfScope {
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
                return Err(StoreError::AssertionOutOfScope {
                    axis: "claim_kind_out_of_scope".into(),
                });
            }
            AssertCoverage::SubjectMismatch => {
                return Err(StoreError::AssertionOutOfScope {
                    axis: "subject_out_of_scope".into(),
                });
            }
            AssertCoverage::AudienceMismatch => {
                return Err(StoreError::AssertionOutOfScope {
                    axis: "audience_mismatch".into(),
                });
            }
        }
        match grant.window_state(now, Duration::zero()) {
            WindowState::Within => {}
            WindowState::NotYetValid => {
                return Err(StoreError::AssertionNotYetValid(
                    grant.not_before.to_rfc3339(),
                ));
            }
            WindowState::Expired => {
                return Err(StoreError::AssertionWindowClosed(
                    grant.expires_at.to_rfc3339(),
                ));
            }
            WindowState::Incoherent => return Err(StoreError::AssertionWindowIncoherent),
        }
        if grant.is_exhausted() {
            return Err(StoreError::AssertionBudgetExhausted {
                max_uses: grant.max_uses.unwrap_or(0),
            });
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
        StoreError::AssertionOutOfScope { axis } => (
            axis.clone(),
            format!("Request falls outside the lease scope: {axis}."),
        ),
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
    const BODY_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
            .evidence(serde_json::json!({}))
            .build()
            .unwrap();
        store
            .record_assertion_transition(gid, &AssertionGrantState::Requested, &r1, Some(m(false)))
            .unwrap();
        let r2 = ReceiptBuilder::new(ReceiptKind::AssertionGrantIssued, ACTOR, &subject)
            .parent_digest(r1.digest.clone())
            .evidence(serde_json::json!({}))
            .build()
            .unwrap();
        store
            .record_assertion_transition(gid, &AssertionGrantState::Issued, &r2, Some(m(true)))
            .unwrap();
        gid
    }

    fn request() -> AssertCheckRequest {
        AssertCheckRequest::new(
            ACTOR,
            "nq:main",
            "sqlite_wal_state",
            "labelwatch/foo",
            EffectClass::Binding,
        )
        .unwrap()
    }

    fn proof(gid: Uuid, jti: &str) -> RequestProof {
        RequestProof {
            grant_id: gid,
            actor: ACTOR.into(),
            claim_kind: "sqlite_wal_state".into(),
            subject_id: "labelwatch/foo".into(),
            audience: "nq:main".into(),
            jti: jti.into(),
            body_digest: Some(BODY_DIGEST.into()),
            issued_at: Utc::now(),
        }
    }

    #[test]
    fn preview_never_authorizes_and_never_consumes() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, Some(5));
        let r = store
            .resolve_assert_preview(&request(), &proof(gid, "jti-preview"), Utc::now())
            .unwrap();
        assert_eq!(r.decision, AssertCheckDecision::RequiredAndAvailable);
        assert!(!r.authorizes_effect, "preview MUST NOT authorize");
        assert_eq!(r.decision_mode.as_deref(), Some("preview"));
        assert!(r.emitted_receipt_digest.is_none());
        assert_eq!(r.principal, ACTOR);
        assert_eq!(r.consumer, "nq:main");
        assert_eq!(r.claim_kind, "sqlite_wal_state");
        assert_eq!(r.target, "labelwatch/foo");
        assert_eq!(r.effect, Some(EffectClass::Binding));
        assert_eq!(r.grant_id, Some(gid.to_string()));
        assert_eq!(r.jti.as_deref(), Some("jti-preview"));
        assert_eq!(r.body_digest.as_deref(), Some(BODY_DIGEST));
        // Nothing consumed.
        assert_eq!(
            store
                .get_assertion_grant(&gid.to_string())
                .unwrap()
                .unwrap()
                .spend_count,
            0
        );
    }

    #[test]
    fn spend_authorizes_and_emits_receipt() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, Some(5));
        let r = store
            .resolve_assert_spend(&request(), &proof(gid, "jti-spend"), Utc::now())
            .unwrap();
        assert_eq!(r.decision, AssertCheckDecision::RequiredAndAvailable);
        assert!(r.authorizes_effect, "spend authorizes");
        assert_eq!(r.decision_mode.as_deref(), Some("spend"));
        assert!(r.emitted_receipt_digest.is_some());
        assert_eq!(r.grant_id, Some(gid.to_string()));
        assert_eq!(r.jti.as_deref(), Some("jti-spend"));
        assert_eq!(r.body_digest.as_deref(), Some(BODY_DIGEST));
        assert_eq!(
            store
                .get_assertion_grant(&gid.to_string())
                .unwrap()
                .unwrap()
                .spend_count,
            1
        );
    }

    #[test]
    fn unbounded_lease_is_stamped_not_certified_sound() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, None); // unbounded
        let r = store
            .resolve_assert_spend(&request(), &proof(gid, "jti-u"), Utc::now())
            .unwrap();
        assert!(r.authorizes_effect);
        assert_eq!(r.reuse_bound.as_deref(), Some("unbounded_kind_scope"));
        assert_eq!(r.certified_sound, Some(false));
    }

    #[test]
    fn replay_via_spend_is_denied() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, None);
        store
            .resolve_assert_spend(&request(), &proof(gid, "dup"), Utc::now())
            .unwrap();
        let r = store
            .resolve_assert_spend(&request(), &proof(gid, "dup"), Utc::now())
            .unwrap();
        assert_eq!(r.decision, AssertCheckDecision::RequiredButDenied);
        assert!(!r.authorizes_effect);
        assert_eq!(r.reason, basis::REPLAY_DETECTED);
    }

    #[test]
    fn descriptive_effect_passes_through_not_required() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store, None);
        let req = AssertCheckRequest::new(
            ACTOR,
            "nq:main",
            "sqlite_wal_state",
            "labelwatch/foo",
            EffectClass::Descriptive,
        )
        .unwrap();
        let r = store
            .resolve_assert_spend(&req, &proof(gid, "jti-d"), Utc::now())
            .unwrap();
        assert_eq!(r.decision, AssertCheckDecision::NotRequired);
        assert!(!r.authorizes_effect);
        // Descriptive never touches the lease.
        assert_eq!(
            store
                .get_assertion_grant(&gid.to_string())
                .unwrap()
                .unwrap()
                .spend_count,
            0
        );
    }

    #[test]
    fn request_and_proof_mismatches_are_axis_specific_and_non_consuming() {
        for axis in [
            "principal_actor",
            "consumer_audience",
            "claim_kind",
            "target_subject",
        ] {
            let mut store = Store::in_memory().unwrap();
            let gid = issued_lease(&mut store, Some(5));
            let jti = format!("mismatch-{axis}");
            let mut mismatched = proof(gid, &jti);
            match axis {
                "principal_actor" => mismatched.actor = "component:other:host".into(),
                "consumer_audience" => mismatched.audience = "nq:other".into(),
                "claim_kind" => mismatched.claim_kind = "other_claim".into(),
                "target_subject" => mismatched.subject_id = "labelwatch/other".into(),
                _ => unreachable!(),
            }

            let preview = store
                .resolve_assert_preview(&request(), &mismatched, Utc::now())
                .unwrap();
            assert_eq!(preview.decision, AssertCheckDecision::RequiredButDenied);
            assert_eq!(
                preview.reason,
                format!("{}:{axis}", assert_basis::REQUEST_PROOF_MISMATCH)
            );
            assert_eq!(preview.decision_mode.as_deref(), Some("preview"));
            assert_eq!(preview.jti.as_deref(), Some(jti.as_str()));
            assert!(!preview.authorizes_effect);

            let denied = store
                .resolve_assert_spend(&request(), &mismatched, Utc::now())
                .unwrap();
            assert_eq!(denied.decision, AssertCheckDecision::RequiredButDenied);
            assert_eq!(
                denied.reason,
                format!("{}:{axis}", assert_basis::REQUEST_PROOF_MISMATCH)
            );
            assert_eq!(denied.decision_mode.as_deref(), Some("spend"));
            assert!(!denied.authorizes_effect);
            assert_eq!(
                store
                    .get_assertion_grant(&gid.to_string())
                    .unwrap()
                    .unwrap()
                    .spend_count,
                0,
                "{axis} mismatch must not spend"
            );

            // Reusing the same jti with a correctly-bound proof must succeed,
            // proving the mismatch path never touched the replay ledger.
            let accepted = store
                .resolve_assert_spend(&request(), &proof(gid, &jti), Utc::now())
                .unwrap();
            assert!(
                accepted.authorizes_effect,
                "{axis} mismatch consumed its jti"
            );
            assert_eq!(
                store
                    .get_assertion_grant(&gid.to_string())
                    .unwrap()
                    .unwrap()
                    .spend_count,
                1
            );
        }
    }

    #[test]
    fn authorizing_spend_requires_canonical_body_digest_without_consuming() {
        for body_digest in [None, Some("not-a-sha256-digest".to_string())] {
            let mut store = Store::in_memory().unwrap();
            let gid = issued_lease(&mut store, Some(5));
            let jti = if body_digest.is_some() {
                "bad-body-digest"
            } else {
                "missing-body-digest"
            };
            let mut invalid = proof(gid, jti);
            invalid.body_digest = body_digest.clone();

            let preview = store
                .resolve_assert_preview(&request(), &invalid, Utc::now())
                .unwrap();
            assert_eq!(preview.decision, AssertCheckDecision::RequiredAndAvailable);
            assert!(!preview.authorizes_effect);
            assert_eq!(preview.body_digest, body_digest);

            let denied = store
                .resolve_assert_spend(&request(), &invalid, Utc::now())
                .unwrap();
            assert_eq!(denied.decision, AssertCheckDecision::RequiredButDenied);
            let expected_basis = if invalid.body_digest.is_some() {
                basis::BODY_DIGEST_INVALID
            } else {
                basis::BODY_DIGEST_REQUIRED
            };
            assert_eq!(denied.reason, expected_basis);
            assert_eq!(denied.decision_mode.as_deref(), Some("spend"));
            assert_eq!(denied.body_digest, invalid.body_digest);
            assert!(!denied.authorizes_effect);
            assert_eq!(
                store
                    .get_assertion_grant(&gid.to_string())
                    .unwrap()
                    .unwrap()
                    .spend_count,
                0
            );

            // The refused jti remains usable with a canonical digest.
            let accepted = store
                .resolve_assert_spend(&request(), &proof(gid, jti), Utc::now())
                .unwrap();
            assert!(accepted.authorizes_effect);
        }
    }
}
