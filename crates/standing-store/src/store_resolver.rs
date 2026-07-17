//! `StoreResolver` — the lease-backed `StandingResolver` (Phase 6 binding
//! surface).
//!
//! The three MVP resolvers (`DenyAll`, `LocalOnly`, `StaticConfig`) answer from
//! static knowledge. This one answers from the live assertion-lease store: it
//! looks up a covering lease by coordinates and, in `Binding` mode, spends it —
//! emitting an `AssertionMade` receipt — so a consumer (Wicket, Nightshift, an
//! NQ binding flip) can point a `StandingResolver` at Standing and get a real,
//! receipt-bearing decision.
//!
//! Consumer-facing name: `StandingToolResolver`. Interior mutability
//! (`Mutex<Store>`) because `StandingResolver::assess` takes `&self` but a spend
//! needs `&mut Store`.

use std::sync::Mutex;

use standing_grant::RequestProof;
use standing_policy::resolver::{
    ResolveError, ResolverMode, StandingDecision, StandingRequest, StandingResolver,
    StandingVerdict, basis,
};

use crate::{AssertionGrantRow, Store, StoreError};

fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub struct StoreResolver {
    store: Mutex<Store>,
    mode: ResolverMode,
}

impl StoreResolver {
    pub fn new(store: Store, mode: ResolverMode) -> Self {
        Self {
            store: Mutex::new(store),
            mode,
        }
    }

    /// Consumer-facing constructor name.
    pub fn standing_tool(store: Store, mode: ResolverMode) -> Self {
        Self::new(store, mode)
    }

    fn allowed(
        &self,
        req: &StandingRequest,
        lease: &AssertionGrantRow,
        receipt_digest: Option<String>,
    ) -> StandingDecision {
        let reason = match &receipt_digest {
            Some(d) => format!("lease {} covers request; spent (receipt {d})", lease.id),
            None => format!(
                "lease {} covers request (visible_not_binding; not spent)",
                lease.id
            ),
        };
        let (reuse_bound, certified_sound) = match lease.max_uses {
            None => (Some("unbounded_kind_scope".to_string()), Some(false)),
            Some(_) => (None, Some(true)),
        };
        StandingDecision {
            verdict: StandingVerdict::Allowed,
            reason,
            verification_mode: "store_grant".to_string(),
            identity_substrate: "hmac_workload_id".to_string(),
            standing_enforced: self.mode.standing_enforced(),
            resolver: "StoreResolver".to_string(),
            standing_basis: "allowed_by_store_grant".to_string(),
            actor: req.actor.id.clone(),
            claim_kind: req.claim_kind.clone(),
            subject_scope: req.subject_scope.clone(),
            jti: req.jti.clone(),
            body_digest: req.body_digest.clone(),
            emitted_receipt_digest: receipt_digest,
            reuse_bound,
            certified_sound,
            scope: vec![format!("{}:{}", req.claim_kind, req.subject_scope)],
            audience: req.audience.clone(),
            evaluated_at: req.now,
            expires_at: lease
                .expires_at
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.to_utc()),
        }
    }

    fn denied(
        &self,
        req: &StandingRequest,
        reason: &str,
        standing_basis: &str,
    ) -> StandingDecision {
        StandingDecision {
            verdict: StandingVerdict::Denied,
            reason: reason.to_string(),
            verification_mode: "store_grant".to_string(),
            identity_substrate: "hmac_workload_id".to_string(),
            standing_enforced: self.mode.standing_enforced(),
            resolver: "StoreResolver".to_string(),
            standing_basis: standing_basis.to_string(),
            actor: req.actor.id.clone(),
            claim_kind: req.claim_kind.clone(),
            subject_scope: req.subject_scope.clone(),
            jti: req.jti.clone(),
            body_digest: req.body_digest.clone(),
            emitted_receipt_digest: None,
            reuse_bound: None,
            certified_sound: None,
            scope: vec![],
            audience: req.audience.clone(),
            evaluated_at: req.now,
            expires_at: None,
        }
    }

    /// Map a spend refusal to a basis string, reusing the same vocabulary the
    /// preflight orchestrator uses.
    fn denied_from_store(&self, req: &StandingRequest, err: &StoreError) -> StandingDecision {
        let b = match err {
            StoreError::AssertionOutOfScope { axis } => axis.clone(),
            StoreError::AssertionWindowClosed(_) => basis::STANDING_EXPIRED.to_string(),
            StoreError::AssertionNotYetValid(_) => basis::GRANT_NOT_YET_VALID.to_string(),
            StoreError::AssertionWindowIncoherent => "window_incoherent".to_string(),
            StoreError::AssertionBudgetExhausted { .. } => "use_budget_exhausted".to_string(),
            StoreError::ReplayDetected { .. } => basis::REPLAY_DETECTED.to_string(),
            StoreError::ClassFrozen { handle, .. } => format!("class_frozen:{handle}"),
            _ => basis::DENY_DEFAULT.to_string(),
        };
        self.denied(req, &format!("assertion refused: {err}"), &b)
    }
}

impl StandingResolver for StoreResolver {
    fn assess(&self, request: &StandingRequest) -> Result<StandingDecision, ResolveError> {
        let mut store = match self.store.lock() {
            Ok(store) => store,
            Err(_) => {
                return Ok(self.denied(
                    request,
                    "store mutex poisoned; refusing because lease state cannot be trusted",
                    basis::DENY_DEFAULT,
                ));
            }
        };
        let now = request.now;

        // `subject_scope` on a request is the concrete subject being asserted
        // about (matched against a lease's coverage pattern).
        let lease = match store.find_active_assertion_lease(
            &request.actor.id,
            &request.audience,
            &request.claim_kind,
            &request.subject_scope,
            now,
        ) {
            Ok(Some(l)) => l,
            Ok(None) => {
                return Ok(self.denied(
                    request,
                    "no covering lease for this actor/audience",
                    basis::STANDING_ABSENT,
                ));
            }
            // Fail-closed on a store error: deny, don't panic or pass. Known
            // covering-lease refusals retain their specific decision basis.
            Err(e) => return Ok(self.denied_from_store(request, &e)),
        };

        match self.mode {
            // visible_not_binding: report availability without spending.
            ResolverMode::VisibleNotBinding => Ok(self.allowed(request, &lease, None)),
            // binding: actually spend the lease (records replay, emits receipt).
            ResolverMode::Binding => {
                // Binding mode requires a replay nonce.
                let jti = match &request.jti {
                    Some(j) => j.clone(),
                    None => {
                        return Ok(self.denied(
                            request,
                            "binding mode requires a per-request jti",
                            basis::JTI_REQUIRED,
                        ));
                    }
                };
                let body_digest = match &request.body_digest {
                    Some(digest) if is_sha256_hex(digest) => digest.clone(),
                    None => {
                        return Ok(self.denied(
                            request,
                            "binding mode requires a body_digest",
                            basis::BODY_DIGEST_REQUIRED,
                        ));
                    }
                    Some(_) => {
                        return Ok(self.denied(
                            request,
                            "body_digest must be 64 hexadecimal SHA-256 characters",
                            basis::BODY_DIGEST_INVALID,
                        ));
                    }
                };
                let grant_id = match uuid::Uuid::parse_str(&lease.id) {
                    Ok(g) => g,
                    Err(_) => {
                        return Ok(self.denied(request, "malformed lease id", basis::DENY_DEFAULT));
                    }
                };
                let proof = RequestProof {
                    grant_id,
                    actor: request.actor.id.clone(),
                    claim_kind: request.claim_kind.clone(),
                    subject_id: request.subject_scope.clone(),
                    audience: request.audience.clone(),
                    jti,
                    body_digest: Some(body_digest),
                    issued_at: now,
                };
                match store.spend_assertion(&proof, now) {
                    Ok(r) => Ok(self.allowed(request, &lease, Some(r.receipt_digest))),
                    Err(e) => Ok(self.denied_from_store(request, &e)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use standing_grant::{AssertionGrantState, Principal};
    use standing_receipt::{ReceiptBuilder, ReceiptKind};
    use uuid::Uuid;

    use crate::AssertionGrantMeta;

    const ACTOR: &str = "component:nq:linode";
    const BODY_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn issued_lease(store: &mut Store) -> Uuid {
        issued_lease_with(
            store,
            Utc::now() - Duration::days(1),
            Some(Utc::now() + Duration::days(365)),
            Some(5),
        )
    }

    fn issued_lease_with(
        store: &mut Store,
        not_before: chrono::DateTime<Utc>,
        expires_at: Option<chrono::DateTime<Utc>>,
        max_uses: Option<u64>,
    ) -> Uuid {
        let gid = Uuid::new_v4();
        let subject = gid.to_string();
        let m = |issued: bool| AssertionGrantMeta {
            actor: ACTOR.into(),
            claim_kind: "sqlite_wal_state".into(),
            subject_scope: "labelwatch/*".into(),
            audience: "nq:main".into(),
            not_before: Some(not_before),
            issued_at: Some(not_before),
            expires_at: if issued { expires_at } else { None },
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

    fn request(jti: Option<&str>) -> StandingRequest {
        let mut r = StandingRequest::new(
            Principal::new(ACTOR, "nq@linode"),
            "sqlite_wal_state",
            "labelwatch/foo",
            "nq:main",
            Utc::now(),
        )
        .unwrap();
        if let Some(j) = jti {
            r = r.with_jti(j);
        }
        r.with_body_digest(BODY_DIGEST)
    }

    #[test]
    fn binding_mode_spends_and_allows() {
        let mut store = Store::in_memory().unwrap();
        issued_lease(&mut store);
        let resolver = StoreResolver::new(store, ResolverMode::Binding);
        let d = resolver.assess(&request(Some("j1"))).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Allowed);
        assert!(d.standing_enforced);
        assert_eq!(d.standing_basis, "allowed_by_store_grant");
        assert_eq!(d.actor, ACTOR);
        assert_eq!(d.claim_kind, "sqlite_wal_state");
        assert_eq!(d.subject_scope, "labelwatch/foo");
        assert_eq!(d.jti.as_deref(), Some("j1"));
        assert_eq!(d.body_digest.as_deref(), Some(BODY_DIGEST));
        assert!(d.emitted_receipt_digest.is_some());
        assert_eq!(d.reuse_bound, None);
        assert_eq!(d.certified_sound, Some(true));
    }

    #[test]
    fn binding_mode_requires_jti() {
        let mut store = Store::in_memory().unwrap();
        issued_lease(&mut store);
        let resolver = StoreResolver::new(store, ResolverMode::Binding);
        let d = resolver.assess(&request(None)).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::JTI_REQUIRED);
    }

    #[test]
    fn binding_mode_requires_body_digest_without_spending() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store);
        let resolver = StoreResolver::new(store, ResolverMode::Binding);
        let mut req = request(Some("j-no-digest"));
        req.body_digest = None;

        let d = resolver.assess(&req).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert!(d.reason.contains("requires a body_digest"));
        assert_eq!(d.standing_basis, basis::BODY_DIGEST_REQUIRED);
        assert_eq!(d.body_digest, None);
        let store = resolver.store.lock().unwrap();
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
    fn binding_mode_rejects_malformed_body_digest_without_spending() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store);
        let resolver = StoreResolver::new(store, ResolverMode::Binding);
        let mut req = request(Some("j-bad-digest"));
        req.body_digest = Some("not-a-sha256-digest".to_string());

        let d = resolver.assess(&req).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert!(d.reason.contains("64 hexadecimal SHA-256 characters"));
        assert_eq!(d.standing_basis, basis::BODY_DIGEST_INVALID);
        let store = resolver.store.lock().unwrap();
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
    fn visible_not_binding_allows_without_spending() {
        let mut store = Store::in_memory().unwrap();
        let gid = issued_lease(&mut store);
        let resolver = StoreResolver::new(store, ResolverMode::VisibleNotBinding);
        let d = resolver.assess(&request(Some("j1"))).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Allowed);
        assert!(!d.standing_enforced);
        assert_eq!(d.emitted_receipt_digest, None);
        // Not spent: spend_count still 0.
        let store = resolver.store.lock().unwrap();
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
    fn no_lease_is_denied_standing_absent() {
        let store = Store::in_memory().unwrap();
        let resolver = StoreResolver::new(store, ResolverMode::Binding);
        let d = resolver.assess(&request(Some("j1"))).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::STANDING_ABSENT);
    }

    #[test]
    fn replay_in_binding_mode_is_denied() {
        let mut store = Store::in_memory().unwrap();
        issued_lease(&mut store);
        let resolver = StoreResolver::new(store, ResolverMode::Binding);
        assert_eq!(
            resolver.assess(&request(Some("dup"))).unwrap().verdict,
            StandingVerdict::Allowed
        );
        let d = resolver.assess(&request(Some("dup"))).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::REPLAY_DETECTED);
    }

    #[test]
    fn frozen_matching_lease_retains_class_frozen_basis() {
        let mut store = Store::in_memory().unwrap();
        issued_lease(&mut store);
        store
            .install_genesis("admin:operator", "hardcoded:v1")
            .unwrap();
        store
            .install_freeze(
                "incident-resolver",
                "claim_kind",
                "sqlite_wal_state",
                None,
                "investigating bad testimony",
                None,
                "admin:operator",
                Utc::now(),
            )
            .unwrap();
        let resolver = StoreResolver::new(store, ResolverMode::Binding);

        let d = resolver.assess(&request(Some("j-frozen"))).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, "class_frozen:incident-resolver");
    }

    #[test]
    fn expired_matching_lease_retains_expired_basis() {
        let mut store = Store::in_memory().unwrap();
        let now = Utc::now();
        issued_lease_with(
            &mut store,
            now - Duration::days(2),
            Some(now - Duration::days(1)),
            Some(5),
        );
        let resolver = StoreResolver::new(store, ResolverMode::Binding);

        let d = resolver.assess(&request(Some("j-expired"))).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::STANDING_EXPIRED);
    }

    #[test]
    fn future_matching_lease_retains_not_yet_valid_basis() {
        let mut store = Store::in_memory().unwrap();
        let now = Utc::now();
        issued_lease_with(
            &mut store,
            now + Duration::days(1),
            Some(now + Duration::days(2)),
            Some(5),
        );
        let resolver = StoreResolver::new(store, ResolverMode::Binding);

        let d = resolver.assess(&request(Some("j-future"))).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::GRANT_NOT_YET_VALID);
    }

    #[test]
    fn exhausted_matching_lease_retains_budget_basis() {
        let mut store = Store::in_memory().unwrap();
        issued_lease_with(
            &mut store,
            Utc::now() - Duration::days(1),
            Some(Utc::now() + Duration::days(1)),
            Some(0),
        );
        let resolver = StoreResolver::new(store, ResolverMode::Binding);

        let d = resolver.assess(&request(Some("j-exhausted"))).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, "use_budget_exhausted");
    }

    #[test]
    fn malformed_matching_lease_retains_window_basis() {
        let mut store = Store::in_memory().unwrap();
        issued_lease_with(&mut store, Utc::now() - Duration::days(1), None, Some(5));
        let resolver = StoreResolver::new(store, ResolverMode::Binding);

        let d = resolver.assess(&request(Some("j-malformed"))).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, "window_incoherent");
    }

    #[test]
    fn usable_covering_lease_wins_over_unusable_candidate() {
        let mut store = Store::in_memory().unwrap();
        let now = Utc::now();
        issued_lease_with(
            &mut store,
            now - Duration::days(2),
            Some(now - Duration::days(1)),
            Some(5),
        );
        issued_lease(&mut store);
        let resolver = StoreResolver::new(store, ResolverMode::Binding);

        let d = resolver.assess(&request(Some("j-valid"))).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Allowed);
    }

    #[test]
    fn unbounded_lease_is_explicitly_not_certified_sound() {
        let mut store = Store::in_memory().unwrap();
        issued_lease_with(
            &mut store,
            Utc::now() - Duration::days(1),
            Some(Utc::now() + Duration::days(1)),
            None,
        );
        let resolver = StoreResolver::new(store, ResolverMode::VisibleNotBinding);

        let d = resolver.assess(&request(None)).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Allowed);
        assert_eq!(d.reuse_bound.as_deref(), Some("unbounded_kind_scope"));
        assert_eq!(d.certified_sound, Some(false));
    }

    #[test]
    fn poisoned_store_mutex_denies_without_panicking() {
        let mut store = Store::in_memory().unwrap();
        issued_lease(&mut store);
        let resolver = StoreResolver::new(store, ResolverMode::Binding);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = resolver.store.lock().unwrap();
            panic!("poison resolver store mutex");
        }));
        assert!(poisoned.is_err());

        let d = resolver.assess(&request(Some("j-poisoned"))).unwrap();

        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::DENY_DEFAULT);
        assert!(d.reason.contains("mutex poisoned"));
    }
}
