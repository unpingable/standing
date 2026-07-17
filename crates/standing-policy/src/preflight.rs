//! Assertion-standing preflight surface — the pure effect-class door.
//!
//! A consumer (NQ, Wicket, Nightshift, AG) about to bind or mutate downstream
//! state asks Standing:
//!
//! > "I am about to assert claim X with effect E. Do I need assert-standing?
//! >  If yes, can you confirm I have it?"
//!
//! Standing answers honestly. For descriptive / advisory effects, act-standing
//! (workload identity + local grant) is sufficient — assert-standing is not
//! required. For binding / mutating effects, assert-standing IS required. The
//! pure [`check_assert`] door reports that requirement without consulting a
//! store; the store-backed preview/spend resolvers then upgrade that sentinel
//! to a lease-backed availability or refusal decision.
//!
//! **This module does not authorize.** It does not mint, persist, lease, or
//! emit receipts. It is read-only inquiry against the existing instance
//! state (genesis + policy). Freeze-safe by construction.
//!
//! See `docs/remote-standing-boundary.md` § Phase 4a.

use serde::{Deserialize, Serialize};

use crate::resolver::{ResolveError, validate_audience, validate_principal};

/// Effect class for a consumer's intended operation.
///
/// Distinguishes operations that can run on act-standing alone (descriptive /
/// advisory) from operations that need assert-standing (binding / mutating).
/// The class is consumer-declared — Standing does not infer it from the
/// claim_kind. Mis-declaring effect is the consumer's failure to refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    /// Pure observation. The consumer surfaces the claim but does not let it
    /// drive downstream state. Act-standing is sufficient.
    Descriptive,
    /// Information-only / recommendation-shaped. The consumer may surface
    /// the claim to an operator but does not bind on it. Act-standing is
    /// sufficient.
    Advisory,
    /// The consumer (or its downstream) will treat the claim as authoritative
    /// without further check. Assert-standing required.
    Binding,
    /// The consumer will mutate state in its domain on the basis of this
    /// claim. Assert-standing required.
    Mutating,
}

/// A consumer's preflight question to Standing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertCheckRequest {
    /// Canonical principal id of the asking actor. Validated against the
    /// same four-form rule as the rest of standing-policy.
    pub principal: String,
    /// Instance-qualified consumer name (e.g. `nq:linode`, `wicket:local`).
    /// The audience-shaped string; same validation rule as `audience` on
    /// `StandingRequest`.
    pub consumer: String,
    /// What kind of claim the consumer is about to assert.
    pub claim_kind: String,
    /// Resource the claim is about.
    pub target: String,
    /// Effect class declared by the consumer.
    pub effect: EffectClass,
}

impl AssertCheckRequest {
    /// Build a request, validating the canonicalization invariants up front
    /// so consumers cannot smuggle bare names into the door.
    pub fn new(
        principal: impl Into<String>,
        consumer: impl Into<String>,
        claim_kind: impl Into<String>,
        target: impl Into<String>,
        effect: EffectClass,
    ) -> Result<Self, ResolveError> {
        let principal = principal.into();
        let consumer = consumer.into();
        validate_principal(&principal)?;
        validate_audience(&consumer)?;
        Ok(Self {
            principal,
            consumer,
            claim_kind: claim_kind.into(),
            target: target.into(),
            effect,
        })
    }
}

/// Standing's structured answer to the preflight.
///
/// The pure door returns `NotRequired` or `RequiredNotImplemented`; store-backed
/// resolution upgrades the latter to `RequiredAndAvailable` or
/// `RequiredButDenied`. Consumers MUST treat unknown variants as conservative
/// refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertCheckDecision {
    /// Effect is descriptive or advisory. Act-standing is sufficient;
    /// assert-standing is not required. The consumer may proceed under
    /// its existing act-standing posture.
    NotRequired,
    /// Effect is binding or mutating. Assert-standing IS required, but this
    /// pure check has not consulted the assertion-lease store. Store-backed
    /// resolution consumes this sentinel; consumers must not authorize from it.
    RequiredNotImplemented,
    /// Effect requires assert-standing, a lease covers this request, and it is
    /// fresh (scope-covered, within-validity, not-replayed, budget-remaining).
    /// Only the **spend** path returns this as authorizing (`authorizes_effect`
    /// true, with `emitted_receipt_digest` set); the **preview** path returns it
    /// as `authorizes_effect = false` — "would be available," not "is granted."
    RequiredAndAvailable,
    /// Effect requires assert-standing and a lease exists (or could), but this
    /// request falls outside it — expired, out of scope, replayed, exhausted, or
    /// no covering lease. `reason` names the axis.
    RequiredButDenied,
}

/// Refusal-mode strings the preflight surface emits in `reason`. Consumers
/// match on these the same way they match on `basis::*` in
/// `StandingDecision::standing_basis`.
pub mod assert_basis {
    pub const EFFECT_NON_BINDING: &str = "effect_non_binding";
    pub const ASSERTION_STANDING_NOT_IMPLEMENTED: &str = "assertion_standing_not_implemented";
    /// Success: a lease covers this request and it is fresh.
    pub const ASSERTION_AVAILABLE: &str = "assertion_available";
    /// No covering lease exists for this actor/audience.
    pub const NO_COVERING_LEASE: &str = "no_covering_lease";
    /// The preflight request and request proof disagree. The concrete decision
    /// appends the mismatch axis, e.g. `request_proof_mismatch:principal_actor`.
    pub const REQUEST_PROOF_MISMATCH: &str = "request_proof_mismatch";
}

/// Cited authority context. Both fields are optional because an instance
/// may not have a genesis installed yet (the silence case) and policy
/// hash is consumer-supplied / store-cached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertCheckWhy {
    /// Digest of this instance's genesis receipt, if installed.
    pub genesis: Option<String>,
    /// Hash of the current policy, if known.
    pub policy: Option<String>,
    /// Free-text explanation. Operator-readable, not consumer-parsed.
    pub note: String,
}

/// Result of a preflight check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertCheckResult {
    pub decision: AssertCheckDecision,
    /// Refusal-mode-shaped string. See `assert_basis::*` for the constants.
    pub reason: String,
    /// What kind of claim required assert-standing, if any.
    /// `"binding_claim"`, `"mutating_claim"`, or `None`.
    pub required_for: Option<String>,
    pub act_standing_sufficient: bool,
    pub assert_standing_required: bool,
    /// **The anti-laundering bit (amendment #2).** True ONLY when the spend path
    /// recorded a replay nonce and emitted an `AssertionMade` receipt whose
    /// digest is in `emitted_receipt_digest`. A `preview` decision, a
    /// `NotRequired`, a `RequiredButDenied`, and a `RequiredNotImplemented` are
    /// all `false`. A consumer that binds/mutates MUST require this true.
    #[serde(default)]
    pub authorizes_effect: bool,
    /// `"preview"` (dry-run, non-consuming) or `"spend"` (recorded), or `None`
    /// for the pure preflight door (which resolves nothing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_mode: Option<String>,
    /// Digest of the `AssertionMade` receipt, when the spend path emitted one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emitted_receipt_digest: Option<String>,
    /// `"unbounded_kind_scope"` when the covering lease has no use budget (L1) —
    /// paired with `certified_sound = Some(false)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse_bound: Option<String>,
    /// Whether the reuse posture is one the math certifies sound (L1). `None`
    /// when not applicable; `Some(false)` for an unbounded lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certified_sound: Option<bool>,
    /// Freshness strength actually established: `"within_validity"` in Phase 4b
    /// (no clock-divergence/MAC yet — NOT full Lean-`Fresh`), or `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness: Option<String>,
    pub why: AssertCheckWhy,
    /// Echoed back from the request so receipts and audit trails on the
    /// consumer side can compose without re-threading.
    #[serde(default)]
    pub principal: String,
    pub consumer: String,
    pub claim_kind: String,
    #[serde(default)]
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<EffectClass>,
    /// Exact proof bindings, populated by store-backed resolution. They remain
    /// present on refusal so the result cannot be detached from the proof it
    /// assessed. The pure effect-class door has no proof and leaves them empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_digest: Option<String>,
}

/// The preflight check itself.
///
/// Pure function: takes a request plus optional cited-authority strings,
/// returns a decision. Does not touch the store, does not emit receipts,
/// does not authorize. Store-backed callers resolve the returned sentinel
/// against a concrete request proof before treating standing as available.
pub fn check_assert(
    request: &AssertCheckRequest,
    genesis_digest: Option<&str>,
    policy_hash: Option<&str>,
) -> AssertCheckResult {
    match request.effect {
        EffectClass::Descriptive | EffectClass::Advisory => AssertCheckResult {
            decision: AssertCheckDecision::NotRequired,
            reason: assert_basis::EFFECT_NON_BINDING.into(),
            required_for: None,
            act_standing_sufficient: true,
            assert_standing_required: false,
            authorizes_effect: false,
            decision_mode: None,
            emitted_receipt_digest: None,
            reuse_bound: None,
            certified_sound: None,
            freshness: None,
            why: AssertCheckWhy {
                genesis: genesis_digest.map(String::from),
                policy: policy_hash.map(String::from),
                note: "Descriptive and advisory effects do not bind downstream consumers. \
                       Act-standing (workload identity + local grant) is sufficient; \
                       assert-standing is not required for this effect class."
                    .into(),
            },
            principal: request.principal.clone(),
            consumer: request.consumer.clone(),
            claim_kind: request.claim_kind.clone(),
            target: request.target.clone(),
            effect: Some(request.effect),
            grant_id: None,
            jti: None,
            body_digest: None,
        },
        EffectClass::Binding | EffectClass::Mutating => {
            let required_for = match request.effect {
                EffectClass::Binding => "binding_claim",
                EffectClass::Mutating => "mutating_claim",
                _ => unreachable!(),
            };
            AssertCheckResult {
                decision: AssertCheckDecision::RequiredNotImplemented,
                reason: assert_basis::ASSERTION_STANDING_NOT_IMPLEMENTED.into(),
                required_for: Some(required_for.into()),
                act_standing_sufficient: false,
                assert_standing_required: true,
                authorizes_effect: false,
                decision_mode: None,
                emitted_receipt_digest: None,
                reuse_bound: None,
                certified_sound: None,
                freshness: None,
                why: AssertCheckWhy {
                    genesis: genesis_digest.map(String::from),
                    policy: policy_hash.map(String::from),
                    note: "Binding and mutating effects require assertion standing. This pure \
                           preflight checks only the effect gate and does not consult the lease \
                           store. The consumer must use store-backed preview/spend resolution; \
                           only a spend result with authorizes_effect=true may authorize."
                        .into(),
                },
                principal: request.principal.clone(),
                consumer: request.consumer.clone(),
                claim_kind: request.claim_kind.clone(),
                target: request.target.clone(),
                effect: Some(request.effect),
                grant_id: None,
                jti: None,
                body_digest: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(effect: EffectClass) -> AssertCheckRequest {
        AssertCheckRequest::new(
            "component:nq:linode",
            "nq:linode",
            "sqlite_wal_state",
            "labelwatch/foo",
            effect,
        )
        .unwrap()
    }

    #[test]
    fn descriptive_effect_does_not_require_assertion() {
        let r = check_assert(&req(EffectClass::Descriptive), None, None);
        assert_eq!(r.decision, AssertCheckDecision::NotRequired);
        assert_eq!(r.reason, assert_basis::EFFECT_NON_BINDING);
        assert!(r.act_standing_sufficient);
        assert!(!r.assert_standing_required);
        assert!(r.required_for.is_none());
    }

    #[test]
    fn advisory_effect_does_not_require_assertion() {
        let r = check_assert(&req(EffectClass::Advisory), None, None);
        assert_eq!(r.decision, AssertCheckDecision::NotRequired);
        assert!(r.act_standing_sufficient);
        assert!(!r.assert_standing_required);
    }

    #[test]
    fn binding_effect_refused_as_not_implemented() {
        let r = check_assert(
            &req(EffectClass::Binding),
            Some("gen-digest"),
            Some("pol-hash"),
        );
        assert_eq!(r.decision, AssertCheckDecision::RequiredNotImplemented);
        assert_eq!(r.reason, assert_basis::ASSERTION_STANDING_NOT_IMPLEMENTED);
        assert_eq!(r.required_for.as_deref(), Some("binding_claim"));
        assert!(!r.act_standing_sufficient);
        assert!(r.assert_standing_required);
        assert_eq!(r.why.genesis.as_deref(), Some("gen-digest"));
        assert_eq!(r.why.policy.as_deref(), Some("pol-hash"));
    }

    #[test]
    fn mutating_effect_refused_as_not_implemented() {
        let r = check_assert(&req(EffectClass::Mutating), None, None);
        assert_eq!(r.decision, AssertCheckDecision::RequiredNotImplemented);
        assert_eq!(r.required_for.as_deref(), Some("mutating_claim"));
    }

    #[test]
    fn bare_consumer_name_is_refused() {
        let err = AssertCheckRequest::new(
            "component:nq:linode",
            "nq",
            "sqlite_wal_state",
            "labelwatch/foo",
            EffectClass::Binding,
        );
        assert!(err.is_err(), "bare consumer name must not validate");
    }

    #[test]
    fn bare_principal_is_refused() {
        let err = AssertCheckRequest::new(
            "nq",
            "nq:linode",
            "sqlite_wal_state",
            "labelwatch/foo",
            EffectClass::Binding,
        );
        assert!(err.is_err(), "bare principal must not validate");
    }

    #[test]
    fn result_echoes_exact_request() {
        let r = check_assert(&req(EffectClass::Binding), None, None);
        assert_eq!(r.principal, "component:nq:linode");
        assert_eq!(r.consumer, "nq:linode");
        assert_eq!(r.claim_kind, "sqlite_wal_state");
        assert_eq!(r.target, "labelwatch/foo");
        assert_eq!(r.effect, Some(EffectClass::Binding));
        assert_eq!(r.grant_id, None);
        assert_eq!(r.jti, None);
        assert_eq!(r.body_digest, None);
    }

    #[test]
    fn new_result_echoes_default_when_deserializing_legacy_shape() {
        let mut legacy =
            serde_json::to_value(check_assert(&req(EffectClass::Binding), None, None)).unwrap();
        let fields = legacy.as_object_mut().unwrap();
        fields.remove("principal");
        fields.remove("target");
        fields.remove("effect");
        fields.remove("grant_id");
        fields.remove("jti");
        fields.remove("body_digest");

        let r: AssertCheckResult = serde_json::from_value(legacy).unwrap();

        assert_eq!(r.principal, "");
        assert_eq!(r.target, "");
        assert_eq!(r.effect, None);
        assert_eq!(r.grant_id, None);
        assert_eq!(r.jti, None);
        assert_eq!(r.body_digest, None);
    }

    #[test]
    fn why_is_present_even_when_inputs_are_none() {
        let r = check_assert(&req(EffectClass::Descriptive), None, None);
        assert!(
            !r.why.note.is_empty(),
            "operator-readable note always present"
        );
    }

    #[test]
    fn decision_serializes_to_snake_case() {
        let r = check_assert(&req(EffectClass::Binding), None, None);
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"required_not_implemented\""));
        assert!(s.contains("\"assertion_standing_not_implemented\""));
    }

    #[test]
    fn effect_class_serializes_to_snake_case() {
        let s = serde_json::to_string(&EffectClass::Binding).unwrap();
        assert_eq!(s, "\"binding\"");
        let s = serde_json::to_string(&EffectClass::Descriptive).unwrap();
        assert_eq!(s, "\"descriptive\"");
    }
}
