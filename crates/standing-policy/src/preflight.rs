//! Assertion-standing preflight surface — Phase 4a "door, not room."
//!
//! A consumer (NQ, Wicket, Nightshift, AG) about to bind or mutate downstream
//! state asks Standing:
//!
//! > "I am about to assert claim X with effect E. Do I need assert-standing?
//! >  If yes, can you confirm I have it?"
//!
//! Standing answers honestly. For descriptive / advisory effects, act-standing
//! (workload identity + local grant) is sufficient — assert-standing is not
//! required. For binding / mutating effects, assert-standing IS required —
//! and as of Phase 4a, the `AssertionGrant` lease lifecycle is not yet
//! installed, so the answer is a structured *cannot testify yet* refusal.
//!
//! This is the **forcing-case detector** for Phase 4b (the lease lifecycle):
//! a consumer that calls `check_assert` for a binding effect and receives
//! `RequiredNotImplemented` has the citable forcing case the lifecycle build
//! needs. Until that happens, the door is open, the room is unbuilt, and the
//! absence is observable.
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
/// Two variants in Phase 4a. Future iterations will add `RequiredAndAvailable`
/// (when the AssertionGrant lifecycle lands) and `RequiredButDenied`
/// (when a grant exists but the request falls outside its scope).
/// Consumers MUST treat unknown variants as conservative refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertCheckDecision {
    /// Effect is descriptive or advisory. Act-standing is sufficient;
    /// assert-standing is not required. The consumer may proceed under
    /// its existing act-standing posture.
    NotRequired,
    /// Effect is binding or mutating. Assert-standing IS required for this
    /// kind of operation, but Standing has no `AssertionGrant` lease
    /// lifecycle installed yet. Refusal is structural, not stylistic.
    RequiredNotImplemented,
}

/// Refusal-mode strings the preflight surface emits in `reason`. Consumers
/// match on these the same way they match on `basis::*` in
/// `StandingDecision::standing_basis`.
pub mod assert_basis {
    pub const EFFECT_NON_BINDING: &str = "effect_non_binding";
    pub const ASSERTION_STANDING_NOT_IMPLEMENTED: &str = "assertion_standing_not_implemented";
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
    pub why: AssertCheckWhy,
    /// Echoed back from the request so receipts and audit trails on the
    /// consumer side can compose without re-threading.
    pub consumer: String,
    pub claim_kind: String,
}

/// The preflight check itself.
///
/// Pure function: takes a request plus optional cited-authority strings,
/// returns a decision. Does not touch the store, does not emit receipts,
/// does not authorize. Phase 4a in one screen.
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
            why: AssertCheckWhy {
                genesis: genesis_digest.map(String::from),
                policy: policy_hash.map(String::from),
                note: "Descriptive and advisory effects do not bind downstream consumers. \
                       Act-standing (workload identity + local grant) is sufficient; \
                       assert-standing is not required for this effect class."
                    .into(),
            },
            consumer: request.consumer.clone(),
            claim_kind: request.claim_kind.clone(),
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
                why: AssertCheckWhy {
                    genesis: genesis_digest.map(String::from),
                    policy: policy_hash.map(String::from),
                    note: "Standing has no AssertionGrant lease lifecycle installed (Phase 4b). \
                           Binding and mutating effects require assert-standing the tool cannot \
                           yet issue. The consumer should either (a) defer the binding action, \
                           (b) run the operation under visible_not_binding posture, or \
                           (c) wait for Phase 4b. See docs/remote-standing-boundary.md."
                        .into(),
                },
                consumer: request.consumer.clone(),
                claim_kind: request.claim_kind.clone(),
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
        let r = check_assert(&req(EffectClass::Binding), Some("gen-digest"), Some("pol-hash"));
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
    fn result_echoes_consumer_and_claim_kind() {
        let r = check_assert(&req(EffectClass::Binding), None, None);
        assert_eq!(r.consumer, "nq:linode");
        assert_eq!(r.claim_kind, "sqlite_wal_state");
    }

    #[test]
    fn why_is_present_even_when_inputs_are_none() {
        let r = check_assert(&req(EffectClass::Descriptive), None, None);
        assert!(!r.why.note.is_empty(), "operator-readable note always present");
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
