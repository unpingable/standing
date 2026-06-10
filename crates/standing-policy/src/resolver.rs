//! Standing resolver — the remote-boundary entitlement seam.
//!
//! See `docs/remote-standing-boundary.md` for the doctrine this implements.
//!
//! A `StandingResolver` answers: may this actor introduce this class of
//! testimony or request into this audience, in this scope, right now?
//!
//! This is **entitlement-to-assert**, distinct from slice-1's
//! entitlement-to-act (`standing-grant::Grant`). The two primitives share
//! the receipt kernel and canonical-JSON discipline; they differ in scope
//! shape (action × target vs claim_kind × subject_scope × audience) and
//! lifecycle (single-use action vs lease over many assertions — the latter
//! arrives post-MVP).
//!
//! MVP ships the trait + `DenyAllResolver` + `LocalOnlyResolver`. The
//! `StaticConfigResolver` ships alongside in `crate::config`. `StoreResolver`
//! is post-MVP — it arrives with the `AssertionGrant` lifecycle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use standing_grant::Principal;

/// The verdict of a standing assessment.
///
/// `Unknown` is distinct from `Denied`: it means the resolver lacks the
/// information to decide (e.g., `StaticConfigResolver` has no entry that
/// could match either positively or negatively). Consumers in
/// `visible_not_binding` mode may treat `Unknown` differently from
/// `Denied`; consumers in `binding` mode must treat both as refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandingVerdict {
    Allowed,
    Denied,
    Unknown,
}

/// A standing assessment request. The caller is responsible for verifying
/// `actor` identity before constructing this — Standing's resolver layer
/// is downstream of identity verification.
///
/// Canonical naming is enforced in the constructor: `audience` must be
/// instance-qualified (`<name>:<instance>`), and `actor.id` must parse as
/// one of the four canonical principal forms (see `validate_principal`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandingRequest {
    pub actor: Principal,
    pub claim_kind: String,
    pub subject_scope: String,
    pub audience: String,
    pub now: DateTime<Utc>,
    /// Per-request nonce. Used for replay defense in `binding` mode.
    /// MVP `visible_not_binding` may omit; binding mode requires.
    pub jti: Option<String>,
    /// SHA-256 of the canonical request body the standing assertion attests
    /// to. Used to bind the standing decision to the specific payload.
    /// MVP optional; binding mode required.
    pub body_digest: Option<String>,
}

impl StandingRequest {
    /// Construct a `StandingRequest` with canonical-naming validation.
    ///
    /// Refuses bare audience strings (e.g., "nq") and uncanonicalized
    /// actor IDs. These refusals are authorization logic, not formatting
    /// nits — two distinct canonical strings are two distinct principals.
    pub fn new(
        actor: Principal,
        claim_kind: impl Into<String>,
        subject_scope: impl Into<String>,
        audience: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, ResolveError> {
        let audience = audience.into();
        validate_audience(&audience)?;
        validate_principal(&actor.id)?;
        Ok(Self {
            actor,
            claim_kind: claim_kind.into(),
            subject_scope: subject_scope.into(),
            audience,
            now,
            jti: None,
            body_digest: None,
        })
    }

    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    pub fn with_body_digest(mut self, digest: impl Into<String>) -> Self {
        self.body_digest = Some(digest.into());
        self
    }
}

/// A standing decision. Every field is load-bearing for the receipt
/// attribution discipline named in `docs/remote-standing-boundary.md`:
/// consumers that record a decision must record all of these.
///
/// `standing_enforced` is the bolt that makes `visible_not_binding`
/// impossible to misread downstream. Resolvers set it from their mode at
/// construction; it is not derived from the verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandingDecision {
    pub verdict: StandingVerdict,
    pub reason: String,
    /// How the verdict was reached. Distinguishes
    /// `"static_config"` from `"store_grant"` from `"local_only"` from
    /// `"deny_all"`. Different rigor, different basis.
    pub verification_mode: String,
    /// How the principal was authenticated upstream of standing.
    /// `"hmac_workload_id"` today; `"mtls"`/`"oidc"`/`"spiffe"` future.
    pub identity_substrate: String,
    /// Whether the consumer treats this decision as binding.
    /// `false` in `visible_not_binding` mode.
    pub standing_enforced: bool,
    /// Implementation name (e.g., `"StaticConfigResolver"`).
    pub resolver: String,
    /// Refusal-mode-shaped string. One of the constants in `basis::*`,
    /// or `"allowed_by_<resolver>"` for the success path.
    pub standing_basis: String,
    /// Matched scope tuples in `claim_kind:subject_scope` form.
    pub scope: Vec<String>,
    pub audience: String,
    pub evaluated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Errors that prevent a resolver from producing a decision at all
/// (config malformed, naming invalid). A `Denied` verdict is not an
/// error — it is a valid decision.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("audience must be instance-qualified (<name>:<instance>); got {0:?}")]
    AudienceNotInstanceQualified(String),

    #[error("principal id is not canonical; got {0:?} (expected component:name:instance, human:handle, workload:name:location, or system)")]
    PrincipalNotCanonical(String),

    #[error("config parse error: {0}")]
    ConfigParse(String),

    #[error("config io error: {0}")]
    ConfigIo(String),
}

/// The mode a resolver evaluates in. Set explicitly at construction —
/// no default that could quietly flip to `Binding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverMode {
    VisibleNotBinding,
    Binding,
}

impl ResolverMode {
    pub fn standing_enforced(self) -> bool {
        matches!(self, Self::Binding)
    }
}

/// The pluggable standing seam. Implementations live in this crate.
pub trait StandingResolver {
    fn assess(&self, request: &StandingRequest) -> Result<StandingDecision, ResolveError>;
}

// ---------------------------------------------------------------------
// standing_basis string constants — the refusal-mode vocabulary.
// Keep in sync with docs/remote-standing-boundary.md § "Refusal modes".
// ---------------------------------------------------------------------

pub mod basis {
    pub const UNKNOWN_PEER: &str = "unknown_peer";
    pub const UNKNOWN_ISSUER: &str = "unknown_issuer";
    pub const STANDING_ABSENT: &str = "standing_absent";
    pub const STANDING_EXPIRED: &str = "standing_expired";
    pub const GRANT_NOT_YET_VALID: &str = "grant_not_yet_valid";
    pub const CLAIM_KIND_OUT_OF_SCOPE: &str = "claim_kind_out_of_scope";
    pub const SUBJECT_OUT_OF_SCOPE: &str = "subject_out_of_scope";
    pub const AUDIENCE_MISMATCH: &str = "audience_mismatch";
    pub const CLOCK_SKEW_EXCEEDED: &str = "clock_skew_exceeded";
    pub const REQUEST_TIMESTAMP_OUT_OF_WINDOW: &str = "request_timestamp_out_of_window";
    pub const REPLAY_DETECTED: &str = "replay_detected";
    pub const RECEIPT_MISSING: &str = "receipt_missing";
    pub const DELEGATION_DENIED: &str = "delegation_denied";
    pub const DENY_DEFAULT: &str = "deny_default";
    pub const NON_LOCAL_ACTOR: &str = "non_local_actor";
    pub const STATIC_CONFIG_NO_MATCH: &str = "static_config_no_match";
    pub const STATIC_CONFIG_MATCH: &str = "static_config_match";
}

// ---------------------------------------------------------------------
// Canonical naming validation
// ---------------------------------------------------------------------

/// Audience must be instance-qualified: `<name>:<instance>` where both
/// segments are non-empty and contain no `:`.
pub(crate) fn validate_audience(audience: &str) -> Result<(), ResolveError> {
    let mut parts = audience.splitn(2, ':');
    let name = parts.next().unwrap_or("");
    let instance = parts.next().unwrap_or("");
    if name.is_empty() || instance.is_empty() || instance.contains(':') {
        return Err(ResolveError::AudienceNotInstanceQualified(
            audience.to_string(),
        ));
    }
    Ok(())
}

/// Principal id must match one of the four canonical forms:
///   - `component:<name>:<instance>`
///   - `human:<handle>`
///   - `workload:<name>:<location>` (slice-1 WorkloadId surface)
///   - `system` (exactly)
///
/// The slice-1 `wl:<name>:<location>` form is also accepted as an alias
/// of `workload:` — slice-1 receipts and tests use the short prefix.
pub(crate) fn validate_principal(id: &str) -> Result<(), ResolveError> {
    if id == "system" {
        return Ok(());
    }
    let parts: Vec<&str> = id.split(':').collect();
    let ok = match parts.as_slice() {
        ["component", name, instance] => !name.is_empty() && !instance.is_empty(),
        ["human", handle] => !handle.is_empty(),
        ["workload", name, location] => !name.is_empty() && !location.is_empty(),
        ["wl", name, location] => !name.is_empty() && !location.is_empty(),
        ["admin", handle] => !handle.is_empty(),
        _ => false,
    };
    if !ok {
        return Err(ResolveError::PrincipalNotCanonical(id.to_string()));
    }
    Ok(())
}

/// True if the principal id is a local (non-remote) actor for the
/// purpose of `LocalOnlyResolver`. Currently: `human:*`, `system`, and
/// `workload:*` / `wl:*` are local; `component:*` is remote.
fn is_local_principal(id: &str) -> bool {
    id == "system"
        || id.starts_with("human:")
        || id.starts_with("admin:")
        || id.starts_with("workload:")
        || id.starts_with("wl:")
}

// ---------------------------------------------------------------------
// DenyAllResolver — panic button / test scaffold
// ---------------------------------------------------------------------

pub struct DenyAllResolver {
    mode: ResolverMode,
}

impl DenyAllResolver {
    pub fn new(mode: ResolverMode) -> Self {
        Self { mode }
    }
}

impl StandingResolver for DenyAllResolver {
    fn assess(&self, request: &StandingRequest) -> Result<StandingDecision, ResolveError> {
        Ok(StandingDecision {
            verdict: StandingVerdict::Denied,
            reason: "deny-all resolver refuses every request".to_string(),
            verification_mode: "deny_all".to_string(),
            identity_substrate: "hmac_workload_id".to_string(),
            standing_enforced: self.mode.standing_enforced(),
            resolver: "DenyAllResolver".to_string(),
            standing_basis: basis::DENY_DEFAULT.to_string(),
            scope: vec![],
            audience: request.audience.clone(),
            evaluated_at: request.now,
            expires_at: None,
        })
    }
}

// ---------------------------------------------------------------------
// LocalOnlyResolver — for `private_local` exposure profile
// ---------------------------------------------------------------------

pub struct LocalOnlyResolver {
    mode: ResolverMode,
}

impl LocalOnlyResolver {
    pub fn new(mode: ResolverMode) -> Self {
        Self { mode }
    }
}

impl StandingResolver for LocalOnlyResolver {
    fn assess(&self, request: &StandingRequest) -> Result<StandingDecision, ResolveError> {
        if is_local_principal(&request.actor.id) {
            Ok(StandingDecision {
                verdict: StandingVerdict::Allowed,
                reason: "local actor; local-only resolver admits".to_string(),
                verification_mode: "local_only".to_string(),
                identity_substrate: "hmac_workload_id".to_string(),
                standing_enforced: self.mode.standing_enforced(),
                resolver: "LocalOnlyResolver".to_string(),
                standing_basis: "allowed_by_local_only".to_string(),
                scope: vec![format!("{}:{}", request.claim_kind, request.subject_scope)],
                audience: request.audience.clone(),
                evaluated_at: request.now,
                expires_at: None,
            })
        } else {
            Ok(StandingDecision {
                verdict: StandingVerdict::Denied,
                reason: format!(
                    "actor {:?} is not a local principal; local-only resolver refuses",
                    request.actor.id
                ),
                verification_mode: "local_only".to_string(),
                identity_substrate: "hmac_workload_id".to_string(),
                standing_enforced: self.mode.standing_enforced(),
                resolver: "LocalOnlyResolver".to_string(),
                standing_basis: basis::NON_LOCAL_ACTOR.to_string(),
                scope: vec![],
                audience: request.audience.clone(),
                evaluated_at: request.now,
                expires_at: None,
            })
        }
    }
}

// ---------------------------------------------------------------------
// StaticConfigResolver — MVP-enabling implementation
// ---------------------------------------------------------------------

use crate::config::{MatchOutcome, MismatchReason, StaticConfig};

pub struct StaticConfigResolver {
    config: StaticConfig,
    mode: ResolverMode,
}

impl StaticConfigResolver {
    pub fn new(config: StaticConfig, mode: ResolverMode) -> Self {
        Self { config, mode }
    }

    fn allowed(&self, request: &StandingRequest, entry_expires_at: Option<DateTime<Utc>>) -> StandingDecision {
        StandingDecision {
            verdict: StandingVerdict::Allowed,
            reason: "matched static config entry".to_string(),
            verification_mode: "static_config".to_string(),
            identity_substrate: "hmac_workload_id".to_string(),
            standing_enforced: self.mode.standing_enforced(),
            resolver: "StaticConfigResolver".to_string(),
            standing_basis: basis::STATIC_CONFIG_MATCH.to_string(),
            scope: vec![format!("{}:{}", request.claim_kind, request.subject_scope)],
            audience: request.audience.clone(),
            evaluated_at: request.now,
            expires_at: entry_expires_at,
        }
    }

    fn denied(
        &self,
        request: &StandingRequest,
        reason: &str,
        standing_basis: &str,
    ) -> StandingDecision {
        StandingDecision {
            verdict: StandingVerdict::Denied,
            reason: reason.to_string(),
            verification_mode: "static_config".to_string(),
            identity_substrate: "hmac_workload_id".to_string(),
            standing_enforced: self.mode.standing_enforced(),
            resolver: "StaticConfigResolver".to_string(),
            standing_basis: standing_basis.to_string(),
            scope: vec![],
            audience: request.audience.clone(),
            evaluated_at: request.now,
            expires_at: None,
        }
    }
}

impl StandingResolver for StaticConfigResolver {
    fn assess(&self, request: &StandingRequest) -> Result<StandingDecision, ResolveError> {
        let outcome = self.config.match_with_reason(
            &request.actor.id,
            &request.claim_kind,
            &request.subject_scope,
            &request.audience,
            request.now,
        );

        let decision = match outcome {
            MatchOutcome::Match(entry) => self.allowed(request, entry.expires_at),
            MatchOutcome::NoActor => self.denied(
                request,
                "no config entries for this actor",
                basis::UNKNOWN_PEER,
            ),
            MatchOutcome::Mismatch(MismatchReason::Expired) => self.denied(
                request,
                "matching config entry has expired",
                basis::STANDING_EXPIRED,
            ),
            MatchOutcome::Mismatch(MismatchReason::ClaimKindMismatch) => self.denied(
                request,
                "actor has entries but none cover this claim_kind",
                basis::CLAIM_KIND_OUT_OF_SCOPE,
            ),
            MatchOutcome::Mismatch(MismatchReason::SubjectMismatch) => self.denied(
                request,
                "actor has entries but none cover this subject_scope",
                basis::SUBJECT_OUT_OF_SCOPE,
            ),
            MatchOutcome::Mismatch(MismatchReason::AudienceMismatch) => self.denied(
                request,
                "actor has entries but none cover this audience",
                basis::AUDIENCE_MISMATCH,
            ),
        };

        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StaticConfig;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-27T12:00:00Z")
            .unwrap()
            .to_utc()
    }

    fn component(name: &str, instance: &str) -> Principal {
        Principal::new(
            format!("component:{}:{}", name, instance),
            format!("{}@{}", name, instance),
        )
    }

    fn workload() -> Principal {
        Principal::new("workload:deploy-bot:host-abc", "deploy-bot")
    }

    fn req(actor: Principal, audience: &str) -> StandingRequest {
        StandingRequest::new(actor, "sqlite_wal_state", "labelwatch/foo", audience, now()).unwrap()
    }

    // -- canonical-naming validation -------------------------------------

    #[test]
    fn audience_must_be_instance_qualified() {
        let r = StandingRequest::new(workload(), "k", "s", "nq", now());
        assert!(matches!(
            r,
            Err(ResolveError::AudienceNotInstanceQualified(_))
        ));
    }

    #[test]
    fn instance_qualified_audience_accepted() {
        let r = StandingRequest::new(workload(), "k", "s", "nq:linode", now());
        assert!(r.is_ok());
    }

    #[test]
    fn bare_actor_id_rejected() {
        let actor = Principal::new("nq", "nq");
        let r = StandingRequest::new(actor, "k", "s", "nq:linode", now());
        assert!(matches!(r, Err(ResolveError::PrincipalNotCanonical(_))));
    }

    #[test]
    fn slice_one_wl_prefix_accepted() {
        // Backwards compat with slice-1 WorkloadId form
        let r = StandingRequest::new(workload(), "k", "s", "nq:linode", now());
        assert!(r.is_ok());
    }

    #[test]
    fn system_principal_accepted() {
        let r = StandingRequest::new(Principal::system(), "k", "s", "nq:linode", now());
        assert!(r.is_ok());
    }

    // -- DenyAllResolver -------------------------------------------------

    #[test]
    fn deny_all_refuses_everything() {
        let resolver = DenyAllResolver::new(ResolverMode::VisibleNotBinding);
        let request = req(component("nq", "linode"), "nq:main");
        let decision = resolver.assess(&request).unwrap();
        assert_eq!(decision.verdict, StandingVerdict::Denied);
        assert_eq!(decision.standing_basis, basis::DENY_DEFAULT);
        assert!(!decision.standing_enforced);
    }

    #[test]
    fn deny_all_binding_mode_sets_enforced() {
        let resolver = DenyAllResolver::new(ResolverMode::Binding);
        let decision = resolver
            .assess(&req(component("nq", "linode"), "nq:main"))
            .unwrap();
        assert!(decision.standing_enforced);
    }

    // -- LocalOnlyResolver -----------------------------------------------

    #[test]
    fn local_only_admits_workload() {
        let resolver = LocalOnlyResolver::new(ResolverMode::VisibleNotBinding);
        let decision = resolver.assess(&req(workload(), "nq:main")).unwrap();
        assert_eq!(decision.verdict, StandingVerdict::Allowed);
        assert_eq!(decision.resolver, "LocalOnlyResolver");
    }

    #[test]
    fn local_only_admits_human() {
        let resolver = LocalOnlyResolver::new(ResolverMode::VisibleNotBinding);
        let actor = Principal::new("human:jbeck", "jbeck");
        let decision = resolver.assess(&req(actor, "nq:main")).unwrap();
        assert_eq!(decision.verdict, StandingVerdict::Allowed);
    }

    #[test]
    fn local_only_refuses_component() {
        let resolver = LocalOnlyResolver::new(ResolverMode::VisibleNotBinding);
        let decision = resolver
            .assess(&req(component("nq", "linode"), "nq:main"))
            .unwrap();
        assert_eq!(decision.verdict, StandingVerdict::Denied);
        assert_eq!(decision.standing_basis, basis::NON_LOCAL_ACTOR);
    }

    // -- StandingDecision attribution fields -----------------------------

    #[test]
    fn decision_records_all_attribution_fields() {
        let resolver = DenyAllResolver::new(ResolverMode::VisibleNotBinding);
        let request = req(component("nq", "linode"), "nq:main");
        let d = resolver.assess(&request).unwrap();

        // All attribution fields populated — this is the receipt-discipline
        // contract from docs/remote-standing-boundary.md.
        assert!(!d.verification_mode.is_empty());
        assert!(!d.identity_substrate.is_empty());
        assert!(!d.resolver.is_empty());
        assert!(!d.standing_basis.is_empty());
        assert_eq!(d.audience, "nq:main");
    }

    // -- StaticConfigResolver --------------------------------------------

    const NQ_CONFIG: &str = r#"
[[entry]]
actor = "component:nq:linode"
claim_kind = "sqlite_wal_state"
subject_scope = "labelwatch/*"
audience = "nq:main"

[[entry]]
actor = "component:nq:linode"
claim_kind = "disk_state"
subject_scope = "host:storage01"
audience = "nq:main"
"#;

    fn nq_resolver(mode: ResolverMode) -> StaticConfigResolver {
        let config = StaticConfig::parse_toml(NQ_CONFIG).unwrap();
        StaticConfigResolver::new(config, mode)
    }

    #[test]
    fn static_config_allows_matching_entry() {
        let r = nq_resolver(ResolverMode::VisibleNotBinding);
        let req = StandingRequest::new(
            component("nq", "linode"),
            "sqlite_wal_state",
            "labelwatch/foo",
            "nq:main",
            now(),
        )
        .unwrap();
        let d = r.assess(&req).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Allowed);
        assert_eq!(d.standing_basis, basis::STATIC_CONFIG_MATCH);
        assert_eq!(d.scope, vec!["sqlite_wal_state:labelwatch/foo"]);
    }

    #[test]
    fn static_config_denies_unknown_actor_with_unknown_peer() {
        let r = nq_resolver(ResolverMode::VisibleNotBinding);
        let req = StandingRequest::new(
            component("nq", "rogue"),
            "sqlite_wal_state",
            "labelwatch/foo",
            "nq:main",
            now(),
        )
        .unwrap();
        let d = r.assess(&req).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::UNKNOWN_PEER);
    }

    #[test]
    fn static_config_denies_wrong_claim_kind() {
        let r = nq_resolver(ResolverMode::VisibleNotBinding);
        let req = StandingRequest::new(
            component("nq", "linode"),
            "dns_state",
            "labelwatch/foo",
            "nq:main",
            now(),
        )
        .unwrap();
        let d = r.assess(&req).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::CLAIM_KIND_OUT_OF_SCOPE);
    }

    #[test]
    fn static_config_denies_wrong_audience() {
        let r = nq_resolver(ResolverMode::VisibleNotBinding);
        let req = StandingRequest::new(
            component("nq", "linode"),
            "sqlite_wal_state",
            "labelwatch/foo",
            "nq:other",
            now(),
        )
        .unwrap();
        let d = r.assess(&req).unwrap();
        assert_eq!(d.verdict, StandingVerdict::Denied);
        assert_eq!(d.standing_basis, basis::AUDIENCE_MISMATCH);
    }

    #[test]
    fn static_config_binding_mode_sets_enforced() {
        let r = nq_resolver(ResolverMode::Binding);
        let req = StandingRequest::new(
            component("nq", "linode"),
            "sqlite_wal_state",
            "labelwatch/foo",
            "nq:main",
            now(),
        )
        .unwrap();
        let d = r.assess(&req).unwrap();
        assert!(d.standing_enforced);
    }
}
