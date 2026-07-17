//! Assertion-grant lease model — entitlement-to-**assert** (Phase 4b).
//!
//! Distinct from the single-use entitlement-to-**act** `Grant` in `grant.rs`.
//! An `AssertionGrant` is a **lease over many assertions**: actor A may assert
//! `claim_kind K` about `subject_scope S` into `audience B` within the window
//! `[not_before, expires_at]`. The lease sits in `Active` and is spent
//! repeatedly (`Active → Active`); each spend is freshness-checked and leaves a
//! receipt. See `docs/remote-standing-boundary.md` §§ 101-178.
//!
//! ## Reuse is bounded on purpose (Lean L1)
//!
//! `~/git/lean` `DeferredWitness.lean:247-268` prices lease reuse: a kind-scoped
//! lease with no use-count budget (`cap = ∞`) is a laundering surface — "blanket
//! clearance, re-smuggled." The certified-sound shape is `cap = k` (finite, with
//! forced re-witness on exhaustion). Hence `max_uses`: `Some(k)` is the bounded
//! middle; `None` is the unbounded frontier a caller must consciously opt into
//! and which the decision surface stamps as not-certified-sound.
//!
//! ## Window is `WithinValidity` + coherence, checked at spend time (Lean L2)
//!
//! `Freshness.lean` names `~/git/standing` as its consumer. Full Lean-`Fresh` is
//! `TemporallyCoherent ∧ DivergenceAcceptable ∧ WithinValidity`. This module
//! enforces `WithinValidity` (inclusive upper bound) + `TemporallyCoherent`
//! (refuse an incoherent window rather than silently pass). The clock-divergence
//! conjunct (skew) arrives in Phase 5; until then callers pass `skew = 0` and
//! may claim only `within_validity`, never full `Fresh`.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::principal::Principal;

/// The state of an assertion-grant lease.
///
/// Terminal states: `Expired`, `Revoked`, `Denied`, `Exhausted`. Unlike the
/// act-grant `GrantState`, there is no single-use `Used` terminal — the lease is
/// spent many times via the `Active → Active` self-loop — and no `Abandoned`
/// (a lease never spent simply expires). `Exhausted` is the use-budget terminal
/// (L1): a `max_uses = Some(k)` lease that has been spent `k` times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionGrantState {
    /// Lease requested, awaiting policy decision.
    Requested,
    /// Policy approved; lease live but not yet spent.
    Issued,
    /// Lease is being spent; STAYS here across many assertions.
    Active,
    /// Window closed (terminal).
    Expired,
    /// Explicitly revoked (terminal).
    Revoked,
    /// Policy refused the request (terminal).
    Denied,
    /// Use budget hit — `spend_count` reached `max_uses` (terminal; forces
    /// re-witness). See L1.
    Exhausted,
}

impl AssertionGrantState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            AssertionGrantState::Expired
                | AssertionGrantState::Revoked
                | AssertionGrantState::Denied
                | AssertionGrantState::Exhausted
        )
    }

    /// The allowed transitions from this state. Note the `Active → Active`
    /// self-loop: that IS the spend.
    pub fn allowed_transitions(&self) -> &[AssertionGrantState] {
        use AssertionGrantState::*;
        match self {
            Requested => &[Issued, Denied],
            Issued => &[Active, Expired, Revoked],
            Active => &[Active, Expired, Revoked, Exhausted],
            Expired | Revoked | Denied | Exhausted => &[],
        }
    }

    pub fn can_transition_to(&self, target: &AssertionGrantState) -> bool {
        self.allowed_transitions().contains(target)
    }
}

impl std::str::FromStr for AssertionGrantState {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "requested" => Ok(AssertionGrantState::Requested),
            "issued" => Ok(AssertionGrantState::Issued),
            "active" => Ok(AssertionGrantState::Active),
            "expired" => Ok(AssertionGrantState::Expired),
            "revoked" => Ok(AssertionGrantState::Revoked),
            "denied" => Ok(AssertionGrantState::Denied),
            "exhausted" => Ok(AssertionGrantState::Exhausted),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for AssertionGrantState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", self));
        f.write_str(&s)
    }
}

/// What an assertion lease covers: `claim_kind × subject_scope × audience`.
/// The `subject_scope` is a **coverage pattern** (per doc §123-140), matched
/// against a request's concrete `subject_id` by [`assertion_covers`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionScope {
    pub claim_kind: String,
    /// Coverage pattern (exact or trailing-`/*`), NOT a concrete subject id.
    pub subject_scope: String,
    /// Instance-qualified audience, e.g. `"nq:linode"`.
    pub audience: String,
}

/// A request to open an assertion lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionGrantRequest {
    /// The speaker this lease is bound to.
    pub actor: Principal,
    pub scope: AssertionScope,
    /// Front of the validity window.
    pub not_before: DateTime<Utc>,
    /// Requested lease duration in seconds (from `not_before`).
    pub duration_secs: u64,
    /// Use-count budget (L1). `None` = unbounded/kind-scope frontier.
    pub max_uses: Option<u64>,
    /// Arbitrary context for the policy engine.
    pub context: serde_json::Value,
}

/// An assertion lease: reusable, window-bounded, budget-bounded speech authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionGrant {
    pub id: Uuid,
    /// The speaker this lease is bound to (stable identity).
    pub actor: Principal,
    pub scope: AssertionScope,
    /// Front of the validity window.
    pub not_before: DateTime<Utc>,
    /// When the lease was issued.
    pub issued_at: DateTime<Utc>,
    /// Back of the validity window (lease boundary).
    pub expires_at: DateTime<Utc>,
    /// Use-count budget (L1). `None` = unbounded (must be stamped
    /// not-certified-sound at the decision surface).
    pub max_uses: Option<u64>,
    /// How many times the lease has been spent.
    pub spend_count: u64,
}

/// Where `now` falls relative to a lease window. `Incoherent` is a refusal, not
/// a pass — an un-orderable window is unknown, and unknown poisons pass (L2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    /// `now` is before `not_before` (minus skew).
    NotYetValid,
    /// `now` is within `[not_before - skew, expires_at + skew]`.
    Within,
    /// `now` is after `expires_at` (plus skew).
    Expired,
    /// `not_before >= expires_at` — the window is not coherent; refuse.
    Incoherent,
}

impl AssertionGrant {
    /// Classify `now` against the window. Follows Lean `WithinValidity`
    /// (inclusive upper bound `now <= expires + skew`) plus `TemporallyCoherent`
    /// (refuse on incoherent ordering). In Wave 1 callers pass `skew = 0`; the
    /// clock-divergence term arrives in Phase 5.
    pub fn window_state(&self, now: DateTime<Utc>, skew: Duration) -> WindowState {
        // Coherence first (L2): an incoherent window is refused, not passed.
        if self.not_before >= self.expires_at {
            return WindowState::Incoherent;
        }
        if now < self.not_before - skew {
            return WindowState::NotYetValid;
        }
        // Inclusive upper bound per Lean WithinValidity: valid through
        // now == expires_at (+ skew), expired strictly after.
        if now > self.expires_at + skew {
            return WindowState::Expired;
        }
        WindowState::Within
    }

    /// True if the use budget is spent (L1). Unbounded leases (`None`) are never
    /// exhausted — but they carry the not-certified-sound stamp instead.
    pub fn is_exhausted(&self) -> bool {
        matches!(self.max_uses, Some(m) if self.spend_count >= m)
    }

    /// Remaining spends, or `None` for an unbounded lease.
    pub fn budget_remaining(&self) -> Option<u64> {
        self.max_uses.map(|m| m.saturating_sub(self.spend_count))
    }
}

/// Version marker for the per-request proof body. Bumped if the signed field
/// set changes (amendment #4 pins the set NOW so Wave 2's MAC signs a fixed
/// shape — no proof-shape archaeology).
pub const PROOF_VERSION: &str = "standing.request_proof.v1";

/// Version marker for the per-spend `AssertionMade` receipt evidence.
pub const ASSERTION_MADE_VERSION: &str = "standing.assertion_made.v1";

/// A per-request proof that a spend is being made under a lease. The Kerberos
/// "request" half of the grant/request split (doc §153-178): the lease is
/// reusable, but each spend carries a fresh, single-use `jti` and names the
/// exact `subject_id` / `body_digest` it attests to.
///
/// The field set is the canonical signed body (amendment #4). Wave 1 records
/// it; Wave 2 adds a `mac` over `canonical_json` of exactly these fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestProof {
    pub grant_id: Uuid,
    /// Speaker principal id.
    pub actor: String,
    pub claim_kind: String,
    /// Concrete subject (matched against the lease's `subject_scope`).
    pub subject_id: String,
    pub audience: String,
    /// Single-use replay nonce, unique per audience.
    pub jti: String,
    /// SHA-256 of the canonical request body this assertion attests to.
    pub body_digest: Option<String>,
    /// When the proof was minted (freshness anchor; signed in Wave 2).
    pub issued_at: DateTime<Utc>,
}

impl RequestProof {
    /// The canonical proof body as JSON — the exact object Wave 2 will MAC.
    /// Keeping this in one place means the signed shape is fixed from Wave 1.
    pub fn canonical_body(&self) -> serde_json::Value {
        serde_json::json!({
            "proof_version": PROOF_VERSION,
            "grant_id": self.grant_id.to_string(),
            "actor": self.actor,
            "claim_kind": self.claim_kind,
            "subject_id": self.subject_id,
            "audience": self.audience,
            "body_digest": self.body_digest,
            "jti": self.jti,
            "issued_at": self.issued_at.to_rfc3339(),
        })
    }
}

/// The outcome of matching a lease's scope against a concrete request. The
/// mismatch axis maps 1:1 onto the `basis::*` refusal constants so the decision
/// surface can name exactly which dimension failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertCoverage {
    Covered,
    ClaimKindMismatch,
    SubjectMismatch,
    AudienceMismatch,
}

/// Does `scope` cover a concrete request? Order is claim_kind → subject →
/// audience, so the emitted basis is deterministic. `claim_kind` and `audience`
/// are exact; `subject_scope` covers `subject_id` by [`subject_scope_matches`]
/// (the same prefix semantics the static-config resolver uses).
pub fn assertion_covers(
    scope: &AssertionScope,
    req_claim_kind: &str,
    req_subject_id: &str,
    req_audience: &str,
) -> AssertCoverage {
    if scope.claim_kind != req_claim_kind {
        return AssertCoverage::ClaimKindMismatch;
    }
    if !subject_scope_matches(&scope.subject_scope, req_subject_id) {
        return AssertCoverage::SubjectMismatch;
    }
    if scope.audience != req_audience {
        return AssertCoverage::AudienceMismatch;
    }
    AssertCoverage::Covered
}

/// Subject-scope matching: exact OR trailing-`*` prefix on `/`-delimited
/// path segments. `"labelwatch/*"` matches `"labelwatch/foo"` and
/// `"labelwatch/foo/bar"` but not `"labelwatchx"` and not `"labelwatch"`
/// (no segments after the slash).
///
/// No regex. No glob beyond a trailing `*`. The `*` must be the last
/// segment after a `/` — `"a/*/b"` is not a valid pattern and falls back
/// to exact match (so it will not match anything other than itself).
///
/// This is the canonical definition, shared by the assertion-lease coverage
/// check ([`assertion_covers`]) and `standing_policy::config` (which re-exports
/// it). Any change is a `kid`-level event — consumers assume scope strings have
/// stable meaning across upgrades.
pub fn subject_scope_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == candidate {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        // Candidate must start with "<prefix>/" AND have at least one
        // character after — empty trailing segment doesn't count.
        if let Some(rest) = candidate.strip_prefix(prefix) {
            return rest.starts_with('/') && rest.len() > 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().to_utc()
    }

    fn lease(
        not_before: &str,
        expires_at: &str,
        max_uses: Option<u64>,
        spend_count: u64,
    ) -> AssertionGrant {
        AssertionGrant {
            id: Uuid::new_v4(),
            actor: Principal::new("component:nq:linode", "nq@linode"),
            scope: AssertionScope {
                claim_kind: "sqlite_wal_state".into(),
                subject_scope: "labelwatch/*".into(),
                audience: "nq:main".into(),
            },
            not_before: t(not_before),
            issued_at: t(not_before),
            expires_at: t(expires_at),
            max_uses,
            spend_count,
        }
    }

    // -- state machine ---------------------------------------------------

    #[test]
    fn active_self_loop_is_allowed() {
        assert!(AssertionGrantState::Active.can_transition_to(&AssertionGrantState::Active));
    }

    #[test]
    fn terminals_allow_nothing() {
        for s in [
            AssertionGrantState::Expired,
            AssertionGrantState::Revoked,
            AssertionGrantState::Denied,
            AssertionGrantState::Exhausted,
        ] {
            assert!(s.is_terminal());
            assert!(s.allowed_transitions().is_empty());
        }
    }

    #[test]
    fn cannot_skip_to_active_from_requested() {
        assert!(!AssertionGrantState::Requested.can_transition_to(&AssertionGrantState::Active));
    }

    #[test]
    fn state_roundtrips_through_string() {
        for s in [
            AssertionGrantState::Requested,
            AssertionGrantState::Issued,
            AssertionGrantState::Active,
            AssertionGrantState::Expired,
            AssertionGrantState::Revoked,
            AssertionGrantState::Denied,
            AssertionGrantState::Exhausted,
        ] {
            assert_eq!(s.to_string().parse::<AssertionGrantState>(), Ok(s));
        }
    }

    // -- window (L2) -----------------------------------------------------

    #[test]
    fn window_within_and_edges() {
        let g = lease("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", None, 0);
        let z = Duration::zero();
        assert_eq!(
            g.window_state(t("2026-01-01T12:00:00Z"), z),
            WindowState::Within
        );
        // Inclusive upper bound: valid AT expiry.
        assert_eq!(
            g.window_state(t("2026-01-02T00:00:00Z"), z),
            WindowState::Within
        );
        // Strictly after expiry: expired.
        assert_eq!(
            g.window_state(t("2026-01-02T00:00:01Z"), z),
            WindowState::Expired
        );
        assert_eq!(
            g.window_state(t("2025-12-31T23:59:59Z"), z),
            WindowState::NotYetValid
        );
    }

    #[test]
    fn incoherent_window_refused_not_passed() {
        // not_before after expires — unknown ordering poisons pass (L2).
        let g = lease("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z", None, 0);
        assert_eq!(
            g.window_state(t("2026-01-01T12:00:00Z"), Duration::zero()),
            WindowState::Incoherent
        );
    }

    #[test]
    fn skew_widens_both_edges() {
        let g = lease("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", None, 0);
        let skew = Duration::seconds(30);
        // 20s before not_before, within skew grace → Within.
        assert_eq!(
            g.window_state(t("2025-12-31T23:59:40Z"), skew),
            WindowState::Within
        );
        // 20s after expiry, within skew grace → Within.
        assert_eq!(
            g.window_state(t("2026-01-02T00:00:20Z"), skew),
            WindowState::Within
        );
    }

    // -- budget (L1) -----------------------------------------------------

    #[test]
    fn bounded_lease_exhausts() {
        let g = lease("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", Some(3), 3);
        assert!(g.is_exhausted());
        assert_eq!(g.budget_remaining(), Some(0));
    }

    #[test]
    fn bounded_lease_with_budget_left() {
        let g = lease("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", Some(3), 1);
        assert!(!g.is_exhausted());
        assert_eq!(g.budget_remaining(), Some(2));
    }

    #[test]
    fn unbounded_lease_never_exhausts() {
        let g = lease(
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
            None,
            1_000_000,
        );
        assert!(!g.is_exhausted());
        assert_eq!(g.budget_remaining(), None);
    }

    // -- coverage --------------------------------------------------------

    fn scope() -> AssertionScope {
        AssertionScope {
            claim_kind: "sqlite_wal_state".into(),
            subject_scope: "labelwatch/*".into(),
            audience: "nq:main".into(),
        }
    }

    #[test]
    fn covers_matching_request() {
        assert_eq!(
            assertion_covers(&scope(), "sqlite_wal_state", "labelwatch/foo", "nq:main"),
            AssertCoverage::Covered
        );
    }

    #[test]
    fn coverage_names_the_failing_axis() {
        assert_eq!(
            assertion_covers(&scope(), "dns_state", "labelwatch/foo", "nq:main"),
            AssertCoverage::ClaimKindMismatch
        );
        assert_eq!(
            assertion_covers(&scope(), "sqlite_wal_state", "other/foo", "nq:main"),
            AssertCoverage::SubjectMismatch
        );
        assert_eq!(
            assertion_covers(&scope(), "sqlite_wal_state", "labelwatch/foo", "nq:other"),
            AssertCoverage::AudienceMismatch
        );
    }

    // -- subject_scope_matches (kid-stable; mirror of the config tests) --

    #[test]
    fn exact_and_prefix_and_no_mid_glob() {
        assert!(subject_scope_matches("host:storage01", "host:storage01"));
        assert!(subject_scope_matches("labelwatch/*", "labelwatch/foo/bar"));
        assert!(!subject_scope_matches("labelwatch/*", "labelwatch"));
        assert!(!subject_scope_matches("labelwatch/*", "labelwatchx"));
        assert!(!subject_scope_matches("a/*/b", "a/x/b"));
        assert!(subject_scope_matches("a/*/b", "a/*/b"));
    }
}
