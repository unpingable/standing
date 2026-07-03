//! Static configuration for `StaticConfigResolver`.
//!
//! TOML format. Each entry names a single `(actor, claim_kind,
//! subject_scope, audience)` tuple that is allowed; everything not
//! matched is refused. Matching semantics are nailed down in
//! `docs/remote-standing-boundary.md` § "Scope matching semantics":
//!
//! - `actor`         exact match on canonical principal string
//! - `claim_kind`    exact match
//! - `subject_scope` exact OR trailing-`*` prefix on `/`-delimited path
//! - `audience`      exact (instance-qualified, e.g. `"nq:linode"`)
//!
//! Any change to matching semantics is a `kid`-level event — consumers
//! must be able to assume scope strings have stable meaning across
//! upgrades.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::resolver::ResolveError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticConfig {
    #[serde(default, rename = "entry")]
    pub entries: Vec<StaticConfigEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticConfigEntry {
    pub actor: String,
    pub claim_kind: String,
    pub subject_scope: String,
    pub audience: String,
    /// Optional expiry. If `None`, the entry is valid indefinitely
    /// (subject to operator-managed config rotation).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl StaticConfig {
    pub fn parse_toml(s: &str) -> Result<Self, ResolveError> {
        toml::from_str(s).map_err(|e| ResolveError::ConfigParse(e.to_string()))
    }

    pub fn load(path: &std::path::Path) -> Result<Self, ResolveError> {
        let s = std::fs::read_to_string(path).map_err(|e| ResolveError::ConfigIo(e.to_string()))?;
        Self::parse_toml(&s)
    }

    /// Find the first entry that matches all four dimensions.
    /// `None` means no entry matches; the resolver translates that into
    /// `Denied` with `standing_basis: static_config_no_match`.
    pub fn find_match(
        &self,
        actor_id: &str,
        claim_kind: &str,
        subject_scope: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> Option<&StaticConfigEntry> {
        self.entries
            .iter()
            .find(|e| e.matches(actor_id, claim_kind, subject_scope, audience, now))
    }

    /// Like `find_match`, but also returns the first dimension that
    /// caused the mismatch when there *is* an entry for this actor but
    /// the scope is wrong. Returns `MatchOutcome::NoActor` if the actor
    /// is not in the config at all (→ `unknown_peer`-shaped refusal).
    pub fn match_with_reason(
        &self,
        actor_id: &str,
        claim_kind: &str,
        subject_scope: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> MatchOutcome<'_> {
        let actor_entries: Vec<&StaticConfigEntry> =
            self.entries.iter().filter(|e| e.actor == actor_id).collect();

        if actor_entries.is_empty() {
            return MatchOutcome::NoActor;
        }

        // Track the most-informative mismatch across all actor entries.
        // Precedence (high → low): an entry that got *farther* into the
        // matching pipeline is more informative — if any entry matched
        // claim_kind, the actor clearly has a grant for this claim_kind,
        // just with the wrong scope/audience.
        //
        // depth: AudienceMismatch(3) > SubjectMismatch(2) > ClaimKindMismatch(1) > Expired(0)
        fn depth(r: MismatchReason) -> u8 {
            match r {
                MismatchReason::AudienceMismatch => 3,
                MismatchReason::SubjectMismatch => 2,
                MismatchReason::ClaimKindMismatch => 1,
                MismatchReason::Expired => 0,
            }
        }

        let mut best_mismatch: Option<MismatchReason> = None;
        for e in &actor_entries {
            let candidate = match e.classify(claim_kind, subject_scope, audience, now) {
                Classification::Match => return MatchOutcome::Match(e),
                Classification::Expired => MismatchReason::Expired,
                Classification::ClaimKindMismatch => MismatchReason::ClaimKindMismatch,
                Classification::SubjectMismatch => MismatchReason::SubjectMismatch,
                Classification::AudienceMismatch => MismatchReason::AudienceMismatch,
            };
            best_mismatch = Some(match best_mismatch {
                None => candidate,
                Some(prev) if depth(candidate) > depth(prev) => candidate,
                Some(prev) => prev,
            });
        }

        MatchOutcome::Mismatch(best_mismatch.unwrap_or(MismatchReason::SubjectMismatch))
    }
}

#[derive(Debug)]
pub enum MatchOutcome<'a> {
    Match(&'a StaticConfigEntry),
    /// Actor has no entries at all — refusal should map to
    /// `static_config_no_match` or `unknown_peer`.
    NoActor,
    /// Actor has entries but none cover this request; this names which
    /// dimension drove the mismatch for receipt attribution.
    Mismatch(MismatchReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchReason {
    Expired,
    ClaimKindMismatch,
    SubjectMismatch,
    AudienceMismatch,
}

enum Classification {
    Match,
    Expired,
    ClaimKindMismatch,
    SubjectMismatch,
    AudienceMismatch,
}

impl StaticConfigEntry {
    pub fn matches(
        &self,
        actor_id: &str,
        claim_kind: &str,
        subject_scope: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> bool {
        self.actor == actor_id
            && matches!(
                self.classify(claim_kind, subject_scope, audience, now),
                Classification::Match
            )
    }

    fn classify(
        &self,
        claim_kind: &str,
        subject_scope: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> Classification {
        if let Some(exp) = self.expires_at
            && now >= exp {
                return Classification::Expired;
            }
        if self.claim_kind != claim_kind {
            return Classification::ClaimKindMismatch;
        }
        if !subject_scope_matches(&self.subject_scope, subject_scope) {
            return Classification::SubjectMismatch;
        }
        if self.audience != audience {
            return Classification::AudienceMismatch;
        }
        Classification::Match
    }
}

// Subject-scope matching is now defined once in `standing_grant::assertion`
// (the `kid`-stable canonical definition), shared by the assertion-lease
// coverage check and this static-config resolver. Re-exported here so existing
// call sites (`classify`) and tests keep resolving `subject_scope_matches`.
pub use standing_grant::subject_scope_matches;

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-27T12:00:00Z")
            .unwrap()
            .to_utc()
    }

    // -- subject_scope_matches -------------------------------------------

    #[test]
    fn exact_subject_matches() {
        assert!(subject_scope_matches("host:storage01", "host:storage01"));
    }

    #[test]
    fn exact_subject_no_partial() {
        assert!(!subject_scope_matches("host:storage01", "host:storage"));
        assert!(!subject_scope_matches("host:storage01", "host:storage012"));
    }

    #[test]
    fn trailing_star_matches_subpath() {
        assert!(subject_scope_matches("labelwatch/*", "labelwatch/foo"));
        assert!(subject_scope_matches("labelwatch/*", "labelwatch/foo/bar"));
    }

    #[test]
    fn trailing_star_does_not_match_base() {
        // "labelwatch/*" requires at least one character after the slash
        assert!(!subject_scope_matches("labelwatch/*", "labelwatch"));
        assert!(!subject_scope_matches("labelwatch/*", "labelwatch/"));
    }

    #[test]
    fn trailing_star_does_not_match_sibling() {
        // No regex prefix-match without the slash boundary
        assert!(!subject_scope_matches("labelwatch/*", "labelwatchx"));
        assert!(!subject_scope_matches("labelwatch/*", "labelwatchx/foo"));
    }

    #[test]
    fn no_mid_glob_promoted_to_regex() {
        // a/*/b is not a valid pattern; falls back to exact-match
        assert!(!subject_scope_matches("a/*/b", "a/x/b"));
        assert!(subject_scope_matches("a/*/b", "a/*/b"));
    }

    // -- TOML parse / match ----------------------------------------------

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

    #[test]
    fn parses_toml() {
        let c = StaticConfig::parse_toml(NQ_CONFIG).unwrap();
        assert_eq!(c.entries.len(), 2);
        assert_eq!(c.entries[0].audience, "nq:main");
    }

    #[test]
    fn finds_exact_subject_match() {
        let c = StaticConfig::parse_toml(NQ_CONFIG).unwrap();
        let e = c.find_match(
            "component:nq:linode",
            "disk_state",
            "host:storage01",
            "nq:main",
            now(),
        );
        assert!(e.is_some());
    }

    #[test]
    fn finds_prefix_subject_match() {
        let c = StaticConfig::parse_toml(NQ_CONFIG).unwrap();
        let e = c.find_match(
            "component:nq:linode",
            "sqlite_wal_state",
            "labelwatch/foo/bar",
            "nq:main",
            now(),
        );
        assert!(e.is_some());
    }

    #[test]
    fn refuses_wrong_audience() {
        let c = StaticConfig::parse_toml(NQ_CONFIG).unwrap();
        let e = c.find_match(
            "component:nq:linode",
            "disk_state",
            "host:storage01",
            "nq:other",
            now(),
        );
        assert!(e.is_none());
    }

    #[test]
    fn refuses_unknown_actor() {
        let c = StaticConfig::parse_toml(NQ_CONFIG).unwrap();
        let outcome = c.match_with_reason(
            "component:nq:other",
            "disk_state",
            "host:storage01",
            "nq:main",
            now(),
        );
        assert!(matches!(outcome, MatchOutcome::NoActor));
    }

    #[test]
    fn match_reason_claim_kind() {
        let c = StaticConfig::parse_toml(NQ_CONFIG).unwrap();
        let outcome = c.match_with_reason(
            "component:nq:linode",
            "dns_state", // not in config
            "host:storage01",
            "nq:main",
            now(),
        );
        match outcome {
            MatchOutcome::Mismatch(MismatchReason::ClaimKindMismatch) => {}
            other => panic!("expected ClaimKindMismatch, got {:?}", other),
        }
    }

    #[test]
    fn match_reason_audience() {
        let c = StaticConfig::parse_toml(NQ_CONFIG).unwrap();
        let outcome = c.match_with_reason(
            "component:nq:linode",
            "disk_state",
            "host:storage01",
            "nq:somewhere-else",
            now(),
        );
        assert!(matches!(
            outcome,
            MatchOutcome::Mismatch(MismatchReason::AudienceMismatch)
        ));
    }

    #[test]
    fn expired_entry_does_not_match() {
        let cfg = r#"
[[entry]]
actor = "component:nq:linode"
claim_kind = "sqlite_wal_state"
subject_scope = "labelwatch/*"
audience = "nq:main"
expires_at = "2026-01-01T00:00:00Z"
"#;
        let c = StaticConfig::parse_toml(cfg).unwrap();
        let outcome = c.match_with_reason(
            "component:nq:linode",
            "sqlite_wal_state",
            "labelwatch/foo",
            "nq:main",
            now(),
        );
        assert!(matches!(
            outcome,
            MatchOutcome::Mismatch(MismatchReason::Expired)
        ));
    }
}
