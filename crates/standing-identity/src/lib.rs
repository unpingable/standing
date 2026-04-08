//! Workload identity for standing.
//!
//! HMAC-signed identity claims with expiry, audience restriction, and
//! unique claim IDs. Not a PKI opera — just a credible, temporally
//! bounded, audience-scoped claim.

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Current schema version for identity claims.
pub const SCHEMA_VERSION: u32 = 1;

/// Default identity TTL: 1 hour.
pub const DEFAULT_TTL_SECS: i64 = 3600;

/// Default clock skew tolerance: 30 seconds.
pub const DEFAULT_SKEW_SECS: i64 = 30;

/// Default key ID when none specified.
pub const DEFAULT_KID: &str = "default";

/// A workload identity claim.
///
/// Fields follow the JWT-ish convention (iat/exp/aud/jti) but this is
/// not JWT — it's a simpler HMAC-signed blob with explicit semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadId {
    /// Schema version. Verifiers must reject unknown versions.
    pub schema_version: u32,
    /// Key ID used to sign this claim. Verifier uses this to select
    /// the correct secret for verification.
    pub kid: String,
    /// Unique claim ID (jti). For replay detection.
    pub jti: String,
    /// Name of the workload (e.g., "deploy-bot")
    pub name: String,
    /// Where it's running (e.g., "host-abc", "k8s/ns/pod")
    pub location: String,
    /// Intended audience (e.g., "standing:prod", "standing:staging")
    pub audience: String,
    /// When this identity was issued (iat)
    pub issued_at: DateTime<Utc>,
    /// When this identity expires (exp)
    pub expires_at: DateTime<Utc>,
    /// HMAC-SHA256 signature over all fields above
    pub signature: String,
}

impl WorkloadId {
    /// Stable opaque principal ID derived from this identity.
    /// Format: "wl:{name}:{location}"
    pub fn principal_id(&self) -> String {
        format!("wl:{}:{}", self.name, self.location)
    }

    /// Human-readable display label.
    pub fn label(&self) -> &str {
        &self.name
    }
}

/// Assessment result: not just pass/fail, but why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentResult {
    /// Identity verified successfully
    Valid,
    /// Signature does not match
    InvalidSignature,
    /// Identity has expired (beyond skew tolerance)
    Expired,
    /// Audience does not match expected audience
    AudienceMismatch,
    /// Identity is not yet valid (issued_at in the future beyond skew)
    NotYetValid,
    /// This jti has already been presented within its validity window
    ReplayDetected,
    /// Schema version is not supported by this verifier
    UnsupportedVersion,
    /// Key ID is not known to this verifier
    UnknownKeyId,
    /// Cannot safely determine standing (e.g., clock uncertainty)
    AssessmentCompromised,
}

/// Errors from identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity assessment: {result:?} — {detail}")]
    Assessment {
        result: AssessmentResult,
        detail: String,
    },

    #[error("HMAC error: {0}")]
    Hmac(String),
}

/// Options for identity creation.
pub struct CreateOptions {
    /// TTL in seconds (default: 3600)
    pub ttl_secs: i64,
    /// Audience (e.g., "standing:prod")
    pub audience: String,
    /// Key ID (default: "default")
    pub kid: String,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_TTL_SECS,
            audience: "standing".to_string(),
            kid: DEFAULT_KID.to_string(),
        }
    }
}

/// Options for identity verification.
pub struct VerifyOptions {
    /// Expected audience. Verification fails if it doesn't match.
    pub expected_audience: String,
    /// Clock skew tolerance in seconds (default: 30)
    pub skew_secs: i64,
    /// Maximum acceptable gap between issuer time and verifier time (default: 300s).
    /// If the gap exceeds this, the assessment is compromised — we cannot
    /// confidently evaluate freshness.
    pub max_clock_divergence_secs: i64,
    /// Verifier's current time (default: Utc::now()). Exposed for testing.
    pub now: Option<DateTime<Utc>>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            expected_audience: "standing".to_string(),
            skew_secs: DEFAULT_SKEW_SECS,
            max_clock_divergence_secs: 300,
            now: None,
        }
    }
}

/// Create a signed workload identity.
pub fn create_identity(
    name: impl Into<String>,
    location: impl Into<String>,
    secret: &[u8],
    opts: &CreateOptions,
) -> Result<WorkloadId, IdentityError> {
    let name = name.into();
    let location = location.into();
    let jti = Uuid::new_v4().to_string();
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::seconds(opts.ttl_secs);
    let audience = opts.audience.clone();
    let kid = opts.kid.clone();

    let signature = sign(SCHEMA_VERSION, &kid, &jti, &name, &location, &audience, &issued_at, &expires_at, secret)?;

    Ok(WorkloadId {
        schema_version: SCHEMA_VERSION,
        kid,
        jti,
        name,
        location,
        audience,
        issued_at,
        expires_at,
        signature,
    })
}

/// Verify a workload identity: version, signature, expiry, audience.
/// Returns AssessmentResult for every outcome — not just pass/fail.
///
/// The `secret` parameter is the key material for the claim's `kid`.
/// Callers should resolve kid → secret before calling this function.
/// If the kid is unknown, return `AssessmentResult::UnknownKeyId` directly.
pub fn verify_identity(
    id: &WorkloadId,
    secret: &[u8],
    opts: &VerifyOptions,
) -> AssessmentResult {
    // Step 0: Schema version — reject unknown versions before anything else.
    // This is the one check that must survive all future evolution.
    if id.schema_version != SCHEMA_VERSION {
        return AssessmentResult::UnsupportedVersion;
    }

    // Step 1: Signature (includes schema_version and kid in the MAC)
    let expected = match sign(
        id.schema_version, &id.kid, &id.jti, &id.name, &id.location, &id.audience,
        &id.issued_at, &id.expires_at, secret,
    ) {
        Ok(s) => s,
        Err(_) => return AssessmentResult::AssessmentCompromised,
    };
    if expected != id.signature {
        return AssessmentResult::InvalidSignature;
    }

    // Step 2: Temporal coherence — expires_at must be after issued_at.
    // A signed assertion where expiry precedes issuance is either a
    // compromised issuer or a clock disaster. Either way, we cannot
    // assess standing.
    if id.expires_at <= id.issued_at {
        return AssessmentResult::AssessmentCompromised;
    }

    let now = opts.now.unwrap_or_else(Utc::now);
    let skew = Duration::seconds(opts.skew_secs);

    // Step 3: Clock divergence — if verifier time and issuer time are
    // too far apart, we cannot confidently evaluate freshness. The
    // signature is valid but the temporal assessment is unreliable.
    let divergence = (now - id.issued_at).num_seconds().abs();
    let max_divergence = opts.max_clock_divergence_secs;
    if divergence > max_divergence {
        // Exception: if the identity is clearly expired (well past
        // expires_at + skew + divergence budget), we can still say
        // "expired" with confidence even under clock uncertainty.
        if now > id.expires_at + Duration::seconds(max_divergence) {
            return AssessmentResult::Expired;
        }
        return AssessmentResult::AssessmentCompromised;
    }

    // Step 4: Not-yet-valid (issued_at in the future beyond skew)
    if id.issued_at > now + skew {
        return AssessmentResult::NotYetValid;
    }

    // Step 5: Expiry (with skew tolerance)
    if now > id.expires_at + skew {
        return AssessmentResult::Expired;
    }

    // Step 6: Audience
    if id.audience != opts.expected_audience {
        return AssessmentResult::AudienceMismatch;
    }

    AssessmentResult::Valid
}

/// Verify and resolve: fail-closed wrapper that returns VerifiedIdentity or error.
///
/// If a `replay_guard` is provided, the jti is checked for replay.
/// If None, replay detection is skipped (caller's responsibility).
pub fn verify_and_resolve(
    id: &WorkloadId,
    secret: &[u8],
    opts: &VerifyOptions,
) -> Result<VerifiedIdentity, IdentityError> {
    verify_and_resolve_with_replay(id, secret, opts, None)
}

/// Verify and resolve with explicit replay guard.
pub fn verify_and_resolve_with_replay(
    id: &WorkloadId,
    secret: &[u8],
    opts: &VerifyOptions,
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<VerifiedIdentity, IdentityError> {
    let result = verify_identity(id, secret, opts);
    match result {
        AssessmentResult::Valid => {
            // Replay check (after all other checks pass)
            if let Some(guard) = replay_guard {
                match guard.check_and_record(&id.jti, &id.audience, id.expires_at) {
                    Ok(true) => {} // New jti, proceed
                    Ok(false) => {
                        return Err(IdentityError::Assessment {
                            result: AssessmentResult::ReplayDetected,
                            detail: format!(
                                "jti {} already presented for audience {}",
                                id.jti, id.audience
                            ),
                        });
                    }
                    Err(e) => {
                        // Storage failure → assessment compromised
                        return Err(IdentityError::Assessment {
                            result: AssessmentResult::AssessmentCompromised,
                            detail: format!("replay guard error: {e}"),
                        });
                    }
                }
            }

            Ok(VerifiedIdentity {
                principal_id: id.principal_id(),
                label: id.name.clone(),
                jti: id.jti.clone(),
                issuer_time: id.issued_at,
                verifier_time: opts.now.unwrap_or_else(Utc::now),
                audience: id.audience.clone(),
            })
        }
        _ => Err(IdentityError::Assessment {
            detail: format!(
                "workload {} (aud: {}, exp: {})",
                id.name, id.audience, id.expires_at.to_rfc3339()
            ),
            result,
        }),
    }
}

/// A verified identity — the output of successful verification.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub principal_id: String,
    pub label: String,
    pub jti: String,
    pub issuer_time: DateTime<Utc>,
    pub verifier_time: DateTime<Utc>,
    pub audience: String,
}

/// Replay guard: tracks seen jti values to detect duplicate presentations.
///
/// Implementors should:
/// - Store (jti, audience) pairs with their expiry time
/// - Return true from `check_and_record` if the jti is new (not seen before)
/// - Return false if the jti has already been seen within its validity window
/// - Periodically purge entries past their expiry + skew
pub trait ReplayGuard {
    /// Check if this jti+audience pair has been seen before.
    /// If new, record it and return Ok(true).
    /// If already seen, return Ok(false).
    /// Errors are storage failures.
    fn check_and_record(
        &mut self,
        jti: &str,
        audience: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, String>;

    /// Purge expired entries. Call periodically.
    fn purge_expired(&mut self) -> Result<u64, String>;
}

fn sign(
    schema_version: u32,
    kid: &str,
    jti: &str,
    name: &str,
    location: &str,
    audience: &str,
    issued_at: &DateTime<Utc>,
    expires_at: &DateTime<Utc>,
    secret: &[u8],
) -> Result<String, IdentityError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| IdentityError::Hmac(e.to_string()))?;
    // schema_version and kid are part of the signed payload —
    // changing either invalidates the signature.
    mac.update(schema_version.to_string().as_bytes());
    mac.update(b"|");
    mac.update(kid.as_bytes());
    mac.update(b"|");
    mac.update(jti.as_bytes());
    mac.update(b"|");
    mac.update(name.as_bytes());
    mac.update(b"|");
    mac.update(location.as_bytes());
    mac.update(b"|");
    mac.update(audience.as_bytes());
    mac.update(b"|");
    mac.update(issued_at.to_rfc3339().as_bytes());
    mac.update(b"|");
    mac.update(expires_at.to_rfc3339().as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret";

    fn default_opts() -> CreateOptions {
        CreateOptions::default()
    }

    fn default_verify() -> VerifyOptions {
        VerifyOptions::default()
    }

    #[test]
    fn create_and_verify() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        let result = verify_identity(&id, SECRET, &default_verify());
        assert_eq!(result, AssessmentResult::Valid);
    }

    #[test]
    fn has_jti() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        assert!(!id.jti.is_empty());
        // jti should be a valid UUID
        assert!(id.jti.parse::<Uuid>().is_ok());
    }

    #[test]
    fn wrong_secret_is_invalid_signature() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        let result = verify_identity(&id, b"wrong", &default_verify());
        assert_eq!(result, AssessmentResult::InvalidSignature);
    }

    #[test]
    fn tampered_name_is_invalid_signature() {
        let mut id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        id.name = "evil".to_string();
        let result = verify_identity(&id, SECRET, &default_verify());
        assert_eq!(result, AssessmentResult::InvalidSignature);
    }

    #[test]
    fn expired_identity_rejected() {
        let opts = CreateOptions { ttl_secs: 1, ..default_opts() };
        let id = create_identity("bot", "host-1", SECRET, &opts).unwrap();

        // Verify at now + 60s (well past 1s TTL + 30s skew)
        let future = Utc::now() + Duration::seconds(60);
        let vopts = VerifyOptions { now: Some(future), ..default_verify() };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::Expired);
    }

    #[test]
    fn not_yet_expired_within_skew_accepted() {
        let opts = CreateOptions { ttl_secs: 1, ..default_opts() };
        let id = create_identity("bot", "host-1", SECRET, &opts).unwrap();

        // Verify at now + 2s — past TTL but within 30s skew
        let near_future = Utc::now() + Duration::seconds(2);
        let vopts = VerifyOptions { now: Some(near_future), ..default_verify() };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::Valid);
    }

    #[test]
    fn wrong_audience_rejected() {
        let opts = CreateOptions {
            audience: "standing:prod".to_string(),
            ..default_opts()
        };
        let id = create_identity("bot", "host-1", SECRET, &opts).unwrap();

        let vopts = VerifyOptions {
            expected_audience: "standing:staging".to_string(),
            ..default_verify()
        };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::AudienceMismatch);
    }

    #[test]
    fn correct_audience_accepted() {
        let opts = CreateOptions {
            audience: "standing:prod".to_string(),
            ..default_opts()
        };
        let id = create_identity("bot", "host-1", SECRET, &opts).unwrap();

        let vopts = VerifyOptions {
            expected_audience: "standing:prod".to_string(),
            ..default_verify()
        };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::Valid);
    }

    #[test]
    fn future_issued_at_rejected() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();

        // Verify as if we're 60s in the past (beyond 30s skew, within 300s divergence)
        let past = Utc::now() - Duration::seconds(60);
        let vopts = VerifyOptions { now: Some(past), ..default_verify() };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::NotYetValid);
    }

    // ---------------------------------------------------------------
    // AssessmentCompromised conditions
    // ---------------------------------------------------------------

    #[test]
    fn temporal_incoherence_is_compromised() {
        // expires_at before issued_at — signed but nonsensical
        let mut id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        let bad_expires = id.issued_at - Duration::seconds(100);
        // Re-sign with the bad expiry so signature is valid
        id.expires_at = bad_expires;
        id.signature = sign(
            id.schema_version, &id.kid, &id.jti, &id.name, &id.location, &id.audience,
            &id.issued_at, &id.expires_at, SECRET,
        ).unwrap();

        let result = verify_identity(&id, SECRET, &default_verify());
        assert_eq!(result, AssessmentResult::AssessmentCompromised);
    }

    #[test]
    fn extreme_clock_divergence_is_compromised() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();

        // Verifier clock is 10 minutes behind issuer (beyond 300s max divergence)
        let way_past = Utc::now() - Duration::seconds(601);
        let vopts = VerifyOptions { now: Some(way_past), ..default_verify() };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::AssessmentCompromised);
    }

    #[test]
    fn extreme_clock_divergence_forward_is_compromised() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();

        // Verifier clock is 10 minutes ahead of issuer (beyond 300s max divergence)
        // But identity is not yet expired (1hr TTL), so this is clock uncertainty
        let way_future = Utc::now() + Duration::seconds(601);
        let vopts = VerifyOptions { now: Some(way_future), ..default_verify() };
        let result = verify_identity(&id, SECRET, &vopts);
        // Within the identity's lifetime but beyond divergence budget —
        // we can't trust our temporal assessment
        assert_eq!(result, AssessmentResult::AssessmentCompromised);
    }

    #[test]
    fn extreme_divergence_but_clearly_expired_is_expired() {
        // If the identity is so old that even accounting for max divergence
        // it's definitely expired, we can say Expired with confidence
        let opts = CreateOptions { ttl_secs: 10, ..default_opts() };
        let id = create_identity("bot", "host-1", SECRET, &opts).unwrap();

        // Verifier is 20 minutes in the future — way beyond divergence,
        // but also way beyond the 10s TTL + 300s divergence budget
        let way_future = Utc::now() + Duration::seconds(1200);
        let vopts = VerifyOptions { now: Some(way_future), ..default_verify() };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::Expired);
    }

    #[test]
    fn tight_divergence_budget_catches_moderate_skew() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();

        // Tighten max divergence to 10s
        let slightly_past = Utc::now() - Duration::seconds(15);
        let vopts = VerifyOptions {
            now: Some(slightly_past),
            max_clock_divergence_secs: 10,
            ..default_verify()
        };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::AssessmentCompromised);
    }

    #[test]
    fn verify_and_resolve_returns_times() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        let verified = verify_and_resolve(&id, SECRET, &default_verify()).unwrap();
        assert_eq!(verified.principal_id, "wl:bot:host-1");
        assert_eq!(verified.audience, "standing");
        assert!(!verified.jti.is_empty());
        // Issuer time should be close to verifier time
        let diff = (verified.verifier_time - verified.issuer_time).num_seconds().abs();
        assert!(diff < 5);
    }

    #[test]
    fn verify_and_resolve_fails_closed() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        let err = verify_and_resolve(&id, b"wrong", &default_verify()).unwrap_err();
        match err {
            IdentityError::Assessment { result, .. } => {
                assert_eq!(result, AssessmentResult::InvalidSignature);
            }
            _ => panic!("expected Assessment error"),
        }
    }

    // ---------------------------------------------------------------
    // Schema version and kid
    // ---------------------------------------------------------------

    #[test]
    fn identity_has_schema_version_and_kid() {
        let id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        assert_eq!(id.schema_version, SCHEMA_VERSION);
        assert_eq!(id.kid, "default");
    }

    #[test]
    fn custom_kid() {
        let opts = CreateOptions {
            kid: "prod-key-2026".to_string(),
            ..default_opts()
        };
        let id = create_identity("bot", "host-1", SECRET, &opts).unwrap();
        assert_eq!(id.kid, "prod-key-2026");

        let result = verify_identity(&id, SECRET, &default_verify());
        assert_eq!(result, AssessmentResult::Valid);
    }

    #[test]
    fn unknown_schema_version_rejected() {
        let mut id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        // Tamper the version (signature will mismatch, but version check is first)
        id.schema_version = 99;

        let result = verify_identity(&id, SECRET, &default_verify());
        assert_eq!(result, AssessmentResult::UnsupportedVersion);
    }

    #[test]
    fn version_zero_rejected() {
        let mut id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        id.schema_version = 0;

        let result = verify_identity(&id, SECRET, &default_verify());
        assert_eq!(result, AssessmentResult::UnsupportedVersion);
    }

    #[test]
    fn tampered_kid_fails_signature() {
        let mut id = create_identity("bot", "host-1", SECRET, &default_opts()).unwrap();
        // kid is part of the signature — changing it without re-signing fails
        id.kid = "stolen-key".to_string();

        let result = verify_identity(&id, SECRET, &default_verify());
        assert_eq!(result, AssessmentResult::InvalidSignature);
    }
}
