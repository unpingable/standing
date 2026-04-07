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

/// Default identity TTL: 1 hour.
pub const DEFAULT_TTL_SECS: i64 = 3600;

/// Default clock skew tolerance: 30 seconds.
pub const DEFAULT_SKEW_SECS: i64 = 30;

/// A workload identity claim.
///
/// Fields follow the JWT-ish convention (iat/exp/aud/jti) but this is
/// not JWT — it's a simpler HMAC-signed blob with explicit semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadId {
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
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_TTL_SECS,
            audience: "standing".to_string(),
        }
    }
}

/// Options for identity verification.
pub struct VerifyOptions {
    /// Expected audience. Verification fails if it doesn't match.
    pub expected_audience: String,
    /// Clock skew tolerance in seconds (default: 30)
    pub skew_secs: i64,
    /// Verifier's current time (default: Utc::now()). Exposed for testing.
    pub now: Option<DateTime<Utc>>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            expected_audience: "standing".to_string(),
            skew_secs: DEFAULT_SKEW_SECS,
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

    let signature = sign(&jti, &name, &location, &audience, &issued_at, &expires_at, secret)?;

    Ok(WorkloadId {
        jti,
        name,
        location,
        audience,
        issued_at,
        expires_at,
        signature,
    })
}

/// Verify a workload identity: signature, expiry, audience.
/// Returns AssessmentResult for every outcome — not just pass/fail.
pub fn verify_identity(
    id: &WorkloadId,
    secret: &[u8],
    opts: &VerifyOptions,
) -> AssessmentResult {
    // Step 1: Signature
    let expected = match sign(
        &id.jti, &id.name, &id.location, &id.audience,
        &id.issued_at, &id.expires_at, secret,
    ) {
        Ok(s) => s,
        Err(_) => return AssessmentResult::AssessmentCompromised,
    };
    if expected != id.signature {
        return AssessmentResult::InvalidSignature;
    }

    let now = opts.now.unwrap_or_else(Utc::now);
    let skew = Duration::seconds(opts.skew_secs);

    // Step 2: Not-yet-valid (issued_at in the future beyond skew)
    if id.issued_at > now + skew {
        return AssessmentResult::NotYetValid;
    }

    // Step 3: Expiry (with skew tolerance)
    if now > id.expires_at + skew {
        return AssessmentResult::Expired;
    }

    // Step 4: Audience
    if id.audience != opts.expected_audience {
        return AssessmentResult::AudienceMismatch;
    }

    AssessmentResult::Valid
}

/// Verify and resolve: fail-closed wrapper that returns VerifiedIdentity or error.
pub fn verify_and_resolve(
    id: &WorkloadId,
    secret: &[u8],
    opts: &VerifyOptions,
) -> Result<VerifiedIdentity, IdentityError> {
    let result = verify_identity(id, secret, opts);
    match result {
        AssessmentResult::Valid => Ok(VerifiedIdentity {
            principal_id: id.principal_id(),
            label: id.name.clone(),
            jti: id.jti.clone(),
            issuer_time: id.issued_at,
            verifier_time: opts.now.unwrap_or_else(Utc::now),
            audience: id.audience.clone(),
        }),
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

fn sign(
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

        // Verify as if we're 5 minutes in the past (beyond 30s skew)
        let past = Utc::now() - Duration::seconds(300);
        let vopts = VerifyOptions { now: Some(past), ..default_verify() };
        let result = verify_identity(&id, SECRET, &vopts);
        assert_eq!(result, AssessmentResult::NotYetValid);
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
}
