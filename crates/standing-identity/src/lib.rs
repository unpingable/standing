//! Workload identity for standing.
//!
//! Minimal: HMAC-signed identity blob. Enough to distinguish "deploy-bot on
//! host X" from "unknown." Not a PKI opera — just a credible claim.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A workload identity claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadId {
    /// Name of the workload (e.g., "deploy-bot")
    pub name: String,
    /// Where it's running (e.g., "host-abc", "k8s/ns/pod")
    pub location: String,
    /// When this identity was created
    pub created_at: DateTime<Utc>,
    /// HMAC-SHA256 signature over (name|location|created_at)
    pub signature: String,
}

/// Errors from identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid signature for workload {0}")]
    InvalidSignature(String),

    #[error("HMAC error: {0}")]
    Hmac(String),
}

/// Create a signed workload identity.
pub fn create_identity(
    name: impl Into<String>,
    location: impl Into<String>,
    secret: &[u8],
) -> Result<WorkloadId, IdentityError> {
    let name = name.into();
    let location = location.into();
    let created_at = Utc::now();
    let signature = sign(&name, &location, &created_at, secret)?;

    Ok(WorkloadId {
        name,
        location,
        created_at,
        signature,
    })
}

/// Verify a workload identity's signature.
pub fn verify_identity(id: &WorkloadId, secret: &[u8]) -> Result<(), IdentityError> {
    let expected = sign(&id.name, &id.location, &id.created_at, secret)?;
    if expected != id.signature {
        return Err(IdentityError::InvalidSignature(id.name.clone()));
    }
    Ok(())
}

fn sign(
    name: &str,
    location: &str,
    created_at: &DateTime<Utc>,
    secret: &[u8],
) -> Result<String, IdentityError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| IdentityError::Hmac(e.to_string()))?;
    mac.update(name.as_bytes());
    mac.update(b"|");
    mac.update(location.as_bytes());
    mac.update(b"|");
    mac.update(created_at.to_rfc3339().as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify() {
        let secret = b"test-secret-key-not-for-prod";
        let id = create_identity("deploy-bot", "host-abc", secret).unwrap();
        verify_identity(&id, secret).unwrap();
    }

    #[test]
    fn wrong_secret_fails() {
        let id = create_identity("deploy-bot", "host-abc", b"secret-1").unwrap();
        assert!(verify_identity(&id, b"secret-2").is_err());
    }

    #[test]
    fn tampered_name_fails() {
        let secret = b"my-secret";
        let mut id = create_identity("deploy-bot", "host-abc", secret).unwrap();
        id.name = "evil-bot".to_string();
        assert!(verify_identity(&id, secret).is_err());
    }
}
