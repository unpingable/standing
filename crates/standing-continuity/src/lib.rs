//! Proof objects for one closed continuity relation: substrate incarnation.
//!
//! These objects carry permission, never empirical truth. Standing signs exact
//! payloads so NQ and Nightshift can verify with public material without
//! receiving authority-minting capability.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use standing_receipt::canonical_json;
use uuid::Uuid;

pub const AUTHORITY_SCHEMA: &str = "standing.continuity_authority.v1";
pub const ISSUANCE_REQUEST_SCHEMA: &str = "standing.continuity_authority_issuance_request.v1";
pub const SIGNED_AUTHORITY_SCHEMA: &str = "standing.signed_continuity_authority.v1";
pub const COMMITMENT_REQUEST_SCHEMA: &str = "standing.continuity_acquisition_commitment_request.v1";
pub const COMMITMENT_SCHEMA: &str = "standing.continuity_acquisition_commitment.v1";
pub const SIGNED_COMMITMENT_SCHEMA: &str = "standing.signed_continuity_acquisition_commitment.v1";
pub const ACQUISITION_BUNDLE_SCHEMA: &str = "standing.continuity_acquisition_bundle.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityRelationV1 {
    SubstrateIncarnation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityEdgeV1 {
    pub subject_ref: String,
    pub relation: ContinuityRelationV1,
    pub predecessor_ref: String,
    pub successor_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityNonclaimV1 {
    TransitionOccurred,
    EvidenceTruth,
    CurrentAttribution,
    RoutineReliance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentNonclaimV1 {
    ProviderInvoked,
    ObservationProduced,
    EvidenceTruth,
    CurrentAttribution,
}

pub fn authority_nonclaims() -> Vec<AuthorityNonclaimV1> {
    vec![
        AuthorityNonclaimV1::TransitionOccurred,
        AuthorityNonclaimV1::EvidenceTruth,
        AuthorityNonclaimV1::CurrentAttribution,
        AuthorityNonclaimV1::RoutineReliance,
    ]
}

pub fn commitment_nonclaims() -> Vec<CommitmentNonclaimV1> {
    vec![
        CommitmentNonclaimV1::ProviderInvoked,
        CommitmentNonclaimV1::ObservationProduced,
        CommitmentNonclaimV1::EvidenceTruth,
        CommitmentNonclaimV1::CurrentAttribution,
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAuthorityIssuanceRequestV1 {
    pub schema: String,
    pub issuance_request_id: Uuid,
    pub replay_identity: String,
    pub edge: ContinuityEdgeV1,
    pub nq_audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAuthorityV1 {
    pub schema: String,
    pub authority_occurrence_ref: Uuid,
    pub issuance_request_id: Uuid,
    pub standing_instance: String,
    pub edge: ContinuityEdgeV1,
    pub nq_audience: String,
    pub issuer_principal: String,
    pub standing_basis_digest: String,
    pub replay_identity: String,
    /// Evidence only. This field is not the causal-precedence proof.
    pub issued_at: DateTime<Utc>,
    pub nonclaims: Vec<AuthorityNonclaimV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingSignedContinuityAuthorityV1 {
    pub schema: String,
    pub key_id: String,
    pub payload: ContinuityAuthorityV1,
    pub payload_digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionCommitmentRequestV1 {
    pub schema: String,
    pub request_id: Uuid,
    pub replay_identity: String,
    pub authority_occurrence_ref: Uuid,
    pub authority_payload_digest: String,
    /// Preallocated NQ acquisition/provider-intake identity.
    pub acquisition_id: String,
    /// Digest of the exact acquisition intent/basis committed before provider
    /// invocation.
    pub acquisition_basis_digest: String,
    pub nq_audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionCommitmentV1 {
    pub schema: String,
    pub commitment_occurrence_ref: Uuid,
    pub request_id: Uuid,
    pub authority_occurrence_ref: Uuid,
    pub authority_payload_digest: String,
    pub acquisition_id: String,
    pub acquisition_basis_digest: String,
    pub nq_audience: String,
    pub standing_instance: String,
    /// Evidence only. Causal order comes from the immutable prerequisite
    /// commitment and NQ's provider-invocation gate.
    pub committed_at: DateTime<Utc>,
    pub replay_identity: String,
    pub nonclaims: Vec<CommitmentNonclaimV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingSignedContinuityAcquisitionCommitmentV1 {
    pub schema: String,
    pub key_id: String,
    pub payload: ContinuityAcquisitionCommitmentV1,
    pub payload_digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionBundleV1 {
    pub schema: String,
    pub authority: StandingSignedContinuityAuthorityV1,
    pub commitment: StandingSignedContinuityAcquisitionCommitmentV1,
}

#[derive(Debug, thiserror::Error)]
pub enum ContinuityError {
    #[error("unsupported schema {0}")]
    UnsupportedSchema(String),
    #[error("unexpected signing key id: expected {expected}, got {actual}")]
    SigningKeyMismatch { expected: String, actual: String },
    #[error("invalid signing seed: expected exactly 32 bytes")]
    InvalidSigningSeed,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("payload digest mismatch")]
    PayloadDigestMismatch,
    #[error("invalid continuity object: {0}")]
    InvalidObject(String),
    #[error("canonical serialization failed: {0}")]
    Canonical(#[from] serde_json::Error),
}

pub struct ContinuitySigner {
    key_id: String,
    key: SigningKey,
}

impl ContinuitySigner {
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8]) -> Result<Self, ContinuityError> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| ContinuityError::InvalidSigningSeed)?;
        Ok(Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn from_seed_hex(
        key_id: impl Into<String>,
        seed_hex: &str,
    ) -> Result<Self, ContinuityError> {
        let seed = hex::decode(seed_hex).map_err(|_| ContinuityError::InvalidSigningSeed)?;
        Self::from_seed(key_id, &seed)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign_authority(
        &self,
        payload: ContinuityAuthorityV1,
    ) -> Result<StandingSignedContinuityAuthorityV1, ContinuityError> {
        validate_authority(&payload)?;
        let canonical = canonical_json(&payload)?;
        let payload_digest = sha256_hex(&canonical);
        let signature = sign_domain(&self.key, SIGNED_AUTHORITY_SCHEMA, &canonical);
        Ok(StandingSignedContinuityAuthorityV1 {
            schema: SIGNED_AUTHORITY_SCHEMA.into(),
            key_id: self.key_id.clone(),
            payload,
            payload_digest,
            signature,
        })
    }

    pub fn sign_commitment(
        &self,
        payload: ContinuityAcquisitionCommitmentV1,
    ) -> Result<StandingSignedContinuityAcquisitionCommitmentV1, ContinuityError> {
        validate_commitment(&payload)?;
        let canonical = canonical_json(&payload)?;
        let payload_digest = sha256_hex(&canonical);
        let signature = sign_domain(&self.key, SIGNED_COMMITMENT_SCHEMA, &canonical);
        Ok(StandingSignedContinuityAcquisitionCommitmentV1 {
            schema: SIGNED_COMMITMENT_SCHEMA.into(),
            key_id: self.key_id.clone(),
            payload,
            payload_digest,
            signature,
        })
    }
}

impl StandingSignedContinuityAuthorityV1 {
    pub fn verify(
        &self,
        expected_key_id: &str,
        public_key_hex: &str,
    ) -> Result<(), ContinuityError> {
        verify_header(
            &self.schema,
            SIGNED_AUTHORITY_SCHEMA,
            &self.key_id,
            expected_key_id,
        )?;
        validate_authority(&self.payload)?;
        verify_payload(
            public_key_hex,
            SIGNED_AUTHORITY_SCHEMA,
            &self.payload,
            &self.payload_digest,
            &self.signature,
        )
    }
}

impl StandingSignedContinuityAcquisitionCommitmentV1 {
    pub fn verify(
        &self,
        expected_key_id: &str,
        public_key_hex: &str,
    ) -> Result<(), ContinuityError> {
        verify_header(
            &self.schema,
            SIGNED_COMMITMENT_SCHEMA,
            &self.key_id,
            expected_key_id,
        )?;
        validate_commitment(&self.payload)?;
        verify_payload(
            public_key_hex,
            SIGNED_COMMITMENT_SCHEMA,
            &self.payload,
            &self.payload_digest,
            &self.signature,
        )
    }
}

impl ContinuityAcquisitionBundleV1 {
    /// Verify both signatures and every cross-object binding in the exported
    /// carrier. Trust still comes from the caller's pinned Standing key.
    pub fn verify(
        &self,
        expected_key_id: &str,
        public_key_hex: &str,
    ) -> Result<(), ContinuityError> {
        if self.schema != ACQUISITION_BUNDLE_SCHEMA {
            return Err(ContinuityError::UnsupportedSchema(self.schema.clone()));
        }
        self.authority.verify(expected_key_id, public_key_hex)?;
        self.commitment.verify(expected_key_id, public_key_hex)?;
        let authority = &self.authority.payload;
        let commitment = &self.commitment.payload;
        if commitment.authority_occurrence_ref != authority.authority_occurrence_ref
            || commitment.authority_payload_digest != self.authority.payload_digest
            || commitment.nq_audience != authority.nq_audience
            || commitment.standing_instance != authority.standing_instance
        {
            return Err(ContinuityError::InvalidObject(
                "commitment does not bind the exact signed authority occurrence, audience, and Standing instance"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Verify the carrier and require its closed edge to equal the transition
    /// whose dependent observation is being evaluated.
    pub fn verify_for_edge(
        &self,
        expected_key_id: &str,
        public_key_hex: &str,
        edge: &ContinuityEdgeV1,
    ) -> Result<(), ContinuityError> {
        self.verify(expected_key_id, public_key_hex)?;
        if &self.authority.payload.edge != edge {
            return Err(ContinuityError::InvalidObject(
                "continuity authority does not match the exact required edge".into(),
            ));
        }
        Ok(())
    }
}

pub fn validate_issuance_request(
    request: &ContinuityAuthorityIssuanceRequestV1,
) -> Result<(), ContinuityError> {
    if request.schema != ISSUANCE_REQUEST_SCHEMA {
        return Err(ContinuityError::UnsupportedSchema(request.schema.clone()));
    }
    validate_edge(&request.edge)?;
    validate_audience(&request.nq_audience)?;
    if request.replay_identity.trim().is_empty() {
        return Err(ContinuityError::InvalidObject(
            "replay_identity must be non-empty".into(),
        ));
    }
    Ok(())
}

pub fn validate_commitment_request(
    request: &ContinuityAcquisitionCommitmentRequestV1,
) -> Result<(), ContinuityError> {
    if request.schema != COMMITMENT_REQUEST_SCHEMA {
        return Err(ContinuityError::UnsupportedSchema(request.schema.clone()));
    }
    validate_digest(
        &request.authority_payload_digest,
        "authority_payload_digest",
    )?;
    validate_digest(
        &request.acquisition_basis_digest,
        "acquisition_basis_digest",
    )?;
    validate_audience(&request.nq_audience)?;
    if request.replay_identity.trim().is_empty() || request.acquisition_id.trim().is_empty() {
        return Err(ContinuityError::InvalidObject(
            "replay_identity and acquisition_id must be non-empty".into(),
        ));
    }
    Ok(())
}

fn validate_authority(payload: &ContinuityAuthorityV1) -> Result<(), ContinuityError> {
    if payload.schema != AUTHORITY_SCHEMA {
        return Err(ContinuityError::UnsupportedSchema(payload.schema.clone()));
    }
    validate_edge(&payload.edge)?;
    validate_audience(&payload.nq_audience)?;
    validate_digest(&payload.standing_instance, "standing_instance")?;
    validate_digest(&payload.standing_basis_digest, "standing_basis_digest")?;
    if payload.issuer_principal.trim().is_empty() || payload.replay_identity.trim().is_empty() {
        return Err(ContinuityError::InvalidObject(
            "issuer_principal and replay_identity must be non-empty".into(),
        ));
    }
    if payload.nonclaims != authority_nonclaims() {
        return Err(ContinuityError::InvalidObject(
            "authority nonclaims must equal the closed v1 set".into(),
        ));
    }
    Ok(())
}

fn validate_commitment(payload: &ContinuityAcquisitionCommitmentV1) -> Result<(), ContinuityError> {
    if payload.schema != COMMITMENT_SCHEMA {
        return Err(ContinuityError::UnsupportedSchema(payload.schema.clone()));
    }
    validate_digest(
        &payload.authority_payload_digest,
        "authority_payload_digest",
    )?;
    validate_digest(
        &payload.acquisition_basis_digest,
        "acquisition_basis_digest",
    )?;
    validate_digest(&payload.standing_instance, "standing_instance")?;
    validate_audience(&payload.nq_audience)?;
    if payload.acquisition_id.trim().is_empty() || payload.replay_identity.trim().is_empty() {
        return Err(ContinuityError::InvalidObject(
            "acquisition_id and replay_identity must be non-empty".into(),
        ));
    }
    if payload.nonclaims != commitment_nonclaims() {
        return Err(ContinuityError::InvalidObject(
            "commitment nonclaims must equal the closed v1 set".into(),
        ));
    }
    Ok(())
}

fn validate_edge(edge: &ContinuityEdgeV1) -> Result<(), ContinuityError> {
    if edge.subject_ref.trim().is_empty()
        || edge.predecessor_ref.trim().is_empty()
        || edge.successor_ref.trim().is_empty()
    {
        return Err(ContinuityError::InvalidObject(
            "edge references must be non-empty".into(),
        ));
    }
    if edge.predecessor_ref == edge.successor_ref {
        return Err(ContinuityError::InvalidObject(
            "predecessor and successor must differ".into(),
        ));
    }
    Ok(())
}

fn validate_audience(value: &str) -> Result<(), ContinuityError> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() < 2
        || parts.iter().any(|part| part.is_empty())
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ContinuityError::InvalidObject(
            "nq_audience must be a non-empty colon-qualified identity".into(),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<(), ContinuityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContinuityError::InvalidObject(format!(
            "{field} must be a lowercase SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn verify_header(
    actual_schema: &str,
    expected_schema: &str,
    actual_key_id: &str,
    expected_key_id: &str,
) -> Result<(), ContinuityError> {
    if actual_schema != expected_schema {
        return Err(ContinuityError::UnsupportedSchema(actual_schema.into()));
    }
    if actual_key_id != expected_key_id {
        return Err(ContinuityError::SigningKeyMismatch {
            expected: expected_key_id.into(),
            actual: actual_key_id.into(),
        });
    }
    Ok(())
}

fn verify_payload<T: Serialize>(
    public_key_hex: &str,
    domain: &str,
    payload: &T,
    expected_digest: &str,
    signature_hex: &str,
) -> Result<(), ContinuityError> {
    let canonical = canonical_json(payload)?;
    if sha256_hex(&canonical) != expected_digest {
        return Err(ContinuityError::PayloadDigestMismatch);
    }
    let public = hex::decode(public_key_hex).map_err(|_| ContinuityError::InvalidPublicKey)?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| ContinuityError::InvalidPublicKey)?;
    let key = VerifyingKey::from_bytes(&public).map_err(|_| ContinuityError::InvalidPublicKey)?;
    let signature =
        hex::decode(signature_hex).map_err(|_| ContinuityError::InvalidSignatureEncoding)?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| ContinuityError::InvalidSignatureEncoding)?;
    key.verify(&signature_preimage(domain, &canonical), &signature)
        .map_err(|_| ContinuityError::InvalidSignature)
}

fn sign_domain(key: &SigningKey, domain: &str, canonical: &[u8]) -> String {
    hex::encode(key.sign(&signature_preimage(domain, canonical)).to_bytes())
}

pub fn signature_preimage(domain: &str, canonical_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 1 + canonical_payload.len());
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(canonical_payload);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> ContinuityAuthorityV1 {
        ContinuityAuthorityV1 {
            schema: AUTHORITY_SCHEMA.into(),
            authority_occurrence_ref: Uuid::from_u128(1),
            issuance_request_id: Uuid::from_u128(2),
            standing_instance: "a".repeat(64),
            edge: ContinuityEdgeV1 {
                subject_ref: "observer:test-office".into(),
                relation: ContinuityRelationV1::SubstrateIncarnation,
                predecessor_ref: "substrate:test-a".into(),
                successor_ref: "substrate:test-b".into(),
            },
            nq_audience: "nq:test".into(),
            issuer_principal: "wl:operator:test".into(),
            standing_basis_digest: "b".repeat(64),
            replay_identity: "issue:test".into(),
            issued_at: "2026-08-24T12:00:00Z".parse().unwrap(),
            nonclaims: authority_nonclaims(),
        }
    }

    #[test]
    fn public_verifier_accepts_exact_payload_and_refuses_substitution() {
        let signer = ContinuitySigner::from_seed("standing.test.v1", &[7; 32]).unwrap();
        let mut signed = signer.sign_authority(payload()).unwrap();
        signed
            .verify("standing.test.v1", &signer.verifying_key_hex())
            .unwrap();
        signed.payload.edge.successor_ref = "substrate:test-c".into();
        assert!(
            signed
                .verify("standing.test.v1", &signer.verifying_key_hex())
                .is_err()
        );
    }

    #[test]
    fn verifier_material_cannot_mint_for_pinned_signer() {
        let signer = ContinuitySigner::from_seed("standing.test.v1", &[9; 32]).unwrap();
        let public = hex::decode(signer.verifying_key_hex()).unwrap();
        let attacker = ContinuitySigner::from_seed("attacker", &public).unwrap();
        let forged = attacker.sign_authority(payload()).unwrap();
        assert!(
            forged
                .verify("standing.test.v1", &signer.verifying_key_hex())
                .is_err()
        );
    }

    #[test]
    fn bundle_refuses_cross_object_substitution_and_wrong_edge() {
        let signer = ContinuitySigner::from_seed("standing.test.v1", &[5; 32]).unwrap();
        let authority = signer.sign_authority(payload()).unwrap();
        let commitment = signer
            .sign_commitment(ContinuityAcquisitionCommitmentV1 {
                schema: COMMITMENT_SCHEMA.into(),
                commitment_occurrence_ref: Uuid::from_u128(3),
                request_id: Uuid::from_u128(4),
                authority_occurrence_ref: authority.payload.authority_occurrence_ref,
                authority_payload_digest: authority.payload_digest.clone(),
                acquisition_id: "acquisition:test".into(),
                acquisition_basis_digest: "c".repeat(64),
                nq_audience: authority.payload.nq_audience.clone(),
                standing_instance: authority.payload.standing_instance.clone(),
                committed_at: "2026-08-24T12:01:00Z".parse().unwrap(),
                replay_identity: "commit:test".into(),
                nonclaims: commitment_nonclaims(),
            })
            .unwrap();
        let bundle = ContinuityAcquisitionBundleV1 {
            schema: ACQUISITION_BUNDLE_SCHEMA.into(),
            authority,
            commitment,
        };
        bundle
            .verify_for_edge(
                "standing.test.v1",
                &signer.verifying_key_hex(),
                &bundle.authority.payload.edge,
            )
            .unwrap();

        let mut wrong_edge = bundle.authority.payload.edge.clone();
        wrong_edge.successor_ref = "substrate:test-c".into();
        assert!(
            bundle
                .verify_for_edge("standing.test.v1", &signer.verifying_key_hex(), &wrong_edge,)
                .is_err()
        );

        let mut substituted = bundle;
        substituted.commitment.payload.authority_payload_digest = "d".repeat(64);
        assert!(
            substituted
                .verify("standing.test.v1", &signer.verifying_key_hex())
                .is_err()
        );
    }

    #[test]
    fn closed_wire_refuses_unknown_relation_and_unknown_fields() {
        let request = serde_json::json!({
            "schema": ISSUANCE_REQUEST_SCHEMA,
            "issuance_request_id": Uuid::from_u128(8),
            "replay_identity": "issue:closed-wire",
            "edge": {
                "subject_ref": "observer:test-office",
                "relation": "mandate_revision",
                "predecessor_ref": "substrate:test-a",
                "successor_ref": "substrate:test-b"
            },
            "nq_audience": "nq:test"
        });
        assert!(serde_json::from_value::<ContinuityAuthorityIssuanceRequestV1>(request).is_err());

        let mut authority = serde_json::to_value(payload()).unwrap();
        authority["continuity_authorized"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<ContinuityAuthorityV1>(authority).is_err());
    }
}
