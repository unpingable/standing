//! Durable Standing ownership for exact substrate-incarnation warrants.
//!
//! The decisive causal fence is a committed prerequisite, not a timestamp:
//! NQ obtains a signed commitment for its preallocated acquisition identity
//! before invoking the provider. A completed acquisition cannot be amended to
//! name a later warrant.

use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use standing_continuity::{
    ACQUISITION_BUNDLE_SCHEMA, AUTHORITY_SCHEMA, COMMITMENT_SCHEMA, ContinuityAcquisitionBundleV1,
    ContinuityAcquisitionCommitmentRequestV1, ContinuityAcquisitionCommitmentV1,
    ContinuityAuthorityIssuanceRequestV1, ContinuityAuthorityV1, ContinuitySigner,
    StandingSignedContinuityAcquisitionCommitmentV1, StandingSignedContinuityAuthorityV1,
    authority_nonclaims, commitment_nonclaims, validate_commitment_request,
    validate_issuance_request,
};
use standing_grant::Principal;
use standing_receipt::{Receipt, ReceiptBuilder, ReceiptKind, canonical_json};
use uuid::Uuid;

use super::{Store, StoreError, insert_receipt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityAuthorityIssueResult {
    pub authority: StandingSignedContinuityAuthorityV1,
    /// Current Standing issuance state. This is not part of the immutable
    /// authority payload and never rewrites the historical occurrence.
    pub state: String,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityCommitResult {
    pub bundle: ContinuityAcquisitionBundleV1,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityAuthorityRow {
    pub authority: StandingSignedContinuityAuthorityV1,
    pub state: String,
    pub verifying_key_hex: String,
    pub latest_receipt_digest: String,
}

#[derive(Debug)]
struct StoredAuthority {
    signed: StandingSignedContinuityAuthorityV1,
    state: String,
    signing_key_id: String,
    verifying_key_hex: String,
    latest_receipt_digest: String,
    request_digest: String,
}

impl Store {
    /// Issue one immutable warrant for one exact substrate-incarnation edge.
    ///
    /// Exact replay by either request id or replay identity converges on the
    /// original occurrence. A changed request under either identity refuses.
    pub fn issue_continuity_authority(
        &mut self,
        request: &ContinuityAuthorityIssuanceRequestV1,
        operator: &Principal,
        signer: &ContinuitySigner,
        now: DateTime<Utc>,
    ) -> Result<ContinuityAuthorityIssueResult, StoreError> {
        validate_issuance_request(request)?;
        if request.nq_audience == operator.id || request.edge.subject_ref == operator.id {
            return Err(standing_continuity::ContinuityError::InvalidObject(
                "the NQ consumer or governed subject cannot issue its own continuity warrant"
                    .into(),
            )
            .into());
        }
        let genesis =
            self.require_genesis_operator(&operator.id, "continuity authority issuance")?;
        let request_digest = request_digest(request, &operator.id)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) = find_authority_replay(&tx, request)? {
            if existing.request_digest != request_digest {
                return Err(StoreError::ContinuityReplayConflict(format!(
                    "issuance request {} / replay {}",
                    request.issuance_request_id, request.replay_identity
                )));
            }
            existing
                .signed
                .verify(&existing.signing_key_id, &existing.verifying_key_hex)?;
            tx.commit()?;
            return Ok(ContinuityAuthorityIssueResult {
                authority: existing.signed,
                state: existing.state,
                replayed: true,
            });
        }

        let authority_occurrence_ref = Uuid::new_v4();
        let issue_receipt = ReceiptBuilder::new(
            ReceiptKind::ContinuityAuthorityIssued,
            &operator.id,
            authority_occurrence_ref.to_string(),
        )
        .parent_digest(&genesis.digest)
        .policy_hash(genesis.policy_hash.clone().unwrap_or_default())
        .timestamp(now)
        .evidence(serde_json::json!({
            "schema": "standing.continuity_authority_issuance.v1",
            "request": request,
            "authority_occurrence_ref": authority_occurrence_ref,
            "standing_instance": genesis.digest,
            "signing_key_id": signer.key_id(),
            "verifying_key_hex": signer.verifying_key_hex(),
            "causal_precedence": "proved_by_pre_provider_acquisition_commitment_not_timestamp",
        }))
        .build()?;

        let payload = ContinuityAuthorityV1 {
            schema: AUTHORITY_SCHEMA.into(),
            authority_occurrence_ref,
            issuance_request_id: request.issuance_request_id,
            standing_instance: genesis.digest.clone(),
            edge: request.edge.clone(),
            nq_audience: request.nq_audience.clone(),
            issuer_principal: operator.id.clone(),
            standing_basis_digest: issue_receipt.digest.clone(),
            replay_identity: request.replay_identity.clone(),
            issued_at: now,
            nonclaims: authority_nonclaims(),
        };
        let signed = signer.sign_authority(payload)?;
        let signed_json = serde_json::to_string(&signed)?;

        insert_receipt(&tx, &issue_receipt)?;
        tx.execute(
            "INSERT INTO continuity_authorities
             (authority_occurrence_ref, issuance_request_id, replay_identity,
              request_digest, subject_ref, relation, predecessor_ref, successor_ref,
              nq_audience, issuer_principal, standing_instance,
              standing_basis_digest, state, signing_key_id, verifying_key_hex,
              signed_authority_json, payload_digest, latest_receipt_digest,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'substrate_incarnation', ?6, ?7,
                     ?8, ?9, ?10, ?11, 'issued', ?12, ?13, ?14, ?15, ?16,
                     ?17, ?17)",
            params![
                authority_occurrence_ref.to_string(),
                request.issuance_request_id.to_string(),
                request.replay_identity,
                request_digest,
                request.edge.subject_ref,
                request.edge.predecessor_ref,
                request.edge.successor_ref,
                request.nq_audience,
                operator.id,
                genesis.digest,
                issue_receipt.digest,
                signer.key_id(),
                signer.verifying_key_hex(),
                signed_json,
                signed.payload_digest,
                issue_receipt.digest,
                now.to_rfc3339(),
            ],
        )?;
        tx.commit()?;

        Ok(ContinuityAuthorityIssueResult {
            authority: signed,
            state: "issued".into(),
            replayed: false,
        })
    }

    /// Commit one exact authority occurrence as the prerequisite of one
    /// preallocated NQ acquisition/provider-intake identity.
    ///
    /// This operation must complete before provider invocation. It cannot be
    /// used to retrofit an authority onto evidence that already exists.
    pub fn commit_continuity_acquisition(
        &mut self,
        request: &ContinuityAcquisitionCommitmentRequestV1,
        authenticated_nq: &Principal,
        signer: &ContinuitySigner,
        now: DateTime<Utc>,
    ) -> Result<ContinuityCommitResult, StoreError> {
        validate_commitment_request(request)?;
        if authenticated_nq.id != request.nq_audience {
            return Err(StoreError::ContinuityRequesterMismatch {
                expected: request.nq_audience.clone(),
                actual: authenticated_nq.id.clone(),
            });
        }
        let request_digest = request_digest(request, &authenticated_nq.id)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) = find_commitment_replay(&tx, request)? {
            if existing.request_digest != request_digest {
                return Err(StoreError::ContinuityReplayConflict(format!(
                    "commitment request {} / replay {} / acquisition {}",
                    request.request_id, request.replay_identity, request.acquisition_id
                )));
            }
            let authority =
                read_authority(&tx, &existing.commitment.payload.authority_occurrence_ref)?;
            authority
                .signed
                .verify(&authority.signing_key_id, &authority.verifying_key_hex)?;
            existing
                .commitment
                .verify(&authority.signing_key_id, &authority.verifying_key_hex)?;
            tx.commit()?;
            return Ok(ContinuityCommitResult {
                bundle: ContinuityAcquisitionBundleV1 {
                    schema: ACQUISITION_BUNDLE_SCHEMA.into(),
                    authority: authority.signed,
                    commitment: existing.commitment,
                },
                replayed: true,
            });
        }

        let authority = read_authority(&tx, &request.authority_occurrence_ref)?;
        if authority.state != "issued" {
            return Err(StoreError::ContinuityAuthorityRevoked(
                request.authority_occurrence_ref.to_string(),
            ));
        }
        if authority.signed.payload_digest != request.authority_payload_digest {
            return Err(StoreError::ContinuityAuthorityDigestMismatch {
                expected: authority.signed.payload_digest,
                actual: request.authority_payload_digest.clone(),
            });
        }
        if authority.signed.payload.nq_audience != request.nq_audience {
            return Err(StoreError::ContinuityAudienceMismatch {
                expected: authority.signed.payload.nq_audience,
                actual: request.nq_audience.clone(),
            });
        }
        if authority.signing_key_id != signer.key_id()
            || authority.verifying_key_hex != signer.verifying_key_hex()
        {
            return Err(StoreError::ContinuitySignerMismatch {
                expected: format!(
                    "{}:{}",
                    authority.signing_key_id, authority.verifying_key_hex
                ),
                actual: format!("{}:{}", signer.key_id(), signer.verifying_key_hex()),
            });
        }
        authority
            .signed
            .verify(&authority.signing_key_id, &authority.verifying_key_hex)?;

        let commitment_occurrence_ref = Uuid::new_v4();
        let payload = ContinuityAcquisitionCommitmentV1 {
            schema: COMMITMENT_SCHEMA.into(),
            commitment_occurrence_ref,
            request_id: request.request_id,
            authority_occurrence_ref: request.authority_occurrence_ref,
            authority_payload_digest: request.authority_payload_digest.clone(),
            acquisition_id: request.acquisition_id.clone(),
            acquisition_basis_digest: request.acquisition_basis_digest.clone(),
            nq_audience: request.nq_audience.clone(),
            standing_instance: authority.signed.payload.standing_instance.clone(),
            committed_at: now,
            replay_identity: request.replay_identity.clone(),
            nonclaims: commitment_nonclaims(),
        };
        let signed_commitment = signer.sign_commitment(payload)?;
        let commitment_json = serde_json::to_string(&signed_commitment)?;
        let receipt = ReceiptBuilder::new(
            ReceiptKind::ContinuityAcquisitionCommitted,
            &authenticated_nq.id,
            request.authority_occurrence_ref.to_string(),
        )
        .parent_digest(&authority.latest_receipt_digest)
        .timestamp(now)
        .evidence(serde_json::json!({
            "schema": "standing.continuity_acquisition_commitment_receipt.v1",
            "authority_occurrence_ref": request.authority_occurrence_ref,
            "authority_payload_digest": request.authority_payload_digest,
            "commitment_occurrence_ref": commitment_occurrence_ref,
            "commitment_payload_digest": signed_commitment.payload_digest,
            "acquisition_id": request.acquisition_id,
            "acquisition_basis_digest": request.acquisition_basis_digest,
            "requester_principal": authenticated_nq.id,
            "provider_invoked": false,
        }))
        .build()?;

        insert_receipt(&tx, &receipt)?;
        tx.execute(
            "INSERT INTO continuity_acquisition_commitments
             (commitment_occurrence_ref, request_id, replay_identity,
              request_digest, authority_occurrence_ref, authority_payload_digest,
              acquisition_id, acquisition_basis_digest, nq_audience,
              requester_principal, signed_commitment_json, payload_digest,
              receipt_digest, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                commitment_occurrence_ref.to_string(),
                request.request_id.to_string(),
                request.replay_identity,
                request_digest,
                request.authority_occurrence_ref.to_string(),
                request.authority_payload_digest,
                request.acquisition_id,
                request.acquisition_basis_digest,
                request.nq_audience,
                authenticated_nq.id,
                commitment_json,
                signed_commitment.payload_digest,
                receipt.digest,
                now.to_rfc3339(),
            ],
        )?;
        let updated = tx.execute(
            "UPDATE continuity_authorities
             SET latest_receipt_digest = ?1, updated_at = ?2
             WHERE authority_occurrence_ref = ?3
               AND state = 'issued'
               AND latest_receipt_digest = ?4",
            params![
                receipt.digest,
                now.to_rfc3339(),
                request.authority_occurrence_ref.to_string(),
                authority.latest_receipt_digest,
            ],
        )?;
        if updated != 1 {
            return Err(StoreError::ContinuityHeadContended);
        }
        tx.commit()?;

        Ok(ContinuityCommitResult {
            bundle: ContinuityAcquisitionBundleV1 {
                schema: ACQUISITION_BUNDLE_SCHEMA.into(),
                authority: authority.signed,
                commitment: signed_commitment,
            },
            replayed: false,
        })
    }

    /// Revoke a warrant for future acquisitions. Existing exact commitments
    /// remain historical proof that the warrant was usable when committed.
    pub fn revoke_continuity_authority(
        &mut self,
        authority_occurrence_ref: Uuid,
        operator: &Principal,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<Receipt, StoreError> {
        self.require_genesis_operator(&operator.id, "continuity authority revocation")?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority = read_authority(&tx, &authority_occurrence_ref)?;
        if authority.state != "issued" {
            return Err(StoreError::ContinuityAuthorityRevoked(
                authority_occurrence_ref.to_string(),
            ));
        }
        let receipt = ReceiptBuilder::new(
            ReceiptKind::ContinuityAuthorityRevoked,
            &operator.id,
            authority_occurrence_ref.to_string(),
        )
        .parent_digest(&authority.latest_receipt_digest)
        .timestamp(now)
        .evidence(serde_json::json!({
            "schema": "standing.continuity_authority_revocation.v1",
            "authority_occurrence_ref": authority_occurrence_ref,
            "reason": reason,
            "historical_commitments_remain_valid": true,
            "new_commitments_permitted": false,
        }))
        .build()?;
        insert_receipt(&tx, &receipt)?;
        let updated = tx.execute(
            "UPDATE continuity_authorities
             SET state = 'revoked', latest_receipt_digest = ?1, updated_at = ?2
             WHERE authority_occurrence_ref = ?3
               AND state = 'issued'
               AND latest_receipt_digest = ?4",
            params![
                receipt.digest,
                now.to_rfc3339(),
                authority_occurrence_ref.to_string(),
                authority.latest_receipt_digest,
            ],
        )?;
        if updated != 1 {
            return Err(StoreError::ContinuityHeadContended);
        }
        tx.commit()?;
        Ok(receipt)
    }

    pub fn get_continuity_authority(
        &self,
        authority_occurrence_ref: Uuid,
    ) -> Result<Option<ContinuityAuthorityRow>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let row = read_authority_optional(&tx, &authority_occurrence_ref)?;
        tx.commit()?;
        Ok(row.map(|stored| ContinuityAuthorityRow {
            authority: stored.signed,
            state: stored.state,
            verifying_key_hex: stored.verifying_key_hex,
            latest_receipt_digest: stored.latest_receipt_digest,
        }))
    }
}

#[derive(Debug)]
struct StoredCommitment {
    commitment: StandingSignedContinuityAcquisitionCommitmentV1,
    request_digest: String,
}

fn find_authority_replay(
    tx: &Transaction<'_>,
    request: &ContinuityAuthorityIssuanceRequestV1,
) -> Result<Option<StoredAuthority>, StoreError> {
    let by_request = read_authority_by_column(
        tx,
        "issuance_request_id",
        &request.issuance_request_id.to_string(),
    )?;
    let by_replay = read_authority_by_column(tx, "replay_identity", &request.replay_identity)?;
    match (by_request, by_replay) {
        (None, None) => Ok(None),
        (Some(a), None) | (None, Some(a)) => Ok(Some(a)),
        (Some(a), Some(b))
            if a.signed.payload.authority_occurrence_ref
                == b.signed.payload.authority_occurrence_ref =>
        {
            Ok(Some(a))
        }
        _ => Err(StoreError::ContinuityReplayConflict(
            "issuance request id and replay identity resolve to different occurrences".into(),
        )),
    }
}

fn find_commitment_replay(
    tx: &Transaction<'_>,
    request: &ContinuityAcquisitionCommitmentRequestV1,
) -> Result<Option<StoredCommitment>, StoreError> {
    let columns = [
        ("request_id", request.request_id.to_string()),
        ("replay_identity", request.replay_identity.clone()),
        ("acquisition_id", request.acquisition_id.clone()),
    ];
    let mut found: Option<StoredCommitment> = None;
    for (column, value) in columns {
        let query = format!(
            "SELECT signed_commitment_json, request_digest
             FROM continuity_acquisition_commitments WHERE {column} = ?1"
        );
        let row: Option<(String, String)> = tx
            .query_row(&query, params![value], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        if let Some((json, request_digest)) = row {
            let candidate = StoredCommitment {
                commitment: serde_json::from_str(&json)?,
                request_digest,
            };
            if let Some(existing) = &found
                && existing.commitment.payload.commitment_occurrence_ref
                    != candidate.commitment.payload.commitment_occurrence_ref
            {
                return Err(StoreError::ContinuityReplayConflict(
                    "commitment identities resolve to different occurrences".into(),
                ));
            }
            found = Some(candidate);
        }
    }
    Ok(found)
}

fn read_authority(
    tx: &Transaction<'_>,
    authority_occurrence_ref: &Uuid,
) -> Result<StoredAuthority, StoreError> {
    read_authority_optional(tx, authority_occurrence_ref)?.ok_or_else(|| {
        StoreError::ContinuityAuthorityNotFound(authority_occurrence_ref.to_string())
    })
}

fn read_authority_optional(
    tx: &Transaction<'_>,
    authority_occurrence_ref: &Uuid,
) -> Result<Option<StoredAuthority>, StoreError> {
    read_authority_by_column(
        tx,
        "authority_occurrence_ref",
        &authority_occurrence_ref.to_string(),
    )
}

fn read_authority_by_column(
    tx: &Transaction<'_>,
    column: &str,
    value: &str,
) -> Result<Option<StoredAuthority>, StoreError> {
    debug_assert!(matches!(
        column,
        "authority_occurrence_ref" | "issuance_request_id" | "replay_identity"
    ));
    let query = format!(
        "SELECT signed_authority_json, state, signing_key_id, verifying_key_hex,
                latest_receipt_digest, request_digest
         FROM continuity_authorities WHERE {column} = ?1"
    );
    let row: Option<(String, String, String, String, String, String)> = tx
        .query_row(&query, params![value], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .optional()?;
    row.map(
        |(
            json,
            state,
            signing_key_id,
            verifying_key_hex,
            latest_receipt_digest,
            request_digest,
        )| {
            Ok(StoredAuthority {
                signed: serde_json::from_str(&json)?,
                state,
                signing_key_id,
                verifying_key_hex,
                latest_receipt_digest,
                request_digest,
            })
        },
    )
    .transpose()
}

fn request_digest<T: Serialize>(
    request: &T,
    authenticated_actor: &str,
) -> Result<String, StoreError> {
    let basis = serde_json::json!({
        "request": request,
        "authenticated_actor": authenticated_actor,
    });
    Ok(hex::encode(Sha256::digest(canonical_json(&basis)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use standing_continuity::{
        COMMITMENT_REQUEST_SCHEMA, ContinuityEdgeV1, ContinuityRelationV1, ISSUANCE_REQUEST_SCHEMA,
    };

    const OPERATOR: &str = "wl:operator:test";
    const NQ: &str = "nq:test";

    fn signer() -> ContinuitySigner {
        ContinuitySigner::from_seed("standing.test.v1", &[11; 32]).unwrap()
    }

    fn issue_request() -> ContinuityAuthorityIssuanceRequestV1 {
        ContinuityAuthorityIssuanceRequestV1 {
            schema: ISSUANCE_REQUEST_SCHEMA.into(),
            issuance_request_id: Uuid::from_u128(1),
            replay_identity: "issue:test-a-to-b".into(),
            edge: ContinuityEdgeV1 {
                subject_ref: "observer:test-office".into(),
                relation: ContinuityRelationV1::SubstrateIncarnation,
                predecessor_ref: "substrate:test-a".into(),
                successor_ref: "substrate:test-b".into(),
            },
            nq_audience: NQ.into(),
        }
    }

    fn setup() -> Store {
        let mut store = Store::in_memory().unwrap();
        store.install_genesis(OPERATOR, "hardcoded:v1").unwrap();
        store
    }

    fn issue(store: &mut Store) -> StandingSignedContinuityAuthorityV1 {
        store
            .issue_continuity_authority(
                &issue_request(),
                &Principal::new(OPERATOR, "operator"),
                &signer(),
                "2026-08-24T12:00:00Z".parse().unwrap(),
            )
            .unwrap()
            .authority
    }

    fn commit_request(
        authority: &StandingSignedContinuityAuthorityV1,
    ) -> ContinuityAcquisitionCommitmentRequestV1 {
        ContinuityAcquisitionCommitmentRequestV1 {
            schema: COMMITMENT_REQUEST_SCHEMA.into(),
            request_id: Uuid::from_u128(2),
            replay_identity: "commit:acq-1".into(),
            authority_occurrence_ref: authority.payload.authority_occurrence_ref,
            authority_payload_digest: authority.payload_digest.clone(),
            acquisition_id: "acquisition:test-1".into(),
            acquisition_basis_digest: "c".repeat(64),
            nq_audience: NQ.into(),
        }
    }

    #[test]
    fn issue_and_commit_exact_replays_converge() {
        let mut store = setup();
        let first = issue(&mut store);
        let replay = store
            .issue_continuity_authority(
                &issue_request(),
                &Principal::new(OPERATOR, "operator"),
                &ContinuitySigner::from_seed("standing.rotated.v2", &[12; 32]).unwrap(),
                "2026-08-25T12:00:00Z".parse().unwrap(),
            )
            .unwrap()
            .authority;
        assert_eq!(first, replay);

        let request = commit_request(&first);
        let first_commit = store
            .commit_continuity_acquisition(
                &request,
                &Principal::new(NQ, "NQ"),
                &signer(),
                "2026-08-24T12:01:00Z".parse().unwrap(),
            )
            .unwrap();
        let replay_commit = store
            .commit_continuity_acquisition(
                &request,
                &Principal::new(NQ, "NQ"),
                &ContinuitySigner::from_seed("standing.rotated.v2", &[12; 32]).unwrap(),
                "2026-08-25T12:01:00Z".parse().unwrap(),
            )
            .unwrap();
        assert!(!first_commit.replayed);
        assert!(replay_commit.replayed);
        assert_eq!(first_commit.bundle, replay_commit.bundle);
    }

    #[test]
    fn changed_replay_refuses() {
        let mut store = setup();
        issue(&mut store);
        let mut changed = issue_request();
        changed.edge.successor_ref = "substrate:test-c".into();
        assert!(matches!(
            store.issue_continuity_authority(
                &changed,
                &Principal::new(OPERATOR, "operator"),
                &signer(),
                Utc::now(),
            ),
            Err(StoreError::ContinuityReplayConflict(_))
        ));
    }

    #[test]
    fn deliberate_second_authority_for_same_edge_is_a_distinct_occurrence() {
        let mut store = setup();
        let first = issue(&mut store);
        let mut second_request = issue_request();
        second_request.issuance_request_id = Uuid::from_u128(10);
        second_request.replay_identity = "issue:test-a-to-b:deliberate-2".into();
        let second = store
            .issue_continuity_authority(
                &second_request,
                &Principal::new(OPERATOR, "operator"),
                &signer(),
                Utc::now(),
            )
            .unwrap()
            .authority;
        assert_eq!(first.payload.edge, second.payload.edge);
        assert_ne!(
            first.payload.authority_occurrence_ref,
            second.payload.authority_occurrence_ref
        );
        assert_ne!(first.payload_digest, second.payload_digest);
    }

    #[test]
    fn governed_subject_and_nq_consumer_cannot_self_issue() {
        let mut store = setup();
        let mut as_subject = issue_request();
        as_subject.edge.subject_ref = OPERATOR.into();
        assert!(
            store
                .issue_continuity_authority(
                    &as_subject,
                    &Principal::new(OPERATOR, "operator"),
                    &signer(),
                    Utc::now(),
                )
                .is_err()
        );

        let mut as_consumer = issue_request();
        as_consumer.nq_audience = OPERATOR.into();
        assert!(
            store
                .issue_continuity_authority(
                    &as_consumer,
                    &Principal::new(OPERATOR, "operator"),
                    &signer(),
                    Utc::now(),
                )
                .is_err()
        );
    }

    #[test]
    fn revocation_blocks_new_commit_but_not_exact_historical_replay() {
        let mut store = setup();
        let authority = issue(&mut store);
        let request = commit_request(&authority);
        let original = store
            .commit_continuity_acquisition(
                &request,
                &Principal::new(NQ, "NQ"),
                &signer(),
                Utc::now(),
            )
            .unwrap();
        store
            .revoke_continuity_authority(
                authority.payload.authority_occurrence_ref,
                &Principal::new(OPERATOR, "operator"),
                "operator revocation",
                Utc::now(),
            )
            .unwrap();
        let authority_replay = store
            .issue_continuity_authority(
                &issue_request(),
                &Principal::new(OPERATOR, "operator"),
                &signer(),
                Utc::now(),
            )
            .unwrap();
        assert!(authority_replay.replayed);
        assert_eq!(authority_replay.state, "revoked");
        assert_eq!(
            original.bundle,
            store
                .commit_continuity_acquisition(
                    &request,
                    &Principal::new(NQ, "NQ"),
                    &signer(),
                    Utc::now(),
                )
                .unwrap()
                .bundle
        );

        let mut new_request = commit_request(&authority);
        new_request.request_id = Uuid::from_u128(3);
        new_request.replay_identity = "commit:acq-2".into();
        new_request.acquisition_id = "acquisition:test-2".into();
        assert!(matches!(
            store.commit_continuity_acquisition(
                &new_request,
                &Principal::new(NQ, "NQ"),
                &signer(),
                Utc::now(),
            ),
            Err(StoreError::ContinuityAuthorityRevoked(_))
        ));
    }

    #[test]
    fn wrong_audience_and_digest_refuse() {
        let mut store = setup();
        let authority = issue(&mut store);
        let request = commit_request(&authority);
        assert!(matches!(
            store.commit_continuity_acquisition(
                &request,
                &Principal::new("nq:other", "other"),
                &signer(),
                Utc::now(),
            ),
            Err(StoreError::ContinuityRequesterMismatch { .. })
        ));

        let mut wrong = request;
        wrong.authority_payload_digest = "d".repeat(64);
        assert!(matches!(
            store.commit_continuity_acquisition(
                &wrong,
                &Principal::new(NQ, "NQ"),
                &signer(),
                Utc::now(),
            ),
            Err(StoreError::ContinuityAuthorityDigestMismatch { .. })
        ));
    }

    #[test]
    fn missing_or_revoked_authority_refuses_before_any_commitment_exists() {
        let mut store = setup();
        let authority = issue(&mut store);
        let mut missing = commit_request(&authority);
        missing.authority_occurrence_ref = Uuid::from_u128(999);
        assert!(matches!(
            store.commit_continuity_acquisition(
                &missing,
                &Principal::new(NQ, "NQ"),
                &signer(),
                Utc::now(),
            ),
            Err(StoreError::ContinuityAuthorityNotFound(_))
        ));

        store
            .revoke_continuity_authority(
                authority.payload.authority_occurrence_ref,
                &Principal::new(OPERATOR, "operator"),
                "not usable for new acquisitions",
                Utc::now(),
            )
            .unwrap();
        assert!(matches!(
            store.commit_continuity_acquisition(
                &commit_request(&authority),
                &Principal::new(NQ, "NQ"),
                &signer(),
                Utc::now(),
            ),
            Err(StoreError::ContinuityAuthorityRevoked(_))
        ));
    }
}
