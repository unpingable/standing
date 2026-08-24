//! SQLite storage and domain service for standing.
//!
//! This is the enforcement layer. The store validates transitions against
//! the grant state machine before writing. The CLI (and any future client)
//! calls into the store — it does not build receipts or manage state directly.
//!
//! Invariant: no state transition without a valid receipt, no receipt without
//! a valid transition. Both are written atomically or neither is.

mod continuity;
pub mod replay;
mod resolve;
mod store_resolver;

pub use continuity::{
    ContinuityAuthorityIssueResult, ContinuityAuthorityRow, ContinuityCommitResult,
};
pub use store_resolver::StoreResolver;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, Transaction, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use chrono::Duration;
use standing_grant::{
    ActorContext, AssertCoverage, AssertionGrant, AssertionGrantMachine, AssertionGrantRequest,
    AssertionGrantState, AssertionScope, GrantError, GrantMachine, GrantRequest, GrantScope,
    GrantState, Principal, PrincipalRole, RequestProof, WindowState, assertion_covers, auth,
};
use standing_policy::{PolicyError, PolicyEvaluator, Verdict};
use standing_receipt::{Receipt, ReceiptBuilder, ReceiptKind};

/// Errors from the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("receipt error: {0}")]
    Receipt(#[from] standing_receipt::ReceiptError),

    #[error("grant lifecycle error: {0}")]
    Grant(#[from] GrantError),

    #[error("policy evaluation error: {0}")]
    Policy(#[from] PolicyError),

    #[error("continuity authority error: {0}")]
    Continuity(#[from] standing_continuity::ContinuityError),

    #[error("continuity authority not found: {0}")]
    ContinuityAuthorityNotFound(String),

    #[error("continuity request replay conflicts with the immutable stored request: {0}")]
    ContinuityReplayConflict(String),

    #[error("continuity authority {0} is revoked for new acquisition commitments")]
    ContinuityAuthorityRevoked(String),

    #[error("continuity authority audience mismatch: expected {expected}, got {actual}")]
    ContinuityAudienceMismatch { expected: String, actual: String },

    #[error("continuity authority signer mismatch: expected {expected}, got {actual}")]
    ContinuitySignerMismatch { expected: String, actual: String },

    #[error("continuity authority digest mismatch: expected {expected}, got {actual}")]
    ContinuityAuthorityDigestMismatch { expected: String, actual: String },

    #[error(
        "continuity commitment requester {actual} is not the authenticated NQ audience {expected}"
    )]
    ContinuityRequesterMismatch { expected: String, actual: String },

    #[error("continuity authority receipt head changed concurrently")]
    ContinuityHeadContended,

    #[error("policy witness does not match its decision field {field}")]
    PolicyWitnessMismatch { field: String },

    #[error("receipt write failed, aborting state transition")]
    ReceiptWriteFailed,

    #[error("grant not found: {0}")]
    GrantNotFound(String),

    #[error("invalid transition: cannot go from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    #[error("receipt kind mismatch for {transition}: expected {expected}, got {actual}")]
    ReceiptKindMismatch {
        transition: String,
        expected: String,
        actual: String,
    },

    #[error("grant expired at {0}")]
    GrantExpired(String),

    #[error("grant not yet valid (not_before {0})")]
    GrantNotYetValid(String),

    #[error(
        "grant expiry timestamp is unparseable ({0}); refusing rather than treating an unreadable expiry as valid"
    )]
    GrantTimeUnparseable(String),

    #[error("scope mismatch: grant authorizes {granted}, attempted {attempted}")]
    ScopeMismatch { granted: String, attempted: String },

    #[error("unauthorized: actor {actor} (role: {role}) cannot perform {transition}")]
    Unauthorized {
        actor: String,
        role: String,
        transition: String,
    },

    #[error(
        "genesis already installed for this instance (digest {0}); a second install would contradict the chain root"
    )]
    GenesisExists(String),

    #[error("{operation} requires an installed genesis operator")]
    GenesisRequired { operation: String },

    #[error("{operation} requires genesis operator {expected}, got {actual}")]
    GenesisOperatorMismatch {
        operation: String,
        expected: String,
        actual: String,
    },

    // -- assertion-lease (Phase 4b) --------------------------------------
    #[error("assertion grant not found: {0}")]
    AssertionGrantNotFound(String),

    #[error("assertion out of lease scope: {axis}")]
    AssertionOutOfScope { axis: String },

    #[error("assertion lease window closed (expired at {0})")]
    AssertionWindowClosed(String),

    #[error("assertion lease not yet valid (not_before {0})")]
    AssertionNotYetValid(String),

    #[error(
        "assertion lease window is incoherent or its stored timestamps are unparseable; refusing rather than guessing"
    )]
    AssertionWindowIncoherent,

    #[error("assertion lease use budget exhausted (max_uses {max_uses})")]
    AssertionBudgetExhausted { max_uses: u64 },

    #[error("replay detected: jti {jti} already seen for audience {audience}")]
    ReplayDetected { jti: String, audience: String },

    #[error("assertion proof MAC invalid or missing — the per-request envelope is not authentic")]
    AssertionMacInvalid,

    #[error(
        "assertion proof clock skew exceeded: issued_at is {0}s in the future beyond tolerance"
    )]
    ClockSkewExceeded(i64),

    #[error("assertion proof timestamp out of window: {0}s old, beyond the freshness horizon")]
    RequestTimestampOutOfWindow(i64),

    #[error(
        "cannot issue an assertion lease with no genesis installed; issuance requires a prior settlement-witness"
    )]
    AssertionNoGenesis,

    #[error("assertion speaker {0} cannot authorize its own lease")]
    AssertionSelfGrant(String),

    #[error("class frozen: {handle} ({reason})")]
    ClassFrozen { handle: String, reason: String },

    #[error("freeze {0} already exists")]
    FreezeExists(String),

    #[error("freeze {0} not found")]
    FreezeNotFound(String),
}

/// The standing store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open or create a store at the given path.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Get a replay guard backed by this store's database.
    pub fn replay_guard(&self) -> Result<replay::SqliteReplayGuard<'_>, StoreError> {
        Ok(replay::SqliteReplayGuard::new(&self.conn)?)
    }

    /// Open an in-memory store (for testing).
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS receipts (
                digest TEXT PRIMARY KEY,
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                subject TEXT NOT NULL,
                parent_digest TEXT,
                evidence TEXT NOT NULL,
                policy_hash TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_receipts_subject ON receipts(subject);
            CREATE INDEX IF NOT EXISTS idx_receipts_actor ON receipts(actor);
            CREATE INDEX IF NOT EXISTS idx_receipts_parent ON receipts(parent_digest);

            CREATE TABLE IF NOT EXISTS grants (
                id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                state TEXT NOT NULL,
                issued_at TEXT,
                expires_at TEXT,
                not_before TEXT,
                latest_receipt_digest TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_grants_subject_id ON grants(subject_id);
            CREATE INDEX IF NOT EXISTS idx_grants_actor ON grants(actor);
            CREATE INDEX IF NOT EXISTS idx_grants_state ON grants(state);

            -- Genesis is the chain root: exactly one per Standing instance.
            -- A second install would contradict the invariant 'this instance
            -- was established by this operator on this date under this policy.'
            CREATE UNIQUE INDEX IF NOT EXISTS uniq_genesis
                ON receipts(kind) WHERE kind = 'genesis_install';

            -- Assertion leases (entitlement-to-assert, Phase 4b). A lease is
            -- reusable (spent many times) but budget-bounded (max_uses, L1) and
            -- window-bounded (not_before/expires_at, L2).
            CREATE TABLE IF NOT EXISTS assertion_grants (
                id TEXT PRIMARY KEY,
                actor TEXT NOT NULL,
                claim_kind TEXT NOT NULL,
                subject_scope TEXT NOT NULL,
                audience TEXT NOT NULL,
                state TEXT NOT NULL,
                not_before TEXT,
                issued_at TEXT,
                expires_at TEXT,
                max_uses INTEGER,
                spend_count INTEGER NOT NULL DEFAULT 0,
                latest_receipt_digest TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_agrants_actor ON assertion_grants(actor);
            CREATE INDEX IF NOT EXISTS idx_agrants_audience ON assertion_grants(audience);
            CREATE INDEX IF NOT EXISTS idx_agrants_state ON assertion_grants(state);

            -- Per-request replay ledger for assertion spends. Keyed on
            -- (jti, audience) exactly like seen_jti, but a SEPARATE namespace:
            -- assertion-proof jtis have a different lifetime (bounded by the
            -- lease window) and a different failure meaning than identity jtis.
            -- Merging the two risks a cross-namespace collision masking a real
            -- replay.
            CREATE TABLE IF NOT EXISTS seen_assertion_jti (
                jti TEXT NOT NULL,
                audience TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (jti, audience)
            );
            CREATE INDEX IF NOT EXISTS idx_seen_ajti_expires ON seen_assertion_jti(expires_at);

            -- Policy-level freezes (incident mode, docs/lifecycle-freeze.md).
            -- A freeze is a deny-overlay on a grant CLASS, not a change to any
            -- grant record. Frozen leases keep counting clock-time toward
            -- expiry (freeze is a deny-overlay, not a stop-clock).
            CREATE TABLE IF NOT EXISTS policy_freezes (
                handle TEXT PRIMARY KEY,      -- incident handle / freeze id
                class_type TEXT NOT NULL,     -- claim_kind | action | actor | audience
                class_value TEXT NOT NULL,
                audience_scope TEXT,          -- optional: screen only this audience
                reason TEXT NOT NULL,
                frozen_at TEXT NOT NULL,
                frozen_until TEXT,            -- optional lazy-expiry (deny-overlay predicate)
                thawed_at TEXT,               -- set on explicit thaw
                freeze_receipt TEXT NOT NULL,
                thaw_receipt TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_freezes_class ON policy_freezes(class_type, class_value);

            -- Exact continuity-edge warrants and their pre-provider acquisition
            -- commitments. These are separate from grants and assertion leases:
            -- a warrant permits reliance on one closed edge; it does not claim
            -- that the transition occurred or that any observation is true.
            CREATE TABLE IF NOT EXISTS continuity_authorities (
                authority_occurrence_ref TEXT PRIMARY KEY,
                issuance_request_id TEXT NOT NULL UNIQUE,
                replay_identity TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL,
                subject_ref TEXT NOT NULL,
                relation TEXT NOT NULL CHECK (relation = 'substrate_incarnation'),
                predecessor_ref TEXT NOT NULL,
                successor_ref TEXT NOT NULL,
                nq_audience TEXT NOT NULL,
                issuer_principal TEXT NOT NULL,
                standing_instance TEXT NOT NULL,
                standing_basis_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('issued', 'revoked')),
                signing_key_id TEXT NOT NULL,
                verifying_key_hex TEXT NOT NULL,
                signed_authority_json TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                latest_receipt_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_continuity_edge
                ON continuity_authorities(subject_ref, relation, predecessor_ref, successor_ref);

            CREATE TABLE IF NOT EXISTS continuity_acquisition_commitments (
                commitment_occurrence_ref TEXT PRIMARY KEY,
                request_id TEXT NOT NULL UNIQUE,
                replay_identity TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL,
                authority_occurrence_ref TEXT NOT NULL,
                authority_payload_digest TEXT NOT NULL,
                acquisition_id TEXT NOT NULL UNIQUE,
                acquisition_basis_digest TEXT NOT NULL,
                nq_audience TEXT NOT NULL,
                requester_principal TEXT NOT NULL,
                signed_commitment_json TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                receipt_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(authority_occurrence_ref)
                    REFERENCES continuity_authorities(authority_occurrence_ref)
            );
            ",
        )?;
        Ok(())
    }

    /// Install the genesis receipt for this Standing instance.
    ///
    /// The genesis is the named root of the receipt chain: an operator's
    /// citable fiat establishing initial policy. `basis = "operator_fiat"`,
    /// `prior_grant = null`, `parent_digest = None`. Exactly one per instance
    /// — a second install returns `GenesisExists`.
    ///
    /// Returns the genesis receipt on success. See `docs/genesis-receipt.md`.
    pub fn install_genesis(
        &mut self,
        operator: &str,
        policy_source: &str,
    ) -> Result<Receipt, StoreError> {
        if let Some(existing) = self.get_genesis()? {
            return Err(StoreError::GenesisExists(existing.digest));
        }

        // MVP: hash the policy_source string as the canonical policy identifier.
        // For HardcodedPolicy this is the version marker itself. For external
        // policy artifacts (post-MVP) the source should be the canonical file
        // bytes; the spec at docs/genesis-receipt.md names that future shape.
        let policy_hash = hex::encode(Sha256::digest(policy_source.as_bytes()));

        let instance_id = Uuid::new_v4();
        let evidence = serde_json::json!({
            "version": "standing.genesis.v1",
            "basis": "operator_fiat",
            "prior_grant": serde_json::Value::Null,
            "policy_source": policy_source,
            "instance_id": instance_id.to_string(),
            "claim": "Operator establishes initial Standing policy by explicit fiat. \
                      No prior grant authorises this; the operator is the genesis \
                      authority of this Standing instance.",
        });

        let receipt = ReceiptBuilder::new(
            ReceiptKind::GenesisInstall,
            operator,
            instance_id.to_string(),
        )
        .evidence(evidence)
        .policy_hash(&policy_hash)
        .build()?;

        let tx = self.conn.transaction()?;
        insert_receipt(&tx, &receipt)?;
        tx.commit()?;

        Ok(receipt)
    }

    /// Get this instance's genesis receipt, if one has been installed.
    pub fn get_genesis(&self) -> Result<Option<ReceiptRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT digest, id, kind, timestamp, actor, subject, parent_digest, evidence, policy_hash
             FROM receipts WHERE kind = 'genesis_install' LIMIT 1",
        )?;
        let mut rows = stmt.query_map([], |row| {
            Ok(ReceiptRow {
                digest: row.get(0)?,
                id: row.get(1)?,
                kind: row.get(2)?,
                timestamp: row.get(3)?,
                actor: row.get(4)?,
                subject: row.get(5)?,
                parent_digest: row.get(6)?,
                evidence: row.get(7)?,
                policy_hash: row.get(8)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Authorize assertion issuance against the immutable genesis operator.
    /// The operator and lease actor are deliberately separate principals: the
    /// speaker cannot mint its own standing.
    pub fn authorize_assertion_issuance(
        &self,
        operator: &str,
        lease_actor: &str,
    ) -> Result<ReceiptRow, StoreError> {
        let genesis = self.get_genesis()?.ok_or(StoreError::AssertionNoGenesis)?;
        if genesis.actor != operator {
            return Err(StoreError::GenesisOperatorMismatch {
                operation: "assertion lease issuance".to_string(),
                expected: genesis.actor,
                actual: operator.to_string(),
            });
        }
        if operator == lease_actor {
            return Err(StoreError::AssertionSelfGrant(lease_actor.to_string()));
        }
        Ok(genesis)
    }

    fn require_genesis_operator(
        &self,
        operator: &str,
        operation: &str,
    ) -> Result<ReceiptRow, StoreError> {
        let genesis = self
            .get_genesis()?
            .ok_or_else(|| StoreError::GenesisRequired {
                operation: operation.to_string(),
            })?;
        if genesis.actor != operator {
            return Err(StoreError::GenesisOperatorMismatch {
                operation: operation.to_string(),
                expected: genesis.actor,
                actual: operator.to_string(),
            });
        }
        Ok(genesis)
    }

    /// Evaluate and persist a complete entitlement-to-act creation flow.
    ///
    /// The request, policy decision, and issue/deny receipts are constructed
    /// by their domain owners, verified as one linear chain, and committed in
    /// the same SQLite transaction as the resulting grant row. Act grants
    /// remain valid on pre-genesis instances for compatibility; when genesis
    /// exists, the request receipt is rooted at it.
    pub fn create_grant(
        &mut self,
        request: &GrantRequest,
        policy: &dyn PolicyEvaluator,
    ) -> Result<GrantCreationResult, StoreError> {
        let genesis_digest = self.get_genesis()?.map(|row| row.digest);
        let mut machine = GrantMachine::request_rooted(request, genesis_digest.as_deref())?;
        let grant_id = machine.grant_id();
        let requested_receipt = machine.chain.tip().clone();

        let decision =
            policy.evaluate(request, &grant_id.to_string(), &requested_receipt.digest)?;
        let policy_receipt = decision.receipt.clone();
        validate_receipt_kind(
            "grant request policy witness",
            &ReceiptKind::PolicyDecision,
            &policy_receipt.kind,
        )?;
        if policy_receipt.policy_hash.as_deref() != Some(decision.policy_hash.as_str()) {
            return Err(StoreError::PolicyWitnessMismatch {
                field: "policy_hash".to_string(),
            });
        }
        let verdict_name = match &decision.verdict {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
        };
        if policy_receipt.evidence["verdict"].as_str() != Some(verdict_name) {
            return Err(StoreError::PolicyWitnessMismatch {
                field: "verdict".to_string(),
            });
        }
        machine.chain.append(policy_receipt.clone())?;

        let (final_receipt, expires_at) = match decision.verdict {
            Verdict::Allow => {
                machine.issue(
                    request.duration_secs,
                    &decision.policy_hash,
                    serde_json::json!({
                        "verdict": "allow",
                        "reason": decision.reason.clone(),
                    }),
                )?;
                let grant = machine
                    .grant
                    .as_ref()
                    .expect("issued GrantMachine always contains its grant");
                (machine.chain.tip().clone(), Some(grant.expires_at))
            }
            Verdict::Deny => {
                machine.deny(
                    &decision.policy_hash,
                    serde_json::json!({
                        "verdict": "deny",
                        "reason": decision.reason.clone(),
                    }),
                )?;
                (machine.chain.tip().clone(), None)
            }
        };
        machine.chain.verify()?;

        let state = machine.state.clone();
        let issued_at = machine.grant.as_ref().map(|grant| grant.issued_at);
        let tx = self.conn.transaction()?;
        insert_receipt(&tx, &requested_receipt)?;
        insert_receipt(&tx, &policy_receipt)?;
        insert_receipt(&tx, &final_receipt)?;
        tx.execute(
            "INSERT INTO grants
                (id, subject_id, actor, action, target, state, issued_at,
                 expires_at, not_before, latest_receipt_digest, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, datetime('now'))",
            params![
                grant_id.to_string(),
                &request.subject.id,
                &request.subject.label,
                &request.scope.action,
                &request.scope.target,
                state.to_string(),
                issued_at.map(|time| time.to_rfc3339()),
                expires_at.map(|time| time.to_rfc3339()),
                request.not_before.map(|time| time.to_rfc3339()),
                &final_receipt.digest,
            ],
        )?;
        tx.commit()?;

        Ok(GrantCreationResult {
            grant_id,
            state,
            reason: decision.reason,
            final_receipt,
            expires_at,
        })
    }

    /// Create and issue an assertion lease under the installed genesis.
    ///
    /// The operator is checked against genesis and must differ from the lease
    /// actor. Requested and issued receipts plus the authoritative row are
    /// committed atomically, so public callers cannot import an already-issued
    /// row or choose its receipt kind/parent independently.
    pub fn create_assertion_lease(
        &mut self,
        request: &AssertionGrantRequest,
        operator: &Principal,
    ) -> Result<AssertionLeaseCreationResult, StoreError> {
        let genesis = self.authorize_assertion_issuance(&operator.id, &request.actor.id)?;
        let mut machine = AssertionGrantMachine::request_rooted(request, Some(&genesis.digest))?;
        let grant_id = machine.grant_id();
        let requested_receipt = machine.chain.tip().clone();
        let policy_hash = genesis.policy_hash.clone().unwrap_or_default();
        machine.issue(
            operator,
            &genesis.digest,
            &policy_hash,
            serde_json::json!({
                "basis": "operator_issued_under_genesis",
                "operator_id": operator.id,
                "lease_actor": request.actor.id,
            }),
        )?;
        machine.chain.verify()?;

        let issued_receipt = machine.chain.tip().clone();
        let grant = machine
            .grant
            .clone()
            .expect("issued AssertionGrantMachine always contains its grant");
        let tx = self.conn.transaction()?;
        insert_receipt(&tx, &requested_receipt)?;
        insert_receipt(&tx, &issued_receipt)?;
        tx.execute(
            "INSERT INTO assertion_grants
                (id, actor, claim_kind, subject_scope, audience, state,
                 not_before, issued_at, expires_at, max_uses, spend_count,
                 latest_receipt_digest, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'issued', ?6, ?7, ?8, ?9, 0, ?10,
                     datetime('now'))",
            params![
                grant_id.to_string(),
                &grant.actor.id,
                &grant.scope.claim_kind,
                &grant.scope.subject_scope,
                &grant.scope.audience,
                grant.not_before.to_rfc3339(),
                grant.issued_at.to_rfc3339(),
                grant.expires_at.to_rfc3339(),
                grant.max_uses.map(|uses| uses as i64),
                &issued_receipt.digest,
            ],
        )?;
        tx.commit()?;

        Ok(AssertionLeaseCreationResult {
            grant_id,
            grant,
            issued_receipt,
            genesis_digest: genesis.digest,
            operator_id: operator.id.clone(),
        })
    }

    /// Internal fixture/setup path: store a receipt and update grant state.
    /// Fail-closed: if receipt write fails, the grant state does not change.
    ///
    /// **This method does NOT validate transitions.** It is restricted to this
    /// crate's tests and fixture helpers. Public callers use
    /// [`Store::create_grant`] or [`Store::transition`].
    ///
    /// For all other mutations, use `Store::transition()` — the only legal
    /// mutation path that enforces adjacency, contextual guards, and CAS.
    #[cfg(test)]
    pub(crate) fn record_transition(
        &mut self,
        grant_id: Uuid,
        state: &GrantState,
        receipt: &Receipt,
        grant_meta: Option<GrantMeta>,
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;

        // Write receipt first. If this fails, nothing changes.
        insert_receipt(&tx, receipt)?;

        // Upsert grant state
        let state_str = serde_json::to_value(state)?
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        if let Some(meta) = grant_meta {
            tx.execute(
                "INSERT INTO grants (id, subject_id, actor, action, target, state, issued_at, expires_at, not_before, latest_receipt_digest, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, datetime('now'))
                 ON CONFLICT(id) DO UPDATE SET
                    state = ?6,
                    issued_at = COALESCE(?7, grants.issued_at),
                    expires_at = COALESCE(?8, grants.expires_at),
                    not_before = COALESCE(?9, grants.not_before),
                    latest_receipt_digest = ?10,
                    updated_at = datetime('now')",
                params![
                    grant_id.to_string(),
                    meta.subject_id,
                    meta.actor,
                    meta.action,
                    meta.target,
                    state_str,
                    meta.issued_at.map(|t| t.to_rfc3339()),
                    meta.expires_at.map(|t| t.to_rfc3339()),
                    meta.not_before.map(|t| t.to_rfc3339()),
                    receipt.digest,
                ],
            )?;
        } else {
            tx.execute(
                "UPDATE grants SET state = ?1, latest_receipt_digest = ?2, updated_at = datetime('now') WHERE id = ?3",
                params![state_str, receipt.digest, grant_id.to_string()],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Get all receipts for a grant subject, in chain order.
    pub fn receipt_chain(&self, grant_id: &str) -> Result<Vec<ReceiptRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT digest, id, kind, timestamp, actor, subject, parent_digest, evidence, policy_hash
             FROM receipts WHERE subject = ?1 ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map(params![grant_id], |row| {
            Ok(ReceiptRow {
                digest: row.get(0)?,
                id: row.get(1)?,
                kind: row.get(2)?,
                timestamp: row.get(3)?,
                actor: row.get(4)?,
                subject: row.get(5)?,
                parent_digest: row.get(6)?,
                evidence: row.get(7)?,
                policy_hash: row.get(8)?,
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// "Why was this allowed?" — find the policy decision receipt for a grant.
    pub fn why_allowed(&self, grant_id: &str) -> Result<Option<ReceiptRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT digest, id, kind, timestamp, actor, subject, parent_digest, evidence, policy_hash
             FROM receipts WHERE subject = ?1 AND kind = 'policy_decision'
             ORDER BY created_at DESC LIMIT 1",
        )?;

        let mut rows = stmt.query_map(params![grant_id], |row| {
            Ok(ReceiptRow {
                digest: row.get(0)?,
                id: row.get(1)?,
                kind: row.get(2)?,
                timestamp: row.get(3)?,
                actor: row.get(4)?,
                subject: row.get(5)?,
                parent_digest: row.get(6)?,
                evidence: row.get(7)?,
                policy_hash: row.get(8)?,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Get the current state of a grant.
    pub fn get_grant(&self, grant_id: &str) -> Result<Option<GrantRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, subject_id, actor, action, target, state, issued_at, expires_at, latest_receipt_digest FROM grants WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![grant_id], map_grant_row)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Checked, atomic state transition with CAS semantics.
    ///
    /// This is the only public post-creation mutation path for grant state;
    /// [`Store::create_grant`] owns the atomic creation flow.
    ///
    /// It:
    /// 1. Reads current grant state and head digest (inside transaction)
    /// 2. Validates adjacency (pure graph via GrantState)
    /// 3. Validates authorization (actor role vs auth matrix)
    /// 4. Applies contextual guards (expiry, subject binding)
    /// 5. Builds a receipt with both subject and actor identity
    /// 6. Commits atomically with CAS on head digest
    ///
    /// Returns the new receipt on success.
    pub fn transition(
        &mut self,
        grant_id: &str,
        target_state: GrantState,
        receipt_kind: ReceiptKind,
        actor_ctx: &ActorContext,
        evidence: serde_json::Value,
        policy_hash: Option<&str>,
    ) -> Result<TransitionResult, StoreError> {
        self.transition_inner(
            grant_id,
            target_state,
            receipt_kind,
            actor_ctx,
            evidence,
            policy_hash,
            None,
        )
    }

    /// Like [`Store::transition`], but for a spend that must match the grant's bound
    /// scope. The attempted `(action, target)` is checked against the issued `GrantScope`
    /// BEFORE any write; a mismatch refuses with [`StoreError::ScopeMismatch`] and leaves
    /// the grant unspent (non-consuming — a wrong-target presentation cannot burn a
    /// single-use grant). Standing owns this refusal; consumers inherit it.
    #[allow(clippy::too_many_arguments)]
    pub fn transition_scoped(
        &mut self,
        grant_id: &str,
        target_state: GrantState,
        receipt_kind: ReceiptKind,
        actor_ctx: &ActorContext,
        evidence: serde_json::Value,
        policy_hash: Option<&str>,
        attempted: &GrantScope,
    ) -> Result<TransitionResult, StoreError> {
        self.transition_inner(
            grant_id,
            target_state,
            receipt_kind,
            actor_ctx,
            evidence,
            policy_hash,
            Some(attempted),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transition_inner(
        &mut self,
        grant_id: &str,
        target_state: GrantState,
        receipt_kind: ReceiptKind,
        actor_ctx: &ActorContext,
        evidence: serde_json::Value,
        policy_hash: Option<&str>,
        attempted_scope: Option<&GrantScope>,
    ) -> Result<TransitionResult, StoreError> {
        let tx = self.conn.transaction()?;

        // Step 1: Read current state (inside transaction for isolation)
        let grant = {
            let mut stmt = tx.prepare(
                "SELECT state, latest_receipt_digest, subject_id, expires_at, action, target, not_before FROM grants WHERE id = ?1",
            )?;
            let mut rows = stmt.query_map(params![grant_id], |row| {
                Ok(GrantSnapshot {
                    state: row.get::<_, String>(0)?,
                    head_digest: row.get::<_, String>(1)?,
                    subject_id: row.get::<_, String>(2)?,
                    expires_at: row.get::<_, Option<String>>(3)?,
                    action: row.get::<_, String>(4)?,
                    target: row.get::<_, String>(5)?,
                    not_before: row.get::<_, Option<String>>(6)?,
                })
            })?;
            match rows.next() {
                Some(row) => row?,
                None => return Err(StoreError::GrantNotFound(grant_id.to_string())),
            }
        };

        // Step 2: Validate adjacency
        let current_state =
            grant
                .state
                .parse::<GrantState>()
                .map_err(|_| StoreError::InvalidTransition {
                    from: grant.state.clone(),
                    to: target_state.to_string(),
                })?;

        if !current_state.can_transition_to(&target_state) {
            return Err(StoreError::InvalidTransition {
                from: current_state.to_string(),
                to: target_state.to_string(),
            });
        }

        // The state and receipt kind describe the same event and therefore
        // cannot be selected independently. Refuse before building or writing
        // a receipt if the caller presents a mismatched pair.
        validate_grant_receipt_kind(&current_state, &target_state, &receipt_kind)?;

        // Step 3: Validate authorization
        if !auth::is_authorized(&current_state, &target_state, actor_ctx.role) {
            return Err(StoreError::Unauthorized {
                actor: actor_ctx.principal.id.clone(),
                role: format!("{:?}", actor_ctx.role),
                transition: format!("{} → {}", current_state, target_state),
            });
        }

        // Step 3b: Subject binding — if acting as Subject, principal must
        // match the grant's bound subject_id
        if actor_ctx.role == PrincipalRole::Subject && actor_ctx.principal.id != grant.subject_id {
            return Err(StoreError::Unauthorized {
                actor: actor_ctx.principal.id.clone(),
                role: "subject (wrong principal)".to_string(),
                transition: format!("{} → {}", current_state, target_state),
            });
        }

        // Step 3c: Scope binding — if the caller named an attempted (action, target),
        // it must match the grant's bound scope. Checked BEFORE any write, so a mismatch
        // refuses without spending (the grant stays unspent — non-consuming, so a
        // wrong-target presentation cannot burn a single-use grant). Standing owns this
        // refusal; a consumer adapting the grant inherits it rather than inventing it.
        if let Some(att) = attempted_scope
            && (att.action != grant.action || att.target != grant.target)
        {
            return Err(StoreError::ScopeMismatch {
                granted: format!("{}/{}", grant.action, grant.target),
                attempted: format!("{}/{}", att.action, att.target),
            });
        }

        // Step 3d: Policy freeze (incident mode). An authorizing transition
        // (Active/Used) on a frozen action/actor class is refused with
        // class_frozen — before any write (non-consuming), and the grant record
        // is untouched (deny-overlay, not a state change). Audience-scoped
        // freezes don't apply to act-grants (they carry no audience).
        if matches!(target_state, GrantState::Active | GrantState::Used)
            && let Some(f) = find_active_freeze(&tx, Utc::now(), |f| {
                f.audience_scope.is_none()
                    && match f.class_type.as_str() {
                        "action" => f.class_value == grant.action,
                        "actor" => f.class_value == grant.subject_id,
                        _ => false,
                    }
            })?
        {
            return Err(StoreError::ClassFrozen {
                handle: f.handle,
                reason: f.reason,
            });
        }

        // Step 3e: not_before window. An authorizing transition before the
        // grant's validity window opens is refused (fail-closed on unparseable
        // time, same discipline as expiry).
        if matches!(target_state, GrantState::Active | GrantState::Used)
            && let Some(ref nb_str) = grant.not_before
        {
            let nb = DateTime::parse_from_rfc3339(nb_str)
                .map(|t| t.to_utc())
                .map_err(|_| StoreError::GrantTimeUnparseable(nb_str.clone()))?;
            if Utc::now() < nb {
                return Err(StoreError::GrantNotYetValid(nb_str.clone()));
            }
        }

        // Step 4: Contextual guards
        // Expiry check: if grant has an expires_at and it's in the past
        // (beyond skew tolerance), the only valid transition is to Expired.
        // Fail-closed on an unparseable timestamp — an expiry we cannot read
        // is unknown, and unknown must not silently pass (the clock-witness
        // doctrine; the assertion path obeys the same rule).
        if let Some(ref expires_at_str) = grant.expires_at {
            let expires_at = DateTime::parse_from_rfc3339(expires_at_str)
                .map(|t| t.to_utc())
                .map_err(|_| StoreError::GrantTimeUnparseable(expires_at_str.clone()))?;
            let skew = Duration::seconds(GRANT_EXPIRY_SKEW_SECS);
            if Utc::now() > expires_at + skew && target_state != GrantState::Expired {
                return Err(StoreError::GrantExpired(expires_at_str.clone()));
            }
        }

        // Step 5: Build receipt with actor identity
        let mut builder = ReceiptBuilder::new(receipt_kind, &actor_ctx.principal.id, grant_id)
            .parent_digest(&grant.head_digest)
            .evidence(serde_json::json!({
                "actor": {
                    "principal_id": actor_ctx.principal.id,
                    "label": actor_ctx.principal.label,
                    "role": actor_ctx.role,
                },
                "subject_id": grant.subject_id,
                "detail": evidence,
            }));

        if let Some(ph) = policy_hash {
            builder = builder.policy_hash(ph);
        }

        let receipt = builder.build()?;

        // Step 6: Atomic write with CAS — only update if head hasn't changed
        insert_receipt(&tx, &receipt)?;

        let target_state_str = serde_json::to_value(&target_state)?
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        let rows_updated = tx.execute(
            "UPDATE grants SET state = ?1, latest_receipt_digest = ?2, updated_at = datetime('now')
             WHERE id = ?3 AND latest_receipt_digest = ?4",
            params![
                target_state_str,
                receipt.digest,
                grant_id,
                grant.head_digest
            ],
        )?;

        if rows_updated == 0 {
            // CAS failed: head changed between read and write
            return Err(StoreError::InvalidTransition {
                from: format!("{} (stale head)", grant.state),
                to: target_state_str,
            });
        }

        tx.commit()?;

        Ok(TransitionResult {
            receipt_digest: receipt.digest.clone(),
            from_state: current_state,
            to_state: target_state,
            receipt,
        })
    }

    /// List grants, optionally filtered by state.
    pub fn list_grants(&self, state_filter: Option<&str>) -> Result<Vec<GrantRow>, StoreError> {
        let mut result = Vec::new();

        match state_filter {
            Some(state) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, subject_id, actor, action, target, state, issued_at, expires_at, latest_receipt_digest FROM grants WHERE state = ?1 ORDER BY updated_at DESC",
                )?;
                let rows = stmt.query_map(params![state], map_grant_row)?;
                for row in rows {
                    result.push(row?);
                }
            }
            None => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, subject_id, actor, action, target, state, issued_at, expires_at, latest_receipt_digest FROM grants ORDER BY updated_at DESC",
                )?;
                let rows = stmt.query_map([], map_grant_row)?;
                for row in rows {
                    result.push(row?);
                }
            }
        }

        Ok(result)
    }
}

/// Clock-skew grace on act-grant expiry, in seconds. A grant one second past
/// expiry on a slightly-fast verifier clock should not hard-fail; the identity
/// layer already applies the same tolerance to claims.
const GRANT_EXPIRY_SKEW_SECS: i64 = 30;

/// Max CAS retries for an assertion spend before giving up (amendment #5).
/// Different-jti spends serialize on the head digest; the loser re-reads and
/// retries rather than surfacing a raw stale-head error to the caller.
const SPEND_CAS_RETRIES: u32 = 5;

/// How far in the future a proof's `issued_at` may be before we call it a clock
/// disagreement rather than a fresh request (seconds).
const PROOF_MAX_SKEW_SECS: i64 = 30;

/// How old a proof's `issued_at` may be and still be evaluable (seconds). Past
/// this, the request is out of the freshness window regardless of MAC validity.
const PROOF_MAX_AGE_SECS: i64 = 300;

/// Keep assertion replay nonces for a short grace after lease expiry so clock
/// disagreement cannot reopen a just-expired replay window.
const ASSERTION_JTI_PURGE_SKEW_SECS: i64 = 30;

fn validate_grant_receipt_kind(
    from: &GrantState,
    to: &GrantState,
    actual: &ReceiptKind,
) -> Result<(), StoreError> {
    let expected = match to {
        GrantState::Requested => ReceiptKind::GrantRequested,
        GrantState::Issued => ReceiptKind::GrantIssued,
        GrantState::Denied => ReceiptKind::GrantDenied,
        GrantState::Active => ReceiptKind::GrantActivated,
        GrantState::Used => ReceiptKind::GrantUsed,
        GrantState::Expired => ReceiptKind::GrantExpired,
        GrantState::Revoked => ReceiptKind::GrantRevoked,
        GrantState::Abandoned => ReceiptKind::GrantAbandoned,
    };
    validate_receipt_kind(&format!("{} -> {}", from, to), &expected, actual)
}

fn validate_assertion_receipt_kind(
    from: &AssertionGrantState,
    to: &AssertionGrantState,
    actual: &ReceiptKind,
) -> Result<(), StoreError> {
    let expected = match (from, to) {
        (AssertionGrantState::Active, AssertionGrantState::Active) => ReceiptKind::AssertionMade,
        (_, AssertionGrantState::Requested) => ReceiptKind::AssertionGrantRequested,
        (_, AssertionGrantState::Issued) => ReceiptKind::AssertionGrantIssued,
        (_, AssertionGrantState::Denied) => ReceiptKind::AssertionGrantDenied,
        (_, AssertionGrantState::Active) => ReceiptKind::AssertionGrantActivated,
        (_, AssertionGrantState::Expired) => ReceiptKind::AssertionGrantExpired,
        (_, AssertionGrantState::Revoked) => ReceiptKind::AssertionGrantRevoked,
        (_, AssertionGrantState::Exhausted) => ReceiptKind::AssertionGrantExhausted,
    };
    validate_receipt_kind(&format!("{} -> {}", from, to), &expected, actual)
}

fn validate_receipt_kind(
    transition: &str,
    expected: &ReceiptKind,
    actual: &ReceiptKind,
) -> Result<(), StoreError> {
    if expected != actual {
        return Err(StoreError::ReceiptKindMismatch {
            transition: transition.to_string(),
            expected: format!("{expected:?}"),
            actual: format!("{actual:?}"),
        });
    }
    Ok(())
}

/// Compute the canonical MAC tag for a request proof: HMAC-SHA256 over the
/// canonical JSON of the proof's fixed signed body (the field set pinned in
/// Wave 1, amendment #4).
fn proof_mac(proof: &RequestProof, secret: &[u8]) -> Result<String, StoreError> {
    let bytes =
        standing_receipt::canonical_json(&proof.canonical_body()).map_err(StoreError::Json)?;
    Ok(standing_identity::hmac_hex(secret, &bytes))
}

impl Store {
    /// Unchecked assertion-lease fixture path. This is crate-private so a
    /// library caller cannot import authority around
    /// [`Store::create_assertion_lease`] / [`Store::transition_assertion`].
    #[cfg(test)]
    pub(crate) fn record_assertion_transition(
        &mut self,
        grant_id: Uuid,
        state: &AssertionGrantState,
        receipt: &Receipt,
        meta: Option<AssertionGrantMeta>,
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        insert_receipt(&tx, receipt)?;

        let state_str = state.to_string();

        if let Some(m) = meta {
            tx.execute(
                "INSERT INTO assertion_grants
                    (id, actor, claim_kind, subject_scope, audience, state,
                     not_before, issued_at, expires_at, max_uses, spend_count,
                     latest_receipt_digest, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, datetime('now'))
                 ON CONFLICT(id) DO UPDATE SET
                    state = ?6,
                    not_before = COALESCE(?7, assertion_grants.not_before),
                    issued_at = COALESCE(?8, assertion_grants.issued_at),
                    expires_at = COALESCE(?9, assertion_grants.expires_at),
                    max_uses = COALESCE(?10, assertion_grants.max_uses),
                    latest_receipt_digest = ?11,
                    updated_at = datetime('now')",
                params![
                    grant_id.to_string(),
                    m.actor,
                    m.claim_kind,
                    m.subject_scope,
                    m.audience,
                    state_str,
                    m.not_before.map(|t| t.to_rfc3339()),
                    m.issued_at.map(|t| t.to_rfc3339()),
                    m.expires_at.map(|t| t.to_rfc3339()),
                    m.max_uses.map(|u| u as i64),
                    receipt.digest,
                ],
            )?;
        } else {
            tx.execute(
                "UPDATE assertion_grants SET state = ?1, latest_receipt_digest = ?2, updated_at = datetime('now') WHERE id = ?3",
                params![state_str, receipt.digest, grant_id.to_string()],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Get an assertion lease's current row.
    pub fn get_assertion_grant(
        &self,
        grant_id: &str,
    ) -> Result<Option<AssertionGrantRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, actor, claim_kind, subject_scope, audience, state, not_before,
                    issued_at, expires_at, max_uses, spend_count, latest_receipt_digest
             FROM assertion_grants WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![grant_id], map_assertion_grant_row)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// List assertion leases, optionally filtered by state and/or audience.
    pub fn list_assertion_grants(
        &self,
        state_filter: Option<&str>,
        audience_filter: Option<&str>,
    ) -> Result<Vec<AssertionGrantRow>, StoreError> {
        let mut sql = String::from(
            "SELECT id, actor, claim_kind, subject_scope, audience, state, not_before,
                    issued_at, expires_at, max_uses, spend_count, latest_receipt_digest
             FROM assertion_grants",
        );
        let mut clauses = Vec::new();
        if state_filter.is_some() {
            clauses.push("state = :state");
        }
        if audience_filter.is_some() {
            clauses.push("audience = :audience");
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY updated_at DESC");

        let mut stmt = self.conn.prepare(&sql)?;
        let mut params_vec: Vec<(&str, &dyn rusqlite::ToSql)> = Vec::new();
        if let Some(s) = state_filter.as_ref() {
            params_vec.push((":state", s));
        }
        if let Some(a) = audience_filter.as_ref() {
            params_vec.push((":audience", a));
        }
        let rows = stmt.query_map(params_vec.as_slice(), map_assertion_grant_row)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Checked lifecycle transition for an assertion lease (activate / revoke /
    /// expire / deny). NOT a spend — see [`Store::spend_assertion`] for the
    /// `Active → Active` self-loop. Mirrors [`Store::transition`] with CAS.
    #[allow(clippy::too_many_arguments)]
    pub fn transition_assertion(
        &mut self,
        grant_id: &str,
        target_state: AssertionGrantState,
        receipt_kind: ReceiptKind,
        actor_ctx: &ActorContext,
        evidence: serde_json::Value,
        policy_hash: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Receipt, StoreError> {
        if target_state == AssertionGrantState::Issued {
            self.require_genesis_operator(&actor_ctx.principal.id, "assertion lease issuance")?;
        }
        let tx = self.conn.transaction()?;
        let snap = read_assertion_snapshot(&tx, grant_id)?;

        let current = snap.state.parse::<AssertionGrantState>().map_err(|_| {
            StoreError::InvalidTransition {
                from: snap.state.clone(),
                to: target_state.to_string(),
            }
        })?;
        if !current.can_transition_to(&target_state) {
            return Err(StoreError::InvalidTransition {
                from: current.to_string(),
                to: target_state.to_string(),
            });
        }

        // Active -> Active is a spend, not a generic lifecycle mutation. The
        // dedicated spend path owns proof, replay, window, budget, and CAS
        // checks; allowing it here would bypass all of them.
        if current == AssertionGrantState::Active && target_state == AssertionGrantState::Active {
            return Err(StoreError::InvalidTransition {
                from: "active (use spend_assertion for the spend self-loop)".to_string(),
                to: target_state.to_string(),
            });
        }

        validate_assertion_receipt_kind(&current, &target_state, &receipt_kind)?;

        if !auth::is_assertion_authorized(&current, &target_state, actor_ctx.role) {
            return Err(StoreError::Unauthorized {
                actor: actor_ctx.principal.id.clone(),
                role: format!("{:?}", actor_ctx.role),
                transition: format!("{} -> {}", current, target_state),
            });
        }

        if current == AssertionGrantState::Requested
            && target_state == AssertionGrantState::Issued
            && actor_ctx.principal.id == snap.actor
        {
            return Err(StoreError::AssertionSelfGrant(snap.actor));
        }

        // Subject binding: a Subject actor may only drive its own lease.
        if actor_ctx.role == PrincipalRole::Subject && actor_ctx.principal.id != snap.actor {
            return Err(StoreError::Unauthorized {
                actor: actor_ctx.principal.id.clone(),
                role: "subject (wrong principal)".to_string(),
                transition: format!("{} → {}", current, target_state),
            });
        }

        // Activation must land inside the validity window (L2). Expire/revoke
        // are allowed regardless.
        if target_state == AssertionGrantState::Active {
            let grant = snapshot_to_grant(&snap, grant_id)?;
            match grant.window_state(now, Duration::zero()) {
                WindowState::Within => {}
                WindowState::NotYetValid => {
                    return Err(StoreError::AssertionNotYetValid(
                        grant.not_before.to_rfc3339(),
                    ));
                }
                WindowState::Expired => {
                    return Err(StoreError::AssertionWindowClosed(
                        grant.expires_at.to_rfc3339(),
                    ));
                }
                WindowState::Incoherent => return Err(StoreError::AssertionWindowIncoherent),
            }
        }

        let receipt = build_assertion_receipt(
            receipt_kind,
            &actor_ctx.principal.id,
            grant_id,
            &snap.head_digest,
            serde_json::json!({
                "actor": {
                    "principal_id": actor_ctx.principal.id,
                    "label": actor_ctx.principal.label,
                    "role": actor_ctx.role,
                },
                "detail": evidence,
            }),
            policy_hash,
        )?;

        insert_receipt(&tx, &receipt)?;
        let rows = tx.execute(
            "UPDATE assertion_grants SET state = ?1, latest_receipt_digest = ?2, updated_at = datetime('now')
             WHERE id = ?3 AND latest_receipt_digest = ?4",
            params![target_state.to_string(), receipt.digest, grant_id, snap.head_digest],
        )?;
        if rows == 0 {
            return Err(StoreError::InvalidTransition {
                from: format!("{} (stale head)", snap.state),
                to: target_state.to_string(),
            });
        }
        tx.commit()?;
        Ok(receipt)
    }

    /// Spend an assertion lease once — the `Active → Active` self-loop.
    ///
    /// All refusal checks run BEFORE any write (non-consuming on refusal). In
    /// order: actor binding, scope coverage (L-scope), validity window (L2),
    /// use budget (L1), then the single-use replay ledger. On success it emits
    /// an `AssertionMade` receipt (auto-emitting `AssertionGrantActivated` first
    /// if the lease was still `Issued`, so the chain never shows a spend without
    /// a prior activation — amendment #3), and, if this spend exhausts the
    /// budget, an `AssertionGrantExhausted` receipt driving the lease terminal
    /// (L1). The whole thing is one transaction with a bounded CAS retry on head
    /// contention (amendment #5); a real replay (`jti` already committed for the
    /// audience) refuses without retry.
    pub fn spend_assertion(
        &mut self,
        proof: &RequestProof,
        now: DateTime<Utc>,
    ) -> Result<AssertionSpendResult, StoreError> {
        let grant_id = proof.grant_id.to_string();

        // Policy freeze (incident mode): a deny-overlay checked before any
        // write — non-consuming (L6). The lease is untouched and keeps counting
        // clock-time toward expiry; the freeze only screens the class.
        if let Some(f) =
            self.active_freeze_for(&proof.claim_kind, &proof.actor, &proof.audience, now)?
        {
            return Err(StoreError::ClassFrozen {
                handle: f.handle,
                reason: f.reason,
            });
        }

        for _attempt in 0..SPEND_CAS_RETRIES {
            let tx = self.conn.transaction()?;
            let snap = read_assertion_snapshot(&tx, &grant_id)?;

            let current = snap.state.parse::<AssertionGrantState>().map_err(|_| {
                StoreError::InvalidTransition {
                    from: snap.state.clone(),
                    to: "active".into(),
                }
            })?;

            // Must be spendable: Active, or Issued (auto-activate). Anything
            // else (Requested/terminal) refuses.
            let needs_activation = match &current {
                AssertionGrantState::Active => false,
                AssertionGrantState::Issued => true,
                AssertionGrantState::Exhausted => {
                    let max = snap.max_uses.unwrap_or(0).max(0) as u64;
                    return Err(StoreError::AssertionBudgetExhausted { max_uses: max });
                }
                other => {
                    return Err(StoreError::InvalidTransition {
                        from: other.to_string(),
                        to: "active (spend)".into(),
                    });
                }
            };

            if !auth::is_assertion_authorized(
                &current,
                &AssertionGrantState::Active,
                PrincipalRole::Subject,
            ) {
                return Err(StoreError::Unauthorized {
                    actor: proof.actor.clone(),
                    role: "Subject".to_string(),
                    transition: format!("{} -> active (spend)", current),
                });
            }

            let grant = snapshot_to_grant(&snap, &grant_id)?;

            // --- refusal checks, all before any write (non-consuming) ---

            if proof.actor != grant.actor.id {
                return Err(StoreError::AssertionOutOfScope {
                    axis: "actor_mismatch".into(),
                });
            }
            match assertion_covers(
                &grant.scope,
                &proof.claim_kind,
                &proof.subject_id,
                &proof.audience,
            ) {
                AssertCoverage::Covered => {}
                AssertCoverage::ClaimKindMismatch => {
                    return Err(StoreError::AssertionOutOfScope {
                        axis: "claim_kind_out_of_scope".into(),
                    });
                }
                AssertCoverage::SubjectMismatch => {
                    return Err(StoreError::AssertionOutOfScope {
                        axis: "subject_out_of_scope".into(),
                    });
                }
                AssertCoverage::AudienceMismatch => {
                    return Err(StoreError::AssertionOutOfScope {
                        axis: "audience_mismatch".into(),
                    });
                }
            }
            match grant.window_state(now, Duration::zero()) {
                WindowState::Within => {}
                WindowState::NotYetValid => {
                    return Err(StoreError::AssertionNotYetValid(
                        grant.not_before.to_rfc3339(),
                    ));
                }
                WindowState::Expired => {
                    return Err(StoreError::AssertionWindowClosed(
                        grant.expires_at.to_rfc3339(),
                    ));
                }
                WindowState::Incoherent => return Err(StoreError::AssertionWindowIncoherent),
            }
            if grant.is_exhausted() {
                return Err(StoreError::AssertionBudgetExhausted {
                    max_uses: grant.max_uses.unwrap_or(0),
                });
            }

            // --- replay ledger (single-use jti per audience) ---
            // Bound the ledger without reopening the expiry boundary: entries
            // are purgeable only after their recorded lease expiry plus the
            // same 30-second skew grace used by identity replay handling.
            let purge_cutoff =
                (now - Duration::seconds(ASSERTION_JTI_PURGE_SKEW_SECS)).to_rfc3339();
            tx.execute(
                "DELETE FROM seen_assertion_jti WHERE expires_at < ?1",
                params![purge_cutoff],
            )?;

            // INSERT OR IGNORE inside this tx: if the row already exists (a
            // committed prior spend), it's a replay. A CAS-failed retry rolls
            // this back, so the same logical spend can re-insert on retry.
            let jti_expires = grant.expires_at.to_rfc3339();
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO seen_assertion_jti (jti, audience, expires_at) VALUES (?1, ?2, ?3)",
                params![proof.jti, proof.audience, jti_expires],
            )?;
            if inserted == 0 {
                // Real replay — do not retry.
                return Err(StoreError::ReplayDetected {
                    jti: proof.jti.clone(),
                    audience: proof.audience.clone(),
                });
            }

            // --- writes, chained to the head ---
            let mut head = snap.head_digest.clone();

            // Auto-activation emits its own receipt (amendment #3).
            if needs_activation {
                let act = build_assertion_receipt(
                    ReceiptKind::AssertionGrantActivated,
                    &grant.actor.id,
                    &grant_id,
                    &head,
                    serde_json::json!({ "auto_activated_by_spend": true }),
                    None,
                )?;
                insert_receipt(&tx, &act)?;
                head = act.digest;
            }

            let new_seq = snap.spend_count.max(0) as u64 + 1;
            let issuance_digest = find_issuance_digest(&tx, &grant_id)?.unwrap_or_default();
            let made = build_assertion_receipt(
                ReceiptKind::AssertionMade,
                &grant.actor.id,
                &grant_id,
                &head,
                serde_json::json!({
                    "version": standing_grant::ASSERTION_MADE_VERSION,
                    "proof": proof.canonical_body(),
                    "spend_seq": new_seq,
                    "authority": issuance_digest,
                }),
                None,
            )?;
            insert_receipt(&tx, &made)?;
            head = made.digest.clone();

            // Exhaustion (L1): if this spend hits the budget, drive terminal.
            let exhausted = matches!(grant.max_uses, Some(m) if new_seq >= m);
            let (final_state, final_head) = if exhausted {
                let exh = build_assertion_receipt(
                    ReceiptKind::AssertionGrantExhausted,
                    &grant.actor.id,
                    &grant_id,
                    &head,
                    serde_json::json!({ "max_uses": grant.max_uses.unwrap_or(0) }),
                    None,
                )?;
                insert_receipt(&tx, &exh)?;
                (AssertionGrantState::Exhausted, exh.digest)
            } else {
                (AssertionGrantState::Active, head)
            };

            // --- CAS on the ORIGINAL head; retry on contention ---
            let rows = tx.execute(
                "UPDATE assertion_grants
                    SET state = ?1, latest_receipt_digest = ?2, spend_count = ?3, updated_at = datetime('now')
                    WHERE id = ?4 AND latest_receipt_digest = ?5",
                params![
                    final_state.to_string(),
                    final_head,
                    new_seq as i64,
                    grant_id,
                    snap.head_digest,
                ],
            )?;
            if rows == 0 {
                // Head moved between read and write — drop tx (rolls back the
                // jti insert too) and retry with a fresh snapshot.
                drop(tx);
                continue;
            }
            tx.commit()?;
            return Ok(AssertionSpendResult {
                receipt_digest: made.digest.clone(),
                spend_seq: new_seq,
                exhausted,
                receipt: made,
            });
        }

        Err(StoreError::InvalidTransition {
            from: "assertion_grant (contended head)".into(),
            to: "active (spend) after retries".into(),
        })
    }

    /// Like [`Store::spend_assertion`], but first AUTHENTICATES the per-request
    /// proof: it checks the proof timestamp against the freshness window and
    /// verifies the `mac` over the proof's canonical body with `secret`. This is
    /// the MAC-verified binding path; plain `spend_assertion` trusts the
    /// transport. Per L5 the MAC must be contemporaneous with the spend — this
    /// method verifies it at spend time and there is no backfill path.
    ///
    /// (Audience-key *distribution* — how a verifier obtains `secret` for a
    /// given actor/audience — is deliberately out of scope here; the caller
    /// resolves the key. This method is the verification capability, not the
    /// distribution layer.)
    pub fn spend_assertion_verified(
        &mut self,
        proof: &RequestProof,
        mac: Option<&str>,
        secret: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AssertionSpendResult, StoreError> {
        // Clock window (fail-closed both directions).
        let ahead = (proof.issued_at - now).num_seconds();
        if ahead > PROOF_MAX_SKEW_SECS {
            return Err(StoreError::ClockSkewExceeded(ahead));
        }
        let age = (now - proof.issued_at).num_seconds();
        if age > PROOF_MAX_AGE_SECS {
            return Err(StoreError::RequestTimestampOutOfWindow(age));
        }

        // MAC over the fixed canonical body (constant-time compare).
        let expected = proof_mac(proof, secret)?;
        match mac {
            Some(m) if ct_eq(m, &expected) => {}
            _ => return Err(StoreError::AssertionMacInvalid),
        }

        self.spend_assertion(proof, now)
    }
}

/// Sign a request proof, producing the MAC a verifier will check. The inverse
/// of the check inside [`Store::spend_assertion_verified`].
pub fn sign_proof(proof: &RequestProof, secret: &[u8]) -> Result<String, StoreError> {
    proof_mac(proof, secret)
}

/// Constant-time string comparison for MAC tags — avoids leaking how many
/// leading characters matched via timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

impl Store {
    /// Install a policy-level freeze over a grant class (incident mode). The
    /// freeze is a positive, signed, receipt-bearing artifact (L6) — NOT the
    /// absence of a grant. It does not touch any grant record; matching requests
    /// are refused with `class_frozen` while the freeze is active. See
    /// docs/lifecycle-freeze.md.
    #[allow(clippy::too_many_arguments)]
    pub fn install_freeze(
        &mut self,
        handle: &str,
        class_type: &str,
        class_value: &str,
        audience_scope: Option<&str>,
        reason: &str,
        frozen_until: Option<DateTime<Utc>>,
        operator: &str,
        now: DateTime<Utc>,
    ) -> Result<Receipt, StoreError> {
        self.require_genesis_operator(operator, "policy freeze")?;
        if self.get_freeze(handle)?.is_some() {
            return Err(StoreError::FreezeExists(handle.to_string()));
        }
        let receipt = ReceiptBuilder::new(ReceiptKind::PolicyFrozen, operator, handle)
            .evidence(serde_json::json!({
                "handle": handle,
                "class_type": class_type,
                "class_value": class_value,
                "audience_scope": audience_scope,
                "reason": reason,
                "frozen_at": now.to_rfc3339(),
                "frozen_until": frozen_until.map(|t| t.to_rfc3339()),
            }))
            .build()?;
        let tx = self.conn.transaction()?;
        insert_receipt(&tx, &receipt)?;
        tx.execute(
            "INSERT INTO policy_freezes
                (handle, class_type, class_value, audience_scope, reason, frozen_at, frozen_until, freeze_receipt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                handle, class_type, class_value, audience_scope, reason,
                now.to_rfc3339(), frozen_until.map(|t| t.to_rfc3339()), receipt.digest,
            ],
        )?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Lift a freeze (explicit thaw). Receipt-bearing; the same grant class is
    /// authorizable again with no re-issue.
    pub fn thaw_freeze(
        &mut self,
        handle: &str,
        operator: &str,
        now: DateTime<Utc>,
    ) -> Result<Receipt, StoreError> {
        self.require_genesis_operator(operator, "policy thaw")?;
        let f = self
            .get_freeze(handle)?
            .ok_or_else(|| StoreError::FreezeNotFound(handle.to_string()))?;
        if f.thawed_at.is_some() {
            return Err(StoreError::FreezeNotFound(format!(
                "{handle} (already thawed)"
            )));
        }
        let receipt = ReceiptBuilder::new(ReceiptKind::PolicyThawed, operator, handle)
            .parent_digest(f.freeze_receipt.clone())
            .evidence(serde_json::json!({ "handle": handle, "thawed_at": now.to_rfc3339() }))
            .build()?;
        let tx = self.conn.transaction()?;
        insert_receipt(&tx, &receipt)?;
        tx.execute(
            "UPDATE policy_freezes SET thawed_at = ?1, thaw_receipt = ?2 WHERE handle = ?3",
            params![now.to_rfc3339(), receipt.digest, handle],
        )?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Fetch a freeze by handle.
    pub fn get_freeze(&self, handle: &str) -> Result<Option<FreezeRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT handle, class_type, class_value, audience_scope, reason, frozen_at, frozen_until, thawed_at, freeze_receipt
             FROM policy_freezes WHERE handle = ?1",
        )?;
        let mut rows = stmt.query_map(params![handle], map_freeze_row)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// List freezes. `active_only` excludes explicitly-thawed ones (but includes
    /// lazily-expired `frozen_until` freezes — the caller filters those against
    /// `now` if it cares).
    pub fn list_freezes(&self, active_only: bool) -> Result<Vec<FreezeRow>, StoreError> {
        let sql = if active_only {
            "SELECT handle, class_type, class_value, audience_scope, reason, frozen_at, frozen_until, thawed_at, freeze_receipt
             FROM policy_freezes WHERE thawed_at IS NULL ORDER BY frozen_at DESC"
        } else {
            "SELECT handle, class_type, class_value, audience_scope, reason, frozen_at, frozen_until, thawed_at, freeze_receipt
             FROM policy_freezes ORDER BY frozen_at DESC"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([], map_freeze_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// The active freeze covering this request, if any. Honors lazy
    /// `frozen_until` expiry (a past `until` no longer matches — deny-overlay
    /// predicate, not a scheduler) and audience scoping (a freeze scoped to
    /// audience B does not screen B', L6).
    pub fn active_freeze_for(
        &self,
        claim_kind: &str,
        actor: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<FreezeRow>, StoreError> {
        find_active_freeze(&self.conn, now, |f| {
            if let Some(scope) = &f.audience_scope
                && scope != audience
            {
                return false; // scoped to a different audience (L6)
            }
            match f.class_type.as_str() {
                "claim_kind" => f.class_value == claim_kind,
                "actor" => f.class_value == actor,
                "audience" => f.class_value == audience,
                _ => false,
            }
        })
    }
}

/// Find the first active (non-thawed, non-lazily-expired) freeze matching
/// `matcher`. Takes a bare `&Connection` so it works both on the store and
/// inside an open transaction (`&Transaction` derefs to `&Connection`).
fn find_active_freeze(
    conn: &Connection,
    now: DateTime<Utc>,
    matcher: impl Fn(&FreezeRow) -> bool,
) -> Result<Option<FreezeRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT handle, class_type, class_value, audience_scope, reason, frozen_at, frozen_until, thawed_at, freeze_receipt
         FROM policy_freezes WHERE thawed_at IS NULL ORDER BY frozen_at DESC",
    )?;
    let rows = stmt.query_map([], map_freeze_row)?;
    for r in rows {
        let f = r?;
        if let Some(until) = &f.frozen_until
            && let Ok(u) = DateTime::parse_from_rfc3339(until)
            && now >= u.to_utc()
        {
            continue; // lazily expired
        }
        if matcher(&f) {
            return Ok(Some(f));
        }
    }
    Ok(None)
}

/// A policy freeze as returned from the store.
#[derive(Debug, Clone)]
pub struct FreezeRow {
    pub handle: String,
    pub class_type: String,
    pub class_value: String,
    pub audience_scope: Option<String>,
    pub reason: String,
    pub frozen_at: String,
    pub frozen_until: Option<String>,
    pub thawed_at: Option<String>,
    pub freeze_receipt: String,
}

fn map_freeze_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FreezeRow> {
    Ok(FreezeRow {
        handle: row.get(0)?,
        class_type: row.get(1)?,
        class_value: row.get(2)?,
        audience_scope: row.get(3)?,
        reason: row.get(4)?,
        frozen_at: row.get(5)?,
        frozen_until: row.get(6)?,
        thawed_at: row.get(7)?,
        freeze_receipt: row.get(8)?,
    })
}

fn map_grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        id: row.get(0)?,
        subject_id: row.get(1)?,
        actor: row.get(2)?,
        action: row.get(3)?,
        target: row.get(4)?,
        state: row.get(5)?,
        issued_at: row.get(6)?,
        expires_at: row.get(7)?,
        latest_receipt_digest: row.get(8)?,
    })
}

fn insert_receipt(tx: &Transaction, receipt: &Receipt) -> Result<(), StoreError> {
    let kind_str = serde_json::to_value(&receipt.kind)?
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    tx.execute(
        "INSERT INTO receipts (digest, id, kind, timestamp, actor, subject, parent_digest, evidence, policy_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            receipt.digest,
            receipt.id.to_string(),
            kind_str,
            receipt.timestamp.to_rfc3339(),
            receipt.actor,
            receipt.subject,
            receipt.parent_digest,
            serde_json::to_string(&receipt.evidence)?,
            receipt.policy_hash,
        ],
    )?;
    Ok(())
}

// -- assertion-lease helpers (Phase 4b) ---------------------------------

fn read_assertion_snapshot(
    tx: &Transaction,
    grant_id: &str,
) -> Result<AssertionSnapshot, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT state, latest_receipt_digest, actor, claim_kind, subject_scope, audience,
                not_before, issued_at, expires_at, max_uses, spend_count
         FROM assertion_grants WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![grant_id], |row| {
        Ok(AssertionSnapshot {
            state: row.get(0)?,
            head_digest: row.get(1)?,
            actor: row.get(2)?,
            claim_kind: row.get(3)?,
            subject_scope: row.get(4)?,
            audience: row.get(5)?,
            not_before: row.get(6)?,
            issued_at: row.get(7)?,
            expires_at: row.get(8)?,
            max_uses: row.get(9)?,
            spend_count: row.get(10)?,
        })
    })?;
    match rows.next() {
        Some(r) => Ok(r?),
        None => Err(StoreError::AssertionGrantNotFound(grant_id.to_string())),
    }
}

/// Rebuild an [`AssertionGrant`] from a stored snapshot so the shared window /
/// coverage / budget predicates can run. Fail-closed (L2): an unparseable or
/// missing `not_before`/`expires_at` is refused as `AssertionWindowIncoherent`,
/// never silently skipped.
fn snapshot_to_grant(
    snap: &AssertionSnapshot,
    grant_id: &str,
) -> Result<AssertionGrant, StoreError> {
    let parse = |o: &Option<String>| -> Result<DateTime<Utc>, StoreError> {
        o.as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.to_utc())
            .ok_or(StoreError::AssertionWindowIncoherent)
    };
    let not_before = parse(&snap.not_before)?;
    let expires_at = parse(&snap.expires_at)?;
    let issued_at = parse(&snap.issued_at).unwrap_or(not_before);
    let id = Uuid::parse_str(grant_id).unwrap_or_else(|_| Uuid::nil());
    Ok(AssertionGrant {
        id,
        actor: Principal::new(snap.actor.clone(), snap.actor.clone()),
        scope: AssertionScope {
            claim_kind: snap.claim_kind.clone(),
            subject_scope: snap.subject_scope.clone(),
            audience: snap.audience.clone(),
        },
        not_before,
        issued_at,
        expires_at,
        max_uses: snap.max_uses.map(|m| m.max(0) as u64),
        spend_count: snap.spend_count.max(0) as u64,
    })
}

fn build_assertion_receipt(
    kind: ReceiptKind,
    actor: &str,
    subject: &str,
    parent_digest: &str,
    evidence: serde_json::Value,
    policy_hash: Option<&str>,
) -> Result<Receipt, StoreError> {
    let mut b = ReceiptBuilder::new(kind, actor, subject)
        .parent_digest(parent_digest)
        .evidence(evidence);
    if let Some(ph) = policy_hash {
        b = b.policy_hash(ph);
    }
    Ok(b.build()?)
}

fn find_issuance_digest(tx: &Transaction, grant_id: &str) -> Result<Option<String>, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT digest FROM receipts WHERE subject = ?1 AND kind = 'assertion_grant_issued'
         ORDER BY created_at ASC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![grant_id], |row| row.get::<_, String>(0))?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

fn map_assertion_grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AssertionGrantRow> {
    Ok(AssertionGrantRow {
        id: row.get(0)?,
        actor: row.get(1)?,
        claim_kind: row.get(2)?,
        subject_scope: row.get(3)?,
        audience: row.get(4)?,
        state: row.get(5)?,
        not_before: row.get(6)?,
        issued_at: row.get(7)?,
        expires_at: row.get(8)?,
        max_uses: row.get::<_, Option<i64>>(9)?.map(|m| m.max(0) as u64),
        spend_count: row.get::<_, i64>(10)?.max(0) as u64,
        latest_receipt_digest: row.get(11)?,
    })
}

/// Metadata for creating/updating an assertion-lease row.
pub struct AssertionGrantMeta {
    pub actor: String,
    pub claim_kind: String,
    pub subject_scope: String,
    pub audience: String,
    pub not_before: Option<DateTime<Utc>>,
    pub issued_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_uses: Option<u64>,
}

/// An assertion lease as returned from the store.
#[derive(Debug)]
pub struct AssertionGrantRow {
    pub id: String,
    pub actor: String,
    pub claim_kind: String,
    pub subject_scope: String,
    pub audience: String,
    pub state: String,
    pub not_before: Option<String>,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub max_uses: Option<u64>,
    pub spend_count: u64,
    pub latest_receipt_digest: String,
}

/// Internal: snapshot of an assertion lease read inside a transaction.
struct AssertionSnapshot {
    state: String,
    head_digest: String,
    actor: String,
    claim_kind: String,
    subject_scope: String,
    audience: String,
    not_before: Option<String>,
    issued_at: Option<String>,
    expires_at: Option<String>,
    max_uses: Option<i64>,
    spend_count: i64,
}

/// Result of a successful assertion spend.
#[derive(Debug)]
pub struct AssertionSpendResult {
    /// Digest of the `AssertionMade` receipt.
    pub receipt_digest: String,
    /// 1-based sequence number of this spend.
    pub spend_seq: u64,
    /// True if this spend hit the use budget and drove the lease to `Exhausted`.
    pub exhausted: bool,
    /// The `AssertionMade` receipt.
    pub receipt: Receipt,
}

/// Result of atomically creating an entitlement-to-act grant.
#[derive(Debug)]
pub struct GrantCreationResult {
    pub grant_id: Uuid,
    pub state: GrantState,
    pub reason: String,
    pub final_receipt: Receipt,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Result of atomically creating and issuing an assertion lease.
#[derive(Debug)]
pub struct AssertionLeaseCreationResult {
    pub grant_id: Uuid,
    pub grant: AssertionGrant,
    pub issued_receipt: Receipt,
    pub genesis_digest: String,
    pub operator_id: String,
}

/// Metadata for creating/updating a grant row.
pub struct GrantMeta {
    /// Stable principal ID the grant is bound to
    pub subject_id: String,
    /// Display label for the actor (human-readable)
    pub actor: String,
    pub action: String,
    pub target: String,
    pub issued_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub not_before: Option<DateTime<Utc>>,
}

/// A receipt as returned from the store.
#[derive(Debug)]
pub struct ReceiptRow {
    pub digest: String,
    pub id: String,
    pub kind: String,
    pub timestamp: String,
    pub actor: String,
    pub subject: String,
    pub parent_digest: Option<String>,
    pub evidence: String,
    pub policy_hash: Option<String>,
}

/// A grant as returned from the store.
#[derive(Debug)]
pub struct GrantRow {
    pub id: String,
    pub subject_id: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub state: String,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub latest_receipt_digest: String,
}

/// Internal: snapshot of grant state read inside a transaction.
struct GrantSnapshot {
    state: String,
    head_digest: String,
    subject_id: String,
    expires_at: Option<String>,
    action: String,
    target: String,
    not_before: Option<String>,
}

/// Result of a successful transition.
#[derive(Debug)]
pub struct TransitionResult {
    pub receipt_digest: String,
    pub from_state: GrantState,
    pub to_state: GrantState,
    pub receipt: Receipt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use standing_grant::Principal;
    use standing_policy::{HardcodedPolicy, PolicyDecision};
    use standing_receipt::{ReceiptBuilder, ReceiptKind};

    const SUBJECT_ID: &str = "wl:deploy-bot:host-abc";

    fn bot_subject() -> ActorContext {
        ActorContext::subject(Principal::new(SUBJECT_ID, "deploy-bot"))
    }

    fn admin_ctx() -> ActorContext {
        ActorContext::admin(Principal::new("admin:jbeck", "jbeck"))
    }

    fn wrong_subject() -> ActorContext {
        ActorContext::subject(Principal::new("wl:evil-bot:host-xyz", "evil-bot"))
    }

    fn meta() -> GrantMeta {
        GrantMeta {
            subject_id: SUBJECT_ID.to_string(),
            actor: "deploy-bot".to_string(),
            action: "deploy".to_string(),
            target: "prod".to_string(),
            issued_at: None,
            expires_at: None,
            not_before: None,
        }
    }

    fn meta_with_expiry(expires_at: DateTime<Utc>) -> GrantMeta {
        GrantMeta {
            subject_id: SUBJECT_ID.to_string(),
            actor: "deploy-bot".to_string(),
            action: "deploy".to_string(),
            target: "prod".to_string(),
            issued_at: Some(Utc::now()),
            expires_at: Some(expires_at),
            not_before: None,
        }
    }

    fn act_request(duration_secs: u64) -> GrantRequest {
        GrantRequest {
            subject: Principal::new(SUBJECT_ID, "deploy-bot"),
            scope: GrantScope {
                action: "deploy".to_string(),
                target: "prod".to_string(),
            },
            duration_secs,
            not_before: None,
            context: serde_json::Value::Null,
        }
    }

    #[test]
    fn checked_grant_creation_is_atomic_and_linear_through_policy() {
        let mut store = Store::in_memory().unwrap();
        let created = store
            .create_grant(&act_request(300), &HardcodedPolicy)
            .unwrap();

        assert_eq!(created.state, GrantState::Issued);
        let chain = store.receipt_chain(&created.grant_id.to_string()).unwrap();
        assert_eq!(
            chain
                .iter()
                .map(|receipt| receipt.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["grant_requested", "policy_decision", "grant_issued"],
        );
        assert!(chain[0].parent_digest.is_none());
        for pair in chain.windows(2) {
            assert_eq!(
                pair[1].parent_digest.as_deref(),
                Some(pair[0].digest.as_str())
            );
        }
        let row = store
            .get_grant(&created.grant_id.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(row.latest_receipt_digest, created.final_receipt.digest);
    }

    #[test]
    fn checked_grant_creation_roots_at_optional_genesis_and_records_denial() {
        let mut store = Store::in_memory().unwrap();
        let genesis = store
            .install_genesis("admin:jbeck", "hardcoded:v1")
            .unwrap();
        let created = store
            .create_grant(&act_request(3601), &HardcodedPolicy)
            .unwrap();

        assert_eq!(created.state, GrantState::Denied);
        assert!(created.reason.contains("exceeds max"));
        let chain = store.receipt_chain(&created.grant_id.to_string()).unwrap();
        assert_eq!(
            chain[0].parent_digest.as_deref(),
            Some(genesis.digest.as_str())
        );
        assert_eq!(
            chain[1].parent_digest.as_deref(),
            Some(chain[0].digest.as_str())
        );
        assert_eq!(
            chain[2].parent_digest.as_deref(),
            Some(chain[1].digest.as_str())
        );
        assert_eq!(chain[2].kind, "grant_denied");
    }

    #[derive(Clone, Copy)]
    enum BadPolicyMode {
        Kind,
        Parent,
        Subject,
        PolicyHash,
        Verdict,
    }

    struct BadPolicy(BadPolicyMode);

    impl PolicyEvaluator for BadPolicy {
        fn evaluate(
            &self,
            _request: &GrantRequest,
            subject: &str,
            parent_digest: &str,
        ) -> Result<PolicyDecision, PolicyError> {
            let kind = match self.0 {
                BadPolicyMode::Kind => ReceiptKind::GrantIssued,
                BadPolicyMode::Parent
                | BadPolicyMode::Subject
                | BadPolicyMode::PolicyHash
                | BadPolicyMode::Verdict => ReceiptKind::PolicyDecision,
            };
            let receipt_subject = match self.0 {
                BadPolicyMode::Subject => "different-grant",
                BadPolicyMode::Kind
                | BadPolicyMode::Parent
                | BadPolicyMode::PolicyHash
                | BadPolicyMode::Verdict => subject,
            };
            let parent = match self.0 {
                BadPolicyMode::Parent => "0",
                BadPolicyMode::Kind
                | BadPolicyMode::Subject
                | BadPolicyMode::PolicyHash
                | BadPolicyMode::Verdict => parent_digest,
            };
            let receipt_policy_hash = match self.0 {
                BadPolicyMode::PolicyHash => "different-policy-hash",
                _ => "bad-policy-hash",
            };
            let receipt_verdict = match self.0 {
                BadPolicyMode::Verdict => "deny",
                _ => "allow",
            };
            let receipt = ReceiptBuilder::new(kind, "bad-policy", receipt_subject)
                .parent_digest(parent)
                .policy_hash(receipt_policy_hash)
                .evidence(serde_json::json!({"verdict": receipt_verdict}))
                .build()?;
            Ok(PolicyDecision {
                verdict: Verdict::Allow,
                reason: "malformed witness".to_string(),
                policy_hash: self.policy_hash(),
                receipt,
            })
        }

        fn policy_hash(&self) -> String {
            "bad-policy-hash".to_string()
        }
    }

    #[test]
    fn checked_grant_creation_rejects_malformed_policy_witnesses_without_writes() {
        for mode in [
            BadPolicyMode::Kind,
            BadPolicyMode::Parent,
            BadPolicyMode::Subject,
            BadPolicyMode::PolicyHash,
            BadPolicyMode::Verdict,
        ] {
            let mut store = Store::in_memory().unwrap();
            assert!(
                store
                    .create_grant(&act_request(300), &BadPolicy(mode))
                    .is_err()
            );
            assert!(store.list_grants(None).unwrap().is_empty());
        }
    }

    /// Set up a grant in "issued" state with a given expiry.
    fn setup_issued_grant(expires_at: DateTime<Utc>) -> (Store, String) {
        let mut store = Store::in_memory().unwrap();
        let grant_id = Uuid::new_v4();
        let id_str = grant_id.to_string();

        let r1 = ReceiptBuilder::new(ReceiptKind::GrantRequested, SUBJECT_ID, &id_str)
            .build()
            .unwrap();
        store
            .record_transition(grant_id, &GrantState::Requested, &r1, Some(meta()))
            .unwrap();

        let r2 = ReceiptBuilder::new(ReceiptKind::GrantIssued, SUBJECT_ID, &id_str)
            .parent_digest(&r1.digest)
            .build()
            .unwrap();
        store
            .record_transition(
                grant_id,
                &GrantState::Issued,
                &r2,
                Some(meta_with_expiry(expires_at)),
            )
            .unwrap();

        (store, id_str)
    }

    /// Set up a grant in "active" state (uses bypass for expired-but-active tests).
    fn setup_active_grant(expires_at: DateTime<Utc>) -> (Store, String) {
        let (mut store, id_str) = setup_issued_grant(expires_at);

        let grant = store.get_grant(&id_str).unwrap().unwrap();
        let r = ReceiptBuilder::new(ReceiptKind::GrantActivated, SUBJECT_ID, &id_str)
            .parent_digest(&grant.latest_receipt_digest)
            .build()
            .unwrap();

        let grant_id: Uuid = id_str.parse().unwrap();
        store
            .record_transition(grant_id, &GrantState::Active, &r, None)
            .unwrap();

        (store, id_str)
    }

    // ---------------------------------------------------------------
    // Spend-time scope matching (Model X / D010, D010a)
    // ---------------------------------------------------------------

    #[test]
    fn scope_mismatch_refuses_and_does_not_consume() {
        // Grant scope is (deploy, prod) per meta(); attempt (deploy, staging).
        let (mut store, id) = setup_active_grant(Utc::now() + Duration::hours(1));
        let err = store
            .transition_scoped(
                &id,
                GrantState::Used,
                ReceiptKind::GrantUsed,
                &bot_subject(),
                serde_json::Value::Null,
                None,
                &GrantScope {
                    action: "deploy".to_string(),
                    target: "staging".to_string(),
                },
            )
            .unwrap_err();
        assert!(
            matches!(err, StoreError::ScopeMismatch { .. }),
            "got {err:?}"
        );

        // Non-consuming (D010a): the grant is unspent, so a subsequently VALID-scope
        // use still succeeds — a wrong-target presentation did not burn the grant.
        let ok = store.transition_scoped(
            &id,
            GrantState::Used,
            ReceiptKind::GrantUsed,
            &bot_subject(),
            serde_json::Value::Null,
            None,
            &GrantScope {
                action: "deploy".to_string(),
                target: "prod".to_string(),
            },
        );
        assert!(
            ok.is_ok(),
            "grant must be unspent after a scope mismatch: {ok:?}"
        );
    }

    #[test]
    fn scope_match_spends_and_single_spend_still_holds() {
        let (mut store, id) = setup_active_grant(Utc::now() + Duration::hours(1));
        let r = store.transition_scoped(
            &id,
            GrantState::Used,
            ReceiptKind::GrantUsed,
            &bot_subject(),
            serde_json::Value::Null,
            None,
            &GrantScope {
                action: "deploy".to_string(),
                target: "prod".to_string(),
            },
        );
        assert!(r.is_ok(), "matching scope should spend: {r:?}");

        // Single-spend composes: a second use is refused (terminal Used).
        let again = store.transition_scoped(
            &id,
            GrantState::Used,
            ReceiptKind::GrantUsed,
            &bot_subject(),
            serde_json::Value::Null,
            None,
            &GrantScope {
                action: "deploy".to_string(),
                target: "prod".to_string(),
            },
        );
        assert!(
            again.is_err(),
            "second spend must be refused (terminal Used)"
        );
    }

    // ---------------------------------------------------------------
    // Basic store operations
    // ---------------------------------------------------------------

    #[test]
    fn store_and_retrieve_receipt() {
        let mut store = Store::in_memory().unwrap();
        let receipt = ReceiptBuilder::new(ReceiptKind::GrantRequested, SUBJECT_ID, "grant-1")
            .build()
            .unwrap();

        let grant_id = Uuid::new_v4();
        store
            .record_transition(grant_id, &GrantState::Requested, &receipt, Some(meta()))
            .unwrap();

        let chain = store.receipt_chain(&receipt.subject).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].digest, receipt.digest);
    }

    #[test]
    fn list_grants_by_state() {
        let mut store = Store::in_memory().unwrap();
        let receipt = ReceiptBuilder::new(ReceiptKind::GrantRequested, SUBJECT_ID, "g1")
            .build()
            .unwrap();

        let grant_id = Uuid::new_v4();
        store
            .record_transition(grant_id, &GrantState::Requested, &receipt, Some(meta()))
            .unwrap();

        assert_eq!(store.list_grants(None).unwrap().len(), 1);
        assert_eq!(store.list_grants(Some("requested")).unwrap().len(), 1);
        assert_eq!(store.list_grants(Some("issued")).unwrap().len(), 0);
    }

    // ---------------------------------------------------------------
    // Domain-level transition tests (happy path)
    // ---------------------------------------------------------------

    #[test]
    fn happy_path_through_domain_layer() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let r = store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap();
        assert_eq!(r.to_state, GrantState::Active);

        let r = store
            .transition(
                &id,
                GrantState::Used,
                ReceiptKind::GrantUsed,
                &bot_subject(),
                serde_json::json!({"deployed": "v1.0"}),
                None,
            )
            .unwrap();
        assert_eq!(r.to_state, GrantState::Used);

        let chain = store.receipt_chain(&id).unwrap();
        assert_eq!(chain.len(), 4);
    }

    // ---------------------------------------------------------------
    // Adjacency / terminal state
    // ---------------------------------------------------------------

    #[test]
    fn rejects_invalid_adjacency() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let err = store
            .transition(
                &id,
                GrantState::Used,
                ReceiptKind::GrantUsed,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    #[test]
    fn rejects_transition_from_terminal() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_active_grant(future);

        store
            .transition(
                &id,
                GrantState::Used,
                ReceiptKind::GrantUsed,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap();

        let err = store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    // ---------------------------------------------------------------
    // Failure mode: expired-but-used
    // ---------------------------------------------------------------

    #[test]
    fn expired_grant_cannot_be_activated() {
        // Well beyond the 30s expiry-skew grace.
        let past = Utc::now() - Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(past);

        let err = store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::GrantExpired(_)));
    }

    #[test]
    fn expired_grant_cannot_be_used() {
        let past = Utc::now() - Duration::seconds(300);
        let (mut store, id) = setup_active_grant(past);

        let err = store
            .transition(
                &id,
                GrantState::Used,
                ReceiptKind::GrantUsed,
                &bot_subject(),
                serde_json::json!({"action": "deploy"}),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::GrantExpired(_)));
    }

    #[test]
    fn grant_expired_within_skew_grace_is_still_usable() {
        // Expired 5s ago — inside the 30s skew grace, so a slightly-fast
        // verifier clock does not hard-fail a just-expired grant.
        let just_past = Utc::now() - Duration::seconds(5);
        let (mut store, id) = setup_active_grant(just_past);

        let r = store.transition(
            &id,
            GrantState::Used,
            ReceiptKind::GrantUsed,
            &bot_subject(),
            serde_json::json!({"action": "deploy"}),
            None,
        );
        assert!(r.is_ok(), "grant within skew grace should still be usable");
    }

    #[test]
    fn act_grant_not_before_refused_then_allowed() {
        let mut store = Store::in_memory().unwrap();
        let grant_id = Uuid::new_v4();
        let id_str = grant_id.to_string();
        let future = Utc::now() + Duration::seconds(300);
        let far = Utc::now() + Duration::seconds(3600);

        let r1 = ReceiptBuilder::new(ReceiptKind::GrantRequested, SUBJECT_ID, &id_str)
            .build()
            .unwrap();
        store
            .record_transition(grant_id, &GrantState::Requested, &r1, Some(meta()))
            .unwrap();
        let r2 = ReceiptBuilder::new(ReceiptKind::GrantIssued, SUBJECT_ID, &id_str)
            .parent_digest(&r1.digest)
            .build()
            .unwrap();
        // Issued with not_before in the future.
        store
            .record_transition(
                grant_id,
                &GrantState::Issued,
                &r2,
                Some(GrantMeta {
                    subject_id: SUBJECT_ID.to_string(),
                    actor: "deploy-bot".to_string(),
                    action: "deploy".to_string(),
                    target: "prod".to_string(),
                    issued_at: Some(Utc::now()),
                    expires_at: Some(far),
                    not_before: Some(future),
                }),
            )
            .unwrap();

        // Activation before not_before is refused.
        let err = store
            .transition(
                &id_str,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::GrantNotYetValid(_)));
    }

    #[test]
    fn act_grant_freeze_blocks_activation_and_thaw_restores() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);
        store
            .install_genesis("admin:jbeck", "hardcoded:v1")
            .unwrap();

        let err = store
            .install_freeze(
                "inc-wrong-op",
                "action",
                "deploy",
                None,
                "not authorized",
                None,
                "admin:eve",
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::GenesisOperatorMismatch { .. }));

        // Freeze the "deploy" action class (setup grants use action=deploy).
        store
            .install_freeze(
                "inc-act",
                "action",
                "deploy",
                None,
                "deploy paused",
                None,
                "admin:jbeck",
                Utc::now(),
            )
            .unwrap();

        let err = store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::ClassFrozen { .. }));

        // Thaw restores — the same grant activates, no re-issue.
        store
            .thaw_freeze("inc-act", "admin:jbeck", Utc::now())
            .unwrap();
        assert!(
            store
                .transition(
                    &id,
                    GrantState::Active,
                    ReceiptKind::GrantActivated,
                    &bot_subject(),
                    serde_json::Value::Null,
                    None,
                )
                .is_ok()
        );
    }

    #[test]
    fn expired_grant_can_be_marked_expired() {
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_issued_grant(past);

        let r = store
            .transition(
                &id,
                GrantState::Expired,
                ReceiptKind::GrantExpired,
                &ActorContext::system(),
                serde_json::Value::Null,
                None,
            )
            .unwrap();
        assert_eq!(r.to_state, GrantState::Expired);
    }

    // ---------------------------------------------------------------
    // Failure mode: revoke-between-issue-and-use
    // ---------------------------------------------------------------

    #[test]
    fn revoked_grant_cannot_be_activated() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        store
            .transition(
                &id,
                GrantState::Revoked,
                ReceiptKind::GrantRevoked,
                &admin_ctx(),
                serde_json::json!({"reason": "security incident"}),
                None,
            )
            .unwrap();

        let err = store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    #[test]
    fn revoked_active_grant_cannot_be_used() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_active_grant(future);

        store
            .transition(
                &id,
                GrantState::Revoked,
                ReceiptKind::GrantRevoked,
                &admin_ctx(),
                serde_json::json!({"reason": "policy change"}),
                None,
            )
            .unwrap();

        let err = store
            .transition(
                &id,
                GrantState::Used,
                ReceiptKind::GrantUsed,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    // ---------------------------------------------------------------
    // Receipt-write-failure rollback
    // ---------------------------------------------------------------

    #[test]
    fn failed_transition_does_not_advance_state() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap();

        assert_eq!(store.get_grant(&id).unwrap().unwrap().state, "active");

        // Invalid adjacency: active → issued
        let err = store.transition(
            &id,
            GrantState::Issued,
            ReceiptKind::GrantIssued,
            &bot_subject(),
            serde_json::Value::Null,
            None,
        );
        assert!(err.is_err());
        assert_eq!(store.get_grant(&id).unwrap().unwrap().state, "active");
    }

    #[test]
    fn grant_not_found_returns_error() {
        let mut store = Store::in_memory().unwrap();
        let err = store
            .transition(
                "nonexistent-id",
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::GrantNotFound(_)));
    }

    // ---------------------------------------------------------------
    // CAS conflict: stale head
    // ---------------------------------------------------------------

    #[test]
    fn stale_head_cas_conflict() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let stale_head = store
            .get_grant(&id)
            .unwrap()
            .unwrap()
            .latest_receipt_digest
            .clone();

        store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap();

        // Manually attempt a write against the stale head
        let stale_receipt = ReceiptBuilder::new(ReceiptKind::GrantRevoked, "admin:jbeck", &id)
            .parent_digest(&stale_head)
            .evidence(serde_json::json!({"reason": "stale attempt"}))
            .build()
            .unwrap();

        let tx = store.conn.transaction().unwrap();
        insert_receipt(&tx, &stale_receipt).unwrap();
        let rows_updated = tx.execute(
            "UPDATE grants SET state = 'revoked', latest_receipt_digest = ?1, updated_at = datetime('now')
             WHERE id = ?2 AND latest_receipt_digest = ?3",
            params![stale_receipt.digest, id, stale_head],
        ).unwrap();
        assert_eq!(rows_updated, 0);
        tx.rollback().unwrap();

        assert_eq!(store.get_grant(&id).unwrap().unwrap().state, "active");
    }

    // ---------------------------------------------------------------
    // Identity authorization tests
    // ---------------------------------------------------------------

    #[test]
    fn wrong_principal_cannot_activate() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let err = store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &wrong_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));
    }

    #[test]
    fn wrong_principal_cannot_use() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_active_grant(future);

        let err = store
            .transition(
                &id,
                GrantState::Used,
                ReceiptKind::GrantUsed,
                &wrong_subject(),
                serde_json::json!({"action": "steal"}),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));
    }

    #[test]
    fn admin_can_revoke() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let r = store
            .transition(
                &id,
                GrantState::Revoked,
                ReceiptKind::GrantRevoked,
                &admin_ctx(),
                serde_json::json!({"reason": "policy"}),
                None,
            )
            .unwrap();
        assert_eq!(r.to_state, GrantState::Revoked);
    }

    #[test]
    fn subject_can_self_revoke() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let r = store
            .transition(
                &id,
                GrantState::Revoked,
                ReceiptKind::GrantRevoked,
                &bot_subject(),
                serde_json::json!({"reason": "no longer needed"}),
                None,
            )
            .unwrap();
        assert_eq!(r.to_state, GrantState::Revoked);
    }

    #[test]
    fn admin_cannot_activate() {
        // Only subject can activate — admin role is not authorized
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let err = store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &admin_ctx(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));
    }

    #[test]
    fn act_transition_rejects_mismatched_receipt_kind_without_advancing() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let err = store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantRevoked,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::ReceiptKindMismatch { .. }));
        assert_eq!(store.get_grant(&id).unwrap().unwrap().state, "issued");
        assert_eq!(store.receipt_chain(&id).unwrap().len(), 2);
    }

    #[test]
    fn subject_cannot_expire_grant() {
        // Only system can mark as expired
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_issued_grant(past);

        let err = store
            .transition(
                &id,
                GrantState::Expired,
                ReceiptKind::GrantExpired,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));
    }

    #[test]
    fn identity_mismatch_does_not_advance_state() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let _ = store.transition(
            &id,
            GrantState::Active,
            ReceiptKind::GrantActivated,
            &wrong_subject(),
            serde_json::Value::Null,
            None,
        );

        // State must still be issued
        assert_eq!(store.get_grant(&id).unwrap().unwrap().state, "issued");
    }

    #[test]
    fn receipt_records_actor_and_subject() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        store
            .transition(
                &id,
                GrantState::Active,
                ReceiptKind::GrantActivated,
                &bot_subject(),
                serde_json::Value::Null,
                None,
            )
            .unwrap();

        let chain = store.receipt_chain(&id).unwrap();
        let activate_receipt = chain.last().unwrap();
        let evidence: serde_json::Value = serde_json::from_str(&activate_receipt.evidence).unwrap();

        // Receipt should contain actor identity and subject binding
        assert_eq!(evidence["actor"]["principal_id"], SUBJECT_ID);
        assert_eq!(evidence["subject_id"], SUBJECT_ID);
        assert_eq!(evidence["actor"]["role"], "subject");
    }

    // ---------------------------------------------------------------
    // Genesis receipt — chain-root for the receipt invariant
    // ---------------------------------------------------------------

    #[test]
    fn genesis_install_succeeds_and_is_retrievable() {
        let mut store = Store::in_memory().unwrap();

        let r = store
            .install_genesis("workload:jbeck:laptop", "hardcoded:v1")
            .unwrap();

        assert_eq!(r.kind, ReceiptKind::GenesisInstall);
        assert_eq!(r.actor, "workload:jbeck:laptop");
        assert!(r.parent_digest.is_none(), "genesis has no parent");
        assert!(r.policy_hash.is_some(), "genesis carries policy hash");

        let fetched = store.get_genesis().unwrap().expect("genesis present");
        assert_eq!(fetched.digest, r.digest);
        assert_eq!(fetched.actor, "workload:jbeck:laptop");
    }

    #[test]
    fn genesis_evidence_carries_fiat_basis_and_instance_id() {
        let mut store = Store::in_memory().unwrap();
        let r = store
            .install_genesis("workload:jbeck:laptop", "hardcoded:v1")
            .unwrap();

        let ev: serde_json::Value = r.evidence;
        assert_eq!(ev["basis"], "operator_fiat");
        assert_eq!(ev["version"], "standing.genesis.v1");
        assert_eq!(ev["policy_source"], "hardcoded:v1");
        assert!(ev["prior_grant"].is_null(), "genesis cites no prior grant");
        assert!(
            ev["instance_id"].as_str().is_some(),
            "genesis names an instance_id"
        );
    }

    #[test]
    fn second_genesis_install_is_refused() {
        let mut store = Store::in_memory().unwrap();
        let first = store
            .install_genesis("workload:jbeck:laptop", "hardcoded:v1")
            .unwrap();

        let err = store
            .install_genesis("workload:eve:laptop", "evil:v1")
            .unwrap_err();

        match err {
            StoreError::GenesisExists(d) => assert_eq!(d, first.digest),
            other => panic!("expected GenesisExists, got {other:?}"),
        }

        // First genesis must still be intact and singular.
        let still = store.get_genesis().unwrap().expect("genesis present");
        assert_eq!(still.digest, first.digest);
        assert_eq!(still.actor, "workload:jbeck:laptop");
    }

    #[test]
    fn get_genesis_returns_none_before_install() {
        let store = Store::in_memory().unwrap();
        assert!(store.get_genesis().unwrap().is_none());
    }

    #[test]
    fn assertion_issuance_binds_genesis_operator_and_distinct_actor() {
        let mut store = Store::in_memory().unwrap();
        assert!(matches!(
            store.authorize_assertion_issuance("wl:operator:laptop", "wl:speaker:host1"),
            Err(StoreError::AssertionNoGenesis)
        ));

        store
            .install_genesis("wl:operator:laptop", "hardcoded:v1")
            .unwrap();
        let genesis = store
            .authorize_assertion_issuance("wl:operator:laptop", "wl:speaker:host1")
            .unwrap();
        assert_eq!(genesis.actor, "wl:operator:laptop");

        assert!(matches!(
            store.authorize_assertion_issuance("wl:impostor:laptop", "wl:speaker:host1"),
            Err(StoreError::GenesisOperatorMismatch { .. })
        ));
        assert!(matches!(
            store.authorize_assertion_issuance("wl:operator:laptop", "wl:operator:laptop"),
            Err(StoreError::AssertionSelfGrant(_))
        ));
    }

    #[test]
    fn policy_hash_is_deterministic_for_same_source() {
        let mut s1 = Store::in_memory().unwrap();
        let mut s2 = Store::in_memory().unwrap();

        let r1 = s1.install_genesis("workload:op:a", "hardcoded:v1").unwrap();
        let r2 = s2.install_genesis("workload:op:b", "hardcoded:v1").unwrap();

        assert_eq!(
            r1.policy_hash, r2.policy_hash,
            "same policy source produces same hash across instances"
        );
    }
}

#[cfg(test)]
mod assertion_tests {
    use super::*;
    use chrono::{Duration, Utc};
    use standing_grant::AssertionGrantState;
    use standing_receipt::{ReceiptBuilder, ReceiptKind};

    const ACTOR: &str = "component:nq:linode";
    const OPERATOR: &str = "admin:jbeck";

    fn install_genesis(store: &mut Store) {
        store.install_genesis(OPERATOR, "hardcoded:v1").unwrap();
    }

    fn meta(
        not_before: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        max_uses: Option<u64>,
    ) -> AssertionGrantMeta {
        AssertionGrantMeta {
            actor: ACTOR.into(),
            claim_kind: "sqlite_wal_state".into(),
            subject_scope: "labelwatch/*".into(),
            audience: "nq:main".into(),
            not_before: Some(not_before),
            issued_at: Some(not_before),
            expires_at,
            max_uses,
        }
    }

    fn assertion_request(actor: &str) -> AssertionGrantRequest {
        AssertionGrantRequest {
            actor: Principal::new(actor, actor),
            scope: AssertionScope {
                claim_kind: "sqlite_wal_state".to_string(),
                subject_scope: "labelwatch/*".to_string(),
                audience: "nq:main".to_string(),
            },
            not_before: Utc::now() - Duration::minutes(1),
            duration_secs: 3600,
            max_uses: Some(3),
            context: serde_json::Value::Null,
        }
    }

    #[test]
    fn checked_assertion_creation_requires_genesis_operator_and_distinct_actor() {
        let operator = Principal::new(OPERATOR, "jbeck");
        let mut no_genesis = Store::in_memory().unwrap();
        let err = no_genesis
            .create_assertion_lease(&assertion_request(ACTOR), &operator)
            .unwrap_err();
        assert!(matches!(err, StoreError::AssertionNoGenesis));
        assert!(
            no_genesis
                .list_assertion_grants(None, None)
                .unwrap()
                .is_empty()
        );

        let mut store = Store::in_memory().unwrap();
        let genesis = store.install_genesis(OPERATOR, "hardcoded:v1").unwrap();
        let impostor = Principal::new("admin:eve", "eve");
        let err = store
            .create_assertion_lease(&assertion_request(ACTOR), &impostor)
            .unwrap_err();
        assert!(matches!(err, StoreError::GenesisOperatorMismatch { .. }));
        let err = store
            .create_assertion_lease(&assertion_request(OPERATOR), &operator)
            .unwrap_err();
        assert!(matches!(err, StoreError::AssertionSelfGrant(_)));
        assert!(store.list_assertion_grants(None, None).unwrap().is_empty());

        let created = store
            .create_assertion_lease(&assertion_request(ACTOR), &operator)
            .unwrap();
        let chain = store.receipt_chain(&created.grant_id.to_string()).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].kind, "assertion_grant_requested");
        assert_eq!(
            chain[0].parent_digest.as_deref(),
            Some(genesis.digest.as_str())
        );
        assert_eq!(chain[1].kind, "assertion_grant_issued");
        assert_eq!(chain[1].actor, OPERATOR);
        assert_eq!(
            chain[1].parent_digest.as_deref(),
            Some(chain[0].digest.as_str())
        );
        let row = store
            .get_assertion_grant(&created.grant_id.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "issued");
        assert_eq!(row.latest_receipt_digest, created.issued_receipt.digest);
    }

    #[test]
    fn checked_assertion_creation_rolls_back_if_receipt_write_fails() {
        let mut store = Store::in_memory().unwrap();
        install_genesis(&mut store);
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_assertion_issue
                 BEFORE INSERT ON receipts
                 WHEN NEW.kind = 'assertion_grant_issued'
                 BEGIN
                   SELECT RAISE(ABORT, 'injected receipt failure');
                 END;",
            )
            .unwrap();

        let before: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
            .unwrap();
        let err = store
            .create_assertion_lease(
                &assertion_request(ACTOR),
                &Principal::new(OPERATOR, "jbeck"),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Sqlite(_)));
        let after: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            after, before,
            "requested receipt must roll back with issuance"
        );
        assert!(store.list_assertion_grants(None, None).unwrap().is_empty());
    }

    /// Create an Issued lease with a valid 2-receipt chain (Requested → Issued).
    fn issued_lease(
        store: &mut Store,
        not_before: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        max_uses: Option<u64>,
    ) -> Uuid {
        let grant_id = Uuid::new_v4();
        let subject = grant_id.to_string();
        let r1 = ReceiptBuilder::new(ReceiptKind::AssertionGrantRequested, ACTOR, &subject)
            .evidence(serde_json::json!({ "scope": "labelwatch/*" }))
            .build()
            .unwrap();
        store
            .record_assertion_transition(
                grant_id,
                &AssertionGrantState::Requested,
                &r1,
                Some(meta(not_before, None, max_uses)),
            )
            .unwrap();
        let r2 = ReceiptBuilder::new(ReceiptKind::AssertionGrantIssued, ACTOR, &subject)
            .parent_digest(r1.digest.clone())
            .evidence(serde_json::json!({ "terms": "full" }))
            .build()
            .unwrap();
        store
            .record_assertion_transition(
                grant_id,
                &AssertionGrantState::Issued,
                &r2,
                Some(meta(not_before, expires_at, max_uses)),
            )
            .unwrap();
        grant_id
    }

    fn proof(grant_id: Uuid, jti: &str, subject_id: &str) -> RequestProof {
        RequestProof {
            grant_id,
            actor: ACTOR.into(),
            claim_kind: "sqlite_wal_state".into(),
            subject_id: subject_id.into(),
            audience: "nq:main".into(),
            jti: jti.into(),
            body_digest: Some("deadbeef".into()),
            issued_at: Utc::now(),
        }
    }

    fn wide() -> (DateTime<Utc>, Option<DateTime<Utc>>) {
        (
            Utc::now() - Duration::days(1),
            Some(Utc::now() + Duration::days(365)),
        )
    }

    #[test]
    fn happy_spend_reuses_lease() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);

        let r1 = store
            .spend_assertion(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now())
            .unwrap();
        assert_eq!(r1.spend_seq, 1);
        assert!(!r1.exhausted);
        let r2 = store
            .spend_assertion(&proof(gid, "jti-1", "labelwatch/bar"), Utc::now())
            .unwrap();
        assert_eq!(r2.spend_seq, 2);

        let g = store
            .get_assertion_grant(&gid.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(g.state, "active");
        assert_eq!(g.spend_count, 2);
    }

    #[test]
    fn first_spend_auto_activates_with_receipt() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);
        store
            .spend_assertion(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now())
            .unwrap();

        let kinds: Vec<String> = store
            .receipt_chain(&gid.to_string())
            .unwrap()
            .into_iter()
            .map(|r| r.kind)
            .collect();
        // Requested, Issued, Activated (auto), AssertionMade — the chain never
        // shows a spend without a prior activation (amendment #3).
        assert_eq!(
            kinds,
            vec![
                "assertion_grant_requested",
                "assertion_grant_issued",
                "assertion_grant_activated",
                "assertion_made",
            ]
        );
    }

    #[test]
    fn scope_mismatch_does_not_consume() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, Some(5));

        // Out-of-scope subject refuses...
        let err = store.spend_assertion(&proof(gid, "jti-x", "other/foo"), Utc::now());
        assert!(matches!(err, Err(StoreError::AssertionOutOfScope { .. })));

        // ...and did not burn the budget OR the jti: the SAME jti now spends.
        store
            .spend_assertion(&proof(gid, "jti-x", "labelwatch/foo"), Utc::now())
            .unwrap();
        let g = store
            .get_assertion_grant(&gid.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(g.spend_count, 1, "refused spend must be non-consuming");
    }

    #[test]
    fn replay_is_refused() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);

        store
            .spend_assertion(&proof(gid, "jti-dup", "labelwatch/foo"), Utc::now())
            .unwrap();
        let replay = store.spend_assertion(&proof(gid, "jti-dup", "labelwatch/foo"), Utc::now());
        assert!(matches!(replay, Err(StoreError::ReplayDetected { .. })));

        let g = store
            .get_assertion_grant(&gid.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(g.spend_count, 1, "replay must not consume");
    }

    #[test]
    fn assertion_replay_ledger_purges_past_grace_but_keeps_live_entries() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);
        let now = Utc::now();

        store
            .conn
            .execute(
                "INSERT INTO seen_assertion_jti (jti, audience, expires_at) VALUES (?1, ?2, ?3)",
                params![
                    "ancient",
                    "nq:main",
                    (now - Duration::hours(1)).to_rfc3339(),
                ],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO seen_assertion_jti (jti, audience, expires_at) VALUES (?1, ?2, ?3)",
                params![
                    "just-expired",
                    "nq:main",
                    (now - Duration::seconds(5)).to_rfc3339(),
                ],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO seen_assertion_jti (jti, audience, expires_at) VALUES (?1, ?2, ?3)",
                params!["live", "nq:main", (now + Duration::hours(1)).to_rfc3339(),],
            )
            .unwrap();

        // A successful spend commits maintenance in the same transaction.
        store
            .spend_assertion(&proof(gid, "trigger", "labelwatch/foo"), now)
            .unwrap();
        let count = |jti: &str| -> i64 {
            store.conn.query_row(
                "SELECT COUNT(*) FROM seen_assertion_jti WHERE jti = ?1 AND audience = 'nq:main'",
                params![jti],
                |row| row.get(0),
            ).unwrap()
        };
        assert_eq!(count("ancient"), 0, "past-grace entry should be purged");
        assert_eq!(
            count("just-expired"),
            1,
            "skew-grace entry must remain defended"
        );
        assert_eq!(count("live"), 1, "unexpired entry must remain defended");

        let replay = store.spend_assertion(&proof(gid, "live", "labelwatch/foo"), now);
        assert!(matches!(replay, Err(StoreError::ReplayDetected { .. })));
        let grace_replay =
            store.spend_assertion(&proof(gid, "just-expired", "labelwatch/foo"), now);
        assert!(matches!(
            grace_replay,
            Err(StoreError::ReplayDetected { .. })
        ));
        assert_eq!(
            store
                .get_assertion_grant(&gid.to_string())
                .unwrap()
                .unwrap()
                .spend_count,
            1,
            "replay refusals must remain non-consuming",
        );
    }

    #[test]
    fn expired_window_refused() {
        let mut store = Store::in_memory().unwrap();
        let nb = Utc::now() - Duration::days(10);
        let exp = Some(Utc::now() - Duration::days(1));
        let gid = issued_lease(&mut store, nb, exp, None);
        let err = store.spend_assertion(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now());
        assert!(matches!(err, Err(StoreError::AssertionWindowClosed(_))));
    }

    #[test]
    fn not_yet_valid_refused() {
        let mut store = Store::in_memory().unwrap();
        let nb = Utc::now() + Duration::days(1);
        let exp = Some(Utc::now() + Duration::days(2));
        let gid = issued_lease(&mut store, nb, exp, None);
        let err = store.spend_assertion(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now());
        assert!(matches!(err, Err(StoreError::AssertionNotYetValid(_))));
    }

    #[test]
    fn missing_expiry_fails_closed() {
        // A lease whose expires_at was never set: snapshot_to_grant refuses
        // rather than treating an unknown window as valid (L2).
        let mut store = Store::in_memory().unwrap();
        let nb = Utc::now() - Duration::days(1);
        let gid = issued_lease(&mut store, nb, None, None);
        let err = store.spend_assertion(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now());
        assert!(matches!(err, Err(StoreError::AssertionWindowIncoherent)));
    }

    #[test]
    fn budget_exhaustion_drives_terminal() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, Some(2));

        store
            .spend_assertion(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now())
            .unwrap();
        let second = store
            .spend_assertion(&proof(gid, "jti-1", "labelwatch/foo"), Utc::now())
            .unwrap();
        assert!(second.exhausted, "the k-th spend exhausts");

        let g = store
            .get_assertion_grant(&gid.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(g.state, "exhausted");

        // Further spends refuse.
        let over = store.spend_assertion(&proof(gid, "jti-2", "labelwatch/foo"), Utc::now());
        assert!(matches!(
            over,
            Err(StoreError::AssertionBudgetExhausted { max_uses: 2 })
        ));

        // The exhaustion receipt is in the chain.
        let kinds: Vec<String> = store
            .receipt_chain(&gid.to_string())
            .unwrap()
            .into_iter()
            .map(|r| r.kind)
            .collect();
        assert!(kinds.contains(&"assertion_grant_exhausted".to_string()));
    }

    #[test]
    fn unknown_lease_refused() {
        let mut store = Store::in_memory().unwrap();
        let err = store.spend_assertion(
            &proof(Uuid::new_v4(), "jti-0", "labelwatch/foo"),
            Utc::now(),
        );
        assert!(matches!(err, Err(StoreError::AssertionGrantNotFound(_))));
    }

    // -- MAC-verified spend (Phase 5) ------------------------------------

    const KEY: &[u8] = b"audience-key";

    #[test]
    fn verified_spend_accepts_valid_mac() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);
        let p = proof(gid, "jti-mac", "labelwatch/foo");
        let mac = crate::sign_proof(&p, KEY).unwrap();
        let r = store
            .spend_assertion_verified(&p, Some(&mac), KEY, Utc::now())
            .unwrap();
        assert_eq!(r.spend_seq, 1);
    }

    #[test]
    fn verified_spend_rejects_bad_and_missing_mac() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);
        let p = proof(gid, "jti-mac", "labelwatch/foo");
        // Wrong key → wrong MAC.
        let bad = crate::sign_proof(&p, b"other-key").unwrap();
        assert!(matches!(
            store.spend_assertion_verified(&p, Some(&bad), KEY, Utc::now()),
            Err(StoreError::AssertionMacInvalid)
        ));
        // Missing MAC.
        assert!(matches!(
            store.spend_assertion_verified(&p, None, KEY, Utc::now()),
            Err(StoreError::AssertionMacInvalid)
        ));
        // The rejected attempts did not consume the lease.
        assert_eq!(
            store
                .get_assertion_grant(&gid.to_string())
                .unwrap()
                .unwrap()
                .spend_count,
            0
        );
    }

    #[test]
    fn verified_spend_rejects_stale_and_future_proofs() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);

        // Too old.
        let mut old = proof(gid, "jti-old", "labelwatch/foo");
        old.issued_at = Utc::now() - Duration::seconds(3600);
        let mac = crate::sign_proof(&old, KEY).unwrap();
        assert!(matches!(
            store.spend_assertion_verified(&old, Some(&mac), KEY, Utc::now()),
            Err(StoreError::RequestTimestampOutOfWindow(_))
        ));

        // Too far in the future (clock disagreement).
        let mut future = proof(gid, "jti-fut", "labelwatch/foo");
        future.issued_at = Utc::now() + Duration::seconds(3600);
        let mac = crate::sign_proof(&future, KEY).unwrap();
        assert!(matches!(
            store.spend_assertion_verified(&future, Some(&mac), KEY, Utc::now()),
            Err(StoreError::ClockSkewExceeded(_))
        ));
    }

    // -- policy freeze (Wave 3) ------------------------------------------

    #[test]
    fn freeze_denies_matching_spend_thaw_restores() {
        let mut store = Store::in_memory().unwrap();
        install_genesis(&mut store);
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);

        // Freeze the claim_kind class.
        store
            .install_freeze(
                "incident-1",
                "claim_kind",
                "sqlite_wal_state",
                None,
                "storage incident",
                None,
                "admin:jbeck",
                Utc::now(),
            )
            .unwrap();

        // A covered spend is now refused with class_frozen — non-consuming.
        let err = store.spend_assertion(&proof(gid, "jf1", "labelwatch/foo"), Utc::now());
        assert!(matches!(err, Err(StoreError::ClassFrozen { .. })));
        assert_eq!(
            store
                .get_assertion_grant(&gid.to_string())
                .unwrap()
                .unwrap()
                .spend_count,
            0
        );

        // Thaw restores — the SAME lease spends again, no re-issue.
        store
            .thaw_freeze("incident-1", "admin:jbeck", Utc::now())
            .unwrap();
        let r = store
            .spend_assertion(&proof(gid, "jf1", "labelwatch/foo"), Utc::now())
            .unwrap();
        assert_eq!(r.spend_seq, 1);
    }

    #[test]
    fn freeze_scoped_to_audience_does_not_screen_others() {
        let mut store = Store::in_memory().unwrap();
        install_genesis(&mut store);
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None); // audience nq:main

        // Freeze claim_kind but scoped to a DIFFERENT audience.
        store
            .install_freeze(
                "incident-2",
                "claim_kind",
                "sqlite_wal_state",
                Some("nq:other"),
                "other-audience incident",
                None,
                "admin:jbeck",
                Utc::now(),
            )
            .unwrap();

        // nq:main is unaffected (L6: scoped freeze doesn't screen B').
        let r = store.spend_assertion(&proof(gid, "jf2", "labelwatch/foo"), Utc::now());
        assert!(
            r.is_ok(),
            "audience-scoped freeze must not screen a different audience"
        );
    }

    #[test]
    fn freeze_until_lazily_expires() {
        let mut store = Store::in_memory().unwrap();
        install_genesis(&mut store);
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);

        // Freeze that already expired (until in the past) — no longer screens.
        store
            .install_freeze(
                "incident-3",
                "claim_kind",
                "sqlite_wal_state",
                None,
                "brief pause",
                Some(Utc::now() - Duration::seconds(10)),
                "admin:jbeck",
                Utc::now(),
            )
            .unwrap();

        let r = store.spend_assertion(&proof(gid, "jf3", "labelwatch/foo"), Utc::now());
        assert!(r.is_ok(), "a past --until freeze should no longer match");
    }

    #[test]
    fn revoke_then_spend_refused() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);
        store
            .spend_assertion(&proof(gid, "jti-0", "labelwatch/foo"), Utc::now())
            .unwrap();

        let admin = ActorContext::admin(Principal::new("admin:jbeck", "jbeck"));
        store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Revoked,
                ReceiptKind::AssertionGrantRevoked,
                &admin,
                serde_json::json!({"reason":"incident"}),
                None,
                Utc::now(),
            )
            .unwrap();

        let err = store.spend_assertion(&proof(gid, "jti-1", "labelwatch/foo"), Utc::now());
        assert!(err.is_err(), "cannot spend a revoked lease");
    }

    #[test]
    fn assertion_lifecycle_enforces_roles_and_subject_binding() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);
        let admin = ActorContext::admin(Principal::new(OPERATOR, "jbeck"));

        let err = store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Active,
                ReceiptKind::AssertionGrantActivated,
                &admin,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));

        let system = ActorContext::system();
        let err = store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Active,
                ReceiptKind::AssertionGrantActivated,
                &system,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));

        let wrong = ActorContext::subject(Principal::new("component:nq:other", "other"));
        let err = store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Active,
                ReceiptKind::AssertionGrantActivated,
                &wrong,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));

        assert_eq!(
            store
                .get_assertion_grant(&gid.to_string())
                .unwrap()
                .unwrap()
                .state,
            "issued"
        );
        assert_eq!(store.receipt_chain(&gid.to_string()).unwrap().len(), 2);
    }

    #[test]
    fn assertion_transition_rejects_kind_mismatch_and_spend_bypass() {
        let mut store = Store::in_memory().unwrap();
        let (nb, exp) = wide();
        let gid = issued_lease(&mut store, nb, exp, None);
        let speaker = ActorContext::subject(Principal::new(ACTOR, "nq@linode"));

        let err = store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Active,
                ReceiptKind::AssertionGrantRevoked,
                &speaker,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::ReceiptKindMismatch { .. }));
        assert_eq!(store.receipt_chain(&gid.to_string()).unwrap().len(), 2);

        store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Active,
                ReceiptKind::AssertionGrantActivated,
                &speaker,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap();
        let err = store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Active,
                ReceiptKind::AssertionMade,
                &speaker,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
        let lease = store
            .get_assertion_grant(&gid.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(lease.state, "active");
        assert_eq!(lease.spend_count, 0);
        assert_eq!(store.receipt_chain(&gid.to_string()).unwrap().len(), 3);
    }

    #[test]
    fn checked_assertion_issue_requires_genesis_operator_and_distinct_speaker() {
        fn requested_lease(store: &mut Store) -> Uuid {
            let gid = Uuid::new_v4();
            let receipt =
                ReceiptBuilder::new(ReceiptKind::AssertionGrantRequested, ACTOR, gid.to_string())
                    .build()
                    .unwrap();
            store
                .record_assertion_transition(
                    gid,
                    &AssertionGrantState::Requested,
                    &receipt,
                    Some(meta(Utc::now(), None, Some(1))),
                )
                .unwrap();
            gid
        }

        let mut store = Store::in_memory().unwrap();
        let gid = requested_lease(&mut store);
        let operator = ActorContext::admin(Principal::new(OPERATOR, "jbeck"));
        let err = store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Issued,
                ReceiptKind::AssertionGrantIssued,
                &operator,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::GenesisRequired { .. }));

        install_genesis(&mut store);
        let impostor = ActorContext::admin(Principal::new("admin:eve", "eve"));
        let err = store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Issued,
                ReceiptKind::AssertionGrantIssued,
                &impostor,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::GenesisOperatorMismatch { .. }));

        let receipt = store
            .transition_assertion(
                &gid.to_string(),
                AssertionGrantState::Issued,
                ReceiptKind::AssertionGrantIssued,
                &operator,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap();
        assert_eq!(receipt.actor, OPERATOR);
        assert_eq!(receipt.evidence["actor"]["principal_id"], OPERATOR);

        let mut self_store = Store::in_memory().unwrap();
        self_store.install_genesis(ACTOR, "hardcoded:v1").unwrap();
        let self_gid = requested_lease(&mut self_store);
        let self_admin = ActorContext::admin(Principal::new(ACTOR, "nq@linode"));
        let err = self_store
            .transition_assertion(
                &self_gid.to_string(),
                AssertionGrantState::Issued,
                ReceiptKind::AssertionGrantIssued,
                &self_admin,
                serde_json::Value::Null,
                None,
                Utc::now(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::AssertionSelfGrant(_)));
        assert_eq!(
            self_store
                .get_assertion_grant(&self_gid.to_string())
                .unwrap()
                .unwrap()
                .state,
            "requested"
        );
        assert_eq!(
            self_store
                .receipt_chain(&self_gid.to_string())
                .unwrap()
                .len(),
            1
        );
    }
}
