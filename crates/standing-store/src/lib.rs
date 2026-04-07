//! SQLite storage and domain service for standing.
//!
//! This is the enforcement layer. The store validates transitions against
//! the grant state machine before writing. The CLI (and any future client)
//! calls into the store — it does not build receipts or manage state directly.
//!
//! Invariant: no state transition without a valid receipt, no receipt without
//! a valid transition. Both are written atomically or neither is.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Transaction};
use uuid::Uuid;

use standing_grant::{ActorContext, GrantState, PrincipalRole, auth};
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

    #[error("receipt write failed, aborting state transition")]
    ReceiptWriteFailed,

    #[error("grant not found: {0}")]
    GrantNotFound(String),

    #[error("invalid transition: cannot go from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    #[error("grant expired at {0}")]
    GrantExpired(String),

    #[error("unauthorized: actor {actor} (role: {role}) cannot perform {transition}")]
    Unauthorized {
        actor: String,
        role: String,
        transition: String,
    },
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
                latest_receipt_digest TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_grants_subject_id ON grants(subject_id);
            CREATE INDEX IF NOT EXISTS idx_grants_actor ON grants(actor);
            CREATE INDEX IF NOT EXISTS idx_grants_state ON grants(state);
            ",
        )?;
        Ok(())
    }

    /// Low-level: store a receipt and update grant state atomically.
    /// Fail-closed: if receipt write fails, the grant state does not change.
    ///
    /// **This method does NOT validate transitions.** It is used only during
    /// grant creation (the `grant request` flow that goes through GrantMachine)
    /// and in tests to set up specific states.
    ///
    /// For all other mutations, use `Store::transition()` — the only legal
    /// mutation path that enforces adjacency, contextual guards, and CAS.
    pub fn record_transition(
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
                "INSERT INTO grants (id, subject_id, actor, action, target, state, issued_at, expires_at, latest_receipt_digest, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))
                 ON CONFLICT(id) DO UPDATE SET
                    state = ?6,
                    issued_at = COALESCE(?7, grants.issued_at),
                    expires_at = COALESCE(?8, grants.expires_at),
                    latest_receipt_digest = ?9,
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
    /// This is the domain-level API. It:
    /// 1. Reads current grant state and head digest
    /// 2. Validates the transition is legal (adjacency via GrantState)
    /// 3. Applies contextual guards (expiry check)
    /// 4. Builds a receipt chained to the current head
    /// 5. Commits receipt + state update atomically, conditional on head not having changed
    ///
    /// Returns the new receipt on success.
    /// Checked, atomic state transition with CAS semantics.
    ///
    /// **This is the only legal mutation path for grant state.**
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
        let tx = self.conn.transaction()?;

        // Step 1: Read current state (inside transaction for isolation)
        let grant = {
            let mut stmt = tx.prepare(
                "SELECT state, latest_receipt_digest, subject_id, expires_at FROM grants WHERE id = ?1",
            )?;
            let mut rows = stmt.query_map(params![grant_id], |row| {
                Ok(GrantSnapshot {
                    state: row.get::<_, String>(0)?,
                    head_digest: row.get::<_, String>(1)?,
                    subject_id: row.get::<_, String>(2)?,
                    expires_at: row.get::<_, Option<String>>(3)?,
                })
            })?;
            match rows.next() {
                Some(row) => row?,
                None => return Err(StoreError::GrantNotFound(grant_id.to_string())),
            }
        };

        // Step 2: Validate adjacency
        let current_state = GrantState::from_str(&grant.state).ok_or_else(|| {
            StoreError::InvalidTransition {
                from: grant.state.clone(),
                to: target_state.to_string(),
            }
        })?;

        if !current_state.can_transition_to(&target_state) {
            return Err(StoreError::InvalidTransition {
                from: current_state.to_string(),
                to: target_state.to_string(),
            });
        }

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
        if actor_ctx.role == PrincipalRole::Subject
            && actor_ctx.principal.id != grant.subject_id
        {
            return Err(StoreError::Unauthorized {
                actor: actor_ctx.principal.id.clone(),
                role: "subject (wrong principal)".to_string(),
                transition: format!("{} → {}", current_state, target_state),
            });
        }

        // Step 4: Contextual guards
        // Expiry check: if grant has an expires_at and it's in the past,
        // the only valid transition is to Expired (not Used, not Active)
        if let Some(ref expires_at_str) = grant.expires_at {
            if let Ok(expires_at) = DateTime::parse_from_rfc3339(expires_at_str) {
                if Utc::now() >= expires_at.to_utc() && target_state != GrantState::Expired {
                    return Err(StoreError::GrantExpired(expires_at_str.clone()));
                }
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
            params![target_state_str, receipt.digest, grant_id, grant.head_digest],
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

        let r = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap();
        assert_eq!(r.to_state, GrantState::Active);

        let r = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed,
            &bot_subject(), serde_json::json!({"deployed": "v1.0"}), None,
        ).unwrap();
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

        let err = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    #[test]
    fn rejects_transition_from_terminal() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_active_grant(future);

        store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap();

        let err = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    // ---------------------------------------------------------------
    // Failure mode: expired-but-used
    // ---------------------------------------------------------------

    #[test]
    fn expired_grant_cannot_be_activated() {
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_issued_grant(past);

        let err = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::GrantExpired(_)));
    }

    #[test]
    fn expired_grant_cannot_be_used() {
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_active_grant(past);

        let err = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed,
            &bot_subject(), serde_json::json!({"action": "deploy"}), None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::GrantExpired(_)));
    }

    #[test]
    fn expired_grant_can_be_marked_expired() {
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_issued_grant(past);

        let r = store.transition(
            &id, GrantState::Expired, ReceiptKind::GrantExpired,
            &ActorContext::system(), serde_json::Value::Null, None,
        ).unwrap();
        assert_eq!(r.to_state, GrantState::Expired);
    }

    // ---------------------------------------------------------------
    // Failure mode: revoke-between-issue-and-use
    // ---------------------------------------------------------------

    #[test]
    fn revoked_grant_cannot_be_activated() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        store.transition(
            &id, GrantState::Revoked, ReceiptKind::GrantRevoked,
            &admin_ctx(), serde_json::json!({"reason": "security incident"}), None,
        ).unwrap();

        let err = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    #[test]
    fn revoked_active_grant_cannot_be_used() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_active_grant(future);

        store.transition(
            &id, GrantState::Revoked, ReceiptKind::GrantRevoked,
            &admin_ctx(), serde_json::json!({"reason": "policy change"}), None,
        ).unwrap();

        let err = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    // ---------------------------------------------------------------
    // Receipt-write-failure rollback
    // ---------------------------------------------------------------

    #[test]
    fn failed_transition_does_not_advance_state() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap();

        assert_eq!(store.get_grant(&id).unwrap().unwrap().state, "active");

        // Invalid adjacency: active → issued
        let err = store.transition(
            &id, GrantState::Issued, ReceiptKind::GrantIssued,
            &bot_subject(), serde_json::Value::Null, None,
        );
        assert!(err.is_err());
        assert_eq!(store.get_grant(&id).unwrap().unwrap().state, "active");
    }

    #[test]
    fn grant_not_found_returns_error() {
        let mut store = Store::in_memory().unwrap();
        let err = store.transition(
            "nonexistent-id", GrantState::Active, ReceiptKind::GrantActivated,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::GrantNotFound(_)));
    }

    // ---------------------------------------------------------------
    // CAS conflict: stale head
    // ---------------------------------------------------------------

    #[test]
    fn stale_head_cas_conflict() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let stale_head = store.get_grant(&id).unwrap().unwrap().latest_receipt_digest.clone();

        store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap();

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

        let err = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &wrong_subject(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));
    }

    #[test]
    fn wrong_principal_cannot_use() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_active_grant(future);

        let err = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed,
            &wrong_subject(), serde_json::json!({"action": "steal"}), None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));
    }

    #[test]
    fn admin_can_revoke() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let r = store.transition(
            &id, GrantState::Revoked, ReceiptKind::GrantRevoked,
            &admin_ctx(), serde_json::json!({"reason": "policy"}), None,
        ).unwrap();
        assert_eq!(r.to_state, GrantState::Revoked);
    }

    #[test]
    fn subject_can_self_revoke() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let r = store.transition(
            &id, GrantState::Revoked, ReceiptKind::GrantRevoked,
            &bot_subject(), serde_json::json!({"reason": "no longer needed"}), None,
        ).unwrap();
        assert_eq!(r.to_state, GrantState::Revoked);
    }

    #[test]
    fn admin_cannot_activate() {
        // Only subject can activate — admin role is not authorized
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let err = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &admin_ctx(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));
    }

    #[test]
    fn subject_cannot_expire_grant() {
        // Only system can mark as expired
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_issued_grant(past);

        let err = store.transition(
            &id, GrantState::Expired, ReceiptKind::GrantExpired,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized { .. }));
    }

    #[test]
    fn identity_mismatch_does_not_advance_state() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        let _ = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &wrong_subject(), serde_json::Value::Null, None,
        );

        // State must still be issued
        assert_eq!(store.get_grant(&id).unwrap().unwrap().state, "issued");
    }

    #[test]
    fn receipt_records_actor_and_subject() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated,
            &bot_subject(), serde_json::Value::Null, None,
        ).unwrap();

        let chain = store.receipt_chain(&id).unwrap();
        let activate_receipt = chain.last().unwrap();
        let evidence: serde_json::Value =
            serde_json::from_str(&activate_receipt.evidence).unwrap();

        // Receipt should contain actor identity and subject binding
        assert_eq!(evidence["actor"]["principal_id"], SUBJECT_ID);
        assert_eq!(evidence["subject_id"], SUBJECT_ID);
        assert_eq!(evidence["actor"]["role"], "subject");
    }
}
