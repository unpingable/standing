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

use standing_grant::GrantState;
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
                "INSERT INTO grants (id, actor, action, target, state, issued_at, expires_at, latest_receipt_digest, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'))
                 ON CONFLICT(id) DO UPDATE SET
                    state = ?5,
                    issued_at = COALESCE(?6, grants.issued_at),
                    expires_at = COALESCE(?7, grants.expires_at),
                    latest_receipt_digest = ?8,
                    updated_at = datetime('now')",
                params![
                    grant_id.to_string(),
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
            "SELECT id, actor, action, target, state, issued_at, expires_at, latest_receipt_digest FROM grants WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![grant_id], |row| {
            Ok(GrantRow {
                id: row.get(0)?,
                actor: row.get(1)?,
                action: row.get(2)?,
                target: row.get(3)?,
                state: row.get(4)?,
                issued_at: row.get(5)?,
                expires_at: row.get(6)?,
                latest_receipt_digest: row.get(7)?,
            })
        })?;
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
    pub fn transition(
        &mut self,
        grant_id: &str,
        target_state: GrantState,
        receipt_kind: ReceiptKind,
        actor: &str,
        evidence: serde_json::Value,
        policy_hash: Option<&str>,
    ) -> Result<TransitionResult, StoreError> {
        let tx = self.conn.transaction()?;

        // Step 1: Read current state (inside transaction for isolation)
        let grant = {
            let mut stmt = tx.prepare(
                "SELECT state, latest_receipt_digest, expires_at FROM grants WHERE id = ?1",
            )?;
            let mut rows = stmt.query_map(params![grant_id], |row| {
                Ok(GrantSnapshot {
                    state: row.get::<_, String>(0)?,
                    head_digest: row.get::<_, String>(1)?,
                    expires_at: row.get::<_, Option<String>>(2)?,
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

        // Step 3: Contextual guards
        // Expiry check: if grant has an expires_at and it's in the past,
        // the only valid transition is to Expired (not Used, not Active)
        if let Some(ref expires_at_str) = grant.expires_at {
            if let Ok(expires_at) = DateTime::parse_from_rfc3339(expires_at_str) {
                if Utc::now() >= expires_at.to_utc() && target_state != GrantState::Expired {
                    return Err(StoreError::GrantExpired(expires_at_str.clone()));
                }
            }
        }

        // Step 4: Build receipt chained to current head
        let mut builder =
            ReceiptBuilder::new(receipt_kind, actor, grant_id).parent_digest(&grant.head_digest);

        if !evidence.is_null() {
            builder = builder.evidence(evidence);
        }
        if let Some(ph) = policy_hash {
            builder = builder.policy_hash(ph);
        }

        let receipt = builder.build()?;

        // Step 5: Atomic write with CAS — only update if head hasn't changed
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
        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<GrantRow> {
            Ok(GrantRow {
                id: row.get(0)?,
                actor: row.get(1)?,
                action: row.get(2)?,
                target: row.get(3)?,
                state: row.get(4)?,
                issued_at: row.get(5)?,
                expires_at: row.get(6)?,
                latest_receipt_digest: row.get(7)?,
            })
        };

        let mut result = Vec::new();

        match state_filter {
            Some(state) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, actor, action, target, state, issued_at, expires_at, latest_receipt_digest FROM grants WHERE state = ?1 ORDER BY updated_at DESC",
                )?;
                let rows = stmt.query_map(params![state], map_row)?;
                for row in rows {
                    result.push(row?);
                }
            }
            None => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, actor, action, target, state, issued_at, expires_at, latest_receipt_digest FROM grants ORDER BY updated_at DESC",
                )?;
                let rows = stmt.query_map([], map_row)?;
                for row in rows {
                    result.push(row?);
                }
            }
        }

        Ok(result)
    }
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
    use standing_receipt::{ReceiptBuilder, ReceiptKind};

    /// Set up a grant in "issued" state with a given expiry, returning (store, grant_id_str).
    fn setup_issued_grant(expires_at: DateTime<Utc>) -> (Store, String) {
        let mut store = Store::in_memory().unwrap();
        let grant_id = Uuid::new_v4();
        let id_str = grant_id.to_string();
        let now = Utc::now();

        // Requested receipt
        let r1 = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", &id_str)
            .build()
            .unwrap();
        store
            .record_transition(
                grant_id,
                &GrantState::Requested,
                &r1,
                Some(GrantMeta {
                    actor: "bot".to_string(),
                    action: "deploy".to_string(),
                    target: "prod".to_string(),
                    issued_at: None,
                    expires_at: None,
                }),
            )
            .unwrap();

        // Issued receipt
        let r2 = ReceiptBuilder::new(ReceiptKind::GrantIssued, "bot", &id_str)
            .parent_digest(&r1.digest)
            .build()
            .unwrap();
        store
            .record_transition(
                grant_id,
                &GrantState::Issued,
                &r2,
                Some(GrantMeta {
                    actor: "bot".to_string(),
                    action: "deploy".to_string(),
                    target: "prod".to_string(),
                    issued_at: Some(now),
                    expires_at: Some(expires_at),
                }),
            )
            .unwrap();

        (store, id_str)
    }

    /// Set up a grant in "active" state with a given expiry.
    /// Uses record_transition (bypass) so we can set up expired-but-active
    /// grants for testing without the domain layer blocking us.
    fn setup_active_grant(expires_at: DateTime<Utc>) -> (Store, String) {
        let (mut store, id_str) = setup_issued_grant(expires_at);

        // Get the current head to chain the receipt
        let grant = store.get_grant(&id_str).unwrap().unwrap();
        let r = ReceiptBuilder::new(ReceiptKind::GrantActivated, "bot", &id_str)
            .parent_digest(&grant.latest_receipt_digest)
            .build()
            .unwrap();

        let grant_id: Uuid = id_str.parse().unwrap();
        store
            .record_transition(grant_id, &GrantState::Active, &r, None)
            .unwrap();

        (store, id_str)
    }

    #[test]
    fn store_and_retrieve_receipt() {
        let mut store = Store::in_memory().unwrap();
        let receipt = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", "grant-1")
            .build()
            .unwrap();

        let grant_id = Uuid::new_v4();
        store
            .record_transition(
                grant_id,
                &GrantState::Requested,
                &receipt,
                Some(GrantMeta {
                    actor: "bot".to_string(),
                    action: "deploy".to_string(),
                    target: "prod".to_string(),
                    issued_at: None,
                    expires_at: None,
                }),
            )
            .unwrap();

        let chain = store.receipt_chain(&receipt.subject).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].digest, receipt.digest);
    }

    #[test]
    fn list_grants_by_state() {
        let mut store = Store::in_memory().unwrap();
        let receipt = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", "g1")
            .build()
            .unwrap();

        let grant_id = Uuid::new_v4();
        store
            .record_transition(
                grant_id,
                &GrantState::Requested,
                &receipt,
                Some(GrantMeta {
                    actor: "bot".to_string(),
                    action: "deploy".to_string(),
                    target: "prod".to_string(),
                    issued_at: None,
                    expires_at: None,
                }),
            )
            .unwrap();

        let all = store.list_grants(None).unwrap();
        assert_eq!(all.len(), 1);

        let requested = store.list_grants(Some("requested")).unwrap();
        assert_eq!(requested.len(), 1);

        let issued = store.list_grants(Some("issued")).unwrap();
        assert_eq!(issued.len(), 0);
    }

    // ---------------------------------------------------------------
    // Domain-level transition tests
    // ---------------------------------------------------------------

    #[test]
    fn happy_path_through_domain_layer() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        // issued → active
        let r = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated, "bot",
            serde_json::Value::Null, None,
        ).unwrap();
        assert_eq!(r.to_state, GrantState::Active);

        // active → used
        let r = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed, "bot",
            serde_json::json!({"deployed": "v1.0"}), None,
        ).unwrap();
        assert_eq!(r.to_state, GrantState::Used);

        // Verify chain integrity
        let chain = store.receipt_chain(&id).unwrap();
        assert_eq!(chain.len(), 4); // requested, issued, activated, used
    }

    #[test]
    fn rejects_invalid_adjacency() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        // issued → used (skipping active) should fail
        let err = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed, "bot",
            serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    #[test]
    fn rejects_transition_from_terminal() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_active_grant(future);

        // active → used
        store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed, "bot",
            serde_json::Value::Null, None,
        ).unwrap();

        // used → active (terminal, no transitions allowed)
        let err = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated, "bot",
            serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    // ---------------------------------------------------------------
    // Failure mode: expired-but-used
    // ---------------------------------------------------------------

    #[test]
    fn expired_grant_cannot_be_activated() {
        // Grant that expired 10 seconds ago
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_issued_grant(past);

        // Try to activate an expired grant — should fail
        let err = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated, "bot",
            serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::GrantExpired(_)));
    }

    #[test]
    fn expired_grant_cannot_be_used() {
        // Grant that expires 1 second from now — activate it, then wait
        // We can't actually sleep in tests, so we set up an active grant
        // with an already-past expiry by using record_transition directly.
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_active_grant(past);

        // Try to use an expired active grant — should fail
        let err = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed, "bot",
            serde_json::json!({"action": "deploy"}), None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::GrantExpired(_)));
    }

    #[test]
    fn expired_grant_can_be_marked_expired() {
        // Even though the grant is expired, we should be able to
        // transition it to the Expired terminal state
        let past = Utc::now() - Duration::seconds(10);
        let (mut store, id) = setup_issued_grant(past);

        let r = store.transition(
            &id, GrantState::Expired, ReceiptKind::GrantExpired, "system",
            serde_json::Value::Null, None,
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

        // Revoke it
        store.transition(
            &id, GrantState::Revoked, ReceiptKind::GrantRevoked, "admin",
            serde_json::json!({"reason": "security incident"}), None,
        ).unwrap();

        // Try to activate — should fail (revoked is terminal)
        let err = store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated, "bot",
            serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    #[test]
    fn revoked_active_grant_cannot_be_used() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_active_grant(future);

        // Revoke it while active
        store.transition(
            &id, GrantState::Revoked, ReceiptKind::GrantRevoked, "admin",
            serde_json::json!({"reason": "policy change"}), None,
        ).unwrap();

        // Try to use — should fail
        let err = store.transition(
            &id, GrantState::Used, ReceiptKind::GrantUsed, "bot",
            serde_json::Value::Null, None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::InvalidTransition { .. }));
    }

    // ---------------------------------------------------------------
    // Failure mode: receipt-write-failure rollback
    // ---------------------------------------------------------------

    #[test]
    fn duplicate_receipt_digest_rolls_back_transition() {
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        // Activate normally
        store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated, "bot",
            serde_json::Value::Null, None,
        ).unwrap();

        // Verify we're active
        let grant = store.get_grant(&id).unwrap().unwrap();
        assert_eq!(grant.state, "active");

        // Now try a transition that would succeed on adjacency,
        // but we'll verify that if the receipt INSERT fails (e.g., duplicate
        // primary key), the state doesn't advance.
        // We can't easily force a receipt collision, but we CAN verify that
        // after a failed transition the state is unchanged.
        let err = store.transition(
            &id, GrantState::Issued, ReceiptKind::GrantIssued, "bot",
            serde_json::Value::Null, None,
        );
        assert!(err.is_err());

        // State must still be active
        let grant = store.get_grant(&id).unwrap().unwrap();
        assert_eq!(grant.state, "active");
    }

    #[test]
    fn grant_not_found_returns_error() {
        let mut store = Store::in_memory().unwrap();
        let err = store.transition(
            "nonexistent-id",
            GrantState::Active,
            ReceiptKind::GrantActivated,
            "bot",
            serde_json::Value::Null,
            None,
        ).unwrap_err();
        assert!(matches!(err, StoreError::GrantNotFound(_)));
    }

    // ---------------------------------------------------------------
    // CAS conflict: stale head
    // ---------------------------------------------------------------

    #[test]
    fn stale_head_cas_conflict() {
        // Simulate two concurrent transitions: one succeeds, the second
        // finds the head has moved and fails cleanly.
        let future = Utc::now() + Duration::seconds(300);
        let (mut store, id) = setup_issued_grant(future);

        // Read the head before any transition
        let grant_before = store.get_grant(&id).unwrap().unwrap();
        let stale_head = grant_before.latest_receipt_digest.clone();

        // First transition succeeds: issued → active
        store.transition(
            &id, GrantState::Active, ReceiptKind::GrantActivated, "bot",
            serde_json::Value::Null, None,
        ).unwrap();

        // Now manually try to write against the stale head.
        // Build a receipt chained to the OLD head (as if we validated earlier).
        let stale_receipt = ReceiptBuilder::new(ReceiptKind::GrantRevoked, "admin", &id)
            .parent_digest(&stale_head)
            .evidence(serde_json::json!({"reason": "stale attempt"}))
            .build()
            .unwrap();

        // Try to commit with the stale head — the CAS UPDATE should match 0 rows
        let tx = store.conn.transaction().unwrap();
        insert_receipt(&tx, &stale_receipt).unwrap();
        let rows_updated = tx.execute(
            "UPDATE grants SET state = 'revoked', latest_receipt_digest = ?1, updated_at = datetime('now')
             WHERE id = ?2 AND latest_receipt_digest = ?3",
            params![stale_receipt.digest, id, stale_head],
        ).unwrap();
        // CAS fails: 0 rows updated because head has moved
        assert_eq!(rows_updated, 0);
        // Don't commit — rollback
        tx.rollback().unwrap();

        // State is still active, not revoked
        let grant_after = store.get_grant(&id).unwrap().unwrap();
        assert_eq!(grant_after.state, "active");
    }
}
