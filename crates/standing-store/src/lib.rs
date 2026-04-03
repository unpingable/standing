//! SQLite storage for standing receipts and grants.
//!
//! Stores receipts and grant state transitions. Supports the "why was this
//! allowed?" query by walking receipt chains.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Transaction};
use uuid::Uuid;

use standing_grant::GrantState;
use standing_receipt::Receipt;

/// Errors from the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("receipt write failed, aborting state transition")]
    ReceiptWriteFailed,
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

    /// Store a receipt and update grant state atomically.
    /// Fail-closed: if receipt write fails, the grant state does not change.
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

#[cfg(test)]
mod tests {
    use super::*;
    use standing_receipt::{ReceiptBuilder, ReceiptKind};

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
}
