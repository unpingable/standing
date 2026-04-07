//! SQLite-backed replay guard for identity jti tracking.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use standing_identity::ReplayGuard;

/// SQLite replay guard: stores seen jti+audience pairs with expiry.
///
/// Uses the same database as the grant store but a separate table.
/// Entries are retained until `expires_at + skew` passes, then purged.
pub struct SqliteReplayGuard<'a> {
    conn: &'a Connection,
}

impl<'a> SqliteReplayGuard<'a> {
    pub fn new(conn: &'a Connection) -> Result<Self, rusqlite::Error> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS seen_jti (
                jti TEXT NOT NULL,
                audience TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (jti, audience)
            );
            CREATE INDEX IF NOT EXISTS idx_seen_jti_expires ON seen_jti(expires_at);",
        )?;
        Ok(Self { conn })
    }
}

impl ReplayGuard for SqliteReplayGuard<'_> {
    fn check_and_record(
        &mut self,
        jti: &str,
        audience: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, String> {
        // Try to insert. If it already exists, the PRIMARY KEY constraint
        // will cause a conflict and we return false (replay detected).
        let result = self.conn.execute(
            "INSERT OR IGNORE INTO seen_jti (jti, audience, expires_at) VALUES (?1, ?2, ?3)",
            params![jti, audience, expires_at.to_rfc3339()],
        );
        match result {
            Ok(rows) => Ok(rows > 0), // 1 = inserted (new), 0 = ignored (duplicate)
            Err(e) => Err(e.to_string()),
        }
    }

    fn purge_expired(&mut self) -> Result<u64, String> {
        let now = Utc::now().to_rfc3339();
        let result = self
            .conn
            .execute("DELETE FROM seen_jti WHERE expires_at < ?1", params![now]);
        match result {
            Ok(rows) => Ok(rows as u64),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // SqliteReplayGuard::new will create the table
        conn
    }

    #[test]
    fn first_presentation_accepted() {
        let conn = setup();
        let mut guard = SqliteReplayGuard::new(&conn).unwrap();
        let exp = Utc::now() + chrono::Duration::seconds(300);
        assert!(guard.check_and_record("jti-1", "standing", exp).unwrap());
    }

    #[test]
    fn replay_detected() {
        let conn = setup();
        let mut guard = SqliteReplayGuard::new(&conn).unwrap();
        let exp = Utc::now() + chrono::Duration::seconds(300);
        assert!(guard.check_and_record("jti-1", "standing", exp).unwrap());
        assert!(!guard.check_and_record("jti-1", "standing", exp).unwrap());
    }

    #[test]
    fn same_jti_different_audience_is_not_replay() {
        let conn = setup();
        let mut guard = SqliteReplayGuard::new(&conn).unwrap();
        let exp = Utc::now() + chrono::Duration::seconds(300);
        assert!(guard.check_and_record("jti-1", "standing:prod", exp).unwrap());
        assert!(guard.check_and_record("jti-1", "standing:staging", exp).unwrap());
    }

    #[test]
    fn purge_removes_expired() {
        let conn = setup();
        let mut guard = SqliteReplayGuard::new(&conn).unwrap();
        let past = Utc::now() - chrono::Duration::seconds(10);
        let future = Utc::now() + chrono::Duration::seconds(300);

        guard.check_and_record("old", "standing", past).unwrap();
        guard.check_and_record("new", "standing", future).unwrap();

        let purged = guard.purge_expired().unwrap();
        assert_eq!(purged, 1);

        // "old" is gone — can be reused (expired anyway)
        assert!(guard.check_and_record("old", "standing", future).unwrap());
        // "new" is still there
        assert!(!guard.check_and_record("new", "standing", future).unwrap());
    }
}
