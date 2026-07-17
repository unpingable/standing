//! SQLite-backed replay guard for identity jti tracking.

use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, params};
use standing_identity::ReplayGuard;

/// Grace period past `expires_at` before a seen-jti entry is purgeable. Keeping
/// an entry a little past its expiry closes a replay window at the boundary:
/// with disagreeing clocks, a just-expired jti could otherwise be purged and
/// then re-presented. Matches the identity layer's skew tolerance.
const PURGE_SKEW_SECS: i64 = 30;

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
        // Only purge entries expired MORE than the skew grace ago, so a
        // just-expired jti stays defended across a clock disagreement.
        let cutoff = (Utc::now() - Duration::seconds(PURGE_SKEW_SECS)).to_rfc3339();
        let result = self.conn.execute(
            "DELETE FROM seen_jti WHERE expires_at < ?1",
            params![cutoff],
        );
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
        // SqliteReplayGuard::new will create the table
        Connection::open_in_memory().unwrap()
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
        assert!(
            guard
                .check_and_record("jti-1", "standing:prod", exp)
                .unwrap()
        );
        assert!(
            guard
                .check_and_record("jti-1", "standing:staging", exp)
                .unwrap()
        );
    }

    #[test]
    fn purge_removes_well_expired_but_keeps_recent() {
        let conn = setup();
        let mut guard = SqliteReplayGuard::new(&conn).unwrap();
        let long_past = Utc::now() - chrono::Duration::seconds(3600);
        let just_expired = Utc::now() - chrono::Duration::seconds(5); // within skew grace
        let future = Utc::now() + chrono::Duration::seconds(300);

        guard
            .check_and_record("ancient", "standing", long_past)
            .unwrap();
        guard
            .check_and_record("just", "standing", just_expired)
            .unwrap();
        guard.check_and_record("live", "standing", future).unwrap();

        // Only "ancient" (past the skew grace) is purged; "just" is retained
        // to close the boundary replay window.
        let purged = guard.purge_expired().unwrap();
        assert_eq!(purged, 1);

        // "ancient" is gone.
        assert!(
            guard
                .check_and_record("ancient", "standing", future)
                .unwrap()
        );
        // "just" is still defended despite being expired.
        assert!(!guard.check_and_record("just", "standing", future).unwrap());
        // "live" is still there.
        assert!(!guard.check_and_record("live", "standing", future).unwrap());
    }
}
