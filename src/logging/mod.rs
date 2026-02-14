//! SQLite-backed request logging.
//!
//! Every proxied request is logged to a SQLite database with its timestamp,
//! method, domain, path, action (allow/deny/ask/system-allow), and reason.
//! The database is accessed through an [`r2d2`] connection pool ([`DbPool`])
//! for thread-safe concurrent writes from async tasks.
//!
//! The [`export`] submodule provides JSON and CSV export of all logs.

pub mod export;

use rusqlite::Connection;

use crate::error::Result;

/// SQLite connection pool type alias (r2d2 + r2d2-sqlite).
pub type DbPool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;

/// Open a connection pool for the given database file path.
///
/// Creates the database and `requests` table if they don't exist.
/// The pool is configured with a maximum of 4 connections.
pub fn open_pool(path: &std::path::Path) -> Result<DbPool> {
    let manager = r2d2_sqlite::SqliteConnectionManager::file(path);
    let pool = r2d2::Pool::builder()
        .max_size(4)
        .build(manager)
        .map_err(|e| crate::error::AgentShieldError::Proxy(e.to_string()))?;
    let conn = pool
        .get()
        .map_err(|e| crate::error::AgentShieldError::Proxy(e.to_string()))?;
    init_db(&conn)?;
    Ok(pool)
}

/// Open an in-memory connection pool (for testing).
pub fn open_memory_pool() -> Result<DbPool> {
    let manager = r2d2_sqlite::SqliteConnectionManager::memory();
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .build(manager)
        .map_err(|e| crate::error::AgentShieldError::Proxy(e.to_string()))?;
    let conn = pool
        .get()
        .map_err(|e| crate::error::AgentShieldError::Proxy(e.to_string()))?;
    init_db(&conn)?;
    Ok(pool)
}

/// A real-time log event broadcast to subscribers (e.g., web dashboard SSE).
///
/// Created alongside each [`RequestLog`] insert and sent via a
/// `tokio::sync::broadcast` channel. Subscribers that lag behind
/// automatically skip missed events.
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// HTTP method.
    pub method: String,
    /// Target domain.
    pub domain: String,
    /// Request path.
    pub path: String,
    /// Decision taken: `"allow"`, `"deny"`, etc.
    pub action: String,
    /// Human-readable reason.
    pub reason: String,
}

/// A single logged request record stored in the `requests` table.
#[derive(Debug, Clone)]
pub struct RequestLog {
    /// Auto-incremented row ID (`None` for new records before insert).
    pub id: Option<i64>,
    /// ISO 8601 timestamp (e.g., `"2026-02-12T10:00:00Z"`).
    pub timestamp: String,
    /// HTTP method (e.g., `"GET"`, `"POST"`, `"CONNECT"`).
    pub method: String,
    /// Target domain (e.g., `"api.github.com"`).
    pub domain: String,
    /// Request path (e.g., `"/v1/messages"`).
    pub path: String,
    /// Decision taken: `"allow"`, `"deny"`, `"ask"`, or `"system-allow"`.
    pub action: String,
    /// Human-readable reason for the decision.
    pub reason: String,
}

/// Initialize the SQLite database and create the requests table if it doesn't exist.
pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS requests (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            method    TEXT NOT NULL,
            domain    TEXT NOT NULL,
            path      TEXT NOT NULL,
            action    TEXT NOT NULL,
            reason    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
        CREATE INDEX IF NOT EXISTS idx_requests_domain ON requests(domain);",
    )?;
    Ok(())
}

/// Log a request to the database.
pub fn log_request(conn: &Connection, log: &RequestLog) -> Result<i64> {
    conn.execute(
        "INSERT INTO requests (timestamp, method, domain, path, action, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            log.timestamp,
            log.method,
            log.domain,
            log.path,
            log.action,
            log.reason,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Query the most recent N log entries.
pub fn query_recent(conn: &Connection, limit: usize) -> Result<Vec<RequestLog>> {
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, method, domain, path, action, reason
         FROM requests ORDER BY id DESC LIMIT ?1",
    )?;

    let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
        Ok(RequestLog {
            id: Some(row.get(0)?),
            timestamp: row.get(1)?,
            method: row.get(2)?,
            domain: row.get(3)?,
            path: row.get(4)?,
            action: row.get(5)?,
            reason: row.get(6)?,
        })
    })?;

    let mut logs = Vec::new();
    for row in rows {
        logs.push(row?);
    }
    Ok(logs)
}

/// Aggregated request statistics from the `requests` table.
#[derive(Debug, Clone, Default)]
pub struct RequestStats {
    /// Total number of logged requests.
    pub total: usize,
    /// Requests allowed by policy.
    pub allowed: usize,
    /// Requests denied by policy or DLP.
    pub denied: usize,
    /// Requests that triggered an ASK prompt.
    pub asked: usize,
    /// Requests bypassed via system allowlist.
    pub system_allowed: usize,
}

/// Query aggregated request counts grouped by action.
///
/// Uses SQL `COUNT(*) GROUP BY action` for efficient aggregation without
/// loading all rows into memory.
pub fn query_stats(conn: &Connection) -> Result<RequestStats> {
    let mut stmt = conn.prepare("SELECT action, COUNT(*) FROM requests GROUP BY action")?;
    let rows = stmt.query_map([], |row| {
        let action: String = row.get(0)?;
        let count: i64 = row.get(1)?;
        Ok((action, count as usize))
    })?;

    let mut stats = RequestStats::default();
    for row in rows {
        let (action, count) = row?;
        stats.total += count;
        match action.as_str() {
            "allow" => stats.allowed = count,
            "deny" => stats.denied = count,
            "ask" => stats.asked = count,
            "system-allow" => stats.system_allowed = count,
            _ => {} // unknown actions still count in total
        }
    }
    Ok(stats)
}

/// Open or create a SQLite database at the given path.
pub fn open_db(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    init_db(&conn)?;
    Ok(conn)
}

/// Open an in-memory SQLite database (for testing).
pub fn open_memory_db() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    init_db(&conn)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_log(domain: &str, method: &str, action: &str) -> RequestLog {
        RequestLog {
            id: None,
            timestamp: "2026-02-12T10:00:00Z".to_string(),
            method: method.to_string(),
            domain: domain.to_string(),
            path: "/test".to_string(),
            action: action.to_string(),
            reason: "test reason".to_string(),
        }
    }

    #[test]
    fn init_and_insert() {
        let conn = open_memory_db().unwrap();
        let id = log_request(&conn, &sample_log("example.com", "GET", "allow")).unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn query_recent_returns_in_desc_order() {
        let conn = open_memory_db().unwrap();
        log_request(&conn, &sample_log("first.com", "GET", "allow")).unwrap();
        log_request(&conn, &sample_log("second.com", "POST", "deny")).unwrap();
        log_request(&conn, &sample_log("third.com", "PUT", "ask")).unwrap();

        let logs = query_recent(&conn, 2).unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].domain, "third.com");
        assert_eq!(logs[1].domain, "second.com");
    }

    #[test]
    fn query_recent_with_limit_larger_than_data() {
        let conn = open_memory_db().unwrap();
        log_request(&conn, &sample_log("only.com", "GET", "allow")).unwrap();

        let logs = query_recent(&conn, 100).unwrap();
        assert_eq!(logs.len(), 1);
    }

    #[test]
    fn open_pool_creates_table() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("pool_test.db");
        let pool = open_pool(&db_path).unwrap();
        let conn = pool.get().unwrap();
        let id = log_request(&conn, &sample_log("pool.com", "GET", "allow")).unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn pool_concurrent_writes() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("concurrent.db");
        let pool = open_pool(&db_path).unwrap();

        for i in 0..10 {
            let conn = pool.get().unwrap();
            log_request(
                &conn,
                &sample_log(&format!("host{}.com", i), "GET", "allow"),
            )
            .unwrap();
        }

        let conn = pool.get().unwrap();
        let logs = query_recent(&conn, 100).unwrap();
        assert_eq!(logs.len(), 10);
    }

    #[test]
    fn open_memory_pool_works() {
        let pool = open_memory_pool().unwrap();
        let conn = pool.get().unwrap();
        log_request(&conn, &sample_log("mem.com", "POST", "deny")).unwrap();
        let logs = query_recent(&conn, 10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].domain, "mem.com");
    }

    #[test]
    fn query_stats_mixed_entries() {
        let conn = open_memory_db().unwrap();
        // Insert 10 mixed entries
        log_request(&conn, &sample_log("a.com", "GET", "allow")).unwrap();
        log_request(&conn, &sample_log("b.com", "GET", "allow")).unwrap();
        log_request(&conn, &sample_log("c.com", "POST", "deny")).unwrap();
        log_request(&conn, &sample_log("d.com", "POST", "deny")).unwrap();
        log_request(&conn, &sample_log("e.com", "POST", "deny")).unwrap();
        log_request(&conn, &sample_log("f.com", "GET", "ask")).unwrap();
        log_request(&conn, &sample_log("g.com", "GET", "system-allow")).unwrap();
        log_request(&conn, &sample_log("h.com", "GET", "system-allow")).unwrap();
        log_request(&conn, &sample_log("i.com", "GET", "allow")).unwrap();
        log_request(&conn, &sample_log("j.com", "DELETE", "deny")).unwrap();

        let stats = query_stats(&conn).unwrap();
        assert_eq!(stats.total, 10);
        assert_eq!(stats.allowed, 3);
        assert_eq!(stats.denied, 4);
        assert_eq!(stats.asked, 1);
        assert_eq!(stats.system_allowed, 2);
    }

    #[test]
    fn query_stats_empty_db() {
        let conn = open_memory_db().unwrap();
        let stats = query_stats(&conn).unwrap();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.denied, 0);
        assert_eq!(stats.asked, 0);
        assert_eq!(stats.system_allowed, 0);
    }

    #[test]
    fn open_db_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_db(&db_path).unwrap();
        log_request(&conn, &sample_log("test.com", "GET", "allow")).unwrap();

        // Re-open and verify
        let conn2 = open_db(&db_path).unwrap();
        let logs = query_recent(&conn2, 10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].domain, "test.com");
    }
}
