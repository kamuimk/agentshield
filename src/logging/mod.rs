pub mod export;

use anyhow::Result;
use rusqlite::Connection;

/// A single logged request record.
#[derive(Debug, Clone)]
pub struct RequestLog {
    pub id: Option<i64>,
    pub timestamp: String,
    pub method: String,
    pub domain: String,
    pub path: String,
    pub action: String,
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
