use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;

use super::RequestLog;

#[derive(Debug, Serialize)]
struct LogEntry {
    id: i64,
    timestamp: String,
    method: String,
    domain: String,
    path: String,
    action: String,
    reason: String,
}

impl From<&RequestLog> for LogEntry {
    fn from(log: &RequestLog) -> Self {
        LogEntry {
            id: log.id.unwrap_or(0),
            timestamp: log.timestamp.clone(),
            method: log.method.clone(),
            domain: log.domain.clone(),
            path: log.path.clone(),
            action: log.action.clone(),
            reason: log.reason.clone(),
        }
    }
}

/// Export all logs as JSON string.
pub fn export_json(conn: &Connection) -> Result<String> {
    let logs = super::query_recent(conn, usize::MAX)?;
    let entries: Vec<LogEntry> = logs.iter().map(LogEntry::from).collect();
    let json = serde_json::to_string_pretty(&entries)?;
    Ok(json)
}

/// Export all logs as CSV string.
pub fn export_csv(conn: &Connection) -> Result<String> {
    let logs = super::query_recent(conn, usize::MAX)?;
    let mut output = String::from("id,timestamp,method,domain,path,action,reason\n");
    for log in &logs {
        output.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            log.id.unwrap_or(0),
            log.timestamp,
            log.method,
            log.domain,
            log.path,
            log.action,
            log.reason,
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{RequestLog, log_request, open_memory_db};

    fn sample_log(domain: &str) -> RequestLog {
        RequestLog {
            id: None,
            timestamp: "2026-02-12T10:00:00Z".to_string(),
            method: "GET".to_string(),
            domain: domain.to_string(),
            path: "/test".to_string(),
            action: "allow".to_string(),
            reason: "test".to_string(),
        }
    }

    #[test]
    fn export_json_format() {
        let conn = open_memory_db().unwrap();
        log_request(&conn, &sample_log("example.com")).unwrap();

        let json = export_json(&conn).unwrap();
        assert!(json.contains("\"domain\": \"example.com\""));
        assert!(json.contains("\"method\": \"GET\""));

        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn export_csv_format() {
        let conn = open_memory_db().unwrap();
        log_request(&conn, &sample_log("example.com")).unwrap();
        log_request(&conn, &sample_log("other.com")).unwrap();

        let csv = export_csv(&conn).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "id,timestamp,method,domain,path,action,reason");
        assert_eq!(lines.len(), 3); // header + 2 data rows
    }

    #[test]
    fn export_empty_db() {
        let conn = open_memory_db().unwrap();

        let json = export_json(&conn).unwrap();
        assert_eq!(json, "[]");

        let csv = export_csv(&conn).unwrap();
        assert_eq!(csv.lines().count(), 1); // header only
    }
}
