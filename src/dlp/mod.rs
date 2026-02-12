pub mod patterns;

use serde::Serialize;

/// Severity level for a DLP finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single DLP finding from scanning a payload.
#[derive(Debug, Clone, Serialize)]
pub struct DlpFinding {
    pub pattern_name: String,
    pub matched_text: String,
    pub severity: Severity,
}

/// Trait for DLP scanners that inspect payloads for sensitive data.
pub trait DlpScanner: Send + Sync {
    fn scan(&self, payload: &[u8]) -> Vec<DlpFinding>;
}
