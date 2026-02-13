//! Data Loss Prevention (DLP) module.
//!
//! Scans outbound HTTP request bodies for sensitive data such as API keys,
//! credentials, PII, and private keys before they leave the network.
//!
//! The scanning pipeline:
//! 1. The proxy extracts the request body (HTTP only; HTTPS CONNECT is opaque)
//! 2. The [`DlpScanner`] trait implementation scans the body against patterns
//! 3. **Critical** findings block the request; **non-critical** findings are logged
//!
//! The built-in [`patterns::RegexScanner`] ships with regex patterns for 15+
//! common secret formats (AI provider keys, AWS, GitHub tokens, etc.).

pub mod patterns;

use serde::Serialize;

/// Severity level for a DLP finding, determining the proxy's response.
///
/// - `Critical` → request is blocked (403 Forbidden)
/// - `High` / `Medium` / `Low` → logged as warnings but request proceeds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    /// Minor concern; informational only.
    Low,
    /// Moderate concern (e.g., email addresses).
    Medium,
    /// Significant concern (e.g., generic API key patterns).
    High,
    /// Must block — confirmed secret or credential.
    Critical,
}

/// A single DLP finding from scanning a payload.
#[derive(Debug, Clone, Serialize)]
pub struct DlpFinding {
    /// Name of the pattern that matched (e.g., `"openai-api-key"`).
    pub pattern_name: String,
    /// Redacted snippet of the matched text (first 4 + last 4 chars).
    pub matched_text: String,
    /// Severity level of this finding.
    pub severity: Severity,
}

/// Trait for DLP scanners that inspect request payloads for sensitive data.
///
/// Implementations must be `Send + Sync` for use across async tasks.
pub trait DlpScanner: Send + Sync {
    /// Scan a raw payload and return all findings.
    fn scan(&self, payload: &[u8]) -> Vec<DlpFinding>;
}
