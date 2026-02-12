use std::collections::HashMap;

use regex::Regex;

use super::{DlpFinding, DlpScanner, Severity};

/// A pattern definition with its regex and severity.
struct PatternDef {
    regex: Regex,
    severity: Severity,
}

/// A DLP scanner that uses regex patterns to detect sensitive data.
pub struct RegexScanner {
    patterns: HashMap<String, PatternDef>,
}

impl RegexScanner {
    /// Create a new RegexScanner with built-in patterns.
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        // OpenAI API key
        patterns.insert(
            "openai-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // AWS Access Key ID
        patterns.insert(
            "aws-access-key".to_string(),
            PatternDef {
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // Generic API key pattern (e.g., "api_key=..." or "apiKey":"...")
        patterns.insert(
            "generic-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#).unwrap(),
                severity: Severity::High,
            },
        );

        // Email address
        patterns.insert(
            "email-address".to_string(),
            PatternDef {
                regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
                severity: Severity::Medium,
            },
        );

        // Private key header
        patterns.insert(
            "private-key".to_string(),
            PatternDef {
                regex: Regex::new(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----").unwrap(),
                severity: Severity::Critical,
            },
        );

        // GitHub Personal Access Token
        patterns.insert(
            "github-token".to_string(),
            PatternDef {
                regex: Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
                severity: Severity::Critical,
            },
        );

        Self { patterns }
    }

    /// Create a RegexScanner with only the specified pattern names (subset of built-in).
    pub fn with_patterns(pattern_names: &[String]) -> Self {
        let all = Self::new();
        let patterns = all
            .patterns
            .into_iter()
            .filter(|(name, _)| pattern_names.contains(name))
            .collect();
        Self { patterns }
    }
}

impl Default for RegexScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DlpScanner for RegexScanner {
    fn scan(&self, payload: &[u8]) -> Vec<DlpFinding> {
        let text = match std::str::from_utf8(payload) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        for (name, def) in &self.patterns {
            for mat in def.regex.find_iter(text) {
                // Redact the matched text: show first 4 and last 4 chars
                let matched = mat.as_str();
                let redacted = if matched.len() > 12 {
                    format!(
                        "{}...{}",
                        &matched[..4],
                        &matched[matched.len() - 4..]
                    )
                } else {
                    matched.to_string()
                };
                findings.push(DlpFinding {
                    pattern_name: name.clone(),
                    matched_text: redacted,
                    severity: def.severity,
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_openai_api_key() {
        let scanner = RegexScanner::new();
        let payload = b"Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = scanner.scan(payload);
        assert!(!findings.is_empty());
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "openai-api-key")
            .expect("should detect openai-api-key");
        assert_eq!(finding.severity, Severity::Critical);
        // matched_text should be redacted
        assert!(finding.matched_text.contains("..."));
    }

    #[test]
    fn detects_aws_access_key() {
        let scanner = RegexScanner::new();
        let payload = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "aws-access-key")
            .expect("should detect aws-access-key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_email_address() {
        let scanner = RegexScanner::new();
        let payload = b"Send to user@example.com please";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "email-address")
            .expect("should detect email");
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn detects_private_key() {
        let scanner = RegexScanner::new();
        let payload = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "private-key")
            .expect("should detect private key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_github_token() {
        let scanner = RegexScanner::new();
        let payload = b"token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "github-token")
            .expect("should detect github token");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn no_findings_for_clean_payload() {
        let scanner = RegexScanner::new();
        let payload = b"Hello, this is a normal message with no secrets.";
        let findings = scanner.scan(payload);
        assert!(findings.is_empty());
    }

    #[test]
    fn handles_non_utf8_payload() {
        let scanner = RegexScanner::new();
        let payload = &[0xFF, 0xFE, 0x00, 0x01];
        let findings = scanner.scan(payload);
        assert!(findings.is_empty());
    }

    #[test]
    fn with_patterns_filters_correctly() {
        let scanner =
            RegexScanner::with_patterns(&["openai-api-key".to_string(), "email-address".to_string()]);
        // Should have only 2 patterns
        assert_eq!(scanner.patterns.len(), 2);
        assert!(scanner.patterns.contains_key("openai-api-key"));
        assert!(scanner.patterns.contains_key("email-address"));
    }

    #[test]
    fn finding_serializes_to_json() {
        let finding = DlpFinding {
            pattern_name: "test".to_string(),
            matched_text: "sk-a...1234".to_string(),
            severity: Severity::Critical,
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"pattern_name\":\"test\""));
        assert!(json.contains("\"severity\":\"Critical\""));
    }

    #[test]
    fn detects_generic_api_key() {
        let scanner = RegexScanner::new();
        let payload = b"api_key=abcdefghijklmnopqrstuvwxyz";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "generic-api-key")
            .expect("should detect generic api key");
        assert_eq!(finding.severity, Severity::High);
    }
}
