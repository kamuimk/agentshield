//! Regex-based DLP pattern scanner.
//!
//! Ships with built-in patterns for detecting common secrets and credentials:
//!
//! | Category | Patterns |
//! |----------|----------|
//! | AI Provider Keys | OpenAI, Anthropic, Google AI, HuggingFace, Cohere, Replicate, Mistral, Groq, Together, Fireworks |
//! | Cloud Keys | AWS Access Key |
//! | Generic | `api_key=...` patterns |
//! | Credentials | Private key headers, GitHub PAT |
//! | PII | Email addresses |
//!
//! All matched text is automatically **redacted** in findings (first 4 + last 4 chars)
//! to avoid leaking secrets in logs.

use std::collections::HashMap;

use regex::Regex;

use super::{DlpFinding, DlpScanner, Severity};

/// Internal pattern definition pairing a compiled regex with its severity.
struct PatternDef {
    regex: Regex,
    severity: Severity,
}

/// A DLP scanner that matches request payloads against a set of regex patterns.
///
/// Use [`RegexScanner::new()`] for all built-in patterns, or
/// [`RegexScanner::with_patterns()`] for a specific subset.
pub struct RegexScanner {
    patterns: HashMap<String, PatternDef>,
}

impl RegexScanner {
    /// Create a new `RegexScanner` with all built-in patterns.
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        // === AI Provider API Keys ===

        // OpenAI API key (sk-..., sk-proj-..., sk-svcacct-...)
        patterns.insert(
            "openai-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // Anthropic API key (sk-ant-api03-...)
        patterns.insert(
            "anthropic-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r"sk-ant-(?:api03|admin)[A-Za-z0-9_-]{20,}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // Google AI / Gemini API key (AIzaSy...)
        patterns.insert(
            "google-ai-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r"AIzaSy[A-Za-z0-9_-]{33}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // HuggingFace API token (hf_...)
        patterns.insert(
            "huggingface-token".to_string(),
            PatternDef {
                regex: Regex::new(r"hf_[A-Za-z0-9]{20,}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // Cohere API key (v2 format, 40-char alphanumeric)
        patterns.insert(
            "cohere-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r##"(?i)(?:cohere[_-]?(?:api[_-]?)?key|co[_-]api[_-]key)\s*[:=]\s*["']?([A-Za-z0-9]{40})["']?"##).unwrap(),
                severity: Severity::Critical,
            },
        );

        // Replicate API token (r8_...)
        patterns.insert(
            "replicate-api-token".to_string(),
            PatternDef {
                regex: Regex::new(r"r8_[A-Za-z0-9]{20,}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // Mistral API key (no fixed prefix, context-based detection)
        patterns.insert(
            "mistral-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r##"(?i)(?:mistral[_-]?(?:api[_-]?)?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?"##).unwrap(),
                severity: Severity::Critical,
            },
        );

        // Groq API key (gsk_...)
        patterns.insert(
            "groq-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r"gsk_[A-Za-z0-9]{20,}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // Together AI API key
        patterns.insert(
            "together-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r##"(?i)(?:together[_-]?(?:api[_-]?)?key)\s*[:=]\s*["']?([A-Fa-f0-9]{64})["']?"##).unwrap(),
                severity: Severity::Critical,
            },
        );

        // Fireworks AI API key (fw_...)
        patterns.insert(
            "fireworks-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r"fw_[A-Za-z0-9]{20,}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // === Cloud & Infrastructure Keys ===

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
                regex: Regex::new(
                    r##"(?i)(api[_-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?"##,
                )
                .unwrap(),
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

    /// Create a `RegexScanner` with only the specified pattern names (subset of built-in).
    ///
    /// Patterns not found in the built-in set are silently ignored.
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
                    format!("{}...{}", &matched[..4], &matched[matched.len() - 4..])
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
        let scanner = RegexScanner::with_patterns(&[
            "openai-api-key".to_string(),
            "email-address".to_string(),
        ]);
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

    // === AI Provider Key Tests ===

    #[test]
    fn detects_anthropic_api_key() {
        let scanner = RegexScanner::new();
        let payload = b"x-api-key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "anthropic-api-key")
            .expect("should detect anthropic api key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_anthropic_admin_key() {
        let scanner = RegexScanner::new();
        let payload = b"x-api-key: sk-ant-admin01-abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "anthropic-api-key")
            .expect("should detect anthropic admin key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_google_ai_api_key() {
        let scanner = RegexScanner::new();
        let payload = b"key=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "google-ai-api-key")
            .expect("should detect google ai api key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_huggingface_token() {
        let scanner = RegexScanner::new();
        // Build token at runtime to avoid GitHub push protection false positive
        let token = format!(
            "Authorization: Bearer {}{}",
            "hf_", "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQ"
        );
        let findings = scanner.scan(token.as_bytes());
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "huggingface-token")
            .expect("should detect huggingface token");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_replicate_api_token() {
        let scanner = RegexScanner::new();
        let payload = b"REPLICATE_API_TOKEN=r8_ABCDEFGHIJKLMNOPQRSTUVWXYZab";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "replicate-api-token")
            .expect("should detect replicate api token");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_groq_api_key() {
        let scanner = RegexScanner::new();
        let payload = b"Authorization: Bearer gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "groq-api-key")
            .expect("should detect groq api key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_fireworks_api_key() {
        let scanner = RegexScanner::new();
        let payload = b"FIREWORKS_API_KEY=fw_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "fireworks-api-key")
            .expect("should detect fireworks api key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_cohere_api_key() {
        let scanner = RegexScanner::new();
        let payload = b"cohere_api_key=abcdefghijABCDEFGHIJabcdefghijABCDEFGHIJ";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "cohere-api-key")
            .expect("should detect cohere api key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_mistral_api_key() {
        let scanner = RegexScanner::new();
        let payload = b"MISTRAL_API_KEY=abcdefghijklmnopqrstuvwxyz123456789012";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "mistral-api-key")
            .expect("should detect mistral api key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_openai_project_key() {
        let scanner = RegexScanner::new();
        let payload = b"Authorization: Bearer sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "openai-api-key")
            .expect("should detect openai project api key");
        assert_eq!(finding.severity, Severity::Critical);
    }
}
