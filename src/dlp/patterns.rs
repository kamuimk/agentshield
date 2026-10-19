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

        // Anthropic API key (sk-ant-api03-..., sk-ant-admin-...)
        // IMPORTANT: Must be inserted before OpenAI to allow scan() to find both,
        // but the OpenAI regex explicitly excludes the sk-ant- prefix.
        patterns.insert(
            "anthropic-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r"sk-ant-(?:api03|admin)[A-Za-z0-9_-]{20,}").unwrap(),
                severity: Severity::Critical,
            },
        );

        // OpenAI API key (sk-..., sk-proj-..., sk-svcacct-..., sk-None-..., sk-admin-...)
        // Note: sk-ant- prefix (Anthropic) is excluded via post-processing in scan(),
        // since Rust regex does not support lookahead.
        patterns.insert(
            "openai-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r"sk-(?:proj-|svcacct-|None-|admin-)?[A-Za-z0-9_-]{20,}")
                    .unwrap(),
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

        // Together AI API key (context-based, alphanumeric 32+)
        patterns.insert(
            "together-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r##"(?i)(?:together[_-]?(?:api[_-]?)?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?"##).unwrap(),
                severity: Severity::Critical,
            },
        );

        // Fireworks AI API key (context-based, no confirmed prefix)
        // Changed from fw_ prefix to context-based detection (Option A from PRD)
        patterns.insert(
            "fireworks-api-key".to_string(),
            PatternDef {
                regex: Regex::new(r##"(?i)(?:fireworks[_-]?(?:api[_-]?)?key)\s*[:=]\s*["']?([A-Za-z0-9_-]{32,})["']?"##).unwrap(),
                severity: Severity::Critical,
            },
        );

        // === Cloud & Infrastructure Keys ===

        // AWS long-term and STS access-key IDs, including case-folded DNS labels.
        patterns.insert(
            "aws-access-key".to_string(),
            PatternDef {
                regex: Regex::new(r"(?i-u:(?:AKIA|ASIA)[0-9A-Z]{16})").unwrap(),
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

        for (name, expression) in [
            (
                "password",
                r#"(?i)(?:password|passwd|client_secret|secret_access_key|session_token)\s*["']?\s*[:=]\s*["']?[^\s"'&,;]{4,}"#,
            ),
            (
                "authorization",
                r"(?im)^authorization:\s*(?:bearer|basic)\s+[^\r\n]{8,}",
            ),
            ("session-cookie", r"(?im)^cookie:\s*[^\r\n]{4,}"),
        ] {
            patterns.insert(
                name.into(),
                PatternDef {
                    regex: Regex::new(expression).unwrap(),
                    severity: Severity::Critical,
                },
            );
        }

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
        // Binary multipart data must not disable inspection of adjacent ASCII keys.
        let mut text = String::from_utf8_lossy(payload).into_owned();
        let decoded = percent_decode(payload);
        if decoded != payload {
            text.push('\n');
            text.push_str(&String::from_utf8_lossy(&decoded));
        }
        // Decode JSON string escapes using the parser, never by executing content.
        let body = payload
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(payload, |offset| &payload[offset + 4..]);
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
            if let Ok(json) = serde_json::to_string(&value) {
                text.push('\n');
                text.push_str(&json);
            }
        }

        // Inspect common transport encodings without executing payload content.
        // Two layers and fixed work/output budgets bound adversarial expansion.
        append_base64_views(&mut text);

        let mut findings = Vec::new();
        for (name, def) in &self.patterns {
            for mat in def.regex.find_iter(&text).take(32) {
                let matched = mat.as_str();

                // Exclude sk-ant- matches from the OpenAI pattern (Anthropic keys).
                // Rust regex lacks lookahead, so we filter here instead.
                if name == "openai-api-key" && matched.starts_with("sk-ant-") {
                    continue;
                }

                // Even a short account value must never become an audit snippet.
                let redacted = "[REDACTED...]".to_string();
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

const MAX_ENCODED_TOKEN: usize = 65_536;
const MAX_DECODED_BYTES: usize = 1_048_576;
const MAX_ENCODED_CANDIDATES: usize = 2_048;

fn append_json_view(input: &[u8], output: &mut Vec<u8>, budget: &mut usize) {
    if *budget == 0
        || !input
            .iter()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|b| matches!(*b, b'{' | b'[' | b'"'))
    {
        return;
    }
    // Each input is one bounded decoded token, not the concatenation of all
    // candidates. Combining tokens first can hide JSON behind unrelated bytes.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(input) {
        if let Ok(json) = serde_json::to_vec(&value) {
            if json != input && json.len() < *budget {
                *budget -= json.len() + 1;
                output.extend_from_slice(&json);
                output.push(b'\n');
            }
        }
    }
}

fn base64_views(input: &[u8], budget: &mut usize, candidates: &mut usize) -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose};
    let mut output = Vec::new();
    let alphabet = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_');
    let mut index = 0;
    while index < input.len() && *budget > 0 && *candidates > 0 {
        if !alphabet(input[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < input.len() && alphabet(input[index]) {
            index += 1;
        }
        while index < input.len() && input[index] == b'=' {
            index += 1;
        }
        let token = &input[start..index];
        if !(8..=MAX_ENCODED_TOKEN).contains(&token.len()) {
            continue;
        }
        *candidates -= 1;
        for engine in [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ] {
            if let Ok(decoded) = engine.decode(token) {
                if decoded.len() + 1 > *budget {
                    break;
                }
                *budget -= decoded.len() + 1;
                output.extend_from_slice(&decoded);
                output.push(b'\n');
                append_json_view(&decoded, &mut output, budget);
                let percent = percent_decode(&decoded);
                if percent != decoded {
                    append_json_view(&percent, &mut output, budget);
                }
                break;
            }
        }
    }
    output
}

fn append_base64_views(text: &mut String) {
    let mut budget = MAX_DECODED_BYTES;
    let mut candidates = MAX_ENCODED_CANDIDATES;
    let mut layer = base64_views(text.as_bytes(), &mut budget, &mut candidates);
    for depth in 0..2 {
        if layer.is_empty() {
            break;
        }
        text.push('\n');
        text.push_str(&String::from_utf8_lossy(&layer));
        let percent = percent_decode(&layer);
        if percent != layer && percent.len() < budget {
            budget -= percent.len() + 1;
            text.push('\n');
            text.push_str(&String::from_utf8_lossy(&percent));
        }
        if depth == 0 {
            layer = base64_views(&percent, &mut budget, &mut candidates);
        }
    }
}

fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = |byte: u8| (byte as char).to_digit(16).map(|value| value as u8);
            if let (Some(a), Some(b)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                output.push(a * 16 + b);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_base64_transport_views_detect_secrets_without_leaking_values() {
        use base64::{Engine as _, engine::general_purpose};
        let scanner = RegexScanner::new();
        let secret = "sk-abcdefghijklmnopqrstuvwxyz1234567890";
        for engine in [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ] {
            let mut binary_secret = vec![0xfb, 0xff];
            binary_secret.extend_from_slice(secret.as_bytes());
            let binary_encoded = engine.encode(&binary_secret);
            assert!(
                scanner
                    .scan(binary_encoded.as_bytes())
                    .iter()
                    .any(|f| f.pattern_name == "openai-api-key")
            );
            let encoded = engine.encode(secret);
            for payload in [
                format!("value={encoded}"),
                format!(r#"{{"file":"{encoded}"}}"#),
                engine.encode(encoded),
            ] {
                let findings = scanner.scan(payload.as_bytes());
                assert!(findings.iter().any(|f| f.pattern_name == "openai-api-key"));
                assert!(findings.iter().all(|f| f.matched_text == "[REDACTED...]"));
            }
        }
        let encoded = general_purpose::STANDARD.encode("sk%2Dabcdefghijklmnopqrstuvwxyz1234567890");
        assert!(
            scanner
                .scan(encoded.as_bytes())
                .iter()
                .any(|f| f.pattern_name == "openai-api-key")
        );
        assert!(
            scanner
                .scan(b"ordinary prose and harmless file metadata")
                .is_empty()
        );
    }

    #[test]
    fn json_escaped_credentials_inside_transport_tokens_are_inspected() {
        use base64::{Engine as _, engine::general_purpose};
        let scanner = RegexScanner::new();
        for (secret, category) in [
            ("sk-abcdefghijklmnopqrstuvwxyz1234567890", "openai-api-key"),
            ("ASIAIOSFODNN7EXAMPLE", "aws-access-key"),
            ("x@y.zz", "email-address"),
        ] {
            let escaped: String = secret.bytes().map(|b| format!("\\u{b:04x}")).collect();
            let json = format!(r#"{{"value":"{escaped}"}}"#);
            let encoded = general_purpose::STANDARD.encode(&json);
            let percent = json.replace('\\', "%5C");
            for payload in [
                encoded.clone(),
                general_purpose::STANDARD.encode(encoded),
                general_purpose::URL_SAFE_NO_PAD.encode(&json),
                general_purpose::STANDARD.encode(percent),
            ] {
                let findings = scanner.scan(format!("transport={payload}").as_bytes());
                assert!(
                    findings.iter().any(|f| f.pattern_name == category),
                    "composed JSON transport was not inspected"
                );
                assert!(findings.iter().all(|f| f.matched_text == "[REDACTED...]"));
            }
        }
    }

    #[test]
    fn short_encoded_account_information_is_not_excluded_by_token_floor() {
        use base64::{Engine as _, engine::general_purpose};
        let scanner = RegexScanner::new();
        // Synthetic local fixture only; no email or DNS request is sent.
        let address = b"x@y.zz";
        let encoded = general_purpose::STANDARD.encode(address);
        assert_eq!(encoded.len(), 8);
        for payload in [encoded.clone(), general_purpose::STANDARD.encode(encoded)] {
            assert!(
                scanner
                    .scan(payload.as_bytes())
                    .iter()
                    .any(|f| f.pattern_name == "email-address")
            );
        }
    }

    #[test]
    fn encoded_view_work_and_output_are_bounded() {
        use base64::{Engine as _, engine::general_purpose};
        let token = general_purpose::STANDARD.encode(vec![b'a'; 48]);
        let input = (token + " ").repeat(100);
        let mut budget = 100;
        let mut candidates = 3;
        let output = base64_views(input.as_bytes(), &mut budget, &mut candidates);
        assert!(output.len() <= 100 && candidates <= 3);
        let huge = vec![b'A'; MAX_ENCODED_TOKEN + 1];
        assert!(base64_views(&huge, &mut budget, &mut candidates).is_empty());
    }

    #[test]
    fn decoded_json_views_share_the_transport_output_budget() {
        use base64::{Engine as _, engine::general_purpose};
        let json = br#"{"value":"x\u0040y.zz"}"#;
        let encoded = general_purpose::STANDARD.encode(json);
        for limit in [0, json.len(), json.len() + 1, 256] {
            let mut budget = limit;
            let mut candidates = 1;
            let output = base64_views(encoded.as_bytes(), &mut budget, &mut candidates);
            assert!(output.len() <= limit);
            assert_eq!(output.len() + budget, limit);
            if limit == 256 {
                assert!(String::from_utf8_lossy(&output).contains("x@y.zz"));
            }
        }
    }

    #[test]
    fn binary_percent_encoded_and_json_escaped_credentials_are_inspected() {
        let scanner = RegexScanner::new();
        for payload in [
            b"\xff\0sk-abcdefghijklmnopqrstuvwxyz1234567890".as_slice(),
            b"key=sk%2Dabcdefghijklmnopqrstuvwxyz1234567890".as_slice(),
            br#"{"value":"sk\u002dabcdefghijklmnopqrstuvwxyz1234567890"}"#.as_slice(),
        ] {
            assert!(
                scanner
                    .scan(payload)
                    .iter()
                    .any(|finding| finding.pattern_name == "openai-api-key")
            );
        }
        let findings = scanner.scan(b"password=shortsecret\r\nAuthorization: Bearer synthetic-access-value\r\nCookie: session=synthetic-value");
        for name in ["password", "authorization", "session-cookie"] {
            assert!(findings.iter().any(|finding| finding.pattern_name == name));
        }
        assert!(
            findings
                .iter()
                .all(|finding| finding.matched_text == "[REDACTED...]")
        );
    }

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
    fn detects_aws_static_and_temporary_keys_after_hostname_case_folding() {
        let scanner = RegexScanner::new();
        for key in [
            "AKIAIOSFODNN7EXAMPLE",
            "akiaiosfodnn7example",
            "ASIAIOSFODNN7EXAMPLE",
            "asiaiosfodnn7example",
        ] {
            let findings = scanner.scan(format!("{key}.example.test").as_bytes());
            assert!(findings.iter().any(|f| f.pattern_name == "aws-access-key" && f.severity == Severity::Critical),
                    "AWS synthetic hostname credential was not classified");
        }
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
        // Context-based: FIREWORKS_API_KEY=<value>
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

    // === R5: Updated pattern tests ===

    #[test]
    fn detects_openai_none_key() {
        let scanner = RegexScanner::new();
        let payload = b"Authorization: Bearer sk-None-abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "openai-api-key")
            .expect("should detect openai sk-None- key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_openai_admin_key() {
        let scanner = RegexScanner::new();
        let payload = b"Authorization: Bearer sk-admin-abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "openai-api-key")
            .expect("should detect openai sk-admin- key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn anthropic_key_not_detected_as_openai() {
        let scanner = RegexScanner::new();
        let payload = b"x-api-key: sk-ant-admin01-abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = scanner.scan(payload);
        // Should be detected as anthropic, NOT openai
        let anthropic = findings
            .iter()
            .find(|f| f.pattern_name == "anthropic-api-key");
        assert!(anthropic.is_some(), "should detect as anthropic key");
        // Should NOT match openai pattern (sk-ant- prefix is anthropic-specific)
        let openai = findings.iter().find(|f| f.pattern_name == "openai-api-key");
        assert!(
            openai.is_none(),
            "sk-ant-admin should NOT be detected as openai key"
        );
    }

    #[test]
    fn detects_fireworks_context_key() {
        let scanner = RegexScanner::new();
        let payload = b"FIREWORKS_API_KEY=abcdefghijklmnopqrstuvwxyz123456789012345678";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "fireworks-api-key")
            .expect("should detect fireworks context-based key");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn detects_together_alphanumeric_key() {
        let scanner = RegexScanner::new();
        let payload = b"TOGETHER_API_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz012345678901";
        let findings = scanner.scan(payload);
        let finding = findings
            .iter()
            .find(|f| f.pattern_name == "together-api-key")
            .expect("should detect together alphanumeric key");
        assert_eq!(finding.severity, Severity::Critical);
    }
}
