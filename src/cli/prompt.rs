//! Interactive approval prompt for ASK policy actions.
//!
//! When a policy rule evaluates to [`Action::Ask`],
//! the proxy sends an [`AskRequest`] through an async channel to the main thread,
//! which displays a TUI prompt via [`prompt_decision`] and returns the user's choice.
//!
//! The prompt supports four actions:
//! - **Allow once** — permit this single request
//! - **Add rule** — auto-generate a permanent allow rule and append to config
//! - **Deny** — block the request
//! - **Inspect** — view the request payload before deciding

use std::io::{BufRead, Write};
use std::path::Path;

use tokio::sync::oneshot;

use crate::error::Result;

use crate::policy::config::{Action, Rule};

/// The user's decision from the interactive approval prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptDecision {
    /// Allow this single request without creating a persistent rule.
    AllowOnce,
    /// Allow and auto-generate a persistent allow rule in the config file.
    AddRule,
    /// Block the request (default for unknown input — fail-closed).
    Deny,
    /// Display the request payload for inspection before deciding.
    Inspect,
}

/// Information about the request being prompted to the user.
#[derive(Debug, Clone)]
pub struct PromptRequest {
    /// HTTP method (e.g., `"POST"`).
    pub method: String,
    /// Target domain (e.g., `"api.github.com"`).
    pub domain: String,
    /// Request path (e.g., `"/repos/user/repo/pulls"`).
    pub path: String,
    /// Optional request body for inspection.
    pub body: Option<String>,
}

/// A request sent from the proxy to the CLI thread for interactive approval.
///
/// Contains a oneshot channel for returning the boolean decision (true = allow).
pub struct AskRequest {
    /// Target domain.
    pub domain: String,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Optional request body for inspection (HTTP only; `None` for CONNECT).
    pub body: Option<String>,
    /// Channel to send the approval decision back to the proxy.
    response_tx: oneshot::Sender<bool>,
}

impl AskRequest {
    /// Create a new ASK request and return the receiver for the response.
    pub fn new(
        domain: String,
        method: String,
        path: String,
        body: Option<String>,
    ) -> (Self, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                domain,
                method,
                path,
                body,
                response_tx: tx,
            },
            rx,
        )
    }

    /// Send the approval decision back to the proxy.
    pub fn respond(self, allowed: bool) {
        // Ignore error if receiver was dropped
        let _ = self.response_tx.send(allowed);
    }
}

/// Display the approval prompt and return the user's decision.
/// Uses the provided reader/writer for testability.
pub fn prompt_decision<R: BufRead, W: Write>(
    req: &PromptRequest,
    reader: &mut R,
    writer: &mut W,
) -> Result<PromptDecision> {
    writeln!(writer)?;
    writeln!(writer, "┌────────────────────────────────────────────────┐")?;
    writeln!(
        writer,
        "│  AgentShield: New outbound request              │"
    )?;
    writeln!(writer, "├────────────────────────────────────────────────┤")?;
    writeln!(writer, "│  {} {}{}", req.method, req.domain, req.path)?;
    writeln!(writer, "│                                                │")?;
    writeln!(writer, "│  [a] Allow once                                │")?;
    writeln!(writer, "│  [r] Add rule (always allow this pattern)      │")?;
    writeln!(writer, "│  [d] Deny                                      │")?;
    writeln!(writer, "│  [i] Inspect payload                           │")?;
    writeln!(writer, "└────────────────────────────────────────────────┘")?;
    write!(writer, "Choice: ")?;
    writer.flush()?;

    let mut input = String::new();
    reader.read_line(&mut input)?;
    let choice = input.trim().to_lowercase();

    match choice.as_str() {
        "a" => Ok(PromptDecision::AllowOnce),
        "r" => Ok(PromptDecision::AddRule),
        "d" => Ok(PromptDecision::Deny),
        "i" => Ok(PromptDecision::Inspect),
        _ => Ok(PromptDecision::Deny), // default to deny for safety
    }
}

/// Generate a new rule from a prompt request.
pub fn generate_rule(req: &PromptRequest) -> Rule {
    let rule_name = format!("auto-{}", req.domain.replace('.', "-"));
    Rule {
        name: rule_name,
        domains: vec![req.domain.clone()],
        methods: Some(vec![req.method.clone()]),
        action: Action::Allow,
        note: Some("Auto-generated from approval prompt".to_string()),
    }
}

/// Append a rule to an existing TOML config file.
pub fn append_rule_to_config(config_path: &Path, rule: &Rule) -> Result<()> {
    let mut content = std::fs::read_to_string(config_path)?;

    let methods_str = match &rule.methods {
        Some(methods) => {
            let quoted: Vec<String> = methods.iter().map(|m| format!("\"{}\"", m)).collect();
            format!("\nmethods = [{}]", quoted.join(", "))
        }
        None => String::new(),
    };

    let note_str = match &rule.note {
        Some(note) => format!("\nnote = \"{}\"", note),
        None => String::new(),
    };

    let domains_quoted: Vec<String> = rule.domains.iter().map(|d| format!("\"{}\"", d)).collect();

    let rule_toml = format!(
        "\n\n[[policy.rules]]\nname = \"{}\"\ndomains = [{}]\naction = \"{}\"{}{}",
        rule.name,
        domains_quoted.join(", "),
        match rule.action {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Ask => "ask",
        },
        methods_str,
        note_str,
    );

    content.push_str(&rule_toml);
    std::fs::write(config_path, content)?;
    Ok(())
}

/// Maximum bytes to display when inspecting a request body.
const MAX_BODY_DISPLAY: usize = 4096;

/// Handle the inspect action: display the request body with truncation.
pub fn handle_inspect<W: Write>(req: &PromptRequest, writer: &mut W) -> Result<()> {
    writeln!(writer, "\n--- Request Payload ---")?;
    match &req.body {
        Some(body) if body.len() > MAX_BODY_DISPLAY => {
            writeln!(
                writer,
                "{} ... (truncated, showing {}/{} bytes)",
                &body[..MAX_BODY_DISPLAY],
                MAX_BODY_DISPLAY,
                body.len()
            )?;
        }
        Some(body) => writeln!(writer, "{}", body)?,
        None => writeln!(writer, "(no body available)")?,
    }
    writeln!(writer, "--- End Payload ---\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::config::AppConfig;
    use std::io::Cursor;

    fn sample_request() -> PromptRequest {
        PromptRequest {
            method: "POST".to_string(),
            domain: "api.github.com".to_string(),
            path: "/repos/user/repo/pulls".to_string(),
            body: Some("{\"title\": \"test PR\"}".to_string()),
        }
    }

    #[test]
    fn prompt_allow_once() {
        let req = sample_request();
        let mut input = Cursor::new(b"a\n");
        let mut output = Vec::new();
        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::AllowOnce);
    }

    #[test]
    fn prompt_add_rule() {
        let req = sample_request();
        let mut input = Cursor::new(b"r\n");
        let mut output = Vec::new();
        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::AddRule);
    }

    #[test]
    fn prompt_deny() {
        let req = sample_request();
        let mut input = Cursor::new(b"d\n");
        let mut output = Vec::new();
        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::Deny);
    }

    #[test]
    fn prompt_inspect() {
        let req = sample_request();
        let mut input = Cursor::new(b"i\n");
        let mut output = Vec::new();
        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::Inspect);
    }

    #[test]
    fn prompt_unknown_defaults_to_deny() {
        let req = sample_request();
        let mut input = Cursor::new(b"x\n");
        let mut output = Vec::new();
        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::Deny);
    }

    #[test]
    fn prompt_displays_request_info() {
        let req = sample_request();
        let mut input = Cursor::new(b"d\n");
        let mut output = Vec::new();
        prompt_decision(&req, &mut input, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("POST"));
        assert!(output_str.contains("api.github.com"));
        assert!(output_str.contains("/repos/user/repo/pulls"));
    }

    #[test]
    fn generate_rule_from_request() {
        let req = sample_request();
        let rule = generate_rule(&req);
        assert_eq!(rule.name, "auto-api-github-com");
        assert_eq!(rule.domains, vec!["api.github.com"]);
        assert_eq!(rule.methods.as_ref().unwrap(), &vec!["POST".to_string()]);
        assert_eq!(rule.action, Action::Allow);
    }

    #[test]
    fn append_rule_to_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agentshield.toml");
        std::fs::write(
            &config_path,
            r#"[proxy]
listen = "127.0.0.1:18080"
mode = "transparent"

[policy]
default = "deny"
"#,
        )
        .unwrap();

        let rule = generate_rule(&sample_request());
        append_rule_to_config(&config_path, &rule).unwrap();

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("[[policy.rules]]"));
        assert!(content.contains("auto-api-github-com"));
        assert!(content.contains("api.github.com"));

        // Verify it's still valid TOML
        let config: AppConfig = toml::from_str(&content).unwrap();
        assert_eq!(config.policy.rules.len(), 1);
        assert_eq!(config.policy.rules[0].name, "auto-api-github-com");
    }

    #[test]
    fn handle_inspect_with_body() {
        let req = sample_request();
        let mut output = Vec::new();
        handle_inspect(&req, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("test PR"));
    }

    #[test]
    fn ask_request_with_body() {
        let (req, _rx) = AskRequest::new(
            "api.github.com".into(),
            "POST".into(),
            "/repos".into(),
            Some("{\"title\":\"PR\"}".into()),
        );
        assert_eq!(req.domain, "api.github.com");
        assert_eq!(req.body, Some("{\"title\":\"PR\"}".into()));
    }

    #[test]
    fn ask_request_without_body() {
        let (req, _rx) = AskRequest::new("example.com".into(), "CONNECT".into(), "/".into(), None);
        assert_eq!(req.body, None);
    }

    #[test]
    fn handle_inspect_without_body() {
        let req = PromptRequest {
            method: "GET".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            body: None,
        };
        let mut output = Vec::new();
        handle_inspect(&req, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("no body available"));
    }

    #[test]
    fn handle_inspect_truncates_large_body() {
        let large_body = "x".repeat(5000);
        let req = PromptRequest {
            method: "POST".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            body: Some(large_body),
        };
        let mut output = Vec::new();
        handle_inspect(&req, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        // Should contain truncation indicator
        assert!(output_str.contains("truncated"));
        // Should NOT contain the full 5000 chars
        assert!(output_str.len() < 5000);
    }

    #[test]
    fn handle_inspect_does_not_truncate_small_body() {
        let small_body = "x".repeat(2000);
        let req = PromptRequest {
            method: "POST".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            body: Some(small_body.clone()),
        };
        let mut output = Vec::new();
        handle_inspect(&req, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(!output_str.contains("truncated"));
        assert!(output_str.contains(&small_body));
    }

    #[test]
    fn inspect_then_allow_sequence() {
        let req = sample_request();
        // Simulate: user types "i" (inspect), then "a" (allow)
        let mut input = Cursor::new(b"i\na\n");
        let mut output = Vec::new();

        // First prompt → inspect
        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::Inspect);

        // Show inspect output
        handle_inspect(&req, &mut output).unwrap();

        // Second prompt → allow
        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::AllowOnce);
    }

    #[test]
    fn inspect_then_deny_sequence() {
        let req = sample_request();
        // Simulate: user types "i" (inspect), then "d" (deny)
        let mut input = Cursor::new(b"i\nd\n");
        let mut output = Vec::new();

        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::Inspect);

        handle_inspect(&req, &mut output).unwrap();

        let decision = prompt_decision(&req, &mut input, &mut output).unwrap();
        assert_eq!(decision, PromptDecision::Deny);
    }

    #[test]
    fn add_rule_generates_valid_config_with_methods() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agentshield.toml");
        std::fs::write(
            &config_path,
            r#"[proxy]
listen = "127.0.0.1:18080"
mode = "transparent"

[policy]
default = "deny"
"#,
        )
        .unwrap();

        // Simulate AddRule flow: generate → append → reload
        let req = PromptRequest {
            method: "PUT".to_string(),
            domain: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            body: None,
        };
        let rule = generate_rule(&req);
        assert_eq!(rule.methods.as_ref().unwrap(), &vec!["PUT".to_string()]);

        append_rule_to_config(&config_path, &rule).unwrap();

        // Reload and verify
        let config: AppConfig =
            toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(config.policy.rules.len(), 1);
        assert_eq!(config.policy.rules[0].name, "auto-api-openai-com");
        assert_eq!(config.policy.rules[0].domains, vec!["api.openai.com"]);
        assert_eq!(config.policy.rules[0].action, Action::Allow);
    }
}
