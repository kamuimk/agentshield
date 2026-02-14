//! Terminal-based ASK responder (stdin/stdout).
//!
//! This module wraps the existing interactive prompt logic from
//! [`cli::prompt`](crate::cli::prompt) into an [`AskResponder`] implementation.
//! It serializes ASK requests through an internal channel so that only one
//! prompt is active at a time.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};

use super::{AskRequestInfo, AskResponder};
use crate::cli::prompt::{
    PromptDecision, PromptRequest, append_rule_to_config, generate_rule, handle_inspect,
    prompt_decision,
};

/// ASK responder that prompts the user via terminal stdin/stdout.
///
/// Created by [`TerminalResponder::new`], which spawns a background task
/// reading from stdin. Requests are serialized so only one prompt is active.
pub struct TerminalResponder {
    tx: mpsc::Sender<(AskRequestInfo, oneshot::Sender<Option<bool>>)>,
}

impl TerminalResponder {
    /// Create a new terminal responder.
    ///
    /// Spawns a background tokio task that processes ASK requests one at a time
    /// via stdin/stdout. `config_path` is used for the "Add Rule" action.
    pub fn new(config_path: PathBuf) -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self::spawn_stdin_handler(rx, config_path);
        Self { tx }
    }

    /// Spawn the background stdin handler task.
    fn spawn_stdin_handler(
        mut rx: mpsc::Receiver<(AskRequestInfo, oneshot::Sender<Option<bool>>)>,
        config_path: PathBuf,
    ) {
        tokio::spawn(async move {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();

            while let Some((info, reply_tx)) = rx.recv().await {
                let prompt_req = PromptRequest {
                    method: info.method,
                    domain: info.domain,
                    path: info.path,
                    body: info.body,
                };
                let mut reader = stdin.lock();
                let mut writer = stdout.lock();

                let result =
                    handle_prompt_loop(&prompt_req, &config_path, &mut reader, &mut writer);
                let _ = reply_tx.send(result);
            }
        });
    }
}

#[async_trait::async_trait]
impl AskResponder for TerminalResponder {
    async fn prompt(&self, req: &AskRequestInfo) -> Option<bool> {
        let (tx, rx) = oneshot::channel();
        if self.tx.send((req.clone(), tx)).await.is_ok() {
            rx.await.ok().flatten()
        } else {
            None // channel closed
        }
    }

    async fn notify_resolved(&self, _req_id: &str, _allowed: bool) {
        // Terminal doesn't need UI updates after resolution by another responder
    }

    fn name(&self) -> &str {
        "terminal"
    }
}

/// Run the interactive prompt loop (inspect → re-prompt, allow/deny/add-rule → return).
///
/// Extracted as a free function for testability with generic reader/writer.
fn handle_prompt_loop<R: BufRead, W: Write>(
    req: &PromptRequest,
    config_path: &std::path::Path,
    reader: &mut R,
    writer: &mut W,
) -> Option<bool> {
    loop {
        match prompt_decision(req, reader, writer) {
            Ok(PromptDecision::Inspect) => {
                handle_inspect(req, writer).ok();
                continue;
            }
            Ok(PromptDecision::AllowOnce) => return Some(true),
            Ok(PromptDecision::AddRule) => {
                let rule = generate_rule(req);
                match append_rule_to_config(config_path, &rule) {
                    Ok(()) => {
                        writeln!(
                            writer,
                            "Rule '{}' added to config (effective next restart)",
                            rule.name
                        )
                        .ok();
                    }
                    Err(e) => {
                        tracing::warn!("Failed to append rule: {}", e);
                    }
                }
                return Some(true);
            }
            Ok(PromptDecision::Deny) => return Some(false),
            Err(_) => return Some(false), // I/O error → deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn terminal_prompt_allow() {
        let req = sample_request();
        let mut input = Cursor::new(b"a\n");
        let mut output = Vec::new();
        let result = handle_prompt_loop(
            &req,
            std::path::Path::new("/tmp/noop.toml"),
            &mut input,
            &mut output,
        );
        assert_eq!(result, Some(true));
    }

    #[test]
    fn terminal_prompt_deny() {
        let req = sample_request();
        let mut input = Cursor::new(b"d\n");
        let mut output = Vec::new();
        let result = handle_prompt_loop(
            &req,
            std::path::Path::new("/tmp/noop.toml"),
            &mut input,
            &mut output,
        );
        assert_eq!(result, Some(false));
    }

    #[test]
    fn terminal_prompt_unknown_defaults_deny() {
        let req = sample_request();
        let mut input = Cursor::new(b"xyz\n");
        let mut output = Vec::new();
        let result = handle_prompt_loop(
            &req,
            std::path::Path::new("/tmp/noop.toml"),
            &mut input,
            &mut output,
        );
        assert_eq!(result, Some(false));
    }

    #[test]
    fn terminal_prompt_inspect_then_allow() {
        let req = sample_request();
        let mut input = Cursor::new(b"i\na\n");
        let mut output = Vec::new();
        let result = handle_prompt_loop(
            &req,
            std::path::Path::new("/tmp/noop.toml"),
            &mut input,
            &mut output,
        );
        assert_eq!(result, Some(true));
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("Request Payload")); // inspect output shown
    }

    #[test]
    fn terminal_prompt_add_rule() {
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

        let req = sample_request();
        let mut input = Cursor::new(b"r\n");
        let mut output = Vec::new();
        let result = handle_prompt_loop(&req, &config_path, &mut input, &mut output);
        assert_eq!(result, Some(true));

        // Verify rule was appended
        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("auto-api-github-com"));
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("added to config"));
    }

    #[tokio::test]
    async fn terminal_responder_name() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("test.toml");
        std::fs::write(&config_path, "").unwrap();
        let responder = TerminalResponder::new(config_path);
        assert_eq!(responder.name(), "terminal");
    }
}
