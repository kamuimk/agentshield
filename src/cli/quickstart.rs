use std::io::{BufRead, Write};
use std::path::Path;

use crate::cli::wrap::{DetectedAgent, template_content};

/// Result of the interactive quickstart wizard.
#[derive(Debug, Clone, PartialEq)]
pub struct QuickstartConfig {
    pub agent: DetectedAgent,
    pub template_name: String,
    pub mitm: bool,
    pub dashboard: bool,
    pub port: u16,
}

/// Display numbered options and return the user's choice (0-based index).
///
/// Shows `[default + 1]` as the default selection. Empty input returns `default`.
/// Out-of-range input triggers a retry.
pub fn prompt_choice<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
    options: &[&str],
    default: usize,
) -> anyhow::Result<usize> {
    loop {
        writeln!(writer, "\n{}", question)?;
        for (i, option) in options.iter().enumerate() {
            writeln!(writer, "  {}) {}", i + 1, option)?;
        }
        write!(writer, "Select [{}]: ", default + 1)?;
        writer.flush()?;

        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            return Ok(default);
        }

        if let Ok(n) = trimmed.parse::<usize>() {
            if n >= 1 && n <= options.len() {
                return Ok(n - 1);
            }
        }

        writeln!(writer, "Invalid choice. Please enter 1-{}.", options.len())?;
    }
}

/// Prompt for a yes/no answer. Returns `default` on empty input.
pub fn prompt_yes_no<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
    default: bool,
) -> anyhow::Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    write!(writer, "{} [{}]: ", question, hint)?;
    writer.flush()?;

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let trimmed = line.trim().to_lowercase();

    if trimmed.is_empty() {
        return Ok(default);
    }

    match trimmed.as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Ok(default),
    }
}

/// Prompt for a text string. Returns `default` on empty input.
pub fn prompt_string<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
    default: &str,
) -> anyhow::Result<String> {
    write!(writer, "{} [{}]: ", question, default)?;
    writer.flush()?;

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let trimmed = line.trim();

    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Run the interactive quickstart wizard, collecting user preferences.
pub fn run_quickstart_wizard<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> anyhow::Result<QuickstartConfig> {
    writeln!(writer, "=== AgentShield Quickstart ===")?;

    // 1. Agent selection
    let agent_options = ["Claude Code", "OpenClaw", "Aider", "Codex", "Other"];
    let agent_idx = prompt_choice(
        reader,
        writer,
        "Which AI agent do you use?",
        &agent_options,
        0,
    )?;
    let agent = match agent_idx {
        0 => DetectedAgent::ClaudeCode,
        1 => DetectedAgent::OpenClaw,
        2 => DetectedAgent::Aider,
        3 => DetectedAgent::Codex,
        _ => DetectedAgent::Unknown,
    };
    let template_name = agent.template_name().to_string();

    // 2. MITM TLS interception
    let mitm = prompt_yes_no(
        reader,
        writer,
        "Enable MITM TLS interception? (scans HTTPS request bodies)",
        false,
    )?;

    // 3. Web dashboard
    let dashboard = prompt_yes_no(reader, writer, "Enable web dashboard?", true)?;

    // 4. Port
    let port_str = prompt_string(reader, writer, "Proxy port", "18080")?;
    let port: u16 = port_str.parse().unwrap_or(18080);

    Ok(QuickstartConfig {
        agent,
        template_name,
        mitm,
        dashboard,
        port,
    })
}

/// Generate a TOML configuration string from the quickstart settings.
///
/// Starts from the agent's built-in template and applies overrides for
/// port, proxy mode, and web dashboard.
pub fn generate_config_toml(qc: &QuickstartConfig) -> anyhow::Result<String> {
    let base = template_content(&qc.template_name)
        .ok_or_else(|| anyhow::anyhow!("Unknown template: {}", qc.template_name))?;

    let mut doc: toml::Table = toml::from_str(base)?;

    // Override proxy settings
    let proxy = doc
        .entry("proxy")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("Invalid [proxy] section"))?;
    proxy.insert(
        "listen".to_string(),
        toml::Value::String(format!("127.0.0.1:{}", qc.port)),
    );
    if qc.mitm {
        proxy.insert("mode".to_string(), toml::Value::String("mitm".to_string()));
    } else {
        proxy.insert(
            "mode".to_string(),
            toml::Value::String("transparent".to_string()),
        );
    }

    // Override web dashboard
    if qc.dashboard {
        let web = doc
            .entry("web")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("Invalid [web] section"))?;
        web.insert("enabled".to_string(), toml::Value::Boolean(true));
        web.entry("listen")
            .or_insert_with(|| toml::Value::String("127.0.0.1:18081".to_string()));
    } else if let Some(web) = doc.get_mut("web").and_then(|v| v.as_table_mut()) {
        web.insert("enabled".to_string(), toml::Value::Boolean(false));
    }

    let toml_str = toml::to_string_pretty(&doc)?;
    Ok(toml_str)
}

/// Run the full quickstart flow: wizard → generate config → write file → print next steps.
///
/// CA generation and DB initialization are left to the caller (main.rs),
/// because `db_path()` / `dirs_path()` live in the binary crate.
/// Returns the resulting [`QuickstartConfig`] so the caller can act on `mitm`, etc.
pub fn cmd_quickstart<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    config_path: &Path,
) -> anyhow::Result<QuickstartConfig> {
    let qc = run_quickstart_wizard(reader, writer)?;

    // Check existing file
    if config_path.exists() {
        let overwrite = prompt_yes_no(
            reader,
            writer,
            &format!("{} already exists. Overwrite?", config_path.display()),
            false,
        )?;
        if !overwrite {
            writeln!(writer, "Aborted.")?;
            return Ok(qc);
        }
    }

    let toml_str = generate_config_toml(&qc)?;
    std::fs::write(config_path, &toml_str)?;
    writeln!(writer, "\nConfig written to {}", config_path.display())?;

    // Next steps
    let agent_name = match qc.agent {
        DetectedAgent::ClaudeCode => "claude",
        DetectedAgent::OpenClaw => "openclaw",
        DetectedAgent::Aider => "aider",
        DetectedAgent::Codex => "codex",
        DetectedAgent::Unknown => "<your-agent>",
    };
    writeln!(writer, "\nDone! Next steps:")?;
    writeln!(
        writer,
        "  agentshield wrap{} -- {}",
        if qc.mitm { " --mitm" } else { "" },
        agent_name,
    )?;
    if qc.dashboard {
        writeln!(
            writer,
            "  Open http://127.0.0.1:18081 for the web dashboard."
        )?;
    }

    Ok(qc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn mock_io(input: &str) -> (Cursor<Vec<u8>>, Vec<u8>) {
        (Cursor::new(input.as_bytes().to_vec()), Vec::new())
    }

    // --- prompt_choice tests ---

    #[test]
    fn prompt_choice_valid_selection() {
        let (mut r, mut w) = mock_io("2\n");
        let result = prompt_choice(&mut r, &mut w, "Pick:", &["A", "B", "C"], 0).unwrap();
        assert_eq!(result, 1); // 0-based index for "B"
    }

    #[test]
    fn prompt_choice_default_on_empty() {
        let (mut r, mut w) = mock_io("\n");
        let result = prompt_choice(&mut r, &mut w, "Pick:", &["A", "B"], 1).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn prompt_choice_retry_then_valid() {
        // First "9" is out of range, then "1" is valid
        let (mut r, mut w) = mock_io("9\n1\n");
        let result = prompt_choice(&mut r, &mut w, "Pick:", &["A", "B"], 0).unwrap();
        assert_eq!(result, 0);
    }

    // --- prompt_yes_no tests ---

    #[test]
    fn prompt_yes_no_yes() {
        let (mut r, mut w) = mock_io("y\n");
        let result = prompt_yes_no(&mut r, &mut w, "Continue?", false).unwrap();
        assert!(result);
    }

    #[test]
    fn prompt_yes_no_no() {
        let (mut r, mut w) = mock_io("n\n");
        let result = prompt_yes_no(&mut r, &mut w, "Continue?", true).unwrap();
        assert!(!result);
    }

    #[test]
    fn prompt_yes_no_default() {
        let (mut r, mut w) = mock_io("\n");
        let result = prompt_yes_no(&mut r, &mut w, "Continue?", true).unwrap();
        assert!(result);
    }

    // --- prompt_string tests ---

    #[test]
    fn prompt_string_custom_value() {
        let (mut r, mut w) = mock_io("9090\n");
        let result = prompt_string(&mut r, &mut w, "Port", "18080").unwrap();
        assert_eq!(result, "9090");
    }

    #[test]
    fn prompt_string_default() {
        let (mut r, mut w) = mock_io("\n");
        let result = prompt_string(&mut r, &mut w, "Port", "18080").unwrap();
        assert_eq!(result, "18080");
    }

    // --- run_quickstart_wizard tests ---

    #[test]
    fn wizard_claude_with_mitm() {
        // Agent=1(Claude), MITM=y, Dashboard=default(Y), Port=default(18080)
        let input = "1\ny\n\n\n";
        let (mut r, mut w) = mock_io(input);
        let qc = run_quickstart_wizard(&mut r, &mut w).unwrap();
        assert_eq!(qc.agent, DetectedAgent::ClaudeCode);
        assert_eq!(qc.template_name, "claude-code-default");
        assert!(qc.mitm);
        assert!(qc.dashboard);
        assert_eq!(qc.port, 18080);
    }

    #[test]
    fn wizard_openclaw_defaults() {
        // Agent=2(OpenClaw), MITM=default(N), Dashboard=default(Y), Port=default
        let input = "2\n\n\n\n";
        let (mut r, mut w) = mock_io(input);
        let qc = run_quickstart_wizard(&mut r, &mut w).unwrap();
        assert_eq!(qc.agent, DetectedAgent::OpenClaw);
        assert_eq!(qc.template_name, "openclaw-default");
        assert!(!qc.mitm);
        assert!(qc.dashboard);
        assert_eq!(qc.port, 18080);
    }

    #[test]
    fn wizard_unknown_custom_port() {
        // Agent=5(Other), MITM=n, Dashboard=n, Port=9090
        let input = "5\nn\nn\n9090\n";
        let (mut r, mut w) = mock_io(input);
        let qc = run_quickstart_wizard(&mut r, &mut w).unwrap();
        assert_eq!(qc.agent, DetectedAgent::Unknown);
        assert_eq!(qc.template_name, "strict");
        assert!(!qc.mitm);
        assert!(!qc.dashboard);
        assert_eq!(qc.port, 9090);
    }

    // --- generate_config_toml tests ---

    #[test]
    fn generate_toml_basic() {
        let qc = QuickstartConfig {
            agent: DetectedAgent::ClaudeCode,
            template_name: "claude-code-default".to_string(),
            mitm: false,
            dashboard: true,
            port: 18080,
        };
        let toml_str = generate_config_toml(&qc).unwrap();
        assert!(toml_str.contains(r#"listen = "127.0.0.1:18080""#));
        assert!(toml_str.contains(r#"mode = "transparent""#));
        assert!(toml_str.contains("enabled = true"));
    }

    #[test]
    fn generate_toml_mitm_mode() {
        let qc = QuickstartConfig {
            agent: DetectedAgent::ClaudeCode,
            template_name: "claude-code-default".to_string(),
            mitm: true,
            dashboard: true,
            port: 18080,
        };
        let toml_str = generate_config_toml(&qc).unwrap();
        assert!(toml_str.contains(r#"mode = "mitm""#));
    }

    #[test]
    fn generate_toml_custom_port() {
        let qc = QuickstartConfig {
            agent: DetectedAgent::Aider,
            template_name: "aider-default".to_string(),
            mitm: false,
            dashboard: false,
            port: 9090,
        };
        let toml_str = generate_config_toml(&qc).unwrap();
        assert!(toml_str.contains(r#"listen = "127.0.0.1:9090""#));
    }

    // --- cmd_quickstart tests (integration-like) ---

    #[test]
    fn cmd_quickstart_creates_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agentshield.toml");

        // Agent=1(Claude), MITM=n, Dashboard=y, Port=default
        let input = "1\nn\ny\n\n";
        let (mut r, mut w) = mock_io(input);

        let qc = cmd_quickstart(&mut r, &mut w, &config_path).unwrap();
        assert_eq!(qc.agent, DetectedAgent::ClaudeCode);
        assert!(!qc.mitm);
        assert!(config_path.exists());

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains(r#"listen = "127.0.0.1:18080""#));
        assert!(content.contains(r#"mode = "transparent""#));
    }

    #[test]
    fn cmd_quickstart_abort_on_existing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agentshield.toml");
        std::fs::write(&config_path, "existing").unwrap();

        // Agent=1, MITM=n, Dashboard=y, Port=default, Overwrite=n
        let input = "1\nn\ny\n\nn\n";
        let (mut r, mut w) = mock_io(input);

        cmd_quickstart(&mut r, &mut w, &config_path).unwrap();
        // File should not be overwritten
        let content = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(content, "existing");
    }

    #[test]
    fn cmd_quickstart_overwrite_existing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agentshield.toml");
        std::fs::write(&config_path, "old").unwrap();

        // Agent=3(Aider), MITM=n, Dashboard=n, Port=9090, Overwrite=y
        let input = "3\nn\nn\n9090\ny\n";
        let (mut r, mut w) = mock_io(input);

        let qc = cmd_quickstart(&mut r, &mut w, &config_path).unwrap();
        assert_eq!(qc.agent, DetectedAgent::Aider);
        assert_eq!(qc.port, 9090);
        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains(r#"listen = "127.0.0.1:9090""#));
    }
}
