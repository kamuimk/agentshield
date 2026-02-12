use agentshield::policy::config::{Action, AppConfig};

const MINIMAL_TOML: &str = r#"
[proxy]
listen = "127.0.0.1:18080"
mode = "transparent"

[policy]
default = "deny"
"#;

const FULL_TOML: &str = r#"
[proxy]
listen = "127.0.0.1:18080"
mode = "transparent"

[policy]
default = "deny"

[[policy.rules]]
name = "anthropic-api"
domains = ["api.anthropic.com"]
action = "allow"

[[policy.rules]]
name = "github-readonly"
domains = ["api.github.com"]
methods = ["GET"]
action = "allow"

[[policy.rules]]
name = "github-write"
domains = ["api.github.com"]
methods = ["POST", "PUT", "DELETE"]
action = "ask"

[dlp]
enabled = false
patterns = ["AWS_KEY", "GITHUB_TOKEN"]
"#;

#[test]
fn parse_minimal_config() {
    let config: AppConfig = toml::from_str(MINIMAL_TOML).unwrap();
    assert_eq!(config.proxy.listen, "127.0.0.1:18080");
    assert_eq!(config.proxy.mode, "transparent");
    assert_eq!(config.policy.default, Action::Deny);
    assert!(config.policy.rules.is_empty());
}

#[test]
fn parse_full_config_with_rules() {
    let config: AppConfig = toml::from_str(FULL_TOML).unwrap();
    assert_eq!(config.policy.rules.len(), 3);

    let rule0 = &config.policy.rules[0];
    assert_eq!(rule0.name, "anthropic-api");
    assert_eq!(rule0.domains, vec!["api.anthropic.com"]);
    assert_eq!(rule0.action, Action::Allow);
    assert!(rule0.methods.is_none());

    let rule1 = &config.policy.rules[1];
    assert_eq!(rule1.name, "github-readonly");
    assert_eq!(
        rule1.methods.as_ref().unwrap(),
        &vec!["GET".to_string()]
    );
    assert_eq!(rule1.action, Action::Allow);

    let rule2 = &config.policy.rules[2];
    assert_eq!(rule2.name, "github-write");
    assert_eq!(rule2.action, Action::Ask);
}

#[test]
fn parse_dlp_config() {
    let config: AppConfig = toml::from_str(FULL_TOML).unwrap();
    let dlp = config.dlp.unwrap();
    assert!(!dlp.enabled);
    assert_eq!(dlp.patterns.unwrap(), vec!["AWS_KEY", "GITHUB_TOKEN"]);
}

#[test]
fn parse_openclaw_template() {
    let template = include_str!("../templates/openclaw-default.toml");
    let config: AppConfig = toml::from_str(template).unwrap();
    assert_eq!(config.policy.default, Action::Deny);
    assert!(config.policy.rules.len() >= 7);

    // Verify specific rules exist
    let rule_names: Vec<&str> = config.policy.rules.iter().map(|r| r.name.as_str()).collect();
    assert!(rule_names.contains(&"anthropic-api"));
    assert!(rule_names.contains(&"github-read"));
    assert!(rule_names.contains(&"github-write"));
}

#[test]
fn action_serialization_roundtrip() {
    assert_eq!(Action::Allow, Action::Allow);
    assert_eq!(Action::Deny, Action::Deny);
    assert_eq!(Action::Ask, Action::Ask);
    assert_ne!(Action::Allow, Action::Deny);
}

#[test]
fn invalid_toml_returns_error() {
    let bad_toml = "this is not valid toml [[[";
    let result = toml::from_str::<AppConfig>(bad_toml);
    assert!(result.is_err());
}

#[test]
fn config_load_from_file() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("agentshield.toml");
    let mut file = std::fs::File::create(&config_path).unwrap();
    write!(file, "{}", MINIMAL_TOML).unwrap();

    let config = AppConfig::load_from_path(&config_path).unwrap();
    assert_eq!(config.proxy.listen, "127.0.0.1:18080");
}
