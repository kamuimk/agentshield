use agentshield::policy::config::AppConfig;

#[test]
fn all_templates_are_valid_toml() {
    let templates = &[
        ("openclaw-default", include_str!("../templates/openclaw-default.toml")),
        ("claude-code-default", include_str!("../templates/claude-code-default.toml")),
        ("strict", include_str!("../templates/strict.toml")),
    ];

    for (name, content) in templates {
        let config: AppConfig = toml::from_str(content)
            .unwrap_or_else(|e| panic!("Template '{}' failed to parse: {}", name, e));
        assert!(
            !config.proxy.listen.is_empty(),
            "Template '{}' has empty listen address",
            name
        );
    }
}

#[test]
fn openclaw_template_has_required_rules() {
    let content = include_str!("../templates/openclaw-default.toml");
    let config: AppConfig = toml::from_str(content).unwrap();

    let names: Vec<&str> = config.policy.rules.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"anthropic-api"), "Missing anthropic-api rule");
    assert!(names.contains(&"github-read"), "Missing github-read rule");
    assert!(names.contains(&"github-write"), "Missing github-write rule");
    assert!(names.contains(&"telegram"), "Missing telegram rule");
}

#[test]
fn template_apply_creates_valid_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("agentshield.toml");

    // Simulate applying a template
    let template = include_str!("../templates/openclaw-default.toml");
    std::fs::write(&config_path, template).unwrap();

    // Load and verify
    let config = AppConfig::load_from_path(&config_path).unwrap();
    assert_eq!(config.proxy.listen, "127.0.0.1:18080");
    assert!(config.policy.rules.len() >= 7);
}
