use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use agentshield::cli::prompt::{self, PromptRequest};
use agentshield::logging;
use agentshield::policy::config::{Action, AppConfig, PolicyConfig, Rule};
use agentshield::policy::evaluator::{self, RequestInfo};
use agentshield::proxy::ProxyServer;

// ===== Template tests =====

#[test]
fn all_templates_are_valid_toml() {
    let templates = &[
        (
            "openclaw-default",
            include_str!("../templates/openclaw-default.toml"),
        ),
        (
            "claude-code-default",
            include_str!("../templates/claude-code-default.toml"),
        ),
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
    assert!(names.contains(&"anthropic-api"));
    assert!(names.contains(&"github-read"));
    assert!(names.contains(&"github-write"));
    assert!(names.contains(&"telegram"));
}

#[test]
fn template_apply_creates_valid_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("agentshield.toml");
    let template = include_str!("../templates/openclaw-default.toml");
    std::fs::write(&config_path, template).unwrap();

    let config = AppConfig::load_from_path(&config_path).unwrap();
    assert_eq!(config.proxy.listen, "127.0.0.1:18080");
    assert!(config.policy.rules.len() >= 7);
}

// ===== End-to-end: proxy + policy + logging =====

#[tokio::test]
async fn e2e_proxy_policy_deny_logs_nothing_yet() {
    // Proxy with deny-all should block and return 403
    let policy = PolicyConfig {
        default: Action::Deny,
        rules: vec![],
    };
    let server = ProxyServer::new("127.0.0.1:0".to_string()).with_policy(policy);
    let addr = server.start().await.unwrap();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT unknown.com:443 HTTP/1.1\r\nHost: unknown.com:443\r\n\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("403"));
    assert!(response.contains("X-AgentShield-Reason"));
}

#[tokio::test]
async fn e2e_openclaw_full_flow() {
    let template = include_str!("../templates/openclaw-default.toml");
    let config: AppConfig = toml::from_str(template).unwrap();
    let server = ProxyServer::new("127.0.0.1:0".to_string()).with_policy(config.policy.clone());
    let addr = server.start().await.unwrap();

    // 1. Anthropic API - should be ALLOWED
    assert_connect_result(addr, "api.anthropic.com:443", "200").await;

    // 2. OpenAI API - should be ALLOWED
    assert_connect_result(addr, "api.openai.com:443", "200").await;

    // 3. Telegram - should be ALLOWED
    assert_connect_result(addr, "api.telegram.org:443", "200").await;

    // 4. Unknown domain - matches wildcard "web-browsing" ASK rule.
    //    ASK passes policy check but actual connection may fail (502).
    //    The key is it does NOT get 403 (policy blocked).
    assert_connect_not_blocked(addr, "random-site.com:443").await;
}

async fn assert_connect_result(proxy_addr: SocketAddr, target: &str, expected_status: &str) {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        target, target
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains(expected_status),
        "CONNECT {} expected {}, got: {}",
        target,
        expected_status,
        response
    );
}

async fn assert_connect_not_blocked(proxy_addr: SocketAddr, target: &str) {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        target, target
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        !response.contains("403"),
        "CONNECT {} should NOT be blocked by policy, got: {}",
        target,
        response
    );
}

// ===== Evaluator edge cases =====

#[test]
fn evaluator_multiple_domains_in_single_rule() {
    let policy = PolicyConfig {
        default: Action::Deny,
        rules: vec![Rule {
            name: "multi-domain".to_string(),
            domains: vec!["a.com".to_string(), "b.com".to_string(), "c.com".to_string()],
            methods: None,
            action: Action::Allow,
            note: None,
        }],
    };

    for domain in &["a.com", "b.com", "c.com"] {
        let req = RequestInfo {
            domain: domain.to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
        };
        let result = evaluator::evaluate(&req, &policy);
        assert_eq!(result.action, Action::Allow, "Failed for domain {}", domain);
    }

    let req = RequestInfo {
        domain: "d.com".to_string(),
        method: "GET".to_string(),
        path: "/".to_string(),
    };
    let result = evaluator::evaluate(&req, &policy);
    assert_eq!(result.action, Action::Deny);
}

#[test]
fn evaluator_case_insensitive_method_matching() {
    let policy = PolicyConfig {
        default: Action::Deny,
        rules: vec![Rule {
            name: "test".to_string(),
            domains: vec!["example.com".to_string()],
            methods: Some(vec!["GET".to_string()]),
            action: Action::Allow,
            note: None,
        }],
    };

    // "get" should still match "GET" rule
    let req = RequestInfo {
        domain: "example.com".to_string(),
        method: "get".to_string(),
        path: "/".to_string(),
    };
    let result = evaluator::evaluate(&req, &policy);
    assert_eq!(result.action, Action::Allow);
}

#[test]
fn evaluator_default_allow_policy() {
    let policy = PolicyConfig {
        default: Action::Allow,
        rules: vec![Rule {
            name: "block-evil".to_string(),
            domains: vec!["evil.com".to_string()],
            methods: None,
            action: Action::Deny,
            note: None,
        }],
    };

    let req = RequestInfo {
        domain: "safe.com".to_string(),
        method: "GET".to_string(),
        path: "/".to_string(),
    };
    let result = evaluator::evaluate(&req, &policy);
    assert_eq!(result.action, Action::Allow);

    let req = RequestInfo {
        domain: "evil.com".to_string(),
        method: "GET".to_string(),
        path: "/".to_string(),
    };
    let result = evaluator::evaluate(&req, &policy);
    assert_eq!(result.action, Action::Deny);
}

// ===== Logging + export integration =====

#[test]
fn logging_full_lifecycle() {
    let conn = logging::open_memory_db().unwrap();

    // Insert several logs
    for i in 0..10 {
        logging::log_request(
            &conn,
            &logging::RequestLog {
                id: None,
                timestamp: format!("2026-02-12T10:{:02}:00Z", i),
                method: if i % 2 == 0 { "GET" } else { "POST" }.to_string(),
                domain: format!("domain{}.com", i),
                path: "/test".to_string(),
                action: if i % 3 == 0 { "deny" } else { "allow" }.to_string(),
                reason: "test".to_string(),
            },
        )
        .unwrap();
    }

    // Query last 5
    let logs = logging::query_recent(&conn, 5).unwrap();
    assert_eq!(logs.len(), 5);
    assert_eq!(logs[0].domain, "domain9.com"); // most recent first

    // Export JSON
    let json = logging::export::export_json(&conn).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 10);

    // Export CSV
    let csv = logging::export::export_csv(&conn).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 11); // header + 10 rows
}

// ===== Prompt + config rule append integration =====

#[test]
fn prompt_add_rule_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("agentshield.toml");

    // Start with strict template
    let template = include_str!("../templates/strict.toml");
    std::fs::write(&config_path, template).unwrap();

    // Verify initially no rules
    let config = AppConfig::load_from_path(&config_path).unwrap();
    assert!(config.policy.rules.is_empty());

    // Simulate user approving a request and adding a rule
    let req = PromptRequest {
        method: "POST".to_string(),
        domain: "api.example.com".to_string(),
        path: "/v1/data".to_string(),
        body: None,
    };
    let rule = prompt::generate_rule(&req);
    prompt::append_rule_to_config(&config_path, &rule).unwrap();

    // Verify rule was added and config is still valid
    let config = AppConfig::load_from_path(&config_path).unwrap();
    assert_eq!(config.policy.rules.len(), 1);
    assert_eq!(config.policy.rules[0].name, "auto-api-example-com");
    assert_eq!(config.policy.rules[0].domains, vec!["api.example.com"]);
    assert_eq!(config.policy.rules[0].action, Action::Allow);

    // Add another rule
    let req2 = PromptRequest {
        method: "GET".to_string(),
        domain: "cdn.example.com".to_string(),
        path: "/assets".to_string(),
        body: None,
    };
    let rule2 = prompt::generate_rule(&req2);
    prompt::append_rule_to_config(&config_path, &rule2).unwrap();

    let config = AppConfig::load_from_path(&config_path).unwrap();
    assert_eq!(config.policy.rules.len(), 2);
}

// ===== Concurrent proxy connections =====

#[tokio::test]
async fn proxy_handles_concurrent_connections() {
    let policy = PolicyConfig {
        default: Action::Deny,
        rules: vec![
            Rule {
                name: "allow-example".to_string(),
                domains: vec!["example.com".to_string()],
                methods: None,
                action: Action::Allow,
                note: None,
            },
        ],
    };

    let server = ProxyServer::new("127.0.0.1:0".to_string()).with_policy(policy);
    let addr = server.start().await.unwrap();

    // Spawn 10 concurrent requests
    let mut handles = vec![];
    for i in 0..10 {
        let addr = addr;
        handles.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let domain = if i % 2 == 0 {
                "example.com"
            } else {
                "blocked.com"
            };
            let req = format!(
                "CONNECT {}:443 HTTP/1.1\r\nHost: {}:443\r\n\r\n",
                domain, domain
            );
            stream.write_all(req.as_bytes()).await.unwrap();

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            let response = String::from_utf8_lossy(&buf[..n]).to_string();
            (domain.to_string(), response)
        }));
    }

    for handle in handles {
        let (domain, response) = handle.await.unwrap();
        if domain == "example.com" {
            assert!(
                response.contains("200"),
                "Expected 200 for example.com, got: {}",
                response
            );
        } else {
            assert!(
                response.contains("403"),
                "Expected 403 for blocked.com, got: {}",
                response
            );
        }
    }
}
