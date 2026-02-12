use super::config::{Action, PolicyConfig, Rule};

/// Represents an HTTP request to be evaluated against policy rules.
pub struct RequestInfo {
    pub domain: String,
    pub method: String,
    pub path: String,
}

/// Result of a policy evaluation, including the action and the reason.
pub struct EvalResult {
    pub action: Action,
    pub reason: String,
    pub matched_rule: Option<String>,
}

/// Evaluate a request against the policy configuration.
/// Rules are matched sequentially; the first matching rule wins.
/// If no rule matches, the default action is returned.
pub fn evaluate(req: &RequestInfo, config: &PolicyConfig) -> EvalResult {
    for rule in &config.rules {
        if matches_rule(req, rule) {
            return EvalResult {
                action: rule.action.clone(),
                reason: format!("Matched rule: {}", rule.name),
                matched_rule: Some(rule.name.clone()),
            };
        }
    }

    EvalResult {
        action: config.default.clone(),
        reason: "No matching rule; default policy applied".to_string(),
        matched_rule: None,
    }
}

/// Check if a request matches a given rule.
fn matches_rule(req: &RequestInfo, rule: &Rule) -> bool {
    // Check domain match
    let domain_matches = rule.domains.iter().any(|d| {
        if d == "*" {
            true
        } else if d.starts_with("*.") {
            // Wildcard subdomain match: "*.example.com" matches "foo.example.com"
            let suffix = &d[1..]; // ".example.com"
            req.domain.ends_with(suffix) || req.domain == d[2..]
        } else {
            req.domain == *d
        }
    });

    if !domain_matches {
        return false;
    }

    // Check method match (if specified)
    if let Some(methods) = &rule.methods {
        let method_upper = req.method.to_uppercase();
        if !methods.iter().any(|m| m.to_uppercase() == method_upper) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::config::{Action, AppConfig, PolicyConfig, Rule};

    fn make_policy(default: Action, rules: Vec<Rule>) -> PolicyConfig {
        PolicyConfig { default, rules }
    }

    fn make_rule(name: &str, domains: Vec<&str>, methods: Option<Vec<&str>>, action: Action) -> Rule {
        Rule {
            name: name.to_string(),
            domains: domains.into_iter().map(|s| s.to_string()).collect(),
            methods: methods.map(|ms| ms.into_iter().map(|s| s.to_string()).collect()),
            action,
            note: None,
        }
    }

    fn make_req(domain: &str, method: &str, path: &str) -> RequestInfo {
        RequestInfo {
            domain: domain.to_string(),
            method: method.to_string(),
            path: path.to_string(),
        }
    }

    #[test]
    fn default_deny_when_no_rules() {
        let policy = make_policy(Action::Deny, vec![]);
        let req = make_req("evil.com", "GET", "/");
        let result = evaluate(&req, &policy);
        assert_eq!(result.action, Action::Deny);
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn allow_matching_domain() {
        let policy = make_policy(
            Action::Deny,
            vec![make_rule("anthropic", vec!["api.anthropic.com"], None, Action::Allow)],
        );
        let req = make_req("api.anthropic.com", "POST", "/v1/messages");
        let result = evaluate(&req, &policy);
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.matched_rule.as_deref(), Some("anthropic"));
    }

    #[test]
    fn deny_non_matching_domain() {
        let policy = make_policy(
            Action::Deny,
            vec![make_rule("anthropic", vec!["api.anthropic.com"], None, Action::Allow)],
        );
        let req = make_req("evil.com", "GET", "/steal");
        let result = evaluate(&req, &policy);
        assert_eq!(result.action, Action::Deny);
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn method_filtering_allows_get() {
        let policy = make_policy(
            Action::Deny,
            vec![make_rule("github-read", vec!["api.github.com"], Some(vec!["GET"]), Action::Allow)],
        );
        let req = make_req("api.github.com", "GET", "/repos/user/repo");
        let result = evaluate(&req, &policy);
        assert_eq!(result.action, Action::Allow);
    }

    #[test]
    fn method_filtering_denies_post() {
        let policy = make_policy(
            Action::Deny,
            vec![make_rule("github-read", vec!["api.github.com"], Some(vec!["GET"]), Action::Allow)],
        );
        let req = make_req("api.github.com", "POST", "/repos/user/repo");
        let result = evaluate(&req, &policy);
        assert_eq!(result.action, Action::Deny);
    }

    #[test]
    fn ask_action_for_write_methods() {
        let policy = make_policy(
            Action::Deny,
            vec![
                make_rule("github-read", vec!["api.github.com"], Some(vec!["GET"]), Action::Allow),
                make_rule("github-write", vec!["api.github.com"], Some(vec!["POST", "PUT", "DELETE"]), Action::Ask),
            ],
        );
        let req = make_req("api.github.com", "POST", "/repos/user/repo/pulls");
        let result = evaluate(&req, &policy);
        assert_eq!(result.action, Action::Ask);
        assert_eq!(result.matched_rule.as_deref(), Some("github-write"));
    }

    #[test]
    fn wildcard_domain_matches_all() {
        let policy = make_policy(
            Action::Deny,
            vec![make_rule("catch-all", vec!["*"], None, Action::Ask)],
        );
        let req = make_req("anything.example.com", "GET", "/");
        let result = evaluate(&req, &policy);
        assert_eq!(result.action, Action::Ask);
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = make_policy(
            Action::Deny,
            vec![
                make_rule("specific", vec!["api.github.com"], Some(vec!["GET"]), Action::Allow),
                make_rule("catch-all", vec!["*"], None, Action::Deny),
            ],
        );
        let req = make_req("api.github.com", "GET", "/repos");
        let result = evaluate(&req, &policy);
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.matched_rule.as_deref(), Some("specific"));
    }

    #[test]
    fn openclaw_template_scenario() {
        let template = include_str!("../../templates/openclaw-default.toml");
        let config: AppConfig = toml::from_str(template).unwrap();

        // Anthropic API should be allowed
        let req = make_req("api.anthropic.com", "POST", "/v1/messages");
        let result = evaluate(&req, &config.policy);
        assert_eq!(result.action, Action::Allow);

        // GitHub GET should be allowed
        let req = make_req("api.github.com", "GET", "/repos/user/repo");
        let result = evaluate(&req, &config.policy);
        assert_eq!(result.action, Action::Allow);

        // GitHub POST should ASK
        let req = make_req("api.github.com", "POST", "/repos/user/repo/pulls");
        let result = evaluate(&req, &config.policy);
        assert_eq!(result.action, Action::Ask);
    }
}
