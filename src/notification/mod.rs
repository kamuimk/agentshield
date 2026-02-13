pub mod telegram;

use crate::error::Result;

/// Events that can trigger notifications.
#[derive(Debug, Clone)]
pub enum NotificationEvent {
    RequestDenied {
        domain: String,
        method: String,
        path: String,
        reason: String,
    },
    DlpFinding {
        domain: String,
        method: String,
        pattern_name: String,
        severity: String,
    },
    ProxyStarted {
        listen_addr: String,
    },
    ProxyShutdown,
}

/// Trait for notification backends.
#[async_trait::async_trait]
pub trait Notifier: Send + Sync {
    async fn notify(&self, event: &NotificationEvent) -> Result<()>;
    fn name(&self) -> &str;
}

/// Format an event into a human-readable message.
pub fn format_message(event: &NotificationEvent) -> String {
    match event {
        NotificationEvent::RequestDenied {
            domain,
            method,
            path,
            reason,
        } => {
            format!(
                "🚫 *Request Denied*\n`{} {}{}` → {}\nReason: {}",
                method, domain, path, "BLOCKED", reason
            )
        }
        NotificationEvent::DlpFinding {
            domain,
            method,
            pattern_name,
            severity,
        } => {
            format!(
                "🔍 *DLP Finding* ({})\n`{} {}`\nPattern: {}",
                severity, method, domain, pattern_name
            )
        }
        NotificationEvent::ProxyStarted { listen_addr } => {
            format!("✅ *AgentShield Started*\nListening on `{}`", listen_addr)
        }
        NotificationEvent::ProxyShutdown => "⏹ *AgentShield Shutdown*".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A mock notifier that collects events for testing.
    pub struct MockNotifier {
        pub events: Arc<Mutex<Vec<NotificationEvent>>>,
    }

    impl MockNotifier {
        pub fn new() -> (Self, Arc<Mutex<Vec<NotificationEvent>>>) {
            let events = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    events: events.clone(),
                },
                events,
            )
        }
    }

    #[async_trait::async_trait]
    impl Notifier for MockNotifier {
        async fn notify(&self, event: &NotificationEvent) -> Result<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }

        fn name(&self) -> &str {
            "mock"
        }
    }

    #[test]
    fn format_deny_message() {
        let event = NotificationEvent::RequestDenied {
            domain: "evil.com".to_string(),
            method: "GET".to_string(),
            path: "/hack".to_string(),
            reason: "default deny".to_string(),
        };
        let msg = format_message(&event);
        assert!(msg.contains("Request Denied"));
        assert!(msg.contains("evil.com"));
        assert!(msg.contains("default deny"));
    }

    #[test]
    fn format_dlp_message() {
        let event = NotificationEvent::DlpFinding {
            domain: "api.example.com".to_string(),
            method: "POST".to_string(),
            pattern_name: "openai-api-key".to_string(),
            severity: "Critical".to_string(),
        };
        let msg = format_message(&event);
        assert!(msg.contains("DLP Finding"));
        assert!(msg.contains("Critical"));
        assert!(msg.contains("openai-api-key"));
    }

    #[test]
    fn format_start_message() {
        let event = NotificationEvent::ProxyStarted {
            listen_addr: "127.0.0.1:18080".to_string(),
        };
        let msg = format_message(&event);
        assert!(msg.contains("Started"));
        assert!(msg.contains("127.0.0.1:18080"));
    }

    #[tokio::test]
    async fn mock_notifier_collects_events() {
        let (mock, events) = MockNotifier::new();
        let event = NotificationEvent::ProxyShutdown;
        mock.notify(&event).await.unwrap();

        let collected = events.lock().unwrap();
        assert_eq!(collected.len(), 1);
        assert!(matches!(collected[0], NotificationEvent::ProxyShutdown));
    }

    #[tokio::test]
    async fn mock_notifier_collects_multiple_events() {
        let (mock, events) = MockNotifier::new();

        mock.notify(&NotificationEvent::ProxyStarted {
            listen_addr: "127.0.0.1:18080".to_string(),
        })
        .await
        .unwrap();

        mock.notify(&NotificationEvent::RequestDenied {
            domain: "evil.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            reason: "default deny".to_string(),
        })
        .await
        .unwrap();

        let collected = events.lock().unwrap();
        assert_eq!(collected.len(), 2);
    }
}
