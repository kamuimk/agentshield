//! ASK response channel abstraction.
//!
//! When a policy rule evaluates to [`Action::Ask`](crate::policy::config::Action::Ask),
//! the proxy broadcasts the request to all registered [`AskResponder`] implementations
//! via [`AskBroadcaster`]. The first responder to answer wins; remaining responders
//! receive a [`notify_resolved`](AskResponder::notify_resolved) callback so they can
//! update their UI (e.g., remove inline buttons in Telegram).
//!
//! If no responder answers within the configured timeout, the request is denied
//! (fail-closed).

use std::sync::Arc;
use std::time::Duration;

/// Information about an ASK request, broadcast to all responders.
#[derive(Debug, Clone)]
pub struct AskRequestInfo {
    /// Unique request ID (UUID v4).
    pub req_id: String,
    /// Target domain (e.g., `"api.github.com"`).
    pub domain: String,
    /// HTTP method (e.g., `"POST"`).
    pub method: String,
    /// Request path (e.g., `"/repos/user/repo/pulls"`).
    pub path: String,
    /// Optional request body (truncated to 4 KB).
    pub body: Option<String>,
}

/// Trait for ASK response backends (Terminal, Telegram, Web Dashboard).
///
/// Implementations must be `Send + Sync` for use across async tasks.
#[async_trait::async_trait]
pub trait AskResponder: Send + Sync {
    /// Present the ASK request and wait for a decision.
    ///
    /// Returns `Some(true)` to allow, `Some(false)` to deny, or `None` if
    /// this responder cannot answer (e.g., not connected).
    async fn prompt(&self, req: &AskRequestInfo) -> Option<bool>;

    /// Notify this responder that another responder already answered.
    ///
    /// Used to update UI state (remove buttons, show result).
    async fn notify_resolved(&self, req_id: &str, allowed: bool);

    /// Human-readable name for logging (e.g., `"terminal"`, `"telegram"`).
    fn name(&self) -> &str;
}

/// Broadcasts ASK requests to multiple responders and adopts the first response.
pub struct AskBroadcaster {
    responders: Vec<Arc<dyn AskResponder>>,
    timeout: Duration,
}

impl AskBroadcaster {
    /// Create a new broadcaster with the given timeout.
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            responders: Vec::new(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Register a responder.
    pub fn add_responder(&mut self, responder: Arc<dyn AskResponder>) {
        self.responders.push(responder);
    }

    /// Broadcast an ASK request and return the first response.
    ///
    /// - Generates a UUID v4 `req_id` and sends the request to all responders.
    /// - Uses `tokio::select!` semantics (via `futures::future::select_all`) to
    ///   adopt the first `Some(bool)` response.
    /// - Calls `notify_resolved` on all responders after resolution.
    /// - Returns `false` (deny) if all responders return `None` or timeout.
    pub async fn ask(
        &self,
        domain: String,
        method: String,
        path: String,
        body: Option<String>,
    ) -> bool {
        if self.responders.is_empty() {
            return false;
        }

        let req_id = uuid::Uuid::new_v4().to_string();

        let info = AskRequestInfo {
            req_id: req_id.clone(),
            domain,
            method,
            path,
            body,
        };

        // Channel to collect responses from all responders
        let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(self.responders.len());

        // Spawn a task for each responder
        for responder in &self.responders {
            let r = responder.clone();
            let info = info.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Some(decision) = r.prompt(&info).await {
                    let _ = tx.send(decision).await;
                }
            });
        }
        drop(tx); // Drop our copy so rx closes when all tasks finish

        // Wait for the first response within timeout
        let allowed = match tokio::time::timeout(self.timeout, rx.recv()).await {
            Ok(Some(allowed)) => allowed,
            _ => false, // timeout, all None, or channel closed → deny
        };

        // Notify all responders of the result
        for r in &self.responders {
            r.notify_resolved(&req_id, allowed).await;
        }

        allowed
    }

    /// Return the number of registered responders.
    pub fn responder_count(&self) -> usize {
        self.responders.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A mock responder that returns a fixed decision after a delay.
    struct MockResponder {
        name: String,
        decision: Option<bool>,
        delay_ms: u64,
        resolved_called: AtomicBool,
        resolved_result: Mutex<Option<bool>>,
    }

    impl MockResponder {
        fn new(name: &str, decision: Option<bool>, delay_ms: u64) -> Self {
            Self {
                name: name.to_string(),
                decision,
                delay_ms,
                resolved_called: AtomicBool::new(false),
                resolved_result: Mutex::new(None),
            }
        }

        fn was_resolved(&self) -> bool {
            self.resolved_called.load(Ordering::SeqCst)
        }

        fn resolved_value(&self) -> Option<bool> {
            *self.resolved_result.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl AskResponder for MockResponder {
        async fn prompt(&self, _req: &AskRequestInfo) -> Option<bool> {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            self.decision
        }

        async fn notify_resolved(&self, _req_id: &str, allowed: bool) {
            self.resolved_called.store(true, Ordering::SeqCst);
            *self.resolved_result.lock().unwrap() = Some(allowed);
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn single_responder_allow() {
        let responder = Arc::new(MockResponder::new("test", Some(true), 0));
        let mut broadcaster = AskBroadcaster::new(30);
        broadcaster.add_responder(responder.clone());

        let result = broadcaster
            .ask("example.com".into(), "GET".into(), "/".into(), None)
            .await;
        assert!(result);
        assert!(responder.was_resolved());
        assert_eq!(responder.resolved_value(), Some(true));
    }

    #[tokio::test]
    async fn single_responder_deny() {
        let responder = Arc::new(MockResponder::new("test", Some(false), 0));
        let mut broadcaster = AskBroadcaster::new(30);
        broadcaster.add_responder(responder.clone());

        let result = broadcaster
            .ask("example.com".into(), "GET".into(), "/".into(), None)
            .await;
        assert!(!result);
        assert!(responder.was_resolved());
        assert_eq!(responder.resolved_value(), Some(false));
    }

    #[tokio::test]
    async fn multiple_responders_first_wins() {
        // Fast responder allows, slow responder would deny
        let fast = Arc::new(MockResponder::new("fast", Some(true), 10));
        let slow = Arc::new(MockResponder::new("slow", Some(false), 500));

        let mut broadcaster = AskBroadcaster::new(30);
        broadcaster.add_responder(fast.clone());
        broadcaster.add_responder(slow.clone());

        let result = broadcaster
            .ask("example.com".into(), "POST".into(), "/".into(), None)
            .await;

        // Fast responder wins → allow
        assert!(result);
        // Both should be notified
        assert!(fast.was_resolved());
        assert!(slow.was_resolved());
    }

    #[tokio::test]
    async fn all_timeout_returns_deny() {
        // Responder takes longer than timeout
        let responder = Arc::new(MockResponder::new("slow", Some(true), 5000));
        let mut broadcaster = AskBroadcaster::new(1); // 1 second timeout
        broadcaster.add_responder(responder.clone());

        let result = broadcaster
            .ask("example.com".into(), "GET".into(), "/".into(), None)
            .await;
        assert!(!result); // timeout → deny
    }

    #[tokio::test]
    async fn no_responders_returns_deny() {
        let broadcaster = AskBroadcaster::new(30);
        let result = broadcaster
            .ask("example.com".into(), "GET".into(), "/".into(), None)
            .await;
        assert!(!result);
    }

    #[tokio::test]
    async fn responder_returns_none_skipped() {
        // First responder can't answer, second allows
        let none_responder = Arc::new(MockResponder::new("none", None, 0));
        let allow_responder = Arc::new(MockResponder::new("allow", Some(true), 10));

        let mut broadcaster = AskBroadcaster::new(30);
        broadcaster.add_responder(none_responder.clone());
        broadcaster.add_responder(allow_responder.clone());

        let result = broadcaster
            .ask("example.com".into(), "GET".into(), "/".into(), None)
            .await;
        assert!(result);
    }

    #[tokio::test]
    async fn all_responders_none_returns_deny() {
        let r1 = Arc::new(MockResponder::new("r1", None, 0));
        let r2 = Arc::new(MockResponder::new("r2", None, 0));

        let mut broadcaster = AskBroadcaster::new(30);
        broadcaster.add_responder(r1);
        broadcaster.add_responder(r2);

        let result = broadcaster
            .ask("example.com".into(), "GET".into(), "/".into(), None)
            .await;
        assert!(!result);
    }

    #[tokio::test]
    async fn ask_request_info_has_uuid() {
        // Verify that req_id is generated
        let responder = Arc::new(MockResponder::new("test", Some(true), 0));
        let mut broadcaster = AskBroadcaster::new(30);
        broadcaster.add_responder(responder);

        // The req_id is generated internally, so we just verify the flow works
        let result = broadcaster
            .ask(
                "api.github.com".into(),
                "POST".into(),
                "/pulls".into(),
                Some("body".into()),
            )
            .await;
        assert!(result);
    }

    #[test]
    fn broadcaster_responder_count() {
        let mut broadcaster = AskBroadcaster::new(30);
        assert_eq!(broadcaster.responder_count(), 0);

        broadcaster.add_responder(Arc::new(MockResponder::new("r1", None, 0)));
        assert_eq!(broadcaster.responder_count(), 1);

        broadcaster.add_responder(Arc::new(MockResponder::new("r2", None, 0)));
        assert_eq!(broadcaster.responder_count(), 2);
    }
}
