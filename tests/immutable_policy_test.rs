//! Real CLI policy lifetime, dashboard authority, and unchanged default reload.
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn cli_freezes_policy_through_dashboard_file_change_and_signal() {
    for integrated in [false, true] {
        for immutable in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let reservations: Vec<_> = (0..2)
                .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
                .collect();
            let proxy = reservations[0].local_addr().unwrap();
            let web = reservations[1].local_addr().unwrap();
            let admin = "synthetic-admin-00000000000000000000";
            let integration = if integrated {
                r#"
[web.integration]
allowed_origins = ["https://host.example"]
read_token = "synthetic-reader-0000000000000000000"
control_token = "synthetic-control-000000000000000000"
"#
            } else {
                ""
            };
            let config = |default| {
                format!(
                    r#"
[proxy]
listen = "{proxy}"
mode = "transparent"
[policy]
default = "{default}"
[web]
enabled = true
listen = "{web}"
auth_token = "{admin}"
{integration}
"#
                )
            };
            let path = root.path().join("config.toml");
            std::fs::write(&path, config("deny")).unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_agentshield"));
            command
                .arg("--config")
                .arg(&path)
                .arg("start")
                .env("AGENTSHIELD_DATA_DIR", root.path().join("state"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if immutable {
                command.arg("--immutable-policy");
            }
            drop(reservations);
            let mut child = OwnedChild(command.spawn().unwrap());
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap();
            let policy_url = format!("http://{web}/api/policy");
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "engine exited at startup"
                );
                if client
                    .get(&policy_url)
                    .bearer_auth(admin)
                    .send()
                    .await
                    .is_ok_and(|r| r.status() == 200)
                {
                    break;
                }
                assert!(Instant::now() < deadline, "dashboard did not become ready");
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            let result = client
                .put(&policy_url)
                .bearer_auth(admin)
                .json(&serde_json::json!({"default":"allow","rules":[]}))
                .send()
                .await
                .unwrap();
            assert_eq!(result.status().as_u16(), if immutable { 403 } else { 200 });
            let mut pages = vec!["/"];
            if integrated {
                pages.push("/embed");
            }
            for page in pages {
                let html = client
                    .get(format!("http://{web}{page}"))
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap();
                assert_eq!(
                    html.contains("window.AGENTSHIELD_READ_ONLY=true;"),
                    immutable
                );
            }
            let policy: serde_json::Value = client
                .get(&policy_url)
                .bearer_auth(admin)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(policy["default"], if immutable { "deny" } else { "allow" });
            std::fs::write(&path, config(if immutable { "allow" } else { "deny" })).unwrap();
            if immutable {
                // Observe beyond normal notify processing, then send HUP too.
                tokio::time::sleep(Duration::from_millis(500)).await;
            } else {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let policy: serde_json::Value = client
                        .get(&policy_url)
                        .bearer_auth(admin)
                        .send()
                        .await
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                    if policy["default"] == "deny" {
                        break;
                    }
                    assert!(Instant::now() < deadline, "default mode stopped reloading");
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            }
            #[cfg(unix)]
            {
                assert!(child.0.try_wait().unwrap().is_none());
                assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGHUP) }, 0);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "HUP terminated the engine"
            );
            let policy: serde_json::Value = client
                .get(&policy_url)
                .bearer_auth(admin)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(policy["default"], "deny");
            let through_proxy = reqwest::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::http(format!("http://{proxy}")).unwrap())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            assert_eq!(
                through_proxy
                    .get("http://policy-proof.invalid/")
                    .send()
                    .await
                    .unwrap()
                    .status(),
                403
            );
        }
    }
}
