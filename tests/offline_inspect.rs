//! CLI contract: stdin only, no config/state, no raw findings or logging.
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn inspect(input: &[u8], root: &std::path::Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .args([
            "--config",
            "missing-config-must-not-be-read.toml",
            "inspect",
        ])
        .current_dir(root)
        .env("HOME", root)
        .env("AGENTSHIELD_DATA_DIR", root.join("must-not-exist"))
        .env("RUST_LOG", "trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn offline_inspection_reports_only_deduplicated_categories() {
    let directory = tempfile::tempdir().unwrap();
    let key = "AKIAIOSFODNN7EXAMPLE";
    let raw = format!("binary:\u{fffd} {key} {key}\nother=ordinary prose");
    let output = inspect(raw.as_bytes(), directory.path());
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 3);
    assert_eq!(value["version"], 1);
    assert_eq!(value["bytes"], raw.len());
    assert_eq!(value["categories"], serde_json::json!(["aws-access-key"]));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(key));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn encoded_input_uses_the_existing_scanner_and_invalid_utf8_does_not_bypass_it() {
    use base64::Engine as _;
    let directory = tempfile::tempdir().unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode("AKIAIOSFODNN7EXAMPLE");
    let mut raw = vec![0xff, 0xfe, b'\n'];
    raw.extend_from_slice(encoded.as_bytes());
    let output = inspect(&raw, directory.path());
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["categories"], serde_json::json!(["aws-access-key"]));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn oversize_is_an_error_without_a_success_report() {
    let directory = tempfile::tempdir().unwrap();
    let output = inspect(&vec![b'!'; 4 * 1024 * 1024 + 1], directory.path());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"inspection_failed\n");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
