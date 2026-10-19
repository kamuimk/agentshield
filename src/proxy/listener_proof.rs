//! One-shot proof of an imported listener, never a traffic or execution grant.
//! Keys arrive only through a local SYSTEM-owned pipe, never config/argv/env.
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const PATH: &str = "/.__agentshield/listener-proof/v1";
const DOMAIN: &[u8] = b"agentshield.listener-proof.v1\0";
const PIPE_PREFIX: &str = r"\\.\pipe\AgentShield.ListenerProof.v1.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    v: u8,
    key: String,
    nonce: String,
    port: u16,
}
impl Drop for Frame {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

fn rejected(stage: &'static str) -> io::Error {
    io::Error::other(stage)
}
fn hex32(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(rejected("listener_proof_frame_invalid"));
    }
    let digit = |b| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(rejected("listener_proof_frame_invalid")),
    };
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(result)
}

/// Opaque startup proof. No Debug/Serialize implementation can reveal its key.
pub struct ListenerProof {
    address: SocketAddr,
    nonce: [u8; 32],
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    expires: Instant,
}
impl ListenerProof {
    fn from_frame(raw: &[u8], address: SocketAddr) -> io::Result<Self> {
        if raw.len() > 512
            || !address.is_ipv4()
            || address.ip() != std::net::Ipv4Addr::LOCALHOST
            || address.port() == 0
        {
            return Err(rejected("listener_proof_frame_invalid"));
        }
        let frame: Frame =
            serde_json::from_slice(raw).map_err(|_| rejected("listener_proof_frame_invalid"))?;
        if frame.v != 1 || frame.port != address.port() {
            return Err(rejected("listener_proof_address_mismatch"));
        }
        let key = Zeroizing::new(hex32(&frame.key)?);
        let nonce = hex32(&frame.nonce)?;
        Ok(Self {
            address,
            nonce,
            key: Mutex::new(Some(key)),
            expires: Instant::now() + Duration::from_secs(30),
        })
    }

    /// A host must authenticate the exact connecting engine process before sending
    /// the frame. SYSTEM ownership alone does not authenticate the client to host.
    pub fn from_system_pipe(path: &str, address: SocketAddr) -> io::Result<Self> {
        if !path.strip_prefix(PIPE_PREFIX).is_some_and(|tail| {
            tail.len() == 32
                && tail
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(rejected("listener_proof_pipe_name_invalid"));
        }
        let raw = read_system_frame(path)?;
        Self::from_frame(&raw, address)
    }

    pub(super) fn binds(&self, address: SocketAddr) -> bool {
        self.address == address
    }
    pub(super) fn schedule_expiry(self: &Arc<Self>) {
        let delay = self.expires.saturating_duration_since(Instant::now());
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Some(proof) = weak.upgrade() {
                if let Ok(mut key) = proof.key.lock() {
                    key.take();
                }
            }
        });
    }

    /// Called before policy/audit/forwarding. Only this reserved origin-form route
    /// is intercepted; it never returns payloads or forwards any request bytes.
    pub(super) fn response(&self, raw: &[u8], local: SocketAddr) -> Option<Vec<u8>> {
        let first = raw.split(|b| *b == b'\n').next()?;
        let line = std::str::from_utf8(first).ok()?;
        if line.split_ascii_whitespace().nth(1) != Some(PATH) {
            return None;
        }
        let reject = |code| {
            Some(format!("HTTP/1.1 {code} Proof Rejected\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").into_bytes())
        };
        if local != self.address {
            return reject(403);
        }
        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut headers);
        let Ok(httparse::Status::Complete(end)) = request.parse(raw) else {
            return reject(400);
        };
        if request.method != Some("GET") || request.version != Some(1) || end != raw.len() {
            return reject(400);
        }
        let host = self.address.to_string();
        let hosts: Vec<_> = request
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("host"))
            .collect();
        let nonces: Vec<_> = request
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("x-agentshield-nonce"))
            .collect();
        if hosts.len() != 1 || hosts[0].value != host.as_bytes() || nonces.len() != 1 {
            return reject(403);
        }
        let Ok(value) = std::str::from_utf8(nonces[0].value)
            .map_err(|_| ())
            .and_then(|s| hex32(s).map_err(|_| ()))
        else {
            return reject(403);
        };
        if !bool::from(value.ct_eq(&self.nonce)) {
            return reject(403);
        }
        let Ok(mut slot) = self.key.lock() else {
            return reject(503);
        };
        if Instant::now() >= self.expires {
            slot.take();
            return reject(410);
        }
        let Some(key) = slot.take() else {
            return reject(410);
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[..]).expect("fixed HMAC key size");
        mac.update(DOMAIN);
        mac.update(&self.address.port().to_be_bytes());
        mac.update(&self.nonce);
        let tag: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Some(format!("HTTP/1.1 200 OK\r\nX-AgentShield-Proof: {tag}\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").into_bytes())
    }
}

#[cfg(not(windows))]
fn read_system_frame(_path: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    Err(rejected("listener_proof_requires_windows"))
}

#[cfg(windows)]
fn read_system_frame(path: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::{
        fs::OpenOptions,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            IsWellKnownSid, OWNER_SECURITY_INFORMATION, WinLocalSystemSid,
        },
        Storage::FileSystem::{FILE_GENERIC_READ, ReadFile},
        System::Pipes::{GetNamedPipeInfo, PeekNamedPipe},
    };
    let file = OpenOptions::new()
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(0)
        .open(path)
        .map_err(|_| rejected("listener_proof_pipe_open_failed"))?;
    let handle = file.as_raw_handle();
    let (mut owner, mut descriptor) = (std::ptr::null_mut(), std::ptr::null_mut());
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let trusted =
        code == 0 && !owner.is_null() && unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } != 0;
    if !descriptor.is_null() {
        unsafe {
            LocalFree(descriptor);
        }
    }
    if !trusted {
        return Err(rejected("listener_proof_pipe_owner_invalid"));
    }
    let mut flags = 0;
    if unsafe {
        GetNamedPipeInfo(
            handle,
            &mut flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
        || flags != 0
    {
        return Err(rejected("listener_proof_pipe_type_invalid"));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let read = |buffer: &mut [u8]| -> io::Result<()> {
        loop {
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(rejected("listener_proof_pipe_invalid"));
            }
            if available as usize >= buffer.len() {
                let mut count = 0;
                if unsafe {
                    ReadFile(
                        handle,
                        buffer.as_mut_ptr(),
                        buffer.len() as u32,
                        &mut count,
                        std::ptr::null_mut(),
                    )
                } == 0
                    || count as usize != buffer.len()
                {
                    return Err(rejected("listener_proof_frame_truncated"));
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(rejected("listener_proof_pipe_timeout"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let mut prefix = [0; 4];
    read(&mut prefix)?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 || length > 512 {
        return Err(rejected("listener_proof_frame_invalid"));
    }
    let mut raw = Zeroizing::new(vec![0; length]);
    read(&mut raw)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn address() -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }
    fn frame(port: u16) -> Vec<u8> {
        format!(
            r#"{{"v":1,"key":"{}","nonce":"{}","port":{port}}}"#,
            "11".repeat(32),
            "22".repeat(32)
        )
        .into_bytes()
    }
    fn proof(address: SocketAddr) -> ListenerProof {
        ListenerProof::from_frame(&frame(address.port()), address).unwrap()
    }
    fn request(address: SocketAddr) -> Vec<u8> {
        format!(
            "GET {PATH} HTTP/1.1\r\nHost: {address}\r\nX-AgentShield-Nonce: {}\r\n\r\n",
            "22".repeat(32)
        )
        .into_bytes()
    }
    fn status(response: Option<Vec<u8>>) -> String {
        String::from_utf8(response.unwrap()).unwrap()
    }

    #[test]
    fn independent_python_hmac_vector_and_single_consumption() {
        let proof = proof(address());
        let response = status(proof.response(&request(address()), address()));
        assert!(response.starts_with("HTTP/1.1 200"));
        // Python hmac.new(0x11*32, DOMAIN + 443.to_bytes(2,'big') + 0x22*32, sha256).
        assert!(
            response.contains("3fceebe166407252ab2ec64430d20c29113c2bb4c1121e1fb99c1e87cb7c9d98")
        );
        assert!(!response.contains(&"11".repeat(32)) && !response.contains(&"22".repeat(32)));
        assert!(proof.key.lock().unwrap().is_none());
        assert!(status(proof.response(&request(address()), address())).starts_with("HTTP/1.1 410"));
    }

    #[test]
    fn malformed_or_foreign_requests_cannot_consume_the_valid_challenge() {
        let valid = String::from_utf8(request(address())).unwrap();
        let cases = [
            valid.replace(&"22".repeat(32), &"33".repeat(32)),
            valid.replace("Host: 127.0.0.1:443", "Host: example.invalid"),
            valid.replace("GET ", "POST "),
            valid.replace(
                "\r\n\r\n",
                &format!("\r\nX-AgentShield-Nonce: {}\r\n\r\n", "22".repeat(32)),
            ),
            valid.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx"),
        ];
        for invalid in cases {
            let proof = proof(address());
            assert!(
                status(proof.response(invalid.as_bytes(), address())).starts_with("HTTP/1.1 4")
            );
            assert!(
                status(proof.response(valid.as_bytes(), address())).starts_with("HTTP/1.1 200")
            );
        }
        let proof = proof(address());
        assert!(
            status(proof.response(valid.as_bytes(), "127.0.0.1:444".parse().unwrap()))
                .starts_with("HTTP/1.1 403")
        );
        assert!(status(proof.response(valid.as_bytes(), address())).starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn strict_frame_and_address_binding_never_echo_secret_data_in_errors() {
        let valid = String::from_utf8(frame(443)).unwrap();
        let cases = [
            valid.replace("\"v\":1", "\"v\":2"),
            valid.replace("\"v\":1", "\"v\":true"),
            valid.replace("\"v\":1", "\"v\":1,\"v\":1"),
            valid.replace("\"port\":443", "\"port\":444"),
            valid.replace(&"11".repeat(32), &"11".repeat(31)),
            valid.replace(&"11".repeat(32), &"FF".repeat(32)),
            valid.replace("\"v\":1", "\"v\":1,\"path\":\"forbidden\""),
            " ".repeat(513),
        ];
        for invalid in cases {
            let error = ListenerProof::from_frame(invalid.as_bytes(), address())
                .err()
                .expect("must reject");
            assert!(error.to_string().starts_with("listener_proof_"));
            assert!(!error.to_string().contains(&"11".repeat(32)));
        }
        for endpoint in ["[::1]:443", "127.0.0.2:443", "127.0.0.1:0"] {
            assert!(
                ListenerProof::from_frame(valid.as_bytes(), endpoint.parse().unwrap()).is_err()
            );
        }
    }

    #[test]
    fn local_route_only_and_expiry_drop_key() {
        let mut proof = proof(address());
        let other = request(address())
            .windows(PATH.len())
            .position(|p| p == PATH.as_bytes())
            .unwrap();
        let mut raw = request(address());
        raw[other] = b'x';
        assert!(proof.response(&raw, address()).is_none());
        proof.expires = Instant::now() - Duration::from_secs(1);
        assert!(status(proof.response(&request(address()), address())).starts_with("HTTP/1.1 410"));
        assert!(proof.key.lock().unwrap().is_none());
    }

    #[test]
    fn simultaneous_replay_has_exactly_one_success() {
        let proof = Arc::new(proof(address()));
        let gate = Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let proof = proof.clone();
                let gate = gate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    status(proof.response(&request(address()), address()))
                })
            })
            .collect();
        let responses: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(
            responses
                .iter()
                .filter(|r| r.starts_with("HTTP/1.1 200"))
                .count(),
            1
        );
        assert_eq!(
            responses
                .iter()
                .filter(|r| r.starts_with("HTTP/1.1 410"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn actual_tcp_proof_is_not_audited_or_forwarded_and_normal_policy_stays_active() {
        use crate::{
            policy::config::{Action, PolicyConfig},
            proxy::ProxyServer,
        };
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, TcpStream},
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let (tx, mut audit) = tokio::sync::broadcast::channel(16);
        let server = ProxyServer::new(local.to_string())
            .with_listener_proof(proof(local))
            .with_policy(Arc::new(std::sync::RwLock::new(PolicyConfig {
                default: Action::Deny,
                rules: vec![],
            })))
            .with_event_channel(tx);
        let (_, stop) = server.start_with_listener(listener).await.unwrap();
        async fn send(local: SocketAddr, raw: &[u8]) -> String {
            let mut connection = TcpStream::connect(local).await.unwrap();
            connection.write_all(raw).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(3),
                connection.read_to_end(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            String::from_utf8(response).unwrap()
        }
        assert!(
            send(local, &request(local))
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            send(local, &request(local))
                .await
                .starts_with("HTTP/1.1 410")
        );
        assert!(matches!(
            audit.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(
            send(
                local,
                b"GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
            )
            .await
            .starts_with("HTTP/1.1 403")
        );
        stop.send(true).unwrap();
    }

    #[tokio::test]
    async fn server_rejects_wrong_endpoint_and_key_expires_without_any_request() {
        use crate::proxy::ProxyServer;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        assert!(
            ProxyServer::new(local.to_string())
                .with_listener_proof(proof(address()))
                .start_with_listener(listener)
                .await
                .is_err()
        );
        let mut proof = proof(address());
        proof.expires = Instant::now() - Duration::from_secs(1);
        let proof = Arc::new(proof);
        proof.schedule_expiry();
        tokio::time::timeout(Duration::from_secs(1), async {
            while proof.key.lock().unwrap().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn only_fixed_local_pipe_namespace_and_supported_platform_are_accepted() {
        for path in [
            "file.txt",
            r"\\remote\pipe\AgentShield.ListenerProof.v1.00000000000000000000000000000000",
            r"\\.\pipe\AgentShield.ListenerProof.v1.../elsewhere",
        ] {
            assert_eq!(
                ListenerProof::from_system_pipe(path, address())
                    .err()
                    .unwrap()
                    .to_string(),
                "listener_proof_pipe_name_invalid"
            );
        }
        #[cfg(not(windows))]
        assert_eq!(
            ListenerProof::from_system_pipe(
                &(PIPE_PREFIX.to_string() + &"0".repeat(32)),
                address()
            )
            .err()
            .unwrap()
            .to_string(),
            "listener_proof_requires_windows"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_pipe_tests {
    use super::*;
    use std::{fs::File, os::windows::io::FromRawHandle};
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_OUTBOUND},
        System::Pipes::{CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS},
    };
    #[test]
    #[ignore = "requires non-SYSTEM owner; run explicitly on the ordinary Windows CI runner"]
    fn regular_owner_pipe_is_rejected_before_any_frame_read() {
        let path = format!("{PIPE_PREFIX}{}", uuid::Uuid::new_v4().simple());
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_REJECT_REMOTE_CLIENTS,
                1,
                1024,
                0,
                1000,
                std::ptr::null(),
            )
        };
        assert_ne!(raw, INVALID_HANDLE_VALUE);
        let _server = unsafe { File::from_raw_handle(raw) };
        let error = ListenerProof::from_system_pipe(&path, "127.0.0.1:443".parse().unwrap())
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "listener_proof_pipe_owner_invalid");
    }
}
