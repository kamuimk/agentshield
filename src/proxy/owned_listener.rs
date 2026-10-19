//! Windows listener handoff. No capability bytes are logged or persisted.
use std::io;

#[cfg(not(windows))]
pub fn from_private_stdin(_expected: &str) -> io::Result<tokio::net::TcpListener> {
    Err(io::Error::other("owned_listener_requires_windows"))
}

#[cfg(windows)]
pub fn from_private_stdin(expected: &str) -> io::Result<tokio::net::TcpListener> {
    use std::{
        io::Read,
        mem::{size_of, zeroed},
        net::{SocketAddr, TcpListener},
        os::windows::io::FromRawSocket,
        sync::OnceLock,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Networking::WinSock::*,
        System::{
            Console::{GetStdHandle, STD_INPUT_HANDLE},
            Pipes::PeekNamedPipe,
        },
    };
    fn rejected(stage: &'static str) -> io::Error {
        io::Error::other(stage)
    }
    let expected: SocketAddr = expected
        .parse()
        .map_err(|_| rejected("owned_listener_address_invalid"))?;
    if !expected.is_ipv4() || expected.ip() != std::net::Ipv4Addr::LOCALHOST || expected.port() == 0
    {
        return Err(rejected("owned_listener_address_invalid"));
    }
    // CPython socket.share returns exactly WSAPROTOCOL_INFOW. Input is only
    // accepted from the trusted controller's dedicated pipe with a short budget.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut input = io::stdin().lock();
    let mut read = |buffer: &mut [u8]| -> io::Result<()> {
        loop {
            let mut available = 0;
            // No pointer from the handoff is used as a buffer or process handle.
            let ok = unsafe {
                PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(rejected("owned_listener_pipe_invalid"));
            }
            if available as usize >= buffer.len() {
                return input
                    .read_exact(buffer)
                    .map_err(|_| rejected("owned_listener_pipe_truncated"));
            }
            if Instant::now() >= deadline {
                return Err(rejected("owned_listener_pipe_timeout"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let mut length = [0; 4];
    read(&mut length)?;
    if u32::from_le_bytes(length) as usize != size_of::<WSAPROTOCOL_INFOW>() {
        return Err(rejected("owned_listener_frame_invalid"));
    }
    let mut info: WSAPROTOCOL_INFOW = unsafe { zeroed() };
    // The destination is aligned, initialized and exactly the native struct size.
    let buffer = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut info as *mut WSAPROTOCOL_INFOW).cast::<u8>(),
            size_of::<WSAPROTOCOL_INFOW>(),
        )
    };
    read(buffer)?;
    if info.iAddressFamily != AF_INET as i32
        || info.iSocketType != SOCK_STREAM
        || info.iProtocol != IPPROTO_TCP
    {
        return Err(rejected("owned_listener_protocol_invalid"));
    }
    // Winsock initialization is held for this process lifetime, matching std's
    // process-wide networking initialization. OS teardown releases that reference.
    static WINSOCK: OnceLock<i32> = OnceLock::new();
    if *WINSOCK.get_or_init(|| unsafe {
        let mut data: WSADATA = zeroed();
        WSAStartup(0x0202, &mut data)
    }) != 0
    {
        return Err(rejected("owned_listener_winsock_unavailable"));
    }
    let raw = unsafe {
        WSASocketW(
            FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO,
            &info,
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if raw == INVALID_SOCKET {
        return Err(rejected("owned_listener_import_failed"));
    }
    // Ownership transfers immediately; every later failure closes this descriptor.
    let listener = unsafe { TcpListener::from_raw_socket(raw as _) };
    for (option, required) in [(SO_EXCLUSIVEADDRUSE, 1), (SO_ACCEPTCONN, 1)] {
        let mut value: i32 = 0;
        let mut length = size_of::<i32>() as i32;
        let code = unsafe {
            getsockopt(
                raw,
                SOL_SOCKET,
                option,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        };
        if code != 0 || length != size_of::<i32>() as i32 || value != required {
            return Err(rejected("owned_listener_socket_invalid"));
        }
    }
    if listener.local_addr()? != expected {
        return Err(rejected("owned_listener_address_mismatch"));
    }
    listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(listener)
}

#[cfg(all(test, not(windows)))]
mod tests {
    #[test]
    fn native_import_is_rejected_off_windows() {
        assert!(
            super::from_private_stdin("127.0.0.1:1234")
                .unwrap_err()
                .to_string()
                .contains("requires_windows")
        );
    }
}
