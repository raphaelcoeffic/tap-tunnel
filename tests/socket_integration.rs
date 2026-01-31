//! Integration tests for the Tunnel socket API.
//!
//! These tests create real network namespaces and verify TCP/UDP functionality
//! using smoltcp as the userspace TCP/IP stack.
//!
//! # Architecture
//!
//! ```text
//! Test Process                │  Target Namespace
//! ────────────────────────────┼───────────────────────
//! smoltcp stack               │  TAP interface (tap0)
//! local_addr: 10.0.0.2/24     │  peer_addr: 10.0.0.1/24
//!                             │  Python server on 10.0.0.1:port
//! ```
//!
//! # Running Tests
//!
//! ```bash
//! cargo test --test socket_integration
//! ```

use std::io::Read;
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tap_tunnel::{TapConfig, Tunnel};

/// Kill a process and all its children using process group.
fn kill_process_tree(child: &mut Child) {
    let pid = child.id() as i32;
    // Kill the entire process group (negative PID)
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    // Also kill the process directly in case it's not the group leader
    let _ = child.kill();
    let _ = child.wait();
}

struct UserNetNamespace {
    child: Child,
    pid: u32,
}

impl UserNetNamespace {
    fn new(script: &str) -> std::io::Result<Self> {
        let mut cmd = Command::new("unshare");
        cmd.args(["--user", "--net", "--map-root-user", "sh", "-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Create a new process group so we can kill all children
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut child = cmd.spawn()?;
        let pid = child.id();

        // Wait for "READY"
        let stdout = child.stdout.as_mut().unwrap();
        let mut buf = [0u8; 64];
        let mut total = 0;
        loop {
            let n = stdout.read(&mut buf[total..])?;
            if n == 0 {
                // Check stderr for error
                let mut stderr_buf = [0u8; 1024];
                let stderr = child.stderr.as_mut().unwrap();
                let n = stderr.read(&mut stderr_buf).unwrap_or(0);
                let stderr_msg = String::from_utf8_lossy(&stderr_buf[..n]);
                return Err(std::io::Error::other(format!(
                    "namespace exited before ready: {}",
                    stderr_msg
                )));
            }
            total += n;
            if String::from_utf8_lossy(&buf[..total]).contains("READY") {
                break;
            }
            if total >= buf.len() {
                return Err(std::io::Error::other(format!(
                    "unexpected output: {}",
                    String::from_utf8_lossy(&buf[..total])
                )));
            }
        }

        Ok(Self { child, pid })
    }

    fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for UserNetNamespace {
    fn drop(&mut self) {
        kill_process_tree(&mut self.child);
    }
}

/// Default TAP interface IP (peer side, in namespace)
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// Default smoltcp stack IP (local side, in test process)
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// Subnet prefix length
const PREFIX_LEN: u8 = 24;

/// Helper to create a network namespace with a TCP echo server.
/// The server listens on the TAP interface IP.
fn tcp_echo_server_ns(port: u16) -> std::io::Result<UserNetNamespace> {
    let script = format!(
        r#"
python3 -c "
import socket
import sys
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Listen on 0.0.0.0 to accept connections on any interface (including tap0)
server.bind(('0.0.0.0', {port}))
server.listen(5)
sys.stdout.write('READY\\n')
sys.stdout.flush()
while True:
    conn, _ = server.accept()
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
    except:
        pass
    finally:
        conn.close()
"
"#
    );
    UserNetNamespace::new(&script)
}

/// Helper to create a network namespace with a UDP echo server.
/// The server listens on the TAP interface IP.
fn udp_echo_server_ns(port: u16) -> std::io::Result<UserNetNamespace> {
    let script = format!(
        r#"
python3 -c "
import socket
import sys
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Listen on 0.0.0.0 to accept packets on any interface (including tap0)
server.bind(('0.0.0.0', {port}))
sys.stdout.write('READY\\n')
sys.stdout.flush()
while True:
    data, addr = server.recvfrom(65536)
    server.sendto(b'echo: ' + data, addr)
"
"#
    );
    UserNetNamespace::new(&script)
}

/// Create default TapConfig for tests
fn test_config() -> TapConfig {
    TapConfig::new()
        .interface_name("tap0")
        .peer_addr(PEER_IP, PREFIX_LEN)
        .local_addr(LOCAL_IP, PREFIX_LEN)
}

use std::sync::Once;

static INIT: Once = Once::new();

fn init_logging() {
    INIT.call_once(env_logger::init);
}

// ============================================================================
// TCP Tests
// ============================================================================

#[tokio::test]
async fn test_tcp_connect_and_exchange() {
    let ns_proc = tcp_echo_server_ns(18080).expect("failed to create namespace");
    let pid = ns_proc.pid();

    // Give the server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    // Connect to the server on the TAP interface IP
    let server_addr = format!("{}:18080", PEER_IP).parse().unwrap();

    let stream = tunnel
        .tcp_connect(server_addr)
        .await
        .expect("failed to tcp_connect");

    // Send data
    stream
        .write_all(b"hello world\n")
        .await
        .expect("write failed");

    // Read response
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.expect("read failed");
    assert_eq!(&buf[..n], b"hello world\n");
}

#[tokio::test]
async fn test_tcp_multiple_messages() {
    let ns_proc = tcp_echo_server_ns(18081).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    let server_addr = format!("{}:18081", PEER_IP).parse().unwrap();
    let stream = tunnel
        .tcp_connect(server_addr)
        .await
        .expect("failed to tcp_connect");

    // Send and receive multiple messages
    for i in 0..5 {
        let msg = format!("message {}\n", i);
        stream
            .write_all(msg.as_bytes())
            .await
            .expect("write failed");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        let response = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(response, format!("message {}\n", i));
    }
}

#[tokio::test]
async fn test_tcp_multiple_connections() {
    let ns_proc = tcp_echo_server_ns(18082).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    let server_addr = format!("{}:18082", PEER_IP).parse().unwrap();

    // Create multiple connections sequentially
    for i in 0..3 {
        let stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("failed to connect");

        let msg = format!("conn {}\n", i);
        stream
            .write_all(msg.as_bytes())
            .await
            .expect("write failed");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        let response = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(response, format!("conn {}\n", i));
    }
}

#[tokio::test]
async fn test_tcp_large_transfer() {
    let ns_proc = tcp_echo_server_ns(18083).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    let server_addr = format!("{}:18083", PEER_IP).parse().unwrap();
    let stream = tunnel
        .tcp_connect(server_addr)
        .await
        .expect("failed to connect");

    // Send 64KB of data
    let data: Vec<u8> = vec![35u8; 65536];
    stream.write_all(&data).await.expect("write failed");

    // Read response (server adds "echo: " prefix)
    let mut received = Vec::new();
    let expected_len = data.len();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while received.len() < expected_len {
        if tokio::time::Instant::now() > deadline {
            panic!(
                "timeout: received {} of {} bytes",
                received.len(),
                expected_len
            );
        }

        let mut buf = [0u8; 8192];
        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read error: {}", e),
            Err(_) => continue,
        }
    }

    assert_eq!(received.len(), expected_len);
    assert_eq!(&received[..], &data[..]);
}

/// Test that TCP retransmissions work correctly under packet loss.
/// This verifies smoltcp's TCP implementation handles lost packets properly.
///
/// Note: FaultInjector applies packet loss to both TX and RX, so 5% configured
/// loss results in approximately 10% effective loss on the connection.
#[tokio::test]
async fn test_tcp_retransmission_with_packet_loss() {
    init_logging();

    let ns_proc = tcp_echo_server_ns(18090).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Configure 5% packet loss - FaultInjector affects both directions,
    // so effective loss is ~10%. Keep it low to avoid TCP handshake delays.
    let config = TapConfig::new()
        .interface_name("tap0")
        .peer_addr(PEER_IP, PREFIX_LEN)
        .local_addr(LOCAL_IP, PREFIX_LEN)
        .packet_loss_percent(4);

    let tunnel = Tunnel::connect_with_config(pid, config)
        .await
        .expect("failed to connect to namespace");

    let server_addr: std::net::SocketAddr = format!("{}:18090", PEER_IP).parse().unwrap();
    let stream = tunnel
        .tcp_connect(server_addr)
        .await
        .expect("failed to connect");

    // Send multiple messages - with packet loss, some will need retransmission
    // TCP guarantees delivery, so all messages should eventually arrive correctly
    for i in 0..3 {
        let msg = format!("message {}\n", i);

        stream
            .write_all(msg.as_bytes())
            .await
            .expect("write failed");

        // Read until we get all expected bytes (TCP echo server returns data unchanged)
        let mut buf = [0u8; 64];
        let mut total = 0;
        while total < msg.len() {
            let n = stream.read(&mut buf[total..]).await.expect("read failed");
            if n == 0 {
                panic!("connection closed before receiving full response");
            }
            total += n;
        }

        let response = String::from_utf8_lossy(&buf[..total]);
        assert_eq!(response, msg, "message {} mismatch", i);
    }

    stream.close();
}

// ============================================================================
// UDP Tests
// ============================================================================

#[tokio::test]
async fn test_udp_send_recv() {
    let ns_proc = udp_echo_server_ns(15000).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    // Bind UDP socket on local address
    let local_bind: std::net::SocketAddr = format!("{}:0", LOCAL_IP).parse().unwrap();
    let socket = tunnel
        .udp_bind(local_bind)
        .await
        .expect("failed to udp_bind");

    // Send data to server
    let server_addr: std::net::SocketAddr = format!("{}:15000", PEER_IP).parse().unwrap();
    socket
        .send_to(b"hello udp", server_addr)
        .await
        .expect("send_to failed");

    // Receive response
    let mut buf = [0u8; 64];
    let (n, from) = socket.recv_from(&mut buf).await.expect("recv_from failed");
    let response = String::from_utf8_lossy(&buf[..n]);
    assert_eq!(response, "echo: hello udp");
    assert_eq!(from.port(), 15000);
}

#[tokio::test]
async fn test_udp_multiple_messages() {
    let ns_proc = udp_echo_server_ns(15002).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    let local_bind: std::net::SocketAddr = format!("{}:0", LOCAL_IP).parse().unwrap();
    let socket = tunnel
        .udp_bind(local_bind)
        .await
        .expect("failed to udp_bind");

    let server_addr: std::net::SocketAddr = format!("{}:15002", PEER_IP).parse().unwrap();

    for i in 0..5 {
        let msg = format!("msg {}", i);
        socket
            .send_to(msg.as_bytes(), server_addr)
            .await
            .expect("send_to failed");

        let mut buf = [0u8; 64];
        let (n, _) = socket.recv_from(&mut buf).await.expect("recv_from failed");
        let response = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(response, format!("echo: msg {}", i));
    }
}
