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
            .stderr(Stdio::piped())
            // Create a new process group so we can kill all children
            .process_group(0);
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

/// Helper to create a network namespace with a TCP client that connects to the given address.
/// The client sends a message, receives a response, then exits.
fn tcp_client_ns(ip: &str, port: u16, message: &str) -> std::io::Result<UserNetNamespace> {
    let script = format!(
        r#"
python3 -c "
import socket
import sys
sys.stdout.write('READY\\n')
sys.stdout.flush()
import time
time.sleep(0.2)  # Give server time to be ready
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('{ip}', {port}))
sock.sendall(b'{message}')
response = sock.recv(4096)
sock.close()
sys.stdout.write('DONE:' + response.decode() + '\\n')
sys.stdout.flush()
# Keep running briefly for the test to complete
time.sleep(0.5)
"
"#,
        ip = ip,
        port = port,
        message = message,
    );
    UserNetNamespace::new(&script)
}

/// Helper to create a namespace with multiple TCP clients connecting concurrently.
fn tcp_multi_client_ns(
    ip: &str,
    port: u16,
    num_clients: usize,
) -> std::io::Result<UserNetNamespace> {
    let script = format!(
        r#"
python3 -c "
import socket
import sys
import threading
import time

def client_worker(client_id):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('{ip}', {port}))
        msg = f'hello from client {{client_id}}'
        sock.sendall(msg.encode())
        response = sock.recv(4096)
        sock.close()
    except Exception as e:
        pass

sys.stdout.write('READY\\n')
sys.stdout.flush()
time.sleep(0.3)  # Give server time to be ready

threads = []
for i in range({num_clients}):
    t = threading.Thread(target=client_worker, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# Keep running briefly for the test to complete
time.sleep(0.5)
"
"#,
        ip = ip,
        port = port,
        num_clients = num_clients,
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
#[ignore]
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

// ============================================================================
// Socket-Path Mode Tests
// ============================================================================

/// Helper struct to manage the proxy process started with --socket-path
struct ProxyProcess {
    child: Child,
}

impl ProxyProcess {
    fn new(target_pid: u32, socket_path: &str) -> std::io::Result<Self> {
        // Find the proxy binary
        let proxy_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("tap-tunnel-proxy")))
            .filter(|p| p.exists())
            .unwrap_or_else(|| std::path::PathBuf::from("target/debug/tap-tunnel-proxy"));

        let mut cmd = Command::new(&proxy_path);
        cmd.args([
            "--pid",
            &target_pid.to_string(),
            "--socket-path",
            socket_path,
            "--tap-addr",
            "10.0.0.1/24",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Create a new process group so we can kill all children
        .process_group(0);

        let child = cmd.spawn()?;
        Ok(Self { child })
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        kill_process_tree(&mut self.child);
    }
}

#[tokio::test]
async fn test_socket_path_mode_tcp() {
    use std::path::Path;

    // Use a unique socket path in /tmp
    let socket_path = format!("/tmp/tap-tunnel-test-{}.sock", std::process::id());

    // Clean up any existing socket
    let _ = std::fs::remove_file(&socket_path);

    // First, create a namespace with a TCP echo server
    let ns_proc = tcp_echo_server_ns(18100).expect("failed to create namespace");
    let pid = ns_proc.pid();

    // Give the server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Start proxy in socket-path mode, pointing to the namespace
    let _proxy =
        ProxyProcess::new(pid, &socket_path).expect("failed to start proxy in socket-path mode");

    // Wait for socket to be created
    for _ in 0..50 {
        if Path::new(&socket_path).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        Path::new(&socket_path).exists(),
        "socket path not created: {}",
        socket_path
    );

    // Give proxy a moment to start listening
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect to proxy via socket path with auto-configuration
    // The new API performs handshake and receives IP config from proxy
    let tunnel = Tunnel::connect_to(&socket_path, None)
        .await
        .expect("failed to connect to proxy via socket path");

    // Connect to the TCP server
    let server_addr = format!("{}:18100", PEER_IP).parse().unwrap();
    let stream = tunnel
        .tcp_connect(server_addr)
        .await
        .expect("failed to tcp_connect");

    // Send and receive data
    stream
        .write_all(b"socket-path mode works!\n")
        .await
        .expect("write failed");

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.expect("read failed");
    assert_eq!(&buf[..n], b"socket-path mode works!\n");

    // Clean up socket
    let _ = std::fs::remove_file(&socket_path);
}

#[tokio::test]
async fn test_socket_path_mode_requested_ip() {
    use std::path::Path;

    // Use a unique socket path
    let socket_path = format!("/tmp/tap-tunnel-test-reqip-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

    // Create a namespace with a TCP echo server
    let ns_proc = tcp_echo_server_ns(18101).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Start proxy in socket-path mode
    let _proxy =
        ProxyProcess::new(pid, &socket_path).expect("failed to start proxy in socket-path mode");

    // Wait for socket to be created
    for _ in 0..50 {
        if Path::new(&socket_path).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect with a requested IP
    let requested_ip = std::net::Ipv4Addr::new(10, 0, 0, 5);
    let tunnel = Tunnel::connect_to(&socket_path, Some(requested_ip))
        .await
        .expect("failed to connect with requested IP");

    // Connect to the TCP server
    let server_addr = format!("{}:18101", PEER_IP).parse().unwrap();
    let stream = tunnel
        .tcp_connect(server_addr)
        .await
        .expect("failed to tcp_connect");

    // Send and receive data
    stream
        .write_all(b"requested IP works!\n")
        .await
        .expect("write failed");

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.expect("read failed");
    assert_eq!(&buf[..n], b"requested IP works!\n");

    let _ = std::fs::remove_file(&socket_path);
}

// ============================================================================
// TCP Listen/Accept Tests
// ============================================================================

#[tokio::test]
async fn test_tcp_listen_accept() {
    init_logging();

    // Create namespace with a TCP client that will connect to us
    let ns_proc = tcp_client_ns(&LOCAL_IP.to_string(), 19000, "hello server!")
        .expect("failed to create namespace with TCP client");
    let pid = ns_proc.pid();

    // Set up tunnel
    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    // Create listener on the smoltcp stack's address
    let listen_addr = format!("{}:19000", LOCAL_IP).parse().unwrap();
    let listener = tunnel
        .tcp_listen(listen_addr)
        .await
        .expect("failed to create listener");

    assert_eq!(listener.local_addr().port(), 19000);

    // Accept connection from client in namespace
    let accept_result = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;

    let (stream, peer_addr) = accept_result
        .expect("accept timed out")
        .expect("accept failed");

    // Peer should be from the TAP interface subnet
    assert!(peer_addr.ip().to_string().starts_with("10.0.0."));

    // Read the client's message
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.expect("read failed");
    assert_eq!(&buf[..n], b"hello server!");

    // Send response
    stream
        .write_all(b"hello client!")
        .await
        .expect("write failed");
}

#[tokio::test]
async fn test_tcp_listen_multiple_accepts() {
    init_logging();

    // We'll accept multiple sequential connections
    let ns_proc = tcp_multi_client_ns(&LOCAL_IP.to_string(), 19001, 3)
        .expect("failed to create namespace with TCP clients");
    let pid = ns_proc.pid();

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    let listen_addr = format!("{}:19001", LOCAL_IP).parse().unwrap();
    let listener = tunnel
        .tcp_listen(listen_addr)
        .await
        .expect("failed to create listener");

    // Accept 3 connections
    for i in 0..3 {
        let accept_result = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;

        let (stream, _peer_addr) = accept_result
            .unwrap_or_else(|_| panic!("accept {} timed out", i))
            .unwrap_or_else(|_| panic!("accept {} failed", i));

        // Read message
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert!(
            msg.starts_with("hello from client"),
            "unexpected message: {}",
            msg
        );

        // Echo back
        stream.write_all(&buf[..n]).await.expect("write failed");
    }
}

#[tokio::test]
async fn test_tcp_listen_with_backlog() {
    init_logging();

    // Create namespace with multiple clients connecting concurrently
    let ns_proc = tcp_multi_client_ns(&LOCAL_IP.to_string(), 19002, 5)
        .expect("failed to create namespace with TCP clients");
    let pid = ns_proc.pid();

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    // Create listener with backlog of 5
    let listen_addr = format!("{}:19002", LOCAL_IP).parse().unwrap();
    let listener = tunnel
        .tcp_listen_with_backlog(listen_addr, 5)
        .await
        .expect("failed to create listener");

    // Accept all 5 connections (they may come in any order)
    let mut accepted = 0;
    for _ in 0..5 {
        let accept_result = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;

        match accept_result {
            Ok(Ok((stream, _peer_addr))) => {
                accepted += 1;
                // Read and echo back
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
            Ok(Err(e)) => {
                eprintln!("accept error: {}", e);
            }
            Err(_) => {
                // Timeout
                break;
            }
        }
    }

    assert!(
        accepted >= 3,
        "expected at least 3 connections, got {}",
        accepted
    );
}

#[tokio::test]
async fn test_tcp_listener_close() {
    init_logging();

    // Create a simple namespace (just needs to exist for the tunnel)
    let ns_proc = tcp_echo_server_ns(19003).expect("failed to create namespace");
    let pid = ns_proc.pid();

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect to namespace");

    // Create and drop a listener
    {
        let listen_addr = format!("{}:19010", LOCAL_IP).parse().unwrap();
        let _listener = tunnel
            .tcp_listen(listen_addr)
            .await
            .expect("failed to create listener");
        // Listener dropped here, should clean up
    }

    // Small delay for cleanup
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Should be able to create a new listener on the same port
    let listen_addr = format!("{}:19010", LOCAL_IP).parse().unwrap();
    let _listener2 = tunnel
        .tcp_listen(listen_addr)
        .await
        .expect("failed to create second listener on same port");
}

// ============================================================================
// Client-Server Integration Tests
// ============================================================================

/// Test tunnel as server: accepts connection, reads request, sends response.
/// Verifies the complete request-response cycle.
#[tokio::test]
async fn test_tunnel_server_echo() {
    init_logging();

    // Create namespace with a client that sends data and expects echo response
    let ns_proc =
        tcp_client_ns(&LOCAL_IP.to_string(), 19100, "ping").expect("failed to create namespace");
    let pid = ns_proc.pid();

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect");

    let listener = tunnel
        .tcp_listen(format!("{}:19100", LOCAL_IP).parse().unwrap())
        .await
        .expect("failed to listen");

    // Accept and implement echo server
    let (stream, peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accept failed");

    assert!(peer.port() > 0, "peer should have valid port");

    // Read request
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    assert_eq!(&buf[..n], b"ping");

    // Send echo response
    stream.write_all(&buf[..n]).await.expect("write failed");
}

/// Test tunnel as client: connects, sends request, receives response.
/// This complements the server test above.
#[tokio::test]
async fn test_tunnel_client_request_response() {
    // Server in namespace that receives "request" and sends back "response"
    let ns_proc = tcp_request_response_server_ns(19101).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect");

    let stream = tunnel
        .tcp_connect(format!("{}:19101", PEER_IP).parse().unwrap())
        .await
        .expect("failed to connect");

    // Send request
    stream.write_all(b"request").await.expect("write failed");

    // Read response
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    assert_eq!(&buf[..n], b"response:request");
}

/// Test bidirectional data transfer: tunnel server handles multiple
/// request-response exchanges on same connection.
#[tokio::test]
async fn test_tunnel_server_multi_exchange() {
    init_logging();

    let ns_proc = tcp_multi_exchange_client_ns(&LOCAL_IP.to_string(), 19102, 5)
        .expect("failed to create namespace");
    let pid = ns_proc.pid();

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect");

    let listener = tunnel
        .tcp_listen(format!("{}:19102", LOCAL_IP).parse().unwrap())
        .await
        .expect("failed to listen");

    let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accept failed");

    // Handle 5 request-response exchanges
    for i in 0..5 {
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        let request = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(request, format!("msg{}", i), "unexpected request");

        let response = format!("ack{}", i);
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write failed");
    }
}

/// Test tunnel client with large bidirectional transfer.
#[tokio::test]
async fn test_tunnel_client_large_bidirectional() {
    let ns_proc = tcp_echo_server_ns(19103).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect");

    let stream = tunnel
        .tcp_connect(format!("{}:19103", PEER_IP).parse().unwrap())
        .await
        .expect("failed to connect");

    // Send 32KB of data
    let send_data: Vec<u8> = (0..32768).map(|i| (i % 256) as u8).collect();
    stream.write_all(&send_data).await.expect("write failed");

    // Read it all back
    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received.len() < send_data.len() {
        if tokio::time::Instant::now() > deadline {
            panic!(
                "timeout: received {} of {} bytes",
                received.len(),
                send_data.len()
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

    assert_eq!(received.len(), send_data.len());
    assert_eq!(received, send_data);
}

/// Test tunnel server with large bidirectional transfer.
#[tokio::test]
async fn test_tunnel_server_large_bidirectional() {
    init_logging();

    // Client sends 32KB and expects it echoed back
    let ns_proc = tcp_large_echo_client_ns(&LOCAL_IP.to_string(), 19104, 32768)
        .expect("failed to create namespace");
    let pid = ns_proc.pid();

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect");

    let listener = tunnel
        .tcp_listen(format!("{}:19104", LOCAL_IP).parse().unwrap())
        .await
        .expect("failed to listen");

    let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accept failed");

    // Read all data from client
    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received.len() < 32768 {
        if tokio::time::Instant::now() > deadline {
            panic!("timeout reading from client: got {} bytes", received.len());
        }
        let mut buf = [0u8; 8192];
        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read error: {}", e),
            Err(_) => continue,
        }
    }

    assert_eq!(received.len(), 32768, "didn't receive all data from client");

    // Echo it back
    stream.write_all(&received).await.expect("write failed");
}

/// Test concurrent client connections from tunnel.
#[tokio::test]
async fn test_tunnel_concurrent_clients() {
    let ns_proc = tcp_echo_server_ns(19105).expect("failed to create namespace");
    let pid = ns_proc.pid();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let tunnel = Tunnel::connect_with_config(pid, test_config())
        .await
        .expect("failed to connect");

    // Spawn 3 concurrent client tasks
    let mut handles = vec![];
    for i in 0..3 {
        let tunnel = tunnel.clone();
        let handle = tokio::spawn(async move {
            let stream = tunnel
                .tcp_connect(format!("{}:19105", PEER_IP).parse().unwrap())
                .await?;

            let msg = format!("client{}", i);
            stream.write_all(msg.as_bytes()).await?;

            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
        });
        handles.push((i, handle));
    }

    // Verify all clients got their echoed messages
    for (i, handle) in handles {
        let result = handle.await.expect("task panicked");
        let response = result.expect("client failed");
        assert_eq!(response, format!("client{}", i));
    }
}

// ============================================================================
// Helper functions for client-server tests
// ============================================================================

/// Server that receives data and responds with "response:" + data
fn tcp_request_response_server_ns(port: u16) -> std::io::Result<UserNetNamespace> {
    let script = format!(
        r#"
python3 -c "
import socket
import sys
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', {port}))
server.listen(5)
sys.stdout.write('READY\\n')
sys.stdout.flush()
while True:
    conn, _ = server.accept()
    try:
        data = conn.recv(4096)
        if data:
            conn.sendall(b'response:' + data)
    finally:
        conn.close()
"
"#
    );
    UserNetNamespace::new(&script)
}

/// Client that sends numbered messages and expects numbered acks
fn tcp_multi_exchange_client_ns(
    ip: &str,
    port: u16,
    num_exchanges: usize,
) -> std::io::Result<UserNetNamespace> {
    let script = format!(
        r#"
python3 -c "
import socket
import sys
import time
sys.stdout.write('READY\\n')
sys.stdout.flush()
time.sleep(0.3)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('{ip}', {port}))
for i in range({num_exchanges}):
    sock.sendall(f'msg{{i}}'.encode())
    response = sock.recv(64)
    expected = f'ack{{i}}'.encode()
    if response != expected:
        sys.stderr.write(f'Expected {{expected}}, got {{response}}\\n')
        sys.exit(1)
sock.close()
time.sleep(0.3)
"
"#,
        ip = ip,
        port = port,
        num_exchanges = num_exchanges,
    );
    UserNetNamespace::new(&script)
}

/// Client that sends N bytes and expects N bytes echoed back
fn tcp_large_echo_client_ns(ip: &str, port: u16, size: usize) -> std::io::Result<UserNetNamespace> {
    let script = format!(
        r#"
python3 -c "
import socket
import sys
import time
sys.stdout.write('READY\\n')
sys.stdout.flush()
time.sleep(0.3)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect(('{ip}', {port}))
# Send data
data = bytes(i % 256 for i in range({size}))
sock.sendall(data)
# Receive echo
received = b''
while len(received) < {size}:
    chunk = sock.recv(8192)
    if not chunk:
        break
    received += chunk
sock.close()
if received != data:
    sys.stderr.write(f'Data mismatch: sent {{len(data)}}, received {{len(received)}}\\n')
    sys.exit(1)
time.sleep(0.3)
"
"#,
        ip = ip,
        port = port,
        size = size,
    );
    UserNetNamespace::new(&script)
}
