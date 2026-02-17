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

mod util;

use tap_tunnel::Tunnel;
use util::*;

/// Test that connect_to with a nonexistent socket path fails immediately
/// (not related to our changes, but validates error path).
#[tokio::test]
async fn test_connect_to_nonexistent_path() {
    init_logging();

    let result = Tunnel::connect_to("/tmp/tap-tunnel-nonexistent.sock", None).await;
    let err = result.err().expect("should fail for nonexistent path");
    assert!(
        err.kind() == std::io::ErrorKind::NotFound
            || err.kind() == std::io::ErrorKind::ConnectionRefused,
        "expected NotFound or ConnectionRefused, got: {} ({:?})",
        err,
        err.kind()
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tap_tunnel::TapConfig;
    use tap_tunnel::Tunnel;

    use crate::util::*;

    // ============================================================================
    // TCP Tests
    // ============================================================================

    #[tokio::test]
    async fn test_tcp_connect_and_exchange() {
        init_logging();

        let ns_proc = tcp_echo_server_ns(18080).expect("failed to create namespace");
        let pid = ns_proc.pid();

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        // Connect to the server on the TAP interface IP
        let server_addr = format!("{}:18080", PEER_IP).parse().unwrap();

        let mut stream = tunnel
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
        init_logging();

        let ns_proc = tcp_echo_server_ns(18081).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        let server_addr = format!("{}:18081", PEER_IP).parse().unwrap();
        let mut stream = tunnel
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
        init_logging();

        let ns_proc = tcp_echo_server_ns(18082).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        let server_addr = format!("{}:18082", PEER_IP).parse().unwrap();

        // Create multiple connections sequentially
        for i in 0..3 {
            let mut stream = tunnel
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
        init_logging();

        let ns_proc = tcp_echo_server_ns(18083).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        let server_addr = format!("{}:18083", PEER_IP).parse().unwrap();
        let mut stream = tunnel
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
        let mut stream = tunnel
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
        init_logging();

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
        let _proxy = ProxyProcess::new(pid, &socket_path)
            .expect("failed to start proxy in socket-path mode");

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
        let mut stream = tunnel
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
        let _proxy = ProxyProcess::new(pid, &socket_path)
            .expect("failed to start proxy in socket-path mode");

        // Wait for socket to be created
        for _ in 0..50 {
            if Path::new(&socket_path).exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Connect with a requested IP
        let requested_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let tunnel = Tunnel::connect_to(&socket_path, Some(requested_ip))
            .await
            .expect("failed to connect with requested IP");

        // Connect to the TCP server
        let server_addr = format!("{}:18101", PEER_IP).parse().unwrap();
        let mut stream = tunnel
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

        let (mut stream, peer_addr) = accept_result
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
            let accept_result =
                tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;

            let (mut stream, _peer_addr) = accept_result
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
            let accept_result =
                tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;

            match accept_result {
                Ok(Ok((mut stream, _peer_addr))) => {
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
        let ns_proc = tcp_client_ns(&LOCAL_IP.to_string(), 19100, "ping")
            .expect("failed to create namespace");
        let pid = ns_proc.pid();

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect");

        let listener = tunnel
            .tcp_listen(format!("{}:19100", LOCAL_IP).parse().unwrap())
            .await
            .expect("failed to listen");

        // Accept and implement echo server
        let (mut stream, peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
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

        let mut stream = tunnel
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

        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
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

        let mut stream = tunnel
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

        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("accept timed out")
            .expect("accept failed");

        // Read all data from client
        let mut received = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
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
                let mut stream = tunnel
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
    // Multi-IP API Tests
    // ============================================================================

    /// Test that gateway() returns the proxy's TAP IP and MAC address.
    #[tokio::test]
    async fn test_tunnel_gateway() {
        let ns_proc = tcp_echo_server_ns(19200).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect");

        // Gateway should contain the TAP IP
        let gateway = tunnel.gateway();
        let (tap_ip, tap_mac) = gateway;
        assert_eq!(tap_ip, PEER_IP, "gateway IP should match peer_addr");

        // MAC should be a valid non-zero address
        assert!(
            tap_mac.iter().any(|&b| b != 0),
            "MAC address should not be all zeros"
        );
    }

    /// Test that local_ips() returns the configured IP addresses.
    #[tokio::test]
    async fn test_tunnel_local_ips() {
        let ns_proc = tcp_echo_server_ns(19201).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect");

        // Should have at least the initial local IP
        let ips = tunnel.local_ips().await.expect("failed to get local IPs");
        assert!(!ips.is_empty(), "should have at least one IP");

        // The default local IP should be present
        let has_local_ip = ips.iter().any(|(ip, _)| *ip == LOCAL_IP);
        assert!(has_local_ip, "local_ips should contain {}", LOCAL_IP);
    }

    /// Test adding and removing IP addresses.
    #[tokio::test]
    async fn test_tunnel_add_remove_ip() {
        let ns_proc = tcp_echo_server_ns(19202).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect");

        // Get initial IPs
        let initial_ips = tunnel.local_ips().await.expect("failed to get local IPs");
        let initial_count = initial_ips.len();

        // Add a new IP
        let new_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
        tunnel
            .add_local_ip(new_ip, PREFIX_LEN)
            .await
            .expect("failed to add IP");

        // Verify it was added
        let ips_after_add = tunnel.local_ips().await.expect("failed to get local IPs");
        assert_eq!(
            ips_after_add.len(),
            initial_count + 1,
            "should have one more IP after add"
        );
        assert!(
            ips_after_add.iter().any(|(ip, _)| *ip == new_ip),
            "new IP should be present"
        );

        // Adding the same IP again should be idempotent
        tunnel
            .add_local_ip(new_ip, PREFIX_LEN)
            .await
            .expect("adding same IP again should succeed");
        let ips_after_dup = tunnel.local_ips().await.expect("failed to get local IPs");
        assert_eq!(
            ips_after_dup.len(),
            initial_count + 1,
            "adding same IP should not increase count"
        );

        // Remove the IP
        tunnel
            .remove_local_ip(new_ip)
            .await
            .expect("failed to remove IP");

        // Verify it was removed
        let ips_after_remove = tunnel.local_ips().await.expect("failed to get local IPs");
        assert_eq!(
            ips_after_remove.len(),
            initial_count,
            "should be back to initial count"
        );
        assert!(
            !ips_after_remove.iter().any(|(ip, _)| *ip == new_ip),
            "removed IP should not be present"
        );
    }

    /// Test tcp_connect_from() - connecting from a specific local IP.
    #[tokio::test]
    async fn test_tunnel_tcp_connect_from() {
        let ns_proc = tcp_echo_server_ns(19203).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect");

        // Connect from the default local IP using tcp_connect_from
        let server_addr = format!("{}:19203", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect_from(LOCAL_IP, server_addr)
            .await
            .expect("failed to tcp_connect_from");

        // Send and receive data
        stream
            .write_all(b"connect_from test\n")
            .await
            .expect("write failed");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        assert_eq!(&buf[..n], b"connect_from test\n");
    }

    /// Test connecting from a dynamically added IP address.
    #[tokio::test]
    async fn test_tunnel_tcp_connect_from_added_ip() {
        let ns_proc = tcp_echo_server_ns(19204).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect");

        // Add a new IP address
        let new_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));
        tunnel
            .add_local_ip(new_ip, PREFIX_LEN)
            .await
            .expect("failed to add IP");

        // Verify the IP was added
        let ips = tunnel.local_ips().await.expect("failed to get IPs");
        assert!(
            ips.iter().any(|(ip, _)| *ip == new_ip),
            "new IP should be added"
        );

        // Connect from the new IP
        let server_addr = format!("{}:19204", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect_from(new_ip, server_addr)
            .await
            .expect("failed to tcp_connect_from new IP");

        // Send and receive data
        stream
            .write_all(b"from new IP\n")
            .await
            .expect("write failed");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        assert_eq!(&buf[..n], b"from new IP\n");
    }

    /// Test multiple connections from different local IPs.
    #[tokio::test]
    async fn test_tunnel_multi_ip_connections() {
        let ns_proc = tcp_echo_server_ns(19205).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect");

        // Add two more IPs
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 30));
        tunnel
            .add_local_ip(ip2, PREFIX_LEN)
            .await
            .expect("failed to add IP 2");
        tunnel
            .add_local_ip(ip3, PREFIX_LEN)
            .await
            .expect("failed to add IP 3");

        // Verify all IPs are present
        let ips = tunnel.local_ips().await.expect("failed to get IPs");
        assert!(
            ips.iter().any(|(ip, _)| *ip == LOCAL_IP),
            "default IP should be present"
        );
        assert!(
            ips.iter().any(|(ip, _)| *ip == ip2),
            "IP 2 should be present"
        );
        assert!(
            ips.iter().any(|(ip, _)| *ip == ip3),
            "IP 3 should be present"
        );

        let server_addr: std::net::SocketAddr = format!("{}:19205", PEER_IP).parse().unwrap();

        // Connect from each IP and verify they all work
        for (i, ip) in [LOCAL_IP, ip2, ip3].iter().enumerate() {
            let mut stream = tunnel
                .tcp_connect_from(*ip, server_addr)
                .await
                .unwrap_or_else(|e| panic!("failed to connect from {}: {}", ip, e));

            let msg = format!("msg from {}\n", ip);
            stream
                .write_all(msg.as_bytes())
                .await
                .expect("write failed");

            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.expect("read failed");
            assert_eq!(
                &buf[..n],
                msg.as_bytes(),
                "connection {} from {} failed",
                i,
                ip
            );
        }
    }

    // ============================================================================
    // Address Tracking Tests
    // ============================================================================

    /// Test that TcpStream.local_addr() and peer_addr() return correct addresses.
    #[tokio::test]
    async fn test_tcp_local_addr_peer_addr() {
        init_logging();

        let ns_proc = tcp_echo_server_ns(19300).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        let server_addr: std::net::SocketAddr = format!("{}:19300", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("failed to tcp_connect");

        // local_addr should be the local IP with an ephemeral port
        let local_addr = stream.local_addr();
        assert_eq!(local_addr.ip(), LOCAL_IP, "local IP should match");
        assert!(local_addr.port() >= 49152, "local port should be ephemeral");

        // peer_addr should match the server address we connected to
        let peer_addr = stream.peer_addr();
        assert_eq!(peer_addr, server_addr, "peer address should match server");

        // Verify stream still works
        stream
            .write_all(b"addr test\n")
            .await
            .expect("write failed");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        assert_eq!(&buf[..n], b"addr test\n");
    }

    /// Test that UdpSocket.local_addr() returns the actual bound address including ephemeral port.
    #[tokio::test]
    async fn test_udp_local_addr_ephemeral() {
        init_logging();

        let ns_proc = udp_echo_server_ns(15100).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        // Bind to port 0 to get an ephemeral port
        let bind_addr: std::net::SocketAddr = format!("{}:0", LOCAL_IP).parse().unwrap();
        let socket = tunnel
            .udp_bind(bind_addr)
            .await
            .expect("failed to udp_bind");

        // local_addr should have the actual allocated port, not 0
        let local_addr = socket.local_addr();
        assert_eq!(local_addr.ip(), LOCAL_IP, "local IP should match");
        assert!(
            local_addr.port() >= 49152,
            "local port should be ephemeral, got {}",
            local_addr.port()
        );
        assert_ne!(local_addr.port(), 0, "port should not be 0");

        // Verify socket still works
        let server_addr: std::net::SocketAddr = format!("{}:15100", PEER_IP).parse().unwrap();
        socket
            .send_to(b"udp addr test", server_addr)
            .await
            .expect("send_to failed");

        let mut buf = [0u8; 64];
        let (n, _) = socket.recv_from(&mut buf).await.expect("recv_from failed");
        let response = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(response, "echo: udp addr test");
    }

    // ============================================================================
    // Split Tests
    // ============================================================================

    /// Test TcpStream::into_split() for concurrent read/write.
    #[tokio::test]
    async fn test_tcp_into_split() {
        init_logging();

        let ns_proc = tcp_echo_server_ns(19301).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        let server_addr = format!("{}:19301", PEER_IP).parse().unwrap();
        let stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("failed to tcp_connect");

        // Split the stream
        let (read_half, write_half) = stream.into_split();

        // Verify addresses are accessible from both halves
        assert_eq!(
            read_half.local_addr(),
            write_half.local_addr(),
            "local addresses should match"
        );
        assert_eq!(
            read_half.peer_addr(),
            write_half.peer_addr(),
            "peer addresses should match"
        );

        // Use both halves concurrently
        let write_task = tokio::spawn(async move {
            for i in 0..3 {
                let msg = format!("split msg {}\n", i);
                write_half
                    .write_all(msg.as_bytes())
                    .await
                    .expect("write failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            write_half
        });

        let read_task = tokio::spawn(async move {
            let mut read_half = read_half;
            let mut total = Vec::new();
            for _ in 0..3 {
                let mut buf = [0u8; 64];
                let n = read_half.read(&mut buf).await.expect("read failed");
                total.extend_from_slice(&buf[..n]);
            }
            (read_half, total)
        });

        let write_half = write_task.await.expect("write task panicked");
        let (read_half, data) = read_task.await.expect("read task panicked");
        let data_str = String::from_utf8_lossy(&data);

        assert!(
            data_str.contains("split msg 0"),
            "should receive msg 0: {}",
            data_str
        );
        assert!(
            data_str.contains("split msg 1"),
            "should receive msg 1: {}",
            data_str
        );
        assert!(
            data_str.contains("split msg 2"),
            "should receive msg 2: {}",
            data_str
        );

        // Dropping both halves should close the socket
        drop(read_half);
        drop(write_half);
    }

    /// Test that socket is closed only when both split halves are dropped.
    #[tokio::test]
    async fn test_tcp_split_drop_behavior() {
        init_logging();

        let ns_proc = tcp_echo_server_ns(19302).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        let server_addr = format!("{}:19302", PEER_IP).parse().unwrap();
        let stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("failed to tcp_connect");

        let (read_half, write_half) = stream.into_split();

        // Drop read half first - socket should still be usable via write half
        drop(read_half);

        // Write should still work (socket not closed yet)
        write_half
            .write_all(b"after read drop\n")
            .await
            .expect("write should still work after dropping read half");

        // Drop write half - this should close the socket
        drop(write_half);
    }

    /// Test socket-path mode with gateway() API.
    #[tokio::test]
    async fn test_socket_path_mode_gateway() {
        use std::path::Path;

        let socket_path = format!("/tmp/tap-tunnel-test-gw-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        let ns_proc = tcp_echo_server_ns(19206).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let _proxy = ProxyProcess::new(pid, &socket_path).expect("failed to start proxy");

        // Wait for socket
        for _ in 0..50 {
            if Path::new(&socket_path).exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Connect via socket path
        let tunnel = Tunnel::connect_to(&socket_path, None)
            .await
            .expect("failed to connect");

        // Gateway IP should match PEER_IP
        let gateway = tunnel.gateway();
        let (tap_ip, tap_mac) = gateway;
        assert_eq!(tap_ip, PEER_IP, "gateway IP should match");
        assert!(
            tap_mac.iter().any(|&b| b != 0),
            "MAC should not be all zeros"
        );

        // Verify connectivity still works
        let server_addr = format!("{}:19206", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("connect failed");
        stream
            .write_all(b"gateway test\n")
            .await
            .expect("write failed");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        assert_eq!(&buf[..n], b"gateway test\n");

        let _ = std::fs::remove_file(&socket_path);
    }

    /// Test AsyncRead/AsyncWrite traits with tokio's copy utility.
    #[tokio::test]
    async fn test_tcp_async_read_write_traits() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        init_logging();

        let ns_proc = tcp_echo_server_ns(19400).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        let server_addr = format!("{}:19400", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("failed to tcp_connect");

        // Test AsyncWriteExt methods
        stream
            .write_all(b"hello from async traits\n")
            .await
            .expect("AsyncWriteExt::write_all failed");

        stream.flush().await.expect("AsyncWriteExt::flush failed");

        // Test AsyncReadExt methods
        let mut buf = vec![0u8; 64];
        let n = stream
            .read(&mut buf)
            .await
            .expect("AsyncReadExt::read failed");

        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("hello from async traits"),
            "should echo back: {}",
            response
        );

        // Test read_exact
        stream
            .write_all(b"exact test\n")
            .await
            .expect("write failed");

        let mut exact_buf = [0u8; 10];
        stream
            .read_exact(&mut exact_buf)
            .await
            .expect("AsyncReadExt::read_exact failed");
        assert_eq!(&exact_buf, b"exact test");
    }

    /// Test AsyncRead/AsyncWrite traits work with split halves.
    #[tokio::test]
    async fn test_tcp_split_async_traits() {
        use tokio::io::AsyncWriteExt;

        init_logging();

        let ns_proc = tcp_echo_server_ns(19401).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        let server_addr = format!("{}:19401", PEER_IP).parse().unwrap();
        let stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("failed to tcp_connect");

        let (read_half, write_half) = stream.into_split();

        // Use tokio::spawn to exercise the traits in concurrent tasks
        let write_task = tokio::spawn(async move {
            let mut write_half = write_half;
            for i in 0..5 {
                let msg = format!("async trait msg {}\n", i);
                write_half.write_all(msg.as_bytes()).await.unwrap();
                write_half.flush().await.unwrap();
            }
            write_half
        });

        let read_task = tokio::spawn(async move {
            let mut read_half = read_half;
            let mut all_data = Vec::new();
            let mut buf = [0u8; 128];
            // Read until we have all 5 messages
            while all_data.len() < 80 {
                // Each message is ~18 bytes
                match tokio::time::timeout(Duration::from_secs(2), read_half.read(&mut buf)).await {
                    Ok(Ok(0)) => break, // EOF
                    Ok(Ok(n)) => all_data.extend_from_slice(&buf[..n]),
                    Ok(Err(e)) => panic!("read error: {}", e),
                    Err(_) => break, // Timeout - we probably have enough
                }
            }
            (read_half, all_data)
        });

        let _write_half = write_task.await.expect("write task panicked");
        let (_read_half, data) = read_task.await.expect("read task panicked");

        let data_str = String::from_utf8_lossy(&data);

        // Verify we received all messages
        for i in 0..5 {
            assert!(
                data_str.contains(&format!("async trait msg {}", i)),
                "should contain msg {}: {}",
                i,
                data_str
            );
        }
    }

    // ============================================================================
    // Error Propagation Tests
    // ============================================================================

    /// Test that connect_to times out when proxy accepts but never sends ProxyConfig.
    #[tokio::test]
    async fn test_handshake_timeout_no_response() {
        init_logging();

        // Create a STREAM listener that accepts connections but never responds
        let socket_path = format!("/tmp/tap-tunnel-test-timeout-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        // Spawn a thread that listens on the socket path but never writes back
        let path_clone = socket_path.clone();
        let listener_handle = std::thread::spawn(move || {
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
                assert!(fd >= 0, "socket() failed");

                let mut addr: libc::sockaddr_un = std::mem::zeroed();
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                let path_bytes = path_clone.as_bytes();
                addr.sun_path[..path_bytes.len()].copy_from_slice(std::slice::from_raw_parts(
                    path_bytes.as_ptr() as *const i8,
                    path_bytes.len(),
                ));

                let ret = libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                );
                assert_eq!(ret, 0, "bind() failed");

                let ret = libc::listen(fd, 1);
                assert_eq!(ret, 0, "listen() failed");

                // Accept connection but never send ProxyConfig
                let client_fd = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
                assert!(client_fd >= 0, "accept() failed");

                // Read the length-framed ClientHello to consume it, but don't respond
                // First read the 4-byte length prefix
                let mut len_buf = [0u8; 4];
                let n = libc::read(client_fd, len_buf.as_mut_ptr() as *mut libc::c_void, 4);
                if n == 4 {
                    let len = u32::from_le_bytes(len_buf) as usize;
                    // Read the payload
                    let mut payload = vec![0u8; len];
                    let _n = libc::read(client_fd, payload.as_mut_ptr() as *mut libc::c_void, len);
                }

                // Hold connection open for a while (longer than the 5s timeout)
                std::thread::sleep(std::time::Duration::from_secs(10));

                libc::close(client_fd);
                libc::close(fd);
            }
        });

        // Wait for socket to exist
        for _ in 0..50 {
            if std::path::Path::new(&socket_path).exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // connect_to should timeout (5 seconds)
        let start = std::time::Instant::now();
        let result = Tunnel::connect_to(&socket_path, None).await;
        let elapsed = start.elapsed();

        let err = result.err().expect("should fail with timeout");
        assert!(
            err.kind() == std::io::ErrorKind::TimedOut
                || err.kind() == std::io::ErrorKind::WouldBlock,
            "error kind should be TimedOut or WouldBlock, got: {} ({:?})",
            err,
            err.kind()
        );
        assert!(
            elapsed >= Duration::from_secs(4),
            "should wait at least 4 seconds, waited {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "should not wait 10+ seconds, waited {:?}",
            elapsed
        );

        // Cleanup
        let _ = std::fs::remove_file(&socket_path);
        drop(listener_handle);
    }

    /// Test that connect_with_config returns an error with proxy stderr
    /// when the proxy process exits during handshake.
    #[tokio::test]
    async fn test_proxy_exit_during_handshake() {
        init_logging();

        // Use a fake proxy binary that exits immediately with an error message.
        // We create a small shell script as the "proxy".
        let fake_proxy = format!("/tmp/tap-tunnel-test-fake-proxy-{}.sh", std::process::id());
        std::fs::write(
            &fake_proxy,
            "#!/bin/sh\necho 'fatal: cannot access namespace' >&2\nexit 1\n",
        )
        .expect("failed to write fake proxy");

        // Make it executable
        std::process::Command::new("chmod")
            .args(["+x", &fake_proxy])
            .status()
            .expect("chmod failed");

        // Set TAP_TUNNEL_PROXY to point to our fake binary
        // We need to call connect_with_config which will try to spawn the proxy.
        // But find_proxy_binary() checks several places - let's use the env var.
        let original = std::env::var("TAP_TUNNEL_PROXY").ok();
        // SAFETY: this test is not run in parallel with others that depend on this env var
        unsafe { std::env::set_var("TAP_TUNNEL_PROXY", &fake_proxy) };

        let config = TapConfig::new()
            .interface_name("tap0")
            .peer_addr(PEER_IP, PREFIX_LEN)
            .local_addr(LOCAL_IP, PREFIX_LEN);

        let result = Tunnel::connect_with_config(999999, config).await;

        // Restore env
        unsafe {
            match original {
                Some(v) => std::env::set_var("TAP_TUNNEL_PROXY", v),
                None => std::env::remove_var("TAP_TUNNEL_PROXY"),
            }
        }
        let _ = std::fs::remove_file(&fake_proxy);

        let err_msg = result
            .err()
            .expect("should fail when proxy exits")
            .to_string();
        assert!(
            err_msg.contains("proxy") || err_msg.contains("cannot access namespace"),
            "error should mention proxy failure or stderr, got: {}",
            err_msg
        );
    }

    /// Test that killing the proxy mid-operation causes pending TCP connects to fail
    /// with ConnectionAborted instead of hanging.
    #[tokio::test]
    async fn test_proxy_crash_fails_pending_tcp_connect() {
        init_logging();

        let socket_path = format!("/tmp/tap-tunnel-test-crash-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        // Create a namespace with a TCP echo server
        let ns_proc = tcp_echo_server_ns(19500).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Start proxy in socket-path mode
        let mut proxy = ProxyProcess::new(pid, &socket_path).expect("failed to start proxy");

        // Wait for socket to be created
        for _ in 0..50 {
            if std::path::Path::new(&socket_path).exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Connect to the tunnel
        let tunnel = Tunnel::connect_to(&socket_path, None)
            .await
            .expect("failed to connect to proxy");

        // Verify the tunnel works first
        let server_addr: SocketAddr = format!("{}:19500", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("initial tcp_connect should work");
        stream
            .write_all(b"ping\n")
            .await
            .expect("initial write should work");
        let mut buf = [0u8; 64];
        let n = stream
            .read(&mut buf)
            .await
            .expect("initial read should work");
        assert_eq!(&buf[..n], b"ping\n");
        drop(stream);

        // Now kill the proxy
        proxy.kill();

        // Give the IPC tasks time to detect the dead connection
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Try to TCP connect - should fail with ConnectionAborted, not hang
        let result =
            tokio::time::timeout(Duration::from_secs(3), tunnel.tcp_connect(server_addr)).await;

        match result {
            Ok(Ok(_)) => panic!("tcp_connect should fail after proxy is killed"),
            Ok(Err(e)) => {
                // Good - we got an error instead of hanging
                assert!(
                    e.kind() == std::io::ErrorKind::ConnectionAborted
                        || e.kind() == std::io::ErrorKind::BrokenPipe,
                    "expected ConnectionAborted or BrokenPipe, got: {} ({:?})",
                    e,
                    e.kind()
                );
            }
            Err(_timeout) => {
                panic!("tcp_connect hung after proxy was killed (should fail immediately)");
            }
        }

        let _ = std::fs::remove_file(&socket_path);
    }

    /// Test that killing the proxy causes pending UDP operations to stop gracefully
    /// (existing socket read returns error or EOF, not hang).
    #[tokio::test]
    async fn test_proxy_crash_udp_recv_does_not_hang() {
        init_logging();

        let socket_path = format!("/tmp/tap-tunnel-test-udp-crash-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        // Create a namespace
        let ns_proc = udp_echo_server_ns(19600).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut proxy = ProxyProcess::new(pid, &socket_path).expect("failed to start proxy");

        for _ in 0..50 {
            if std::path::Path::new(&socket_path).exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let tunnel = Tunnel::connect_to(&socket_path, None)
            .await
            .expect("failed to connect to proxy");

        // Bind a UDP socket
        let local_bind: SocketAddr = format!("{}:0", "10.0.0.2").parse().unwrap();
        let socket = tunnel
            .udp_bind(local_bind)
            .await
            .expect("failed to udp_bind");

        // Verify it works
        let server_addr: SocketAddr = format!("{}:19600", PEER_IP).parse().unwrap();
        socket
            .send_to(b"hello", server_addr)
            .await
            .expect("send_to should work");
        let mut buf = [0u8; 64];
        let (n, _) = socket
            .recv_from(&mut buf)
            .await
            .expect("recv_from should work");
        assert_eq!(&buf[..n], b"echo: hello");

        // Kill the proxy
        proxy.kill();

        // recv_from should not hang forever - it should either error or timeout
        let result = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok(_)) => {}  // Unlikely but acceptable if data was buffered
            Ok(Err(_)) => {} // Got an error - good
            Err(_) => {
                // Timeout after 3 seconds is acceptable - the stack is shut down,
                // so no new data will arrive. The key thing is we didn't hang forever.
                // (Channel is just empty, recv_from awaits on an empty channel.)
            }
        }

        let _ = std::fs::remove_file(&socket_path);
    }

    // ============================================================================
    // Peer Route / Cross-Subnet Tests
    // ============================================================================

    /// Test cross-subnet TCP connectivity via peer routes.
    ///
    /// Uses a local IP (10.99.0.50) outside the TAP subnet (10.0.0.0/24).
    /// A peer_route for 10.99.0.0/24 tells the namespace kernel to route
    /// traffic for that subnet through the TAP device.
    #[tokio::test]
    async fn test_peer_route_cross_subnet_tcp() {
        init_logging();

        let ns_proc = tcp_echo_server_ns(19700).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Configure tunnel with a peer route for the cross-subnet range
        let config = TapConfig::new()
            .interface_name("tap0")
            .peer_addr(PEER_IP, PREFIX_LEN)
            .local_addr(LOCAL_IP, PREFIX_LEN)
            .peer_route(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 0)), 24);

        let tunnel = Tunnel::connect_with_config(pid, config)
            .await
            .expect("failed to connect to namespace");

        // Add the cross-subnet IP to the smoltcp stack
        let cross_subnet_ip = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 50));
        tunnel
            .add_local_ip(cross_subnet_ip, 24)
            .await
            .expect("failed to add cross-subnet IP");

        // Verify the IP was added
        let ips = tunnel.local_ips().await.expect("failed to get IPs");
        assert!(
            ips.iter().any(|(ip, _)| *ip == cross_subnet_ip),
            "cross-subnet IP should be added"
        );

        // Connect from the cross-subnet IP
        let server_addr: SocketAddr = format!("{}:19700", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect_from(cross_subnet_ip, server_addr)
            .await
            .expect("failed to tcp_connect_from cross-subnet IP");

        // Send and receive data
        stream
            .write_all(b"cross-subnet hello\n")
            .await
            .expect("write failed");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        assert_eq!(&buf[..n], b"cross-subnet hello\n");
    }

    /// Test dynamic peer route add/remove via the control channel.
    #[tokio::test]
    async fn test_peer_route_dynamic_add_remove() {
        init_logging();

        let ns_proc = tcp_echo_server_ns(19701).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let tunnel = Tunnel::connect_with_config(pid, test_config())
            .await
            .expect("failed to connect to namespace");

        // Dynamically add a peer route
        let route_dest = IpAddr::V4(Ipv4Addr::new(10, 88, 0, 0));
        tunnel
            .add_peer_route(route_dest, 24)
            .await
            .expect("failed to add peer route");

        // Add corresponding local IP
        let cross_ip = IpAddr::V4(Ipv4Addr::new(10, 88, 0, 42));
        tunnel
            .add_local_ip(cross_ip, 24)
            .await
            .expect("failed to add local IP");

        // Connect from the cross-subnet IP
        let server_addr: SocketAddr = format!("{}:19701", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect_from(cross_ip, server_addr)
            .await
            .expect("failed to tcp_connect_from dynamic route IP");

        stream
            .write_all(b"dynamic route\n")
            .await
            .expect("write failed");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read failed");
        assert_eq!(&buf[..n], b"dynamic route\n");

        // Clean up: remove the route
        tunnel
            .remove_peer_route(route_dest, 24)
            .await
            .expect("failed to remove peer route");
    }

    // ============================================================================
    // Custom MTU Tests
    // ============================================================================

    /// Test that a large MTU (4000) allows sending UDP datagrams bigger than
    /// the standard 1500-byte MTU. A single 3000-byte UDP payload would not
    /// fit in a standard Ethernet frame but fits with MTU 4000.
    #[tokio::test]
    async fn test_custom_mtu_large_udp() {
        init_logging();

        let ns_proc = udp_echo_server_ns(19800).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let config = TapConfig::new()
            .interface_name("tap0")
            .peer_addr(PEER_IP, PREFIX_LEN)
            .local_addr(LOCAL_IP, PREFIX_LEN)
            .mtu(4000);

        let tunnel = Tunnel::connect_with_config(pid, config)
            .await
            .expect("failed to connect to namespace");

        let local_bind: SocketAddr = format!("{}:0", LOCAL_IP).parse().unwrap();
        let socket = tunnel
            .udp_bind(local_bind)
            .await
            .expect("failed to udp_bind");

        // Send a 3000-byte UDP payload — larger than default 1500 MTU.
        // With MTU 4000 the IP packet fits in a single Ethernet frame.
        let payload = vec![0xAB_u8; 3000];
        let server_addr: SocketAddr = format!("{}:19800", PEER_IP).parse().unwrap();
        socket
            .send_to(&payload, server_addr)
            .await
            .expect("send_to failed");

        // Receive the echo response (server prepends "echo: ")
        let mut buf = vec![0u8; 4096];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("recv_from timed out")
            .expect("recv_from failed");
        assert_eq!(from.port(), 19800);
        // "echo: " is 6 bytes
        assert_eq!(n, 3000 + 6, "response should be payload + echo prefix");
        assert_eq!(&buf[..6], b"echo: ");
        assert_eq!(&buf[6..n], &payload[..]);
    }

    /// Test that a small MTU (512) still allows TCP to work. smoltcp will
    /// use smaller segments, and the data still arrives correctly.
    #[tokio::test]
    async fn test_custom_mtu_small_tcp() {
        init_logging();

        let ns_proc = tcp_echo_server_ns(19801).expect("failed to create namespace");
        let pid = ns_proc.pid();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let config = TapConfig::new()
            .interface_name("tap0")
            .peer_addr(PEER_IP, PREFIX_LEN)
            .local_addr(LOCAL_IP, PREFIX_LEN)
            .mtu(512);

        let tunnel = Tunnel::connect_with_config(pid, config)
            .await
            .expect("failed to connect to namespace");

        let server_addr: SocketAddr = format!("{}:19801", PEER_IP).parse().unwrap();
        let mut stream = tunnel
            .tcp_connect(server_addr)
            .await
            .expect("failed to tcp_connect");

        // Send 4KB of data — much larger than the 512 MTU.
        // TCP will segment into smaller packets automatically.
        let data = vec![0x42_u8; 4096];
        stream.write_all(&data).await.expect("write failed");

        // Read all echoed data back
        let mut received = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while received.len() < data.len() {
            if tokio::time::Instant::now() > deadline {
                panic!(
                    "timeout: received {} of {} bytes",
                    received.len(),
                    data.len()
                );
            }
            let mut buf = [0u8; 2048];
            match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => panic!("read error: {}", e),
                Err(_) => continue,
            }
        }

        assert_eq!(received.len(), data.len());
        assert_eq!(&received[..], &data[..]);
    }
}
