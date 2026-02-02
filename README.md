# tap-tunnel

A Rust library for sending and receiving IP packets to/from a network namespace
via a TAP interface, and creating TCP/UDP sockets within the namespace. No special
capabilities required - leverages the target's user namespace.

## Features

- **Unified API**: Single `Tunnel` type provides both raw packet and socket access
- **Raw Packets**: Send/receive IP packets via a TAP interface
- **Sockets**: Create TCP/UDP sockets that work within the namespace
- No fork() - uses a spawned helper binary for clean async support
- Works with any process that has a user namespace (containers, unprivileged namespaces)

## Usage

```rust
use tap_tunnel::{TapConfig, Tunnel};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Connect to the network namespace of PID 1234
    // Configures tap0 with 10.0.0.1/24 inside the namespace
    let config = TapConfig::new().address(Ipv4Addr::new(10, 0, 0, 1), 24);
    let tunnel = Tunnel::connect_with_config(1234, config).await?;

    // Raw packet access
    let mut buf = [0u8; 1500];
    let n = tunnel.recv(&mut buf).await?;
    tunnel.send(&buf[..n]).await?;

    // TCP client
    let mut tcp = tunnel.tcp_connect("10.0.0.100:8080").await?;
    tcp.write_all(b"hello\n").await?;

    // UDP
    let udp = tunnel.udp_bind("10.0.0.1:0").await?;
    udp.send_to(b"ping", "10.0.0.100:5000".parse()?).await?;

    // TCP server
    let listener = tunnel.tcp_listen("10.0.0.1:9000").await?;
    let (stream, peer) = listener.accept().await?;

    Ok(())
}
```

## How it works

```
┌─────────────────────────────┐     ┌─────────────────────────────────┐
│  Your process               │     │  Helper process (in namespace)  │
│                             │     │                                 │
│  tunnel.send(packet) ──────►│     │  ◄── TAP interface (tap0)       │
│  tunnel.recv() ◄────────────│◄───►│                                 │
│  tunnel.tcp_connect() ─────►│     │  Handles ARP, relays IP packets │
│  tunnel.udp_bind() ────────►│     │  Creates sockets in namespace   │
└─────────────────────────────┘     └─────────────────────────────────┘
   Unix socketpairs (packet + control)
```

The library spawns a helper binary (`tap-tunnel-helper`) that:
1. Joins the target PID's user namespace (gaining capabilities)
2. Joins the target's network namespace
3. Starts a tokio runtime for async I/O
4. Creates and configures a TAP interface
5. Handles both packet relay and socket operations
6. Relays data between your process and the namespace

The helper binary is automatically discovered in:
1. Same directory as your executable
2. `TAP_TUNNEL_HELPER` environment variable
3. System PATH

## Building

```bash
# Build both the library and helper binary
cargo build --release

# The helper binary will be at target/release/tap-tunnel-helper
```

## Testing

Run the included echo responder example:

```bash
# Terminal 1: Create a network namespace
unshare --user --net --map-root-user bash
echo $$  # Note the PID

# Terminal 2: Run the echo tunnel
cargo run --example echo_tunnel <PID>

# Terminal 1: Ping the virtual host
ping 10.0.0.2  # Should get replies
```

Enable debug logging with `RUST_LOG`:

```bash
RUST_LOG=debug cargo run --example echo_tunnel <PID>
RUST_LOG=trace cargo run --example echo_tunnel <PID>  # very verbose
```

## API

### Tunnel

- `Tunnel::connect(pid)` - Connect with default settings (tap0, no IP)
- `Tunnel::connect_with_config(pid, config)` - Connect with custom config

**Raw Packets:**
- `tunnel.send(&[u8])` - Send an IP packet into the namespace
- `tunnel.recv(&mut [u8])` - Receive an IP packet from the namespace

**Sockets:**
- `tunnel.tcp_connect(addr)` - Create a TCP connection
- `tunnel.tcp_listen(addr)` - Create a TCP listener (default backlog: 16)
- `tunnel.tcp_listen_with_backlog(addr, backlog)` - Create a TCP listener with custom backlog
- `tunnel.udp_bind(addr)` - Create a UDP socket

**TcpListener:**
- `listener.accept()` - Accept incoming connection, returns `(TcpStream, SocketAddr)`
- `listener.local_addr()` - Get the local address the listener is bound to

Note: The backlog is implemented by maintaining multiple sockets in the Listen state
on the same endpoint. When a connection is accepted, a replacement listening socket
is spawned to maintain the backlog capacity. This mirrors smoltcp's model where each
listening socket can only accept one connection.

### TapConfig

```rust
TapConfig::new()
    .interface_name("tap0")                // TAP interface name (default: "tap0")
    .address(Ipv4Addr::new(10, 0, 0, 1), 24)  // Configure IP on the interface
```

## Container / Socket Path Mode

When the proxy runs inside a container, you can use socket-path mode to establish a connection.
The proxy binds to a Unix socket, and the library connects to it.

```bash
# Inside container: Proxy binds and waits for connection
# No --pid needed when already running in the target namespace
tap-tunnel-proxy --socket-path /shared/frame.sock --tap-addr 10.0.0.1/24

# On host: Library connects to the socket
```

```rust
use tap_tunnel::{TapConfig, Tunnel};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = TapConfig::new()
        .local_addr(Ipv4Addr::new(10, 0, 0, 2), 24)
        .peer_addr(Ipv4Addr::new(10, 0, 0, 1), 24);

    // Connect to the proxy's socket (mounted from container)
    let tunnel = Tunnel::connect_to("/shared/frame.sock", config).await?;

    // Use TCP/UDP as normal
    let mut tcp = tunnel.tcp_connect("10.0.0.1:8080".parse().unwrap()).await?;
    Ok(())
}
```
