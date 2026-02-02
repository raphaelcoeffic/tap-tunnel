# tap-tunnel

A Rust library for creating TCP/UDP sockets within a network namespace via a
userspace TCP/IP stack (smoltcp). No special capabilities required - leverages
the target's user namespace.

## Features

- **Socket API**: Create TCP/UDP sockets that work within the namespace
- **Multi-IP Support**: Dynamically add/remove IP addresses on the interface
- **No Privileges**: Works via user namespace - no root required

## Usage

```rust
use tap_tunnel::{TapConfig, Tunnel};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Connect to the network namespace of PID 1234
    // - peer_addr: IP for the TAP interface in the namespace
    // - local_addr: IP for the smoltcp stack (our side)
    let config = TapConfig::new()
        .peer_addr(Ipv4Addr::new(10, 0, 0, 1), 24)
        .local_addr(Ipv4Addr::new(10, 0, 0, 2), 24);
    let tunnel = Tunnel::connect_with_config(1234, config).await?;

    // TCP client
    let mut tcp = tunnel.tcp_connect("10.0.0.1:8080".parse()?).await?;
    tcp.write_all(b"hello\n").await?;

    // UDP
    let udp = tunnel.udp_bind("10.0.0.2:0".parse()?).await?;
    udp.send_to(b"ping", "10.0.0.1:5000".parse()?).await?;

    // TCP server
    let listener = tunnel.tcp_listen("10.0.0.2:9000".parse()?).await?;
    let (stream, peer) = listener.accept().await?;

    Ok(())
}
```

## How it works

```
┌─────────────────────────────┐     ┌─────────────────────────────────┐
│  Your process               │     │  Tunnel proxy (in namespace)    │
│                             │     │                                 │
│  tunnel.tcp_connect() ─────►│     │  ◄── TAP interface (tap0)       │
│  tunnel.tcp_listen() ──────►│◄───►│                                 │
│  tunnel.udp_bind() ────────►│     │  Relays ethernet frames         │
│                             │     │                                 │
└─────────────────────────────┘     └─────────────────────────────────┘
                Unix socketpair (frames + control)
```

The library spawns a proxy (`tap-tunnel-proxy`) that:
1. Joins the target PID's user namespace (gaining capabilities)
2. Joins the target's network namespace
3. Creates and configures a TAP interface
4. Handles frame relay (both directions)

The proxy binary is automatically discovered in:
1. Same directory as your executable
2. `TAP_TUNNEL_PROXY` environment variable
3. System PATH

## Building

```bash
# Build both the library and helper binary
cargo build --workspace --release

# The helper binary will be at target/release/tap-tunnel-proxy
```

## Testing

Run the included echo example:

```bash
# Terminal 1: Create a network namespace
unshare --user --net --map-root-user bash
echo $$  # Note the PID

# Terminal 2: Run the echo example
cargo run --example tcp_echo <PID>

# Terminal 1: Connect to the virtual host
nc 10.0.0.2 8080  # Type messages, they echo back
```

Enable debug logging with `RUST_LOG`:

```bash
RUST_LOG=debug cargo run --example tcp_echo <PID>
RUST_LOG=trace cargo run --example tcp_echo <PID>  # very verbose
```

## API

### Tunnel

**Connection:**
- `Tunnel::connect(pid)` - Connect with default settings
- `Tunnel::connect_with_config(pid, config)` - Connect with custom config
- `Tunnel::connect_to(socket_path, local_ip)` - Connect via Unix socket (container mode)

**Sockets:**
- `tunnel.tcp_connect(addr)` - Create a TCP connection (uses default local IP)
- `tunnel.tcp_connect_from(local_ip, addr)` - Create a TCP connection from specific IP
- `tunnel.tcp_listen(addr)` - Create a TCP listener (default backlog: 8)
- `tunnel.tcp_listen_with_backlog(addr, backlog)` - Create a TCP listener with custom backlog
- `tunnel.udp_bind(addr)` - Create a UDP socket

**Multi-IP Management:**
- `tunnel.add_local_ip(ip, prefix_len)` - Add an IP address to the interface
- `tunnel.remove_local_ip(ip)` - Remove an IP address from the interface
- `tunnel.local_ips()` - List current IP addresses on the interface
- `tunnel.gateway()` - Get the proxy's TAP IP and MAC address

**TcpListener:**
- `listener.accept()` - Accept incoming connection, returns `(TcpStream, SocketAddr)`
- `listener.local_addr()` - Get the local address the listener is bound to

Note: The backlog is implemented by maintaining multiple sockets in the Listen state
on the same endpoint. When a connection is accepted, a replacement listening socket
is spawned to maintain the backlog capacity.

### TapConfig

```rust
TapConfig::new()
    .interface_name("tap0")                      // TAP interface name (default: "tap0")
    .peer_addr(Ipv4Addr::new(10, 0, 0, 1), 24)   // IP for TAP interface (namespace side)
    .local_addr(Ipv4Addr::new(10, 0, 0, 2), 24)  // IP for smoltcp stack (our side)
```

## Container / Socket Path Mode

When the proxy runs inside a container, you can use socket-path mode to establish a connection.
The proxy binds to a Unix socket, and the library connects to it. The proxy sends its identity
(TAP IP, MAC, prefix) during handshake, and the client picks its own IP from the subnet.

```bash
# Inside container: Proxy binds and waits for connection
# No --pid needed when already running in the target namespace
tap-tunnel-proxy --socket-path /shared/frame.sock --tap-addr 10.0.0.1/24
```

```rust
use tap_tunnel::Tunnel;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Connect with default IP (TAP IP + 1, e.g., 10.0.0.2)
    let tunnel = Tunnel::connect_to("/shared/frame.sock", None).await?;

    // Or specify your own IP from the subnet
    let tunnel = Tunnel::connect_to(
        "/shared/frame.sock",
        Some(Ipv4Addr::new(10, 0, 0, 5))
    ).await?;

    // Get proxy's gateway info
    if let Some((tap_ip, tap_mac)) = tunnel.gateway() {
        println!("Gateway: {} ({:02x?})", tap_ip, tap_mac);
    }

    // Add additional IPs dynamically
    tunnel.add_local_ip(Ipv4Addr::new(10, 0, 0, 10), 24).await?;

    // Connect from a specific local IP
    let stream = tunnel.tcp_connect_from(
        Ipv4Addr::new(10, 0, 0, 10),
        "10.0.0.1:8080".parse()?
    ).await?;

    Ok(())
}
```
