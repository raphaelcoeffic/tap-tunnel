# tap-tunnel

A Rust library for sending and receiving IP packets to/from a network namespace
via a TAP interface. No special capabilities required - leverages the target's
user namespace.

## Usage

```rust
use tap_tunnel::{TapConfig, TapTunnel};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Connect to the network namespace of PID 1234
    // Configures tap0 with 10.0.0.1/24 inside the namespace
    let config = TapConfig::new().address(Ipv4Addr::new(10, 0, 0, 1), 24);
    let tunnel = TapTunnel::connect_with_config(1234, config).await?;

    // Receive an IP packet from the namespace
    let mut buf = [0u8; 1500];
    let n = tunnel.recv(&mut buf).await?;

    // Send an IP packet into the namespace
    tunnel.send(&buf[..n]).await?;

    Ok(())
}
```

## How it works

```
┌─────────────────────────────┐     ┌─────────────────────────────────┐
│  Your process               │     │  Child process (in namespace)   │
│                             │     │                                 │
│  TapTunnel::send(packet) ──►│     │  ◄── TAP interface (tap0)       │
│  TapTunnel::recv() ◄────────│◄───►│                                 │
│                             │     │  Handles ARP, relays IP packets │
└─────────────────────────────┘     └─────────────────────────────────┘
        Unix socketpair (SOCK_SEQPACKET)
```

The library forks a child process that:
1. Joins the target PID's user namespace (gaining capabilities)
2. Joins the target's network namespace
3. Creates and configures a TAP interface
4. Relays IP packets between the TAP and your process
5. Handles ARP requests automatically

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

### TapTunnel

- `TapTunnel::connect(pid)` - Connect with default settings (tap0, no IP)
- `TapTunnel::connect_with_config(pid, config)` - Connect with custom config
- `tunnel.send(&[u8])` - Send an IP packet into the namespace
- `tunnel.recv(&mut [u8])` - Receive an IP packet from the namespace

### TapConfig

```rust
TapConfig::new()
    .interface_name("tap0")                // TAP interface name (default: "tap0")
    .address(Ipv4Addr::new(10, 0, 0, 1), 24)  // Configure IP on the interface
```
