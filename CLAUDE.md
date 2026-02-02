# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build the library and proxy binary (workspace)
cargo build --workspace

# Run all integration tests (requires Linux with user namespace support)
cargo test --test socket_integration

# Run a specific test
cargo test --test socket_integration test_tcp_single_connection

# Run with debug logging
RUST_LOG=debug cargo test --test socket_integration -- --no-capture

# Run examples (requires a target namespace PID)
cargo run --example tcp_echo <PID>
cargo run --example udp_echo <PID>
```

## Testing Setup

Integration tests spawn isolated network namespaces using `unshare --user --net --map-root-user`. Tests run Python echo servers inside the namespace to verify TCP/UDP connectivity. Python 3 is required.

To manually test:
```bash
# Terminal 1: Create namespace
unshare --user --net --map-root-user bash
echo $$  # Note this PID

# Terminal 2: Connect to it
cargo run --example tcp_echo <PID>
```

## Architecture

This library enables TCP/UDP socket access to processes in Linux network namespaces without elevated privileges, using a userspace TCP/IP stack (smoltcp).

### Two-Process Model

```
Client Process                          Target Namespace
─────────────────────────────────────────────────────────
User async code (tokio)
    ↓
Tunnel API (tcp_connect, udp_bind)
    ↓ crossbeam channels
smoltcp Stack Thread (blocking)
    ├─ Interface + SocketSet
    ├─ Poll loop with 1ms tick
    └─ ProxyDevice
    ↓ Unix SEQPACKET socketpair
IPC Reader/Writer Threads  ←──────────→  tap-tunnel-proxy binary
                                            ├─ Joins user+net namespaces
                                            ├─ Creates TAP device
                                            └─ Relays Ethernet frames
```

### Workspace Structure

- **`tap-tunnel`** (root): Main library crate
- **`proxy/`**: Separate crate for the `tap-tunnel-proxy` binary

### Key Components

- **`src/lib.rs`**: `Tunnel` and `TapConfig` API, proxy binary discovery/spawning, IPC thread setup
- **`src/stack/mod.rs`**: smoltcp integration - `run_stack()` poll loop, `StackCommand` enum for socket operations, pending operation handling
- **`src/stack/device.rs`**: `ProxyDevice` implementing smoltcp's `Device` trait over channels
- **`src/socket/`**: `TcpStream` and `UdpSocket` async wrappers that send commands to the stack thread
- **`proxy/src/main.rs`**: Proxy binary - joins target namespace, creates TAP device, relays Ethernet frames
- **`proxy/src/namespace.rs`**: `join_namespace(pid)` - joins user namespace first, then network namespace
- **`proxy/src/tap.rs`**: TAP device creation via `/dev/net/tun` ioctl

### Data Flow

1. User calls `tunnel.tcp_connect()` → sends `StackCommand::TcpConnect` via channel
2. Stack thread creates smoltcp TCP socket, initiates connection
3. smoltcp generates Ethernet frames → `ProxyDevice` → IPC writer thread → Unix socket
4. Proxy process receives frames → writes to TAP device → kernel delivers to namespace
5. Response frames flow back through the same path in reverse

### IP Address Configuration

- `peer_addr`: IP assigned to TAP interface inside namespace (server side)
- `local_addr`: IP used by smoltcp stack (client side)
- Both must be on the same subnet for the point-to-point link to work

### Proxy Binary Discovery

The `tap-tunnel-proxy` binary is found in order:
1. Same directory as executable
2. `TAP_TUNNEL_PROXY` environment variable
3. `target/debug` or `target/release` (development)
4. System PATH
