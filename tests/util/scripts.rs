// ============================================================================
// Helper functions for client-server tests
// ============================================================================

use std::io::Result;

use super::UserNetNamespace;

/// Helper to create a network namespace with a TCP echo server.
/// The server listens on the TAP interface IP.
pub fn tcp_echo_server_ns(port: u16) -> Result<UserNetNamespace> {
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
pub fn tcp_client_ns(
    ip: &str,
    port: u16,
    message: &str,
) -> Result<UserNetNamespace> {
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
pub fn tcp_multi_client_ns(
    ip: &str,
    port: u16,
    num_clients: usize,
) -> Result<UserNetNamespace> {
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
pub fn udp_echo_server_ns(port: u16) -> Result<UserNetNamespace> {
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

/// Server that receives data and responds with "response:" + data
pub fn tcp_request_response_server_ns(port: u16) -> Result<UserNetNamespace> {
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
pub fn tcp_multi_exchange_client_ns(
    ip: &str,
    port: u16,
    num_exchanges: usize,
) -> Result<UserNetNamespace> {
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
pub fn tcp_large_echo_client_ns(
    ip: &str,
    port: u16,
    size: usize,
) -> Result<UserNetNamespace> {
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
