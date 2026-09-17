//! Native Messaging HTTP transport.
//!
//! Listener lifecycle (bind retry, accept loop), the fixed worker pool with
//! its bounded queue, and raw HTTP request parsing / response serialization.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use zeroize::Zeroizing;

use pwdvault_application::AppState;
use pwdvault_domain::constants;

use super::protocol::{error_response, handle_connection, NativeResponse};

const HTTP_WORKERS: usize = 8;
const HTTP_QUEUE_CAPACITY: usize = 64;
const HTTP_HEADER_LIMIT: usize = 16 * 1024;
const HTTP_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the listening socket with `SO_REUSEADDR` (X2).
///
/// std sets it on Windows but not on Unix, where a previous instance's
/// TIME_WAIT sockets made quick app restarts fail with `AddrInUse`. socket2
/// normalizes the behavior across all three platforms.
fn bind_listener(addr: &SocketAddr) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&(*addr).into())?;
    socket.listen(128)?;
    Ok(TcpListener::from(socket))
}

/// Bind with a bounded retry schedule for `AddrInUse` only (X2): 1s / 2s / 4s,
/// i.e. a worst case of ~7s before giving up. A live port holder is expected
/// to release the port (app restart race), while permission errors must fail
/// immediately. Persistent failure returns through the existing
/// `native-server-error` emit path in the caller.
fn bind_with_retry(addr: &SocketAddr) -> std::io::Result<TcpListener> {
    const RETRY_DELAYS_MS: [u64; 3] = [1_000, 2_000, 4_000];
    let mut attempt = 0usize;
    loop {
        match bind_listener(addr) {
            Ok(listener) => return Ok(listener),
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse
                    && attempt < RETRY_DELAYS_MS.len() =>
            {
                attempt += 1;
                tracing::warn!(
                    attempt,
                    port = addr.port(),
                    error = %error,
                    "native messaging port busy; retrying bind"
                );
                std::thread::sleep(Duration::from_millis(RETRY_DELAYS_MS[attempt - 1]));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Start the native messaging HTTP server
///
/// Requests are processed by a fixed worker pool and bounded queue. This keeps
/// slow or malformed loopback clients from creating unbounded OS threads.
pub fn start_server(
    port: u16,
    state: Arc<AppState>,
    app_handle: Option<tauri::AppHandle>,
) -> Result<(), String> {
    let addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .map_err(|error| format!("Server error: {error}"))?;
    let listener = bind_with_retry(&addr).map_err(|error| format!("Server error: {error}"))?;

    tracing::info!(port = port, "native messaging server started");

    // Bound accepted sockets before HTTP parsing. tiny_http's internal task
    // pool grew one thread per slow connection, so bounding only parsed
    // requests was insufficient against slowloris traffic.
    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(HTTP_QUEUE_CAPACITY);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..HTTP_WORKERS {
        let receiver = receiver.clone();
        let state = state.clone();
        let app_handle = app_handle.clone();
        std::thread::Builder::new()
            .name(format!("pwdvault-http-{index}"))
            .spawn(move || loop {
                let request = {
                    let guard = receiver.lock().expect("HTTP queue lock poisoned");
                    guard.recv()
                };
                match request {
                    Ok(stream) => handle_connection(stream, state.clone(), app_handle.clone()),
                    Err(_) => break,
                }
            })
            .map_err(|error| format!("Failed to start HTTP worker: {error}"))?;
    }

    for incoming in listener.incoming() {
        let stream = incoming.map_err(|error| format!("Accept failed: {error}"))?;
        if let Err(error) = sender.try_send(stream) {
            match error {
                mpsc::TrySendError::Full(mut stream) => {
                    reject_busy_connection(&mut stream);
                }
                mpsc::TrySendError::Disconnected(_) => {
                    return Err("HTTP worker pool stopped".to_string());
                }
            }
        }
    }

    Ok(())
}

fn reject_busy_connection(stream: &mut TcpStream) {
    // Drain bytes already delivered by a complete client request so macOS does
    // not replace the 503 response with an immediate RST when the socket is
    // dropped. Never wait here: the accept loop must remain bounded even for
    // slow clients.
    if stream.set_nonblocking(true).is_ok() {
        let mut drained = 0usize;
        let mut buffer = [0u8; 4096];
        while drained < HTTP_HEADER_LIMIT {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => drained += read,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        let _ = stream.set_nonblocking(false);
    }
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
    let response = error_response(0, "Server busy; retry later".to_string());
    let _ = write_http_response(stream, 503, &response);
    let _ = stream.shutdown(Shutdown::Write);
}

#[derive(Debug)]
pub(super) struct ParsedHttpRequest {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) headers: HashMap<String, String>,
    pub(super) body: Zeroizing<String>,
}

#[derive(Debug)]
pub(super) struct HttpFailure {
    pub(super) status: u16,
    pub(super) message: String,
}

impl HttpFailure {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

pub(super) fn read_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, HttpFailure> {
    stream
        .set_read_timeout(Some(HTTP_IO_TIMEOUT))
        .map_err(|_| HttpFailure::new(500, "Request failed"))?;
    stream
        .set_write_timeout(Some(HTTP_IO_TIMEOUT))
        .map_err(|_| HttpFailure::new(500, "Request failed"))?;

    let mut buffer = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
        if buffer.len() >= HTTP_HEADER_LIMIT {
            return Err(HttpFailure::new(431, "Request headers too large"));
        }
        let mut chunk = [0u8; 4096];
        let read = stream
            .read(&mut chunk)
            .map_err(|_| HttpFailure::new(408, "Request timeout"))?;
        if read == 0 {
            return Err(HttpFailure::new(400, "Invalid request"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > HTTP_HEADER_LIMIT + constants::MAX_BODY_SIZE {
            return Err(HttpFailure::new(413, "Request too large"));
        }
    };

    let header_bytes = &buffer[..header_end];
    let header_text =
        std::str::from_utf8(header_bytes).map_err(|_| HttpFailure::new(400, "Invalid request"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
    let path = request_parts
        .next()
        .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
    if request_parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(HttpFailure::new(400, "Invalid request"));
    }

    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || value.contains(['\r', '\n']) || headers.contains_key(&name) {
            return Err(HttpFailure::new(400, "Invalid request"));
        }
        headers.insert(name, value.trim().to_string());
    }

    if method != "POST" {
        return Err(HttpFailure::new(405, "POST required"));
    }
    if headers.contains_key("transfer-encoding") {
        return Err(HttpFailure::new(400, "Transfer-Encoding is not supported"));
    }
    let content_type_is_json = headers
        .get("content-type")
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !content_type_is_json {
        return Err(HttpFailure::new(
            415,
            "Content-Type application/json required",
        ));
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length > 0)
        .ok_or_else(|| HttpFailure::new(411, "Valid Content-Length required"))?;
    if content_length > constants::MAX_BODY_SIZE {
        return Err(HttpFailure::new(413, "Request too large"));
    }

    let body_start = header_end + 4;
    let mut body = Vec::with_capacity(content_length);
    let already_read = buffer.len().saturating_sub(body_start).min(content_length);
    body.extend_from_slice(&buffer[body_start..body_start + already_read]);
    while body.len() < content_length {
        let mut chunk = [0u8; 8192];
        let remaining = content_length - body.len();
        let read_limit = remaining.min(chunk.len());
        let read = stream
            .read(&mut chunk[..read_limit])
            .map_err(|_| HttpFailure::new(408, "Request timeout"))?;
        if read == 0 {
            return Err(HttpFailure::new(400, "Content-Length mismatch"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8(body).map_err(|_| HttpFailure::new(400, "Invalid request"))?;

    Ok(ParsedHttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: Zeroizing::new(body),
    })
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

pub(super) fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    response: &NativeResponse,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(response).unwrap_or_default();
    let headers = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Type: application/json\r\n\
         Cache-Control: no-store\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        status_reason(status),
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}
