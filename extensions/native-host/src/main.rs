//! PwdVault Native Messaging Host
//!
//! Bridges the browser's Native Messaging protocol (stdin/stdout with 4-byte
//! length-prefixed JSON) to the PwdVault desktop app's local HTTP API on
//! `127.0.0.1:17429`.
//!
//! This binary is launched by the browser as a child process. The browser
//! writes messages to our stdin and reads responses from our stdout.
//!
//! Protocol (Chrome/Firefox Native Messaging standard):
//!   - Each message = 4-byte native-endian length prefix + UTF-8 JSON payload
//!   - stdin → incoming requests from the browser
//!   - stdout → responses back to the browser
//!
//! The binary does NOT implement any business logic. It forwards each request
//! verbatim to the desktop app's HTTP API. Caller identity is derived only
//! from browser-supplied process arguments; request JSON is never trusted for
//! this purpose. The desktop app handles pairing, authentication, crypto, and
//! database access.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: u16 = 17429;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024; // 10 MB, matches server limit
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;
const MAX_HTTP_HEADER_SIZE: usize = 64 * 1024;
const FIREFOX_ADDON_ID: &str = "pwdvault@pwdvault.app";
const PROTOCOL_VERSION: u64 = 1;

#[derive(Debug, PartialEq, Eq)]
struct CallerContext {
    /// Stable label used to bind a pairing challenge to its browser caller.
    label: String,
    /// Extension-shaped Origin label retained by the loopback bridge.
    origin: String,
}

fn main() {
    // Buffer stdout so length-prefixed frames are written atomically.
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let stdin = io::stdin();
    let mut input = stdin.lock();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let caller = match parse_caller_args(&args) {
        Ok(caller) => caller,
        Err(error) => {
            let _ = send_error(&mut out, 0, &error);
            return;
        }
    };

    loop {
        let mut msg = match read_message(&mut input) {
            Ok(m) => m,
            Err(ReadError::EndOfStream) => break,
            Err(ReadError::TooLarge) => {
                let _ = send_error(&mut out, 0, "Message too large");
                // The oversized frame body is still on stdin; continuing would
                // interpret its first four bytes as a new frame length.
                break;
            }
            Err(ReadError::Io(e)) => {
                // A broken stdin pipe (e.g. browser restarted) is a normal
                // shutdown; surface other failures for diagnostics, then exit.
                let _ = send_error(&mut out, 0, &format!("stdin read error: {}", e));
                break;
            }
        };

        if let Err(error) = validate_protocol_version(&msg) {
            let _ = send_error(&mut out, extract_id(&msg).unwrap_or(0), &error);
            msg.fill(0);
            continue;
        }

        let mut response = match forward_to_server(&msg, &caller) {
            Ok(body) => body,
            Err(e) => {
                // The browser expects a JSON object, not a bare error string.
                // Wrap the transport error in the server's NativeResponse shape.
                let err = serde_json::json!({
                    "id": extract_id(&msg).unwrap_or(0),
                    "success": false,
                    "error": e,
                    "error_code": "HOST_TRANSPORT_ERROR",
                    "error_message": e,
                    "retry_after": null,
                });
                err.to_string().into_bytes()
            }
        };
        msg.fill(0);

        if write_message(&mut out, &response).is_err() {
            // If stdout is broken there's nothing useful we can do.
            break;
        }
        response.fill(0);
    }
}

/// Parse the caller identity supplied by the browser when it launches the
/// native host. Chrome passes the calling extension origin as its first
/// argument. Firefox passes the native-host manifest path followed by the
/// add-on ID. The values are tightly validated before being copied to HTTP
/// headers to prevent caller spoofing and header injection.
fn parse_caller_args(args: &[String]) -> Result<CallerContext, String> {
    let first = args.first().ok_or("Missing browser caller identity")?;

    if let Some(raw_id) = first.strip_prefix("chrome-extension://") {
        let extension_id = raw_id.strip_suffix('/').unwrap_or(raw_id);
        let valid_id = extension_id.len() == 32
            && extension_id
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'p'));
        if !valid_id {
            return Err("Invalid Chrome extension caller".to_string());
        }
        let origin = format!("chrome-extension://{extension_id}/");
        return Ok(CallerContext {
            label: origin.clone(),
            origin,
        });
    }

    let addon_id = args.get(1).ok_or("Missing Firefox add-on identity")?;
    if addon_id != FIREFOX_ADDON_ID {
        return Err("Invalid Firefox add-on caller".to_string());
    }

    // Firefox's first argument is the browser-selected manifest path. It is
    // not an authorization value, but requiring a non-empty JSON path catches
    // malformed/manual launches before accepting the stable add-on ID.
    if first.is_empty() || !first.to_ascii_lowercase().ends_with(".json") {
        return Err("Invalid Firefox native-host manifest argument".to_string());
    }

    let label = format!("moz-extension://{addon_id}");
    Ok(CallerContext {
        label: label.clone(),
        origin: label,
    })
}

/// Errors that can occur while reading a framed message from stdin.
#[derive(Debug)]
enum ReadError {
    /// Browser closed stdin (normal shutdown).
    EndOfStream,
    /// Declared length exceeds `MAX_MESSAGE_SIZE`.
    TooLarge,
    /// Underlying I/O failure.
    Io(io::Error),
}

/// Read a single Chrome NM message (4-byte length prefix + JSON) from stdin.
fn read_message<R: Read>(reader: &mut R) -> Result<Vec<u8>, ReadError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ReadError::EndOfStream);
        }
        Err(e) => return Err(ReadError::Io(e)),
    }

    let len = u32::from_ne_bytes(len_buf);
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_MESSAGE_SIZE {
        return Err(ReadError::TooLarge);
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            ReadError::EndOfStream
        } else {
            ReadError::Io(e)
        }
    })?;
    Ok(buf)
}

/// Write a single Chrome NM message to stdout.
fn write_message<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = (payload.len() as u32).to_ne_bytes();
    writer.write_all(&len)?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Send a JSON error frame back to the browser (best-effort).
fn send_error<W: Write>(writer: &mut W, id: u32, error: &str) -> io::Result<()> {
    let body = serde_json::json!({
        "id": id,
        "success": false,
        "error": error,
        "error_code": "HOST_TRANSPORT_ERROR",
        "error_message": error,
        "retry_after": null,
    });
    let bytes = body.to_string().into_bytes();
    write_message(writer, &bytes)
}

/// Extract the `id` field (if present) so transport-error frames stay
/// correlated with the original request.
fn extract_id(payload: &[u8]) -> Option<u32> {
    let value = serde_json::from_slice::<serde_json::Value>(payload).ok()?;
    let n = value.get("id")?.as_u64()?;
    u32::try_from(n).ok()
}

fn validate_protocol_version(payload: &[u8]) -> Result<(), String> {
    let value = serde_json::from_slice::<serde_json::Value>(payload)
        .map_err(|_| "Invalid native messaging JSON".to_string())?;
    match value.get("protocol_version").and_then(|version| version.as_u64()) {
        Some(PROTOCOL_VERSION) => Ok(()),
        Some(_) => Err("Unsupported protocol version; update PwdVault and the browser extension"
            .to_string()),
        None => Err("Missing protocol version; update the browser extension".to_string()),
    }
}

/// Forward a raw JSON payload to the desktop app's HTTP API and return the
/// raw response body. Communication is plain loopback TCP.
///
/// The request is POSTed to `/api/<command>` with the payload as the body,
/// matching what the extension does over `fetch`. The server dispatches on the
/// `command` field in the body, so the path is informational, but we keep it
/// consistent with the extension for log readability.
///
/// Because Native Messaging has no concept of HTTP headers, the extension
/// carries the Bearer token in a body field `auth_token`; we lift it into an
/// `Authorization` header here so the server's existing header-based auth works
/// unchanged.
fn forward_to_server(payload: &[u8], caller: &CallerContext) -> Result<Vec<u8>, String> {
    let command = extract_command(payload).unwrap_or_else(|| "request".to_string());
    let path = format!("/api/{}", command);
    let auth_header = extract_auth_header(payload);

    let mut stream = TcpStream::connect((SERVER_HOST, SERVER_PORT)).map_err(|e| {
        format!(
            "Cannot connect to desktop app ({}:{}): {}",
            SERVER_HOST, SERVER_PORT, e
        )
    })?;

    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("Set read timeout: {}", e))?;
    stream
        .set_write_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("Set write timeout: {}", e))?;

    let body_len = payload.len();

    // Build a minimal HTTP/1.1 POST. We hand-write headers because the
    // dependency footprint of this binary must stay tiny (serde only).
    let request = match auth_header.as_deref() {
        Some(token) => format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Origin: {}\r\n\
             X-PwdVault-Caller: {}\r\n\
             Authorization: Bearer {}\r\n\
             Connection: close\r\n\
             \r\n",
            path,
            SERVER_HOST,
            SERVER_PORT,
            body_len,
            caller.origin,
            caller.label,
            token
        ),
        None => format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Origin: {}\r\n\
             X-PwdVault-Caller: {}\r\n\
             Connection: close\r\n\
             \r\n",
            path, SERVER_HOST, SERVER_PORT, body_len, caller.origin, caller.label
        ),
    };

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write request line: {}", e))?;
    stream
        .write_all(payload)
        .map_err(|e| format!("Write request body: {}", e))?;
    stream
        .flush()
        .map_err(|e| format!("Flush request: {}", e))?;

    // Read the full response. Since we send `Connection: close`, the server
    // closes the socket after the body, so reading to EOF yields everything.
    let mut response = Vec::with_capacity(4096);
    (&mut stream)
        .take((MAX_RESPONSE_SIZE + MAX_HTTP_HEADER_SIZE + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|e| format!("Read response: {}", e))?;

    // Split headers from body at the first blank line.
    let body = split_http_body(&response);
    if body.len() > MAX_RESPONSE_SIZE {
        return Err("Desktop response exceeds native messaging limit".to_string());
    }
    Ok(body)
}

/// Extract the body from a raw HTTP response by finding the `\r\n\r\n`
/// separator between headers and body. Falls back to the full payload if the
/// separator is missing (defensive; should not happen in practice).
fn split_http_body(response: &[u8]) -> Vec<u8> {
    let sep = b"\r\n\r\n";
    if let Some(idx) = find_subslice(response, sep) {
        response[idx + sep.len()..].to_vec()
    } else {
        response.to_vec()
    }
}

/// Find the starting index of `needle` in `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract the `command` field from the JSON payload so the request path can
/// mirror the extension's. Returns `None` if absent or unparseable.
fn extract_command(payload: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<serde_json::Value>(payload).ok()?;
    value.get("command")?.as_str().map(str::to_owned)
}

/// Extract the `auth_token` field the extension carries in the body (since NM
/// has no HTTP headers). Returns `None` when absent (e.g. for the `pair`
/// command). The caller lifts this into an `Authorization: Bearer` header.
fn extract_auth_header(payload: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<serde_json::Value>(payload).ok()?;
    value.get("auth_token")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_http_body_finds_separator() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(split_http_body(resp), b"hello");
    }

    #[test]
    fn split_http_body_no_separator_returns_input() {
        let resp = b"just a body";
        assert_eq!(split_http_body(resp), b"just a body");
    }

    #[test]
    fn find_subslice_locates_needle() {
        assert_eq!(find_subslice(b"abc\r\n\r\ndef", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subslice(b"abcdef", b"xyz"), None);
    }

    #[test]
    fn extract_command_reads_field() {
        let payload = br#"{"id":1,"command":"pair"}"#;
        assert_eq!(extract_command(payload), Some("pair".to_string()));
    }

    #[test]
    fn extract_command_missing_returns_none() {
        let payload = br#"{"id":1}"#;
        assert_eq!(extract_command(payload), None);
    }

    #[test]
    fn extract_auth_header_reads_token() {
        let payload = br#"{"id":1,"command":"get_entry","auth_token":"abc123"}"#;
        assert_eq!(extract_auth_header(payload), Some("abc123".to_string()));
    }

    #[test]
    fn extract_auth_header_missing_returns_none() {
        let payload = br#"{"id":1,"command":"pair"}"#;
        assert_eq!(extract_auth_header(payload), None);
    }

    #[test]
    fn extract_id_reads_numeric_field() {
        let payload = br#"{"id":42,"command":"get_entry"}"#;
        assert_eq!(extract_id(payload), Some(42));
    }

    #[test]
    fn extract_id_missing_returns_none() {
        let payload = br#"{"command":"pair"}"#;
        assert_eq!(extract_id(payload), None);
    }

    #[test]
    fn protocol_version_is_required_and_bounded() {
        assert!(validate_protocol_version(br#"{"protocol_version":1,"command":"handshake"}"#).is_ok());
        assert!(validate_protocol_version(br#"{"command":"handshake"}"#).is_err());
        assert!(validate_protocol_version(br#"{"protocol_version":2,"command":"handshake"}"#).is_err());
    }

    #[test]
    fn parses_chrome_caller_origin_from_browser_args() {
        let args = vec!["chrome-extension://abcdefghijklmnopabcdefghijklmnop/".to_string()];
        let caller = parse_caller_args(&args).expect("valid Chrome caller");
        assert_eq!(caller.label, args[0]);
        assert_eq!(caller.origin, args[0]);
    }

    #[test]
    fn parses_firefox_addon_id_from_browser_args() {
        let args = vec![
            "/Library/Application Support/Mozilla/NativeMessagingHosts/com.pwdvault.app.json"
                .to_string(),
            FIREFOX_ADDON_ID.to_string(),
        ];
        let caller = parse_caller_args(&args).expect("valid Firefox caller");
        assert_eq!(caller.label, "moz-extension://pwdvault@pwdvault.app");
    }

    #[test]
    fn rejects_missing_or_invalid_browser_caller() {
        assert!(parse_caller_args(&[]).is_err());
        assert!(parse_caller_args(&["chrome-extension://attacker/".to_string()]).is_err());
        assert!(parse_caller_args(&[
            "/tmp/com.pwdvault.app.json".to_string(),
            "attacker@example.com".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn request_payload_cannot_override_caller_identity() {
        let payload = br#"{"origin":"moz-extension://attacker","command":"pair"}"#;
        assert_eq!(extract_command(payload), Some("pair".to_string()));
        // Caller parsing has no payload parameter by design.
        assert!(parse_caller_args(&[]).is_err());
    }

    #[test]
    fn write_then_read_roundtrip() {
        // Round-trip a framed message through an in-memory buffer.
        let mut buf: Vec<u8> = Vec::new();
        let payload = br#"{"command":"pair"}"#;
        write_message(&mut buf, payload).unwrap();

        let mut cursor = io::Cursor::new(buf);
        let read_back = read_message(&mut cursor).unwrap();
        assert_eq!(read_back, payload);
    }

    #[test]
    fn read_message_eof_signals_end_of_stream() {
        let empty: &[u8] = &[];
        let mut cursor = io::Cursor::new(empty);
        match read_message(&mut cursor) {
            Err(ReadError::EndOfStream) => {}
            other => panic!("expected EndOfStream, got {:?}", other),
        }
    }

    #[test]
    fn read_message_oversize_rejects() {
        // 4-byte length prefix declaring > MAX_MESSAGE_SIZE.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_SIZE + 1).to_ne_bytes());
        let mut cursor = io::Cursor::new(buf);
        match read_message(&mut cursor) {
            Err(ReadError::TooLarge) => {}
            other => panic!("expected TooLarge, got {:?}", other),
        }
    }
}
