//! PwdVault Native Messaging Host
//!
//! Communicates between Chrome and the PwdVault desktop app.
//!
//! Protocol:
//! - Chrome sends messages via stdin (4-byte length prefix + JSON)
//! - Host forwards to local HTTP server
//! - Host returns responses via stdout (4-byte length prefix + JSON)

use std::io::{self, Read, Write};
use std::net::TcpStream;

const SERVER_PORT: u16 = 17429;

fn main() {
    // Get message from stdin
    let message = match read_message() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to read message: {}", e);
            write_error(&format!("Read error: {}", e));
            return;
        }
    };

    // Forward to local server
    let response = match forward_to_server(&message) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to forward message: {}", e);
            write_error(&format!("Connection error: {}", e));
            return;
        }
    };

    // Write response to stdout
    if let Err(e) = write_message(&response) {
        eprintln!("Failed to write response: {}", e);
    }
}

/// Read a message from stdin (Chrome native messaging format)
fn read_message() -> io::Result<String> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    // Read 4-byte length prefix
    let mut len_bytes = [0u8; 4];
    handle.read_exact(&mut len_bytes)?;

    let len = u32::from_ne_bytes(len_bytes) as usize;

    // Read message body
    let mut buffer = vec![0u8; len];
    handle.read_exact(&mut buffer)?;

    String::from_utf8(buffer)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write a message to stdout (Chrome native messaging format)
fn write_message(message: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let bytes = message.as_bytes();
    let len = bytes.len() as u32;

    // Write 4-byte length prefix
    handle.write_all(&len.to_ne_bytes())?;

    // Write message body
    handle.write_all(bytes)?;

    handle.flush()
}

/// Write an error response
fn write_error(error: &str) {
    let response = serde_json::json!({
        "success": false,
        "error": error
    });
    let _ = write_message(&response.to_string());
}

/// Forward message to local HTTP server
fn forward_to_server(message: &str) -> io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", SERVER_PORT))?;

    // Build HTTP request
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: 127.0.0.1:{}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        SERVER_PORT,
        message.len(),
        message
    );

    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    // Read response
    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    // Extract body from HTTP response
    if let Some(body_start) = response.find("\r\n\r\n") {
        Ok(response[body_start + 4..].to_string())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP response"))
    }
}