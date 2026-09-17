//! P3.2 cloud storage abstraction: the [`CloudBackend`] trait, the WebDAV
//! implementation (D4 conditional writes), and the [`MockCloudBackend`] test
//! double.
//!
//! The cloud is DUMB STORAGE (D1): it sees only opaque ciphertext blobs. The
//! trait is deliberately tiny — stat/download/upload/upload_unique/delete —
//! so every provider (WebDAV, Baidu Netdisk) can implement it.
//! Conflict safety comes from `Precondition`:
//! - [`Precondition::IfMatch`] → `If-Match: <etag>` (WebDAV): the server
//!   rejects the PUT with 412 when the file changed underneath us (D4);
//! - [`Precondition::IfAbsent`] → `If-None-Match: *`: create-only semantics
//!   for the initial container bootstrap (two devices racing "connect" —
//!   exactly one wins).
//!
//! `delete` is the one addition to the plan's trait sketch: snapshot history
//! rotation (D4, keep the last 10) is impossible without it on a backend
//! with no directory listing, and the engine tracks the file names itself.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use thiserror::Error;
use zeroize::Zeroizing;

/// Cap for downloaded container/manifest bytes — refuses to buffer
/// unbounded server-supplied payloads (same defense as the update check).
pub(crate) const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// Network timeout for one backend request. Sync payloads are small
/// ciphertext blobs; this bounds a hung server without stretching the D8
/// window (which never contains network I/O anyway).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Error, Debug)]
pub enum BackendError {
    /// The remote file changed under us (412 on If-Match / If-None-Match).
    /// Callers re-pull, re-merge and retry (D4).
    #[error("Remote state changed concurrently")]
    Conflict,
    /// Credentials rejected or missing (401/403).
    #[error("Authentication failed: {0}")]
    Auth(String),
    /// Any transport/HTTP failure. The string is safe for logs (no secrets).
    #[error("Network error: {0}")]
    Network(String),
    /// The backend kind is known but not usable in this build (Baidu without
    /// compiled-in AppKey credentials, P3.4/P3.8).
    #[error("Backend is not configured")]
    NotConfigured,
}

/// Metadata of a remote file. `etag` is `None` on servers without ETag
/// support — the engine then falls back to manifest rev comparison (P3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStat {
    pub etag: Option<String>,
    pub size: u64,
}

/// Precondition for [`CloudBackend::upload`] (D4). `Unconditional` is the
/// third variant beyond the plan's sketch, required for derived artifacts
/// (the rev manifest) and for servers without ETag support (P3.8 degraded
/// mode — the manifest rev check runs instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// Overwrite only if the remote still carries this exact ETag.
    IfMatch(String),
    /// Create-only: fail if the file already exists (bootstrap semantics).
    IfAbsent,
    /// Plain PUT, no precondition.
    Unconditional,
}

/// Opaque cloud storage for the encrypted sync container (D1/D4).
pub trait CloudBackend: Send + Sync {
    /// Stat a file; `Ok(None)` when it does not exist.
    fn stat(&self, path: &str) -> Result<Option<RemoteStat>, BackendError>;

    /// Download the full file body.
    fn download(&self, path: &str) -> Result<Vec<u8>, BackendError>;

    /// Upload with a write precondition ([`Precondition`]).
    fn upload(
        &self,
        path: &str,
        body: &[u8],
        precondition: Precondition,
    ) -> Result<(), BackendError>;

    /// Upload a unique-named file (history snapshots, D4) with no
    /// precondition — unique names cannot conflict.
    fn upload_unique(&self, path: &str, body: &[u8]) -> Result<(), BackendError>;

    /// Delete a file. Deleting a missing file succeeds (idempotent) — the
    /// engine prunes history on a best-effort basis.
    fn delete(&self, path: &str) -> Result<(), BackendError>;
}

// ---------------------------------------------------------------------------
// MockCloudBackend — in-memory test double
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockInner {
    /// path → (body, etag counter)
    files: HashMap<String, (Vec<u8>, u64)>,
    /// Injected conflict schedule: the head entry is the number of
    /// consecutive preconditioned uploads to reject with `Conflict` before
    /// succeeding; it is consumed by upload attempts.
    conflict_schedule: VecDeque<usize>,
}

/// In-memory [`CloudBackend`] for tests (P3.6 item 4): a plain KV store with
/// monotonic ETags plus an injectable conflict sequence that simulates
/// another device winning the upload race. [`MockCloudBackend::handle`]
/// clones share the same storage so two fake devices can fight over one
/// cloud.
#[derive(Clone, Default)]
pub struct MockCloudBackend {
    inner: Arc<Mutex<MockInner>>,
}

impl MockCloudBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// A handle sharing this backend's storage (fake second device).
    pub fn handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Seed the store directly (e.g. pre-existing remote container).
    pub fn put_file(&self, path: &str, body: &[u8]) {
        let mut inner = self.inner.lock().expect("mock backend lock poisoned");
        bump_etag_insert(&mut inner.files, path, body);
    }

    /// Read raw stored bytes (test assertions).
    pub fn get_file(&self, path: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .expect("mock backend lock poisoned")
            .files
            .get(path)
            .map(|(body, _)| body.clone())
    }

    /// Schedule `count` preconditioned uploads to fail with `Conflict`.
    pub fn push_conflicts(&self, count: usize) {
        self.inner
            .lock()
            .expect("mock backend lock poisoned")
            .conflict_schedule
            .push_back(count);
    }
}

/// Insert/overwrite with a monotonically increasing ETag counter.
fn bump_etag_insert(files: &mut HashMap<String, (Vec<u8>, u64)>, path: &str, body: &[u8]) {
    let etag = files.get(path).map(|(_, e)| e + 1).unwrap_or(1);
    files.insert(path.to_string(), (body.to_vec(), etag));
}

impl CloudBackend for MockCloudBackend {
    fn stat(&self, path: &str) -> Result<Option<RemoteStat>, BackendError> {
        let inner = self.inner.lock().expect("mock backend lock poisoned");
        Ok(inner.files.get(path).map(|(body, etag)| RemoteStat {
            etag: Some(format!("mock-{etag}")),
            size: body.len() as u64,
        }))
    }

    fn download(&self, path: &str) -> Result<Vec<u8>, BackendError> {
        let inner = self.inner.lock().expect("mock backend lock poisoned");
        inner
            .files
            .get(path)
            .map(|(body, _)| body.clone())
            .ok_or_else(|| BackendError::Network(format!("missing file: {path}")))
    }

    fn upload(
        &self,
        path: &str,
        body: &[u8],
        precondition: Precondition,
    ) -> Result<(), BackendError> {
        let mut inner = self.inner.lock().expect("mock backend lock poisoned");
        match &precondition {
            Precondition::IfMatch(etag) => {
                let matches = inner
                    .files
                    .get(path)
                    .is_some_and(|(_, current)| &format!("mock-{current}") == etag);
                if !matches {
                    return Err(BackendError::Conflict);
                }
            }
            Precondition::IfAbsent => {
                if inner.files.contains_key(path) {
                    return Err(BackendError::Conflict);
                }
            }
            Precondition::Unconditional => {}
        }
        // Injected race simulation (D4: another device won the PUT race).
        if let Some(remaining) = inner.conflict_schedule.front_mut() {
            if *remaining > 0 {
                *remaining -= 1;
                return Err(BackendError::Conflict);
            }
            inner.conflict_schedule.pop_front();
        }
        bump_etag_insert(&mut inner.files, path, body);
        Ok(())
    }

    fn upload_unique(&self, path: &str, body: &[u8]) -> Result<(), BackendError> {
        // Unique names never conflict — a plain unconditional write (D4),
        // same shape as the WebDAV implementation's unconditional PUT.
        let mut inner = self.inner.lock().expect("mock backend lock poisoned");
        bump_etag_insert(&mut inner.files, path, body);
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<(), BackendError> {
        self.inner
            .lock()
            .expect("mock backend lock poisoned")
            .files
            .remove(path);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebDAV implementation (ureq 3 + Basic Auth)
// ---------------------------------------------------------------------------

/// WebDAV [`CloudBackend`] over ureq 3 with Basic Auth (P3.2).
///
/// Only the verbs needed here are used: PROPFIND (Depth:0 stat), GET, PUT
/// (conditional), MKCOL (405 ignored — collection exists), DELETE. ureq 3
/// has no convenience API for arbitrary verbs, so requests are built with
/// `http::Request` (re-exported as `ureq::http`) and sent via
/// [`ureq::Agent::run`].
pub struct WebDavBackend {
    /// Server root, e.g. `https://dav.jianguoyun.com/dav` (no trailing slash).
    server_root: String,
    /// `Authorization` header value (`Basic base64(user:password)`), kept
    /// zeroized-on-drop — it carries the password material.
    auth_header: Zeroizing<String>,
    agent: ureq::Agent,
}

/// Validate a remote path and URL-encode it segment by segment.
///
/// Guards against path traversal (`..`), absolute-path escapes and header
/// injection (control characters) — the path components come from user
/// config (`remote_dir`) plus engine-generated file names. Shared with the
/// Baidu adapter (P3.4), which reuses the validated+percent-encoded form as
/// its `path` API parameter value.
pub(crate) fn encode_remote_path(path: &str) -> Result<String, BackendError> {
    let mut encoded = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(BackendError::Network(format!(
                "invalid remote path segment in {path:?}"
            )));
        }
        let mut out = String::with_capacity(segment.len());
        for byte in segment.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(byte as char)
                }
                // Control characters can never be part of a legitimate DAV
                // path and would break request framing.
                0..=0x1f | 0x7f => {
                    return Err(BackendError::Network(
                        "invalid character in remote path".to_string(),
                    ))
                }
                // Anything else (spaces, unicode) is percent-encoded.
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        encoded.push(out);
    }
    Ok(encoded.join("/"))
}

impl WebDavBackend {
    /// Build a backend for `server_url` (trailing slashes normalized away)
    /// with Basic Auth from `username`/`password`.
    pub fn new(
        server_url: &str,
        username: &str,
        password: Zeroizing<String>,
    ) -> Result<Self, BackendError> {
        let root = server_url.trim_end_matches('/');
        if !(root.starts_with("https://") || root.starts_with("http://")) || root.len() <= 8 {
            return Err(BackendError::Network(
                "server URL must be an http(s) URL with a host".to_string(),
            ));
        }
        let credentials = format!("{}:{}", username, password.as_str());
        let auth_header =
            Zeroizing::new(format!("Basic {}", BASE64.encode(credentials.as_bytes())));

        // - allow_non_standard_methods(true): PROPFIND/MKCOL are WebDAV
        //   extension verbs that ureq's HTTP/1.1 method whitelist rejects
        //   otherwise (ureq#1015, config available since 3.4.2).
        // - http_status_as_error(false): return raw responses so 412 can map
        //   to `Conflict` and 404 to `Ok(None)` instead of generic errors.
        // - max_redirects(0): a 3xx must never silently re-send Basic Auth
        //   credentials to a different origin (the response comes back and
        //   is mapped to a Network error by the status check).
        let config = ureq::config::Config::builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .allow_non_standard_methods(true)
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        Ok(Self {
            server_root: root.to_string(),
            auth_header,
            agent: config.into(),
        })
    }

    /// Full URL for a remote path, after path validation/encoding.
    fn url_for(&self, path: &str) -> Result<String, BackendError> {
        let encoded = encode_remote_path(path)?;
        Ok(format!("{}/{}", self.server_root, encoded))
    }

    /// Send a request and return the raw response (any HTTP status).
    fn send(
        &self,
        method: &str,
        url: String,
        body: &[u8],
        headers: &[(&str, String)],
    ) -> Result<ureq::http::Response<ureq::Body>, BackendError> {
        let verb = ureq::http::Method::from_bytes(method.as_bytes())
            .map_err(|e| BackendError::Network(format!("bad method {method:?}: {e}")))?;
        let mut builder = ureq::http::Request::builder()
            .method(verb)
            .uri(url)
            .header("Authorization", self.auth_header.as_str());
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let request = builder
            .body(body.to_vec())
            .map_err(|e| BackendError::Network(format!("request build failed: {e}")))?;
        self.agent
            .run(request)
            .map_err(|e| BackendError::Network(format!("{method} failed: {e}")))
    }

    /// Is this status the "precondition failed" answer?
    fn is_precondition_failed(status: u16) -> bool {
        status == 412
    }

    /// PROPFIND Depth:0 stat with hand-rolled getetag/getcontentlength
    /// extraction (P3.2 — no XML parser dependency).
    fn propfind_stat(&self, path: &str) -> Result<Option<RemoteStat>, BackendError> {
        let url = self.url_for(path)?;
        let body = br#"<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><D:getcontentlength/></D:prop></D:propfind>"#;
        let mut response = self.send(
            "PROPFIND",
            url,
            body,
            &[
                ("Depth", "0".to_string()),
                ("Content-Type", "application/xml".to_string()),
            ],
        )?;
        match response.status().as_u16() {
            207 => {}
            // 409: some servers (坚果云 among them) answer PROPFIND with
            // Conflict instead of 404 when an ANCESTOR collection of the
            // path is missing (e.g. the remote dir before the first
            // connect). An ancestor cannot exist without the leaf existing
            // first — the leaf is absent. Bootstrap will MKCOL it on upload.
            404 | 409 => return Ok(None),
            401 | 403 => return Err(BackendError::Auth("PROPFIND rejected credentials".into())),
            other => {
                return Err(BackendError::Network(format!(
                    "PROPFIND failed with HTTP {other}"
                )))
            }
        }
        let xml = response
            .body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD_BYTES)
            .read_to_string()
            .map_err(|e| BackendError::Network(format!("PROPFIND body read failed: {e}")))?;
        let etag = xml_prop_value(&xml, "getetag");
        let size = xml_prop_value(&xml, "getcontentlength")
            .and_then(|text| text.parse::<u64>().ok())
            .unwrap_or(0);
        Ok(Some(RemoteStat { etag, size }))
    }

    /// MKCOL every ancestor collection of `path`, outermost first; 405
    /// (already exists) is ignored (P3.2). Most WebDAV servers refuse PUTs
    /// (409) into non-existent collections, so uploads create them on
    /// demand. Unknown MKCOL answers are tolerated and left to the retried
    /// PUT to decide.
    fn ensure_parent_dir(&self, path: &str) -> Result<(), BackendError> {
        let mut ancestors: Vec<String> = Vec::new();
        let mut current = path;
        while let Some((parent, _)) = current.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            ancestors.push(parent.to_string());
            current = parent;
        }
        for parent in ancestors.iter().rev() {
            let url = self.url_for(parent)?;
            let response = self.send("MKCOL", url, &[], &[])?;
            match response.status().as_u16() {
                // 201 created; 405 collection already exists; some servers
                // answer 301/405-family for existing collections — treat any
                // non-auth failure as "probably exists" and let the retried
                // PUT decide.
                201 | 405 | 301 => {}
                401 | 403 => return Err(BackendError::Auth("MKCOL rejected credentials".into())),
                _ => {}
            }
        }
        Ok(())
    }
}

impl CloudBackend for WebDavBackend {
    fn stat(&self, path: &str) -> Result<Option<RemoteStat>, BackendError> {
        self.propfind_stat(path)
    }

    fn download(&self, path: &str) -> Result<Vec<u8>, BackendError> {
        let url = self.url_for(path)?;
        let mut response = self.send("GET", url, &[], &[])?;
        match response.status().as_u16() {
            200 => {}
            // Same ancestor-missing nuance as stat: a 409 GET means the leaf
            // is absent (the engine treats any download error as a transient
            // failure and re-stats, so this stays consistent).
            404 | 409 => return Err(BackendError::Network("remote file vanished".to_string())),
            401 | 403 => return Err(BackendError::Auth("GET rejected credentials".into())),
            other => {
                return Err(BackendError::Network(format!(
                    "GET failed with HTTP {other}"
                )))
            }
        }
        response
            .body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD_BYTES)
            .read_to_vec()
            .map_err(|e| BackendError::Network(format!("GET body read failed: {e}")))
    }

    fn upload(
        &self,
        path: &str,
        body: &[u8],
        precondition: Precondition,
    ) -> Result<(), BackendError> {
        let url = self.url_for(path)?;
        let headers: Vec<(&str, String)> = match &precondition {
            Precondition::IfMatch(etag) => vec![("If-Match", etag.clone())],
            Precondition::IfAbsent => vec![("If-None-Match", "*".to_string())],
            Precondition::Unconditional => vec![],
        };
        match self.send("PUT", url.clone(), body, &headers) {
            Ok(response) => {
                let status = response.status().as_u16();
                match status {
                    200..=299 => Ok(()),
                    // 412 = precondition failed = someone else wrote first.
                    s if Self::is_precondition_failed(s) => Err(BackendError::Conflict),
                    401 | 403 => Err(BackendError::Auth("PUT rejected credentials".into())),
                    // Missing parent collection — create it and retry once.
                    409 => self.retry_after_mkcol(&url, body, &headers),
                    other => Err(BackendError::Network(format!(
                        "PUT failed with HTTP {other}"
                    ))),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn upload_unique(&self, path: &str, body: &[u8]) -> Result<(), BackendError> {
        // Unique file name → no precondition (D4); create parent on demand.
        let url = self.url_for(path)?;
        match self.send("PUT", url.clone(), body, &[]) {
            Ok(response) => {
                let status = response.status().as_u16();
                match status {
                    200..=299 => Ok(()),
                    401 | 403 => Err(BackendError::Auth("PUT rejected credentials".into())),
                    409 => self.retry_after_mkcol(&url, body, &[]),
                    other => Err(BackendError::Network(format!(
                        "PUT failed with HTTP {other}"
                    ))),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn delete(&self, path: &str) -> Result<(), BackendError> {
        let url = self.url_for(path)?;
        let response = self.send("DELETE", url, &[], &[])?;
        match response.status().as_u16() {
            200..=299 => Ok(()),
            404 => Ok(()), // already gone — idempotent
            401 | 403 => Err(BackendError::Auth("DELETE rejected credentials".into())),
            other => Err(BackendError::Network(format!(
                "DELETE failed with HTTP {other}"
            ))),
        }
    }
}

impl WebDavBackend {
    /// MKCOL the parent collection, then replay the exact same PUT once.
    fn retry_after_mkcol(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, String)],
    ) -> Result<(), BackendError> {
        let path = url
            .strip_prefix(&self.server_root)
            .unwrap_or(url)
            .trim_start_matches('/');
        self.ensure_parent_dir(path)?;
        let response = self.send("PUT", url.to_string(), body, headers)?;
        let status = response.status().as_u16();
        match status {
            200..=299 => Ok(()),
            s if Self::is_precondition_failed(s) => Err(BackendError::Conflict),
            401 | 403 => Err(BackendError::Auth("PUT rejected credentials".into())),
            other => Err(BackendError::Network(format!(
                "PUT failed with HTTP {other}"
            ))),
        }
    }
}

/// Minimal XML text extraction for one DAV property (P3.2: no XML parser).
///
/// Matches `<any-prefix:getetag>TEXT</any-prefix:getetag>` (namespace
/// prefixes vary across servers: `d:`, `D:`, `lp1:`, none) and returns the
/// trimmed TEXT. Self-closing or missing elements yield `None`.
fn xml_prop_value(xml: &str, local_name: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(relative) = lower[search_from..].find(local_name) {
        let name_start = search_from + relative;
        // The match must open a tag: either `<name` or `<prefix:name`.
        let opens_tag = match lower[..name_start].chars().last() {
            Some('<') => true,
            Some(':') => {
                let prefix_start = lower[..name_start - 1].rfind('<');
                match prefix_start {
                    Some(pos) => {
                        let prefix = &lower[pos + 1..name_start - 1];
                        !prefix.is_empty() && !prefix.contains('<') && !prefix.contains('>')
                    }
                    None => false,
                }
            }
            _ => false,
        };
        if !opens_tag {
            search_from = name_start + local_name.len();
            continue;
        }
        // Content starts after the closing '>' of the opening tag.
        let after_name = name_start + local_name.len();
        let content_start = lower[after_name..].find('>')? + after_name + 1;
        // Self-closing element (`<d:getetag/>`) → no content.
        if lower.as_bytes().get(content_start - 2) == Some(&b'/') {
            return None;
        }
        // Find the matching close tag `</...local_name`.
        let close_relative = lower[content_start..].find("</")?;
        let close_start = content_start + close_relative;
        let close_tail = &lower[close_start + 2..];
        let close_end = close_tail.find('>')?;
        if !close_tail[..close_end].ends_with(local_name) {
            search_from = close_start + 2;
            continue;
        }
        return Some(xml[content_start..close_start].trim().to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P3.2 path validation: traversal and control characters are rejected
    /// before any request leaves the process; ordinary names pass through.
    #[test]
    fn remote_path_validation_rejects_traversal_and_controls() {
        assert!(encode_remote_path("dir/pwdvault-sync.pwsync").is_ok());
        assert!(encode_remote_path("history/pwdvault-sync-r1.pwsync").is_ok());
        assert!(encode_remote_path("../etc/passwd").is_err());
        assert!(encode_remote_path("dir/../..").is_err());
        assert!(encode_remote_path("dir//file").is_err());
        // Spaces are encoded, not rejected (users have dirs with spaces).
        assert_eq!(encode_remote_path("dir/a b").unwrap(), "dir/a%20b");
        assert!(encode_remote_path("bad\u{7f}").is_err());
        assert!(encode_remote_path("bad\u{1}").is_err());
    }

    /// The tiny-XML extractor handles the namespace-prefix zoo of real DAV
    /// servers and ignores unrelated tags.
    #[test]
    fn xml_prop_extraction_handles_prefixes_and_missing_tags() {
        let doc = r#"<D:multistatus><D:response><D:href>/x</D:href><D:propstat><D:prop>
            <lp1:getetag>"abc-1"</lp1:getetag>
            <lp1:getcontentlength>1234</lp1:getcontentlength>
        </D:prop></D:propstat></D:response></D:multistatus>"#;
        assert_eq!(xml_prop_value(doc, "getetag").unwrap(), "\"abc-1\"");
        assert_eq!(xml_prop_value(doc, "getcontentlength").unwrap(), "1234");
        assert!(xml_prop_value(doc, "getlastmodified").is_none());

        let plain = r#"<response><getetag>"q-2"</getetag></response>"#;
        assert_eq!(xml_prop_value(plain, "getetag").unwrap(), "\"q-2\"");
        assert!(xml_prop_value("<d:getetag/>", "getetag").is_none());
        assert!(xml_prop_value("no tags at all", "getetag").is_none());
    }

    /// P3.6 item 4: the mock implements the exact precondition semantics the
    /// engine relies on (IfMatch mismatch → Conflict; IfAbsent on existing →
    /// Conflict; conflict scheduling consumed in order).
    #[test]
    fn mock_backend_preconditions_and_conflict_schedule() {
        let cloud = MockCloudBackend::new();
        cloud.put_file("c.pwsync", b"v1");

        let stat = cloud.stat("c.pwsync").unwrap().unwrap();
        assert_eq!(stat.size, 2);

        // IfMatch with the current etag succeeds and bumps the etag.
        cloud
            .upload(
                "c.pwsync",
                b"v2",
                Precondition::IfMatch(stat.etag.clone().unwrap()),
            )
            .unwrap();
        let stat2 = cloud.stat("c.pwsync").unwrap().unwrap();
        assert_ne!(stat2.etag, stat.etag);

        // Stale etag → Conflict; missing file with IfMatch → Conflict.
        assert!(matches!(
            cloud.upload(
                "c.pwsync",
                b"v3",
                Precondition::IfMatch(stat.etag.clone().unwrap())
            ),
            Err(BackendError::Conflict)
        ));
        assert!(matches!(
            cloud.upload("new.pwsync", b"x", Precondition::IfMatch("mock-9".into())),
            Err(BackendError::Conflict)
        ));
        // IfAbsent on existing → Conflict; on missing → Ok.
        assert!(matches!(
            cloud.upload("c.pwsync", b"v3", Precondition::IfAbsent),
            Err(BackendError::Conflict)
        ));
        cloud
            .upload("new.pwsync", b"x", Precondition::IfAbsent)
            .unwrap();

        // Conflict scheduling: uploads fail twice, then succeed.
        cloud.push_conflicts(2);
        assert!(matches!(
            cloud.upload(
                "c.pwsync",
                b"v3",
                Precondition::IfMatch(stat2.etag.clone().unwrap())
            ),
            Err(BackendError::Conflict)
        ));
        assert!(matches!(
            cloud.upload(
                "c.pwsync",
                b"v3",
                Precondition::IfMatch(stat2.etag.clone().unwrap())
            ),
            Err(BackendError::Conflict)
        ));
        cloud
            .upload(
                "c.pwsync",
                b"v3",
                Precondition::IfMatch(stat2.etag.unwrap()),
            )
            .unwrap();
        assert_eq!(cloud.get_file("c.pwsync").unwrap(), b"v3".to_vec());

        // Handles share storage; delete is idempotent.
        let other = cloud.handle();
        other.delete("c.pwsync").unwrap();
        other.delete("c.pwsync").unwrap();
        assert!(cloud.stat("c.pwsync").unwrap().is_none());
    }
}
