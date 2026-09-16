//! P3.4 Baidu Netdisk (百度网盘) adapter: the [`BaiduBackend`]
//! [`CloudBackend`] implementation (the OAuth2 pairing flow lives in
//! [`super::baidu_oauth`]).
//!
//! Wire contract (P3.4 / D4):
//! - stat = `filemetas` (size / md5 / dlink). Baidu has no ETags and no
//!   native conditional writes, so the `etag` slot carries the sibling
//!   manifest's revision as `rev:<n>`; `upload(IfMatch)` re-reads that
//!   manifest and reports [`BackendError::Conflict`] when the rev moved.
//! - download = the `dlink` URL with the access token appended. Baidu
//!   REQUIRES a `User-Agent` header on dlink requests.
//! - upload = precreate → superfile (4 MiB slices) → create, followed by a
//!   post-upload stat re-verification (size/md5 consistency, D4).
//! - token rejection (HTTP 401/403 or `errno: -6`) refreshes the token ONCE
//!   and retries; a failed refresh maps to [`BackendError::Auth`].
//!
//! Race window (accepted by the plan, D4): the manifest-rev guard is
//! SIMULATED — check-then-write is not atomic on Baidu's side, so a
//! concurrent writer can slip in between the guard and the final `create`.
//! The post-upload re-verification narrows but cannot close that window;
//! recovery rests on the engine's conflict loop (re-pull → re-merge →
//! retry) and the rolling history snapshots.

use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use super::backend::{
    encode_remote_path, BackendError, CloudBackend, Precondition, RemoteStat, MAX_DOWNLOAD_BYTES,
};
use super::baidu_oauth::{token_request, BaiduTokens};
use super::engine::MANIFEST_FILE;
use pwdvault_infrastructure::keychain::{
    SecretStore, SecretStoreError, SYNC_BAIDU_TOKEN_ACCOUNT,
};

/// Pan API base (production; tests inject the stub via
/// [`BaiduBackend::with_endpoints`]).
const PAN_API_BASE: &str = "https://pan.baidu.com";
/// OAuth base (production; also used by the OAuth commands in
/// [`super::baidu_oauth`]).
pub(crate) const OAUTH_API_BASE: &str = "https://openapi.baidu.com";
/// Baidu superfile slice size (P3.4: 4 MiB — containers are far smaller).
const UPLOAD_SLICE_SIZE: usize = 4 * 1024 * 1024;
/// Network timeout for one backend request (same bound as the WebDAV
/// backend; network I/O never runs inside the D8 window).
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Baidu rejects dlink requests without a User-Agent (P3.4).
pub(crate) const USER_AGENT: &str = concat!("pwdvault/", env!("CARGO_PKG_VERSION"));

/// Internal failure classification for one Baidu API call: either the token
/// was rejected (retryable after one refresh) or the failure is terminal.
enum ApiError {
    TokenExpired,
    Other(BackendError),
}

impl From<BackendError> for ApiError {
    fn from(err: BackendError) -> Self {
        ApiError::Other(err)
    }
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Validate a caller-supplied remote path and return its Baidu-absolute
/// form (`/apps/...`). Reuses the WebDAV segment validator: traversal
/// (`..`), empty segments and control characters never reach the network;
/// the returned value is already percent-encoded for use as an API
/// parameter value.
fn baidu_absolute_path(path: &str) -> Result<String, BackendError> {
    Ok(format!("/{}", encode_remote_path(path)?))
}

/// Percent-encode one query/form VALUE (everything but unreserved bytes) —
/// unlike [`encode_remote_path`] it keeps no path-segment semantics.
pub(crate) fn encode_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// MD5 hex digest (Baidu precreate block_list + post-upload verification).
pub(crate) fn md5_hex(bytes: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Baidu-absolute path of the rev manifest next to `baidu_path` (D4 layout).
fn manifest_path_for(baidu_path: &str) -> String {
    match baidu_path.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/{MANIFEST_FILE}"),
        None => format!("/{MANIFEST_FILE}"),
    }
}

fn is_manifest_path(baidu_path: &str) -> bool {
    baidu_path.ends_with(MANIFEST_FILE)
}

/// Minimal multipart/form-data for a single `file` field (ureq 3 ships no
/// multipart helper). Boundary from the OS CSPRNG.
fn multipart_body(content: &[u8]) -> (String, Vec<u8>) {
    use rand::RngCore;
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let boundary: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut body = Vec::with_capacity(content.len() + 256);
    body.extend_from_slice(
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"pwdvault-sync.bin\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

// ---------------------------------------------------------------------------
// BaiduBackend
// ---------------------------------------------------------------------------

/// Baidu Netdisk [`CloudBackend`] (P3.4). All network calls go through the
/// injectable endpoints — production points at the official Baidu domains,
/// tests at a local stub.
pub struct BaiduBackend {
    /// Pan API base, no trailing slash.
    api_base: String,
    /// OAuth base, no trailing slash.
    oauth_base: String,
    app_key: String,
    /// OAuth client secret — zeroized on drop.
    secret_key: Zeroizing<String>,
    /// Non-interactive credential store holding the token JSON under
    /// [`SYNC_BAIDU_TOKEN_ACCOUNT`]. Read per request so a refreshed token
    /// is visible to every later call.
    token_store: Arc<dyn SecretStore>,
    agent: ureq::Agent,
}

impl BaiduBackend {
    /// Production constructor (official endpoints + compiled-in
    /// AppKey/SecretKey). The caller checks [`baidu_configured`] first.
    pub fn new(app_key: &str, secret_key: &str, token_store: Arc<dyn SecretStore>) -> Self {
        Self::with_endpoints(PAN_API_BASE, OAUTH_API_BASE, app_key, secret_key, token_store)
    }

    /// Endpoint-injecting constructor — tests point at the local stub while
    /// production uses the official Baidu domains (P3.4 requirement).
    pub fn with_endpoints(
        api_base: &str,
        oauth_base: &str,
        app_key: &str,
        secret_key: &str,
        token_store: Arc<dyn SecretStore>,
    ) -> Self {
        let config = ureq::config::Config::builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            // dlink answers redirect to the data nodes — downloads must
            // follow. ureq only follows redirects for safe methods; the
            // dlink URL (access token appended) may therefore reach a Baidu
            // CDN host — accepted: the container is E2E encrypted and the
            // token is app-scoped (same tradeoff as the official SDKs).
            .max_redirects(5)
            .build();
        Self {
            api_base: api_base.trim_end_matches('/').to_string(),
            oauth_base: oauth_base.trim_end_matches('/').to_string(),
            app_key: app_key.to_string(),
            secret_key: Zeroizing::new(secret_key.to_string()),
            token_store,
            agent: config.into(),
        }
    }

    /// Send one request with the mandatory User-Agent header and return
    /// (status, body) — body reads are capped at [`MAX_DOWNLOAD_BYTES`].
    fn send(
        &self,
        method: &str,
        url: String,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(u16, Vec<u8>), BackendError> {
        let verb = ureq::http::Method::from_bytes(method.as_bytes())
            .map_err(|e| BackendError::Network(format!("bad method {method:?}: {e}")))?;
        let mut builder = ureq::http::Request::builder()
            .method(verb)
            .uri(url)
            // Baidu REQUIRES a User-Agent on dlink requests (P3.4); harmless
            // and diagnosable on the JSON endpoints.
            .header("User-Agent", USER_AGENT);
        if let Some(content_type) = content_type {
            builder = builder.header("Content-Type", content_type);
        }
        let request = builder
            .body(body)
            .map_err(|e| BackendError::Network(format!("request build failed: {e}")))?;
        let mut response = self
            .agent
            .run(request)
            .map_err(|e| BackendError::Network(format!("{method} failed: {e}")))?;
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD_BYTES)
            .read_to_vec()
            .map_err(|e| BackendError::Network(format!("{method} body read failed: {e}")))?;
        Ok((status, bytes))
    }

    // -- token plumbing ------------------------------------------------------

    fn load_tokens(&self) -> Result<BaiduTokens, BackendError> {
        let bytes = self.token_store.get(SYNC_BAIDU_TOKEN_ACCOUNT).map_err(|err| {
            match err {
                SecretStoreError::NotFound => BackendError::Auth(
                    "Baidu Netdisk is not linked — complete the authorization flow first"
                        .to_string(),
                ),
                other => BackendError::Auth(format!("credential store unavailable: {other}")),
            }
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|_| BackendError::Auth("stored Baidu token is corrupt — re-authorize".into()))
    }

    fn save_tokens(&self, tokens: &BaiduTokens) -> Result<(), BackendError> {
        let bytes = serde_json::to_vec(tokens)
            .map_err(|e| BackendError::Network(format!("token serialization failed: {e}")))?;
        self.token_store
            .set(SYNC_BAIDU_TOKEN_ACCOUNT, &bytes)
            .map_err(|err| BackendError::Auth(format!("cannot persist Baidu token: {err}")))
    }

    /// Refresh the token pair ONCE (P3.4). Baidu refresh tokens are
    /// single-use, so the fresh pair must be persisted before use.
    fn refresh_tokens(&self, current: &BaiduTokens) -> Result<BaiduTokens, BackendError> {
        let query = format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
            encode_value(&current.refresh_token),
            encode_value(&self.app_key),
            encode_value(&self.secret_key),
        );
        let fresh = token_request(&self.oauth_base, &query)?;
        self.save_tokens(&fresh)?;
        Ok(fresh)
    }

    /// Run `op` with the current access token; on token rejection (HTTP
    /// 401/403 or `errno: -6`) refresh once and retry (P3.4). A second
    /// rejection after a successful refresh surfaces as [`BackendError::Auth`].
    fn with_access_token<T>(
        &self,
        op: impl Fn(&str) -> Result<T, ApiError>,
    ) -> Result<T, BackendError> {
        let tokens = self.load_tokens()?;
        match op(&tokens.access_token) {
            Ok(value) => Ok(value),
            Err(ApiError::Other(err)) => Err(err),
            Err(ApiError::TokenExpired) => {
                let fresh = self.refresh_tokens(&tokens)?;
                op(&fresh.access_token).map_err(|err| match err {
                    ApiError::Other(e) => e,
                    ApiError::TokenExpired => BackendError::Auth(
                        "token rejected even after a refresh — re-authorize Baidu Netdisk".into(),
                    ),
                })
            }
        }
    }

    // -- pan API calls -------------------------------------------------------

    /// `filemetas` for one path: `Ok(None)` = file does not exist.
    fn filemetas(&self, access_token: &str, baidu_path: &str) -> Result<Option<FileMeta>, ApiError> {
        let url = format!(
            "{}/rest/2.0/xpan/file?method=filemetas&access_token={}&dlink=1&path={}",
            self.api_base,
            encode_value(access_token),
            encode_value(baidu_path),
        );
        let (status, body) = self.send("GET", url, Vec::new(), None)?;
        if status == 401 || status == 403 {
            return Err(ApiError::TokenExpired);
        }
        let parsed: FileMetasResponse = serde_json::from_slice(&body)
            .map_err(|_| BackendError::Network("filemetas returned non-JSON".to_string()))?;
        match parsed.errno {
            0 => Ok(parsed.list.into_iter().next()),
            // -6 身份验证失败: access token invalid/expired.
            -6 => Err(ApiError::TokenExpired),
            // 31066 / 12: file does not exist.
            31066 | 12 => Ok(None),
            other => Err(BackendError::Network(format!("filemetas errno {other}")).into()),
        }
    }

    /// GET a dlink URL with the access token appended (Baidu requirement);
    /// the User-Agent header is set centrally in [`BaiduBackend::send`].
    fn fetch_dlink(&self, access_token: &str, dlink: &str) -> Result<Vec<u8>, ApiError> {
        let separator = if dlink.contains('?') { '&' } else { '?' };
        let url = format!("{dlink}{separator}access_token={}", encode_value(access_token));
        let (status, body) = self.send("GET", url, Vec::new(), None)?;
        if status == 401 || status == 403 {
            return Err(ApiError::TokenExpired);
        }
        if !(200..300).contains(&status) {
            return Err(BackendError::Network(format!(
                "dlink download failed with HTTP {status}"
            ))
            .into());
        }
        Ok(body)
    }

    /// Read the current manifest rev (the D4 rev-comparison basis). `None`
    /// when the manifest is absent or unreadable — the same degraded mode
    /// the engine uses for ETag-less WebDAV servers (unconditional writes).
    fn fetch_manifest_rev(&self, baidu_manifest_path: &str) -> Result<Option<u64>, BackendError> {
        self.with_access_token(|token| {
            let Some(meta) = self.filemetas(token, baidu_manifest_path)? else {
                return Ok(None);
            };
            let Some(dlink) = meta.dlink else {
                return Ok(None);
            };
            let bytes = self.fetch_dlink(token, &dlink)?;
            let manifest: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| BackendError::Network("sync manifest is corrupt".to_string()))?;
            Ok(manifest.get("rev").and_then(|rev| rev.as_u64()))
        })
    }

    /// The simulated If-Match (D4): `token` is the `rev:<n>` string handed
    /// out by [`CloudBackend::stat`]. Re-reads the sibling manifest and
    /// reports [`BackendError::Conflict`] when the rev moved. Fails CLOSED
    /// on a token we did not mint — `stat` is the only producer, so a
    /// foreign token means the caller mixed backends.
    fn guard_manifest_rev(&self, baidu_path: &str, token: &str) -> Result<(), BackendError> {
        let Some(expected) = token.strip_prefix("rev:").and_then(|rev| rev.parse::<u64>().ok())
        else {
            return Err(BackendError::Conflict);
        };
        match self.fetch_manifest_rev(&manifest_path_for(baidu_path))? {
            // Manifest gone since our stat — treat as a concurrent change.
            None => Err(BackendError::Conflict),
            Some(rev) if rev == expected => Ok(()),
            Some(_) => Err(BackendError::Conflict),
        }
    }

    /// The Baidu three-step upload (P3.4): precreate → superfile per 4 MiB
    /// slice → create (commit). Every step goes through
    /// [`with_access_token`], so a mid-upload expiry refreshes once.
    fn slice_upload(&self, baidu_path: &str, body: &[u8]) -> Result<(), BackendError> {
        let slices: Vec<&[u8]> = if body.is_empty() {
            vec![&[]]
        } else {
            body.chunks(UPLOAD_SLICE_SIZE).collect()
        };
        let block_list: Vec<String> = slices.iter().map(|slice| md5_hex(slice)).collect();
        let block_json = serde_json::to_string(&block_list)
            .map_err(|e| BackendError::Network(format!("block_list serialization failed: {e}")))?;
        let size = body.len();

        // 1. precreate — registers the upload, returns the upload id.
        let upload_id = self.with_access_token(|token| {
            let form = format!(
                "path={}&size={size}&isdir=0&block_list={}",
                encode_value(baidu_path),
                encode_value(&block_json),
            );
            let url = format!(
                "{}/rest/2.0/xpan/file?method=precreate&access_token={}",
                self.api_base,
                encode_value(token)
            );
            let (status, response) =
                self.send("POST", url, form.into_bytes(), Some(FORM_CONTENT_TYPE))?;
            require_ok(status, &response, "precreate")?;
            let value: serde_json::Value = serde_json::from_slice(&response)
                .map_err(|_| BackendError::Network("precreate returned non-JSON".to_string()))?;
            check_errno(&value, "precreate")?;
            upload_id_of(&value)
        })?;

        // 2. superfile — one multipart request per 4 MiB slice.
        for (partseq, slice) in slices.iter().enumerate() {
            self.with_access_token(|token| {
                let url = format!(
                    "{}/rest/2.0/xpan/file?method=superfile&access_token={}&path={}&uploadid={}&partseq={partseq}",
                    self.api_base,
                    encode_value(token),
                    encode_value(baidu_path),
                    encode_value(&upload_id),
                );
                let (boundary, multipart) = multipart_body(slice);
                let content_type = format!("multipart/form-data; boundary={boundary}");
                let (status, response) = self.send("POST", url, multipart, Some(&content_type))?;
                require_ok(status, &response, "superfile")?;
                let value: serde_json::Value = serde_json::from_slice(&response).map_err(|_| {
                    BackendError::Network("superfile returned non-JSON".to_string())
                })?;
                check_errno(&value, "superfile")
            })?;
        }

        // 3. create — commit (isdir=0, size, mtime per plan P3.4).
        self.with_access_token(|token| {
            let form = format!(
                "path={}&size={size}&isdir=0&block_list={}&uploadid={}&mtime={}",
                encode_value(baidu_path),
                encode_value(&block_json),
                encode_value(&upload_id),
                now_secs(),
            );
            let url = format!(
                "{}/rest/2.0/xpan/file?method=create&access_token={}",
                self.api_base,
                encode_value(token)
            );
            let (status, response) =
                self.send("POST", url, form.into_bytes(), Some(FORM_CONTENT_TYPE))?;
            require_ok(status, &response, "create")?;
            let value: serde_json::Value = serde_json::from_slice(&response)
                .map_err(|_| BackendError::Network("create returned non-JSON".to_string()))?;
            check_errno(&value, "create")
        })
    }

    /// D4 post-upload re-verification: stat the file and require size (and
    /// md5, when the API reports one) to match what we sent.
    fn verify_upload(&self, baidu_path: &str, body: &[u8]) -> Result<(), BackendError> {
        let meta = self
            .with_access_token(|token| self.filemetas(token, baidu_path))?
            .ok_or_else(|| {
                BackendError::Network("uploaded file missing after create".to_string())
            })?;
        if meta.size != body.len() as u64 {
            return Err(BackendError::Network(format!(
                "post-upload verification failed: remote size {} != local {}",
                meta.size,
                body.len()
            )));
        }
        if !meta.md5.is_empty() && meta.md5 != md5_hex(body) {
            return Err(BackendError::Network(
                "post-upload verification failed: content md5 mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Map a non-2xx status; 401/403 and `errno: -6` (which Baidu may ride on
/// any HTTP status) request a token refresh.
fn require_ok(status: u16, body: &[u8], step: &str) -> Result<(), ApiError> {
    if status == 401 || status == 403 {
        return Err(ApiError::TokenExpired);
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        if value.get("errno").and_then(|errno| errno.as_i64()) == Some(-6) {
            return Err(ApiError::TokenExpired);
        }
    }
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(BackendError::Network(format!(
            "{step} returned HTTP {status}"
        ))
        .into())
    }
}

/// Map a Baidu JSON envelope `errno` (0 = ok, -6 = invalid token).
fn check_errno(value: &serde_json::Value, step: &str) -> Result<(), ApiError> {
    match value.get("errno").and_then(|errno| errno.as_i64()) {
        Some(0) | None => Ok(()),
        Some(-6) => Err(ApiError::TokenExpired),
        Some(other) => Err(BackendError::Network(format!("{step} errno {other}")).into()),
    }
}

/// `uploadid` arrives as a JSON string or number depending on the endpoint.
fn upload_id_of(value: &serde_json::Value) -> Result<String, ApiError> {
    match value.get("uploadid") {
        Some(serde_json::Value::String(id)) => Ok(id.clone()),
        Some(serde_json::Value::Number(id)) => Ok(id.to_string()),
        _ => Err(BackendError::Network("response missing uploadid".to_string()).into()),
    }
}

/// One entry of the filemetas `list` (only the fields we consume).
#[derive(Debug, serde::Deserialize)]
struct FileMeta {
    #[serde(default)]
    size: u64,
    #[serde(default)]
    md5: String,
    #[serde(default)]
    dlink: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct FileMetasResponse {
    #[serde(default)]
    errno: i64,
    #[serde(default)]
    list: Vec<FileMeta>,
}

impl CloudBackend for BaiduBackend {
    fn stat(&self, path: &str) -> Result<Option<RemoteStat>, BackendError> {
        let baidu_path = baidu_absolute_path(path)?;
        // The conditional-write token is the sibling manifest's rev (D4):
        // `IfMatch` on Baidu is simulated by re-reading the manifest before
        // an upload. For the manifest itself (and while it is absent) there
        // is no token — the engine then runs its degraded manifest-rev check
        // or writes unconditionally.
        let etag = if is_manifest_path(&baidu_path) {
            None
        } else {
            self.fetch_manifest_rev(&manifest_path_for(&baidu_path))?
                .map(|rev| format!("rev:{rev}"))
        };
        let meta = self.with_access_token(|token| self.filemetas(token, &baidu_path))?;
        Ok(meta.map(|meta| RemoteStat { etag, size: meta.size }))
    }

    fn download(&self, path: &str) -> Result<Vec<u8>, BackendError> {
        let baidu_path = baidu_absolute_path(path)?;
        self.with_access_token(|token| {
            let Some(meta) = self.filemetas(token, &baidu_path)? else {
                return Err(BackendError::Network("remote file vanished".to_string()).into());
            };
            let Some(dlink) = meta.dlink else {
                return Err(BackendError::Network("filemetas returned no dlink".to_string()).into());
            };
            self.fetch_dlink(token, &dlink)
        })
    }

    fn upload(
        &self,
        path: &str,
        body: &[u8],
        precondition: Precondition,
    ) -> Result<(), BackendError> {
        let baidu_path = baidu_absolute_path(path)?;
        // D4 on Baidu: preconditions are SIMULATED (no native If-Match).
        // Check-then-write is not atomic — the race window between the
        // guard and the final `create` is real and accepted by the plan
        // (see the module docs for the recovery paths).
        match &precondition {
            Precondition::IfMatch(token) => self.guard_manifest_rev(&baidu_path, token)?,
            Precondition::IfAbsent => {
                let exists =
                    self.with_access_token(|token| self.filemetas(token, &baidu_path))?.is_some();
                if exists {
                    return Err(BackendError::Conflict);
                }
            }
            Precondition::Unconditional => {}
        }
        self.slice_upload(&baidu_path, body)?;
        self.verify_upload(&baidu_path, body)
    }

    fn upload_unique(&self, path: &str, body: &[u8]) -> Result<(), BackendError> {
        // Unique names cannot conflict (D4) — no precondition.
        let baidu_path = baidu_absolute_path(path)?;
        self.slice_upload(&baidu_path, body)?;
        self.verify_upload(&baidu_path, body)
    }

    fn delete(&self, path: &str) -> Result<(), BackendError> {
        let baidu_path = baidu_absolute_path(path)?;
        let filelist_json = serde_json::to_string(&[baidu_path.as_str()])
            .map_err(|e| BackendError::Network(format!("filelist serialization failed: {e}")))?;
        self.with_access_token(|token| {
            let url = format!(
                "{}/rest/2.0/xpan/filemanager?method=delete&access_token={}&filelist={}",
                self.api_base,
                encode_value(token),
                encode_value(&filelist_json),
            );
            let (status, response) = self.send("POST", url, Vec::new(), None)?;
            require_ok(status, &response, "delete")?;
            let value: serde_json::Value = serde_json::from_slice(&response)
                .map_err(|_| BackendError::Network("delete returned non-JSON".to_string()))?;
            match value.get("errno").and_then(|errno| errno.as_i64()) {
                Some(0) | None => Ok(()),
                // 12 = file does not exist — deleting a missing file
                // succeeds (idempotent, same contract as WebDAV).
                Some(12) | Some(31066) => Ok(()),
                Some(-6) => Err(ApiError::TokenExpired),
                Some(other) => {
                    Err(BackendError::Network(format!("delete errno {other}")).into())
                }
            }
        })
    }
}
