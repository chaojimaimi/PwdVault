# PwdVault 架构整改实施方案（v1.0.5）

> **版本**：v1.0.5
> **日期**：2026-07-04
> **范围**：针对架构评估中识别的设计不足（A/B/C/D 四大类，E 发布与分发暂不涉及），给出详细整改建议与可执行实施方案。
> **目标**：从"优秀的个人项目"升级为"可对外发布的可靠产品"。

---

## 目录

- [一、整改优先级矩阵](#一整改优先级矩阵)
- [二、P0 整改（安全关键）](#二p0-整改安全关键)
  - [A2. HTTP 端口加固 + pair 配对确认](#a2-http-端口加固--pair-配对确认)
  - [B1. 元数据加密](#b1-元数据加密)
  - [B2. 全库完整性 MAC](#b2-全库完整性-mac)
- [三、P1 整改](#三p1-整改)
  - [A1. 抽 service 层消除双写](#a1-抽-service-层消除双写)
  - [A3. keystore 移入 AppState](#a3-keystore-移入-appstate)
  - [B3. Zeroizing\<String\> 替换 unsafe](#b3-zeroizingstring-替换-unsafe)
  - [B4. 缩短明文密码生命周期](#b4-缩短明文密码生命周期)
  - [B6. 错误信息脱敏](#b6-错误信息脱敏)
- [四、P2 整改](#四p2-整改)
  - [A4. 自锁改事件驱动](#a4-自锁改事件驱动)
  - [B5. CSP 去 unsafe-inline](#b5-csp-去-unsafe-inline)
  - [C1/C2. 引入 tracing 结构化日志](#c1c2-引入-tracing-结构化日志)
  - [C3/C4. 常量集中 + 缩进修复](#c3c4-常量集中--缩进修复)
- [五、P3 整改](#五p3-整改)
  - [D1. 拆分 Context](#d1-拆分-context)
  - [D2. 数据缓存层](#d2-数据缓存层)
  - [D3. 文档同步](#d3-文档同步)
- [六、整改路线图](#六整改路线图)

---

## 一、整改优先级矩阵

| 编号 | 项 | 优先级 | 工作量 | 风险 |
|---|---|---|---|---|
| A2 | HTTP 端口 + pair 配对确认 | P0 | 中 | 高（安全） |
| B1 | 元数据加密 | P0 | 中 | 高（安全） |
| B2 | 全库完整性 MAC | P0 | 小 | 高（安全） |
| A1 | 抽 service 层消除双写 | P1 | 大 | 中（维护） |
| A3 | keystore 移入 AppState | P1 | 中 | 中（测试） |
| B3 | `Zeroizing<String>` 替换 unsafe | P1 | 小 | 低 |
| B4 | 缩短明文密码生命周期 | P1 | 中 | 中 |
| B6 | 错误信息脱敏 | P1 | 小 | 低 |
| A4 | 自锁改事件驱动 | P2 | 小 | 低 |
| B5 | CSP 去 `unsafe-inline` | P2 | 中 | 低 |
| C1/C2 | 引入 `tracing` | P2 | 中 | 低 |
| C3/C4 | 常量集中 + 缩进修复 | P2 | 小 | 低 |
| D1 | 拆分 Context | P3 | 中 | 低 |
| D2 | 数据缓存层 | P3 | 中 | 低 |
| D3 | 文档同步 | P3 | 小 | 低 |

---

## 二、P0 整改（安全关键）

### A2. HTTP 端口加固 + pair 配对确认

**目标**：消除"本机任意进程伪装扩展 Origin 拿 token"的攻击面。

**方案**：分两步走，先做配对确认（短期落地），再换传输（长期）。

#### Step 1（短期）pair 改为带外确认 + 一次性配对码

桌面端在收到 `/api/pair` 时弹窗显示 6 位配对码，用户在扩展 popup 输入相同码后才发 token。

新增 `src-tauri/src/pairing.rs`：

```rust
use std::sync::Mutex;
use once_cell::sync::Lazy;
use rand::Rng;

/// 一次性配对会话：60s 有效，只能用一次
struct PairSession {
    code: String,           // 6 位数字
    expires_at: std::time::Instant,
    origin: Option<String>, // 发起 pair 的扩展 origin
}

static SESSION: Lazy<Mutex<Option<PairSession>>> = Lazy::new(|| Mutex::new(None));

/// 创建配对会话（扩展调用 /api/pair 时触发）
pub fn create_session(origin: Option<String>) -> String {
    let mut rng = rand::rngs::OsRng;
    let code: String = (0..6).map(|_| rng.gen_range(0..10).to_string()).collect();
    let session = PairSession {
        code: code.clone(),
        expires_at: std::time::Instant::now() + std::time::Duration::from_secs(60),
        origin,
    };
    *SESSION.lock().unwrap() = Some(session);
    code
}

/// 验证用户在桌面输入的码（桌面 UI 调用）
pub fn verify(code: &str) -> bool {
    let mut guard = SESSION.lock().unwrap();
    if let Some(s) = guard.take() {  // take = 一次性
        s.code == code && s.expires_at > std::time::Instant::now()
    } else {
        false
    }
}
```

`/api/pair` 改为：

```rust
"pair" => {
    // 原有 rate limit 保留
    let code = pairing::create_session(origin.clone());
    // 通过 Tauri event 通知前端弹窗
    let _ = app_handle.emit("pair-request", &code);
    Ok(json!({ "pending": true }))  // 不再直接返回 token
}
```

新增 HTTP 端点 `/api/pair/confirm`：

```rust
"pair_confirm" => {
    let user_code = req.code.ok_or("Code required")?;
    if pairing::verify(&user_code) {
        let token = auth::get_token();
        Ok(json!({ "token": token }))
    } else {
        Err("Invalid or expired code".to_string())
    }
}
```

扩展 background.js 改为先调 `pair` → 等用户在桌面输入码 → 调 `pair_confirm`。

#### Step 2（长期）换 Unix socket / Windows named pipe

替换 `native_messaging.rs` 的 `tiny_http::Server::http` 为基于 `tokio` + `interprocess` 的本地 socket：

```rust
// 用 platform-specific 路径，例如 ~/Library/Application Support/com.pwdvault.app/api.sock
let sock_path = paths::socket_path();
let listener = interprocess::local_socket::LocalSocketListener::bind(sock_path)?;
// 服务器端通过 SO_PEERCRED (Linux) / getpeereid (macOS) 验证对端 uid == 本进程 uid
```

native host 二进制同样改为连 socket 而非 TCP。改完后端口 17429 可彻底关闭，CSP 的 `connect-src http://127.0.0.1:17429` 也可移除。

#### 验证

- 单元测试 `pairing::create_session` / `verify` 一次性、过期失效。
- 集成测试：未确认时 `pair_confirm` 失败；确认后拿到 token。
- 手动验证：用 `curl` 伪造 `Origin: chrome-extension://xxx` 调 `/api/pair`，应只收到 `{pending:true}` 而非 token。

---

### B1. 元数据加密

**目标**：拿到 vault.db 文件的人无法直接读到 title/url/username。

**方案**：把整个 `PasswordEntry`（除 id 外）序列化后整体加密，存到 redb 的 value 里。

#### Step 1 数据结构

在 `database/mod.rs` 改造：

```rust
/// 存储在 redb 的条目（id 明文 key，value 整体加密）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEntry {
    pub id: String,
    pub encrypted_blob: Vec<u8>,  // EncryptedData(bincode) of EntryPayload
}

/// 解密后的明文 payload（含原 PasswordEntry 所有字段）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPayload {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub encrypted_password: Vec<u8>,  // 二次加密的密码（保留分层）
    pub encrypted_notes: Option<Vec<u8>>,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
}
```

#### Step 2 加解密包装

新增 `database/entry_codec.rs`：

```rust
use crate::crypto::{encrypt, decrypt, get_key, EncryptedData};

pub fn seal(payload: &EntryPayload) -> Result<StoredEntry, VaultError> {
    let key = get_key()?;
    let plain = bincode::serialize(payload)
        .map_err(|e| VaultError::InternalError(e.to_string()))?;
    let enc = encrypt(&key, &plain)?;
    let blob = bincode::serialize(&enc)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    Ok(StoredEntry { id: payload.id.clone(), encrypted_blob: blob })
}

pub fn open(stored: &StoredEntry) -> Result<EntryPayload, VaultError> {
    let key = get_key()?;
    let enc: EncryptedData = bincode::deserialize(&stored.encrypted_blob)
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
    let plain = decrypt(&key, &enc)?;
    let payload = bincode::deserialize(&plain)
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
    Ok(payload)
}
```

#### Step 3 迁移

新增 `VAULT_META` 表存 schema 版本：

```rust
const META_TABLE: TableDefinition<&str, u32> = TableDefinition::new("meta");
// key "schema_version" = 1 (legacy) | 2 (encrypted metadata)
```

启动时若 `schema_version == 1`，在 `setup_vault` 解锁后做一次性迁移：

1. 遍历 ENTRIES_TABLE，读旧 `PasswordEntry`（明文元数据）
2. 用 `seal` 重新封装为 `StoredEntry`
3. 全部写回后更新 `schema_version = 2`

迁移在一个 redb 写事务内完成，失败回滚。

#### Step 4 影响范围

- `list_all_entries` 仍返回 `EntrySummary`，但内部需逐条 `open` 解密元数据。如担心性能，可在内存维护解密缓存（仅元数据，密码仍按需解密）。
- `Group` 同样改为加密存储（group name 也算元数据）。
- 导入导出 `BackupPayload` 字段不变（仍是明文，因为导出时本就要解密）。

#### 验证

- 测试：用 redb 命令行工具直接 dump vault.db，确认 ENTRIES_TABLE 的 value 是不可读的密文。
- 测试：迁移前后 round-trip 一致（v1 db → migrate → 读取 → 与原数据对比）。
- 测试：v1 db 迁移失败时（模拟 key 错误）数据零变更。

---

### B2. 全库完整性 MAC

**目标**：防回滚到旧版本、防条目互换。

**方案**：在 `VAULT_META` 表维护一个全库 HMAC，覆盖所有条目的 (id, ciphertext) 摘要。

新增 `database/integrity.rs`：

```rust
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

/// 计算当前全库 digest（按 id 排序，对每条 ciphertext 做 hash 链）
pub fn compute_db_digest(db: &Database, integrity_key: &[u8; 32]) -> Result<[u8; 32], DatabaseError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(ENTRIES_TABLE)?;
    let mut mac = HmacSha256::new_from_slice(integrity_key).unwrap();
    for result in table.iter()? {
        let (k, v) = result?;
        mac.update(k.value().as_bytes());
        mac.update(v.value());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

/// 启动时校验：DB 中存的 expected_digest == compute_db_digest
pub fn verify_integrity(db: &Database, integrity_key: &[u8; 32]) -> Result<bool, DatabaseError> {
    let txn = db.begin_read()?;
    let meta = txn.open_table(META_TABLE)?;
    let stored = meta.get("db_digest")?.map(|v| v.value().to_vec()).unwrap_or_default();
    drop(txn);
    let actual = compute_db_digest(db, integrity_key)?;
    Ok(stored == actual)
}

/// 每次写操作后更新 digest
pub fn refresh_digest(db: &Database, integrity_key: &[u8; 32]) -> Result<(), DatabaseError> {
    let digest = compute_db_digest(db, integrity_key)?;
    let txn = db.begin_write()?;
    {
        let mut meta = txn.open_table(META_TABLE)?;
        meta.insert("db_digest", digest.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}
```

**integrity_key 从哪来**：在 `init_vault` 时由主密码再派生一个独立子密钥（HKDF），与加密 key 分离：

```rust
// kdf.rs 新增
use hkdf::Hkdf;

pub fn derive_subkeys(master_key: &[u8; 32], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    hk.expand(b"pwdvault/encryption", &mut enc_key).unwrap();
    hk.expand(b"pwdvault/integrity", &mut mac_key).unwrap();
    (enc_key, mac_key)
}
```

`keystore` 改为存两个 key（或只存 master，每次派生）。VerificationData 增加 `mac_salt` 字段。

**启动校验流程**：

1. `setup_vault` 时 `verify_integrity` 失败 → 拒绝解锁，提示"数据库已被外部篡改或回滚"。
2. 每次写 entry/group 后 `refresh_digest`。

#### 验证

- 测试：复制一条 entry 的 ciphertext 到另一条 id 上 → 启动校验失败。
- 测试：备份 vault.db 后改一条再恢复 → 校验失败。
- 测试：正常 CRUD 后 digest 更新且校验通过。

---

## 三、P1 整改

### A1. 抽 service 层消除双写

**目标**：Tauri command 与 HTTP handler 共享同一份业务实现。

**方案**：新建 `src-tauri/src/service/` 目录，按域拆分：

```
service/
├── mod.rs
├── vault.rs      // init / unlock / lock / setup
├── entries.rs    // create / get / list / update / remove / count
├── groups.rs     // create / list / remove / update
├── settings.rs   // get / update
└── backup.rs     // export / import
```

每个 service 函数签名只依赖 `&Arc<AppState>` + 业务参数，返回 `Result<T, VaultError>`。例：

```rust
// service/entries.rs
pub fn create_entry(state: &Arc<AppState>, req: CreateEntryRequest) -> Result<EntrySummary, VaultError> {
    if !crypto::is_unlocked() {
        return Err(VaultError::VaultLocked);
    }
    validate_entry_input(&req)?;
    let db = get_db(state)?;
    let key = crypto::get_key()?;
    let enc_pwd = encrypt(&key, req.password.as_bytes())?;
    // ... 原有逻辑
    state.touch_activity();
    Ok(entry.into())
}
```

Tauri command 退化为薄包装：

```rust
#[tauri::command]
fn create_entry(request: CreateEntryRequest, state: State<'_, Arc<AppState>>) -> Result<EntrySummary, VaultError> {
    service::entries::create_entry(&state, request)
}
```

HTTP handler 同样：

```rust
"create_entry" => {
    let req: CreateEntryRequest = serde_json::from_value(req.request.ok_or("...")?)?;
    service::entries::create_entry(&state, req)
}
```

**迁移策略**：按端点逐步迁移，每迁一个跑一遍两边的测试。先从最简单的 `get_entry_count` / `lock_vault` 开始，最后做 `import_vault`。

#### 验证

迁移完成后，搜索 `lib.rs` 和 `native_messaging.rs` 中是否还有 `encrypt(` / `decrypt(` / `save_entry(` 等业务调用 —— 应为零。

---

### A3. keystore 移入 AppState

**目标**：去掉全局静态，恢复多线程测试。

**方案**：

`AppState` 增加：

```rust
pub struct AppState {
    // ...
    pub keystore: Mutex<Option<[u8; KEY_SIZE]>>,
    pub mac_key: Mutex<Option<[u8; 32]>>,  // 配合 B2
}
```

`crypto/keystore.rs` 的函数改为接收 `&AppState`：

```rust
pub fn set_key(state: &AppState, key: [u8; KEY_SIZE]) -> Result<(), KeyStoreError> {
    let mut ks = state.keystore.lock().expect("keystore lock poisoned");
    if let Some(existing) = ks.as_ref() {
        if existing == &key { return Ok(()); }
        return Err(KeyStoreError::AlreadyUnlocked);
    }
    *ks = Some(key);
    Ok(())
}

pub fn get_key(state: &AppState) -> Result<[u8; KEY_SIZE], KeyStoreError> {
    state.keystore.lock().expect("keystore lock poisoned")
        .ok_or(KeyStoreError::VaultLocked)
}

pub fn is_unlocked(state: &AppState) -> bool {
    state.keystore.lock().expect("keystore lock poisoned").is_some()
}

pub fn clear_key(state: &AppState) {
    let mut ks = state.keystore.lock().expect("keystore lock poisoned");
    if let Some(mut k) = ks.take() { k.zeroize(); }
}
```

`static KEYSTORE` 删除。`unlock_with_password` 等改为 `unlock_with_password(state, password, verification_data)`。

**测试改造**：每个 `setup_test_state()` 创建独立 `AppState`，不再共享全局 → 可恢复 `--test-threads=N`。删除 CLAUDE.md 中"必须 `--test-threads=1`"的注释。

#### 验证

`cargo test --test-threads=4` 全绿。

---

### B3. `Zeroizing<String>` 替换 unsafe

**目标**：消除 `lib.rs` 中 `unsafe { entry.password.as_bytes_mut() }.zeroize()` 的 unsafe 块。

**方案**：

`ExportEntry` / `EntryResponse` 的敏感字段改用 `zeroize::Zeroizing<String>`：

```rust
use zeroize::Zeroizing;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportEntry {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub password: Zeroizing<String>,  // drop 时自动 zeroize
    pub notes: Option<Zeroizing<String>>,
    // ...
}
```

`import_vault` 中的 `unsafe` 块直接删除：

```rust
// 原:
// for mut entry in payload.entries {
//     unsafe { entry.password.as_bytes_mut() }.zeroize();
// }
// 改: 无需任何代码，Zeroizing 在 drop 时自动清零
```

`EntryResponse.password` 同样改 `Zeroizing<String>`。注意 `serde` 默认支持 `Zeroizing<T>`（实现了 Serialize/Deserialize）。

#### 验证

编译无 unsafe 块；测试导入导出 round-trip 正常。

---

### B4. 缩短明文密码生命周期（已实施）

**目标**：前端不长期持有明文密码；仅在用户真正需要时解密，用完立即清除。

#### 桌面端

1. `get_entry` 拆分为两个端点：
   - `get_entry_meta(id)` → 返回 `EntrySummary`（id/title/url/username/tags/group/timestamps，不含 password/notes）
   - `get_entry_secret(id)` → 返回 `EntrySecretResponse { password, notes, last_used_at }`；调用后立即更新 `last_used_at` 并刷新全库 MAC

2. 后端新增 `src-tauri/src/lib.rs::EntrySecretResponse`，`service/entries.rs` 实现 `get_entry_meta` / `get_entry_secret`；旧的 `get_entry` 与 `EntryResponse` 已移除，杜绝误用。

3. `AppContext.tsx` 的 `selectedEntry` 改为 `EntrySummary | null`；`selectEntry(id)` 只调 `get_entry_meta`。

4. `EntryScreen.tsx` 进入编辑模式时才调用一次 `get_entry_secret` 加载密码/notes，保存在组件局部 state；组件卸载时立即清空 password/notes。"复制密码"优先使用当前表单中的密码，否则临时拉取 secret。

5. `VaultScreen.tsx` 的"复制密码"改为直接调 `get_entry_secret`，不再通过全局 state 传递明文。

#### 扩展端

6. 扩展路径仍通过 HTTP `get_entry_secret` 获取密码；后续可结合 A2 的 socket 方案进一步加密传输。

#### 验证

- `cargo test` 全绿，含 `test_get_entry_meta_and_secret` 验证 meta 无密码、secret 含密码且 `last_used_at` 更新。
- `pnpm build` 通过；`pnpm test` 全绿。
- 在 EntryScreen 用 React DevTools 查看 `AppContext.selectedEntry`，确认不含 `password`/`notes`。

---

### B6. 错误信息脱敏

**目标**：HTTP API 不泄露内部结构。

**方案**：

新增 `VaultError::public_message()`：

```rust
impl VaultError {
    /// 返回给前端/扩展的脱敏消息（不含路径、序列化细节）
    pub fn public_message(&self) -> String {
        match self {
            VaultError::VaultLocked => "Vault is locked".to_string(),
            VaultError::VaultAlreadyExists => "Vault already exists".to_string(),
            VaultError::InvalidPassword => "Invalid password".to_string(),
            VaultError::EntryNotFound => "Entry not found".to_string(),
            VaultError::RateLimited { retry_after_secs } => format!("Too many attempts. Retry in {}s", retry_after_secs),
            VaultError::InvalidBackup(_) => "Invalid backup file".to_string(),
            // 内部错误统一脱敏
            VaultError::EncryptionFailed(_) | VaultError::DecryptionFailed(_)
            | VaultError::DatabaseError(_) | VaultError::InternalError(_) => "Internal error".to_string(),
        }
    }
}
```

`native_messaging.rs` 的 `execute_command` 返回 `Err(String)` 处全部改用 `e.public_message()`（service 层返回 `VaultError`，HTTP 层转换）。

完整日志（含细节）走 `tracing::error!`（见 C2）只写本地日志文件。

#### 验证

测试触发 `DatabaseError` 时，HTTP 响应 body 为 `{"error":"Internal error"}`，不含 redb 错误堆栈。

---

## 四、P2 整改

### A4. 自锁改事件驱动

**目标**：消除 30 秒延迟。

**方案**：把轮询线程改为"sleep 到截止时间"模型：

```rust
fn start_auto_lock_thread(state: Arc<AppState>) {
    std::thread::spawn(move || loop {
        let deadline = {
            let activity = state.last_activity.lock().unwrap();
            let timeout = *state.auto_lock_secs.lock().unwrap();
            activity.map(|t| t + Duration::from_secs(timeout))
        };
        match deadline {
            Some(d) => {
                let now = Instant::now();
                if d > now {
                    std::thread::sleep(d - now);
                    // 醒来后重新检查（可能活动已被更新）
                    let should_lock = {
                        let activity = state.last_activity.lock().unwrap();
                        let timeout = *state.auto_lock_secs.lock().unwrap();
                        is_unlocked() && activity.map(|t| t.elapsed().as_secs() >= timeout).unwrap_or(false)
                    };
                    if should_lock {
                        state.lock_vault();
                        state.reload_window();
                    }
                } else {
                    // 已超时
                    state.lock_vault();
                    state.reload_window();
                }
            }
            None => std::thread::sleep(Duration::from_secs(5)),  // 未解锁，空转
        }
    });
}
```

每次 `touch_activity` 后通过 `Condvar` 唤醒线程重新计算 deadline（更精确，但代码复杂度上升；简化版可保留 sleep 但缩短到 1s 检查间隔）。

#### 验证

测试设置 `auto_lock_secs = 2`，操作后等 2.5s 必锁；操作后 1.5s 再操作，再等 2.5s 才锁。

---

### B5. CSP 去 `unsafe-inline`

**目标**：消除 `style-src 'unsafe-inline'`。

**方案**：

1. 全局搜索内联 style：`grep -rn 'style=' src/`，逐个改为 className + CSS。
2. 动态样式（如主题色变量）已经走 CSS custom properties，无需 inline。
3. StrengthMeter 等组件若用 `style={{ width: ${pct}% }}`，改为 CSS variable：

```tsx
<div className="meter-fill" style={{ '--fill': pct + '%' } as React.CSSProperties} />
```

CSS 用 `.meter-fill { width: var(--fill); }`。CSS variable 不违反 CSP。

4. `tauri.conf.json` 改为 `style-src 'self'`。

#### 验证

浏览器 DevTools Console 无 CSP 违规；功能正常。

---

### C1/C2. 引入 tracing 结构化日志（已实施）

**实施内容**：

1. `Cargo.toml` 新增 `tracing`、`tracing-subscriber`（含 `env-filter`）、`tracing-appender` 依赖。
2. `paths.rs` 新增 `log_dir()` 返回 `<app_data>/logs` 目录。
3. `lib.rs::run()` 初始化日志：daily-rotated 文件 `pwdvault.log`，默认级别 `pwdvault=info`，支持 `RUST_LOG` 覆盖。
4. 全局搜索替换 `println!`/`eprintln!` → `tracing::info!`/`tracing::error!`：
   - `native_messaging.rs`：server 启动日志
   - `lib.rs`：native host 注册失败、HTTP server 启动失败
   - `native_host_setup.rs`：浏览器注册失败

#### 验证

- `grep -rn 'println!\|eprintln!' src-tauri/src/` 返回零结果。
- 日志写入 `<app_data>/logs/pwdvault.log`，按日滚动。

---

### C3/C4. 常量集中 + 缩进修复（已实施）

**实施内容**：

1. 新建 `src-tauri/src/constants.rs`，集中所有跨模块共享的常量：
   - 输入长度上限：`MAX_FIELD_LENGTH` / `MAX_PASSWORD_LENGTH` / `MAX_NOTES_LENGTH` / `MAX_BODY_SIZE`
   - 自动锁：`AUTO_LOCK_SECS`
   - 速率限制：`MAX_FAILED_ATTEMPTS` / `LOCKOUT_DURATION_SECS`（test/prod 分离）/ `MAX_PAIR_REQUESTS_PER_MIN`
   - 原生通信：`NATIVE_MESSAGING_PORT`

2. `lib.rs`、`service/entries.rs`、`service/vault.rs`、`native_messaging.rs` 删除各自的本地常量定义，改为引用 `constants::`。

3. `lib.rs` 中 `use database::{...}` 块缩进已与上下文一致（0 空格）。

#### 验证

- `grep -rn '4096\|65536' src-tauri/src/` 只在 `constants.rs` 和 `kdf.rs`（Argon2 memory cost，语义不同）出现。
- `cargo test` 81 passed。

---

## 五、P3 整改

### D1. 拆分 Context（已实施）

**实施内容**：

1. 新建 `src/context/AuthContext.tsx`：管理 `screen` / `isInitialized` / `isUnlocked` / `isLoading` / `error` + `initialize` / `unlock` / `lock` / `navigate`。
2. 新建 `src/context/VaultContext.tsx`：管理 `entries` / `groups` / `selectedGroupId` / `selectedEntry` / `searchQuery` + entries/groups CRUD + `getEntrySecret` / `exportVault` / `importVault`。
3. 新建 `src/context/SettingsContext.tsx`：管理 `settings` / `updateInfo` + `loadSettings` / `updateSettings` / `checkForUpdates` / `dismissUpdate`。
4. `AppContext.tsx` 改为 facade：`AppProvider` 嵌套 `AuthProvider > SettingsProvider > VaultProvider`，并通过 `AppContextBridge` 合并三个子 context 为 `{ state, dispatch, actions }` 形态，保持向后兼容。
5. 新增细粒度 hooks：`useAuth()` / `useVault()` / `useSettings()`，新代码应优先使用。

#### 验证

- `pnpm build` + `pnpm test`（27 passed）全绿，现有 9 个调用 `useApp()` 的文件无需改动。

---

### D2. 数据缓存层（已实施）

**实施内容**：

新建 `src/hooks/useEntries.ts`，提供轻量级 entry 缓存 + 乐观更新：

- `entries`：当前 entries 列表（来自 VaultContext）
- `getById(id)`：O(1) Map 查找
- `refresh()`：重新拉取 entries
- `optimisticUpdate(id, patch)`：本地先更新，UI 即时响应
- `optimisticAdd(entry)`：本地先插入
- `optimisticRemove(id)`：本地先删除

未引入 `@tanstack/react-query`，保持 bundle 小（gzip ~84KB）。

#### 验证

- `pnpm build` 通过；`useEntries` 可在任意组件中调用。


---

### D3. 文档同步（已实施）

**实施内容**：

更新 `CLAUDE.md`：

1. Key Architectural Decisions §1 改为：Tauri IPC only；浏览器扩展使用独立 background.js + Native Messaging + HTTP API。
2. Test Suite Summary：Rust 81 tests / Frontend 27 tests；移除 `--test-threads=1` 要求（A3 已解除全局 keystore 约束）。
3. Development Commands：`cargo test` 不再带 `--test-threads=1`。
4. Technical Notes：更新为"Rust tests are parallel-safe"。
5. Known Issues：原"Pre-existing test failures"项标记为 Resolved。

---

## 六、整改路线图

按依赖关系排序的执行顺序：

```
Phase 1 (P0 安全)
  ├─ B2 全库完整性 MAC（先做，因为引入 mac_key）
  ├─ B1 元数据加密（依赖 B2 的 subkey 派生）
  └─ A2 pair 配对确认（独立，可并行）

Phase 2 (P1 架构)
  ├─ A3 keystore 移入 AppState（先做，A1 依赖它）
  ├─ A1 抽 service 层（依赖 A3 完成）
  ├─ B3 Zeroizing<String>（独立）
  ├─ B4 缩短明文生命周期（依赖 A1 的 get_entry 拆分）
  └─ B6 错误脱敏（依赖 A1 的 service 返回 VaultError）

Phase 3 (P2 质量)
  ├─ A4 自锁事件驱动
  ├─ B5 CSP 收紧
  ├─ C1/C2 tracing
  └─ C3/C4 常量集中

Phase 4 (P3 前端)
  ├─ D1 拆分 Context
  ├─ D2 数据缓存
  └─ D3 文档同步
```

每个 Phase 完成后跑全量测试 + `cargo audit`，确认无回归再进入下一阶段。

---

## 附录：相关文件索引

| 模块 | 关键文件 |
|---|---|
| 加密核心 | `src-tauri/src/crypto/{cipher,kdf,keystore,verification}.rs` |
| 业务逻辑 | `src-tauri/src/lib.rs`, `src-tauri/src/native_messaging.rs` |
| 数据存储 | `src-tauri/src/database/mod.rs` |
| 认证 | `src-tauri/src/auth.rs` |
| 前端状态 | `src/context/AppContext.tsx` |
| 前端 API | `src/api/vault.ts` |
| 配置 | `src-tauri/tauri.conf.json`, `package.json` |
| 文档 | `CLAUDE.md`, `DESIGN.md`, `Code-Security-Audit.md` |
