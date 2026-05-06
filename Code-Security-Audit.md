# PwdVault 代码安全审计报告

| 项目 | 详情 |
|------|------|
| **审计日期** | 2026-05-06 |
| **项目名称** | PwdVault — 本地优先密码管理器 |
| **技术栈** | Tauri v2 + Rust (后端), React 19 + TypeScript (前端), Chrome/Firefox MV3 (浏览器扩展) |
| **当前版本** | v1.0.0 |
| **审计方法** | 静态代码分析（SAST），基于 OWASP Top 10、CWE/SANS Top 25 |
| **审计范围** | Rust 后端（9 个源文件）、React 前端（18 个源文件）、浏览器扩展（7 个源文件） |
| **审计工具** | AI 辅助代码安全审计（code-auditor agent，逐文件静态分析 + 数据流追踪） |

---

## 问题统计

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **CRITICAL** | 4 | 17% |
| **HIGH** | 8 | 35% |
| **MEDIUM** | 7 | 30% |
| **LOW** | 4 | 18% |
| **合计** | **23** | 100% |

### 按模块分布

| 模块 | CRITICAL | HIGH | MEDIUM | LOW | 小计 |
|------|----------|------|--------|-----|------|
| Rust 后端 | 2 | 4 | 3 | 1 | 10 |
| React 前端 | 0 | 2 | 2 | 3 | 7 |
| 浏览器扩展 | 2 | 2 | 2 | 0 | 6 |

---

## CRITICAL 级别漏洞（4个）

---

### [BE-CRIT-001] HTTP API 无认证 — 任何本地进程可访问密码库

#### 漏洞说明

HTTP 服务器在 `127.0.0.1:17429` 上暴露了所有密码库操作，包括 `unlock_vault`、`get_entry`（返回解密密码）、`export_vault`（导出所有解密密码）、`import_vault`（覆盖所有数据）和 `lock_vault`，**没有任何形式的认证机制**。

同一台机器上的任何进程都可以通过 HTTP POST 请求访问这些端点。服务器接受来自任何来源的请求（CORS `Access-Control-Allow-Origin: *`），没有会话 token、API 密钥或共享密钥。恶意脚本、被入侵的浏览器标签页或任何本地执行的恶意软件都可以轻易枚举、解密和窃取所有存储的密码。

**CWE-306: Missing Authentication for Critical Function**

#### 漏洞位置

| 文件 | 行号 | 说明 |
|------|------|------|
| `src-tauri/src/native_messaging.rs` | 81-94 | 服务器启动，无认证中间件 |
| `src-tauri/src/native_messaging.rs` | 96-110 | CORS 通配符，允许所有来源 |
| `src-tauri/src/native_messaging.rs` | 191-886 | 所有命令处理器，均无认证检查 |

#### 关键点

```rust
// native_messaging.rs:81-94 — 服务器直接处理请求，无认证
pub fn start_server(port: u16, state: Arc<AppState>) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", port);
    let server = Server::http(&addr)
        .map_err(|e| format!("Failed to bind server: {}", e))?;
    for request in server.incoming_requests() {
        handle_request(request, state.clone());  // 直接处理，无认证
    }
    Ok(())
}

// native_messaging.rs:96-110 — CORS 允许所有来源
fn add_cors_headers(response: &mut Response<std::io::Cursor<Vec<u8>>>) {
    response.add_header(
        tiny_http::Header::from_bytes("Access-Control-Allow-Origin".as_bytes(), "*".as_bytes())
            .expect("valid CORS header")
    );
}
```

#### 攻击场景

```bash
# 攻击者在同一台机器执行：
curl -X POST http://127.0.0.1:17429/api/get_entry \
  -H 'Content-Type: application/json' \
  -d '{"id":1,"command":"get_entry","id_param":"<any-uuid>"}'
# 返回: {"success":true,"data":{"password":"明文密码",...}}

curl -X POST http://127.0.0.1:17429/api/export_vault \
  -H 'Content-Type: application/json' \
  -d '{"id":1,"command":"export_vault","export_password":"attacker-key"}'
# 返回: 所有密码的加密备份

curl -X POST http://127.0.0.1:17429/api/import_vault \
  -d '{"id":1,"command":"import_vault",...}'
# 效果: 用攻击者控制的数据覆盖所有密码库数据
```

#### 修复建议

1. 在桌面应用首次启动时生成随机 API Token（256 位），存储在仅当前用户可读的文件中（`chmod 600`）
2. 每个 HTTP 请求验证 `Authorization: Bearer <token>` 头
3. 浏览器扩展通过 native messaging 握手或共享文件获取 token
4. 将 CORS 通配符替换为特定的 `chrome-extension://` 和 `moz-extension://` 来源

```rust
// 示例修复代码
fn handle_request(mut request: Request, state: Arc<AppState>) {
    if request.method() != &tiny_http::Method::Options {
        let expected_token = get_or_create_api_token().unwrap_or_default();
        let auth_header = request.headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"));
        match auth_header {
            Some(h) if h.value.as_str() == format!("Bearer {}", expected_token) => {}
            _ => {
                let resp = create_error_response(0, "Unauthorized".to_string());
                let _ = request.respond(resp);
                return;
            }
        }
    }
    // ... 继续处理
}
```

---

### [BE-CRIT-002] 密钥验证失败后未零化 — 内存中残留派生密钥

#### 漏洞说明

在 `verification.rs` 中，`verify_password()` 和 `unlock_with_password()` 使用 Argon2id 从密码派生密钥。当密码不正确时，派生的密钥（`[u8; 32]`）留在栈上直到函数返回。更严重的是，当 `unlock_with_password()` 中 `set_key()` 失败时，`key` 数组未零化直接返回给调用者。

即使验证失败（错误密码），派生的密钥字节仍然留在内存中。虽然是错误的密钥，但仍会泄露有关密码派生的信息，可能有助于对内存转储进行暴力破解攻击。

**CWE-316: Cleartext Storage of Sensitive Information in Memory**

#### 漏洞位置

| 文件 | 行号 | 说明 |
|------|------|------|
| `src-tauri/src/crypto/verification.rs` | 60-72 | `verify_password` — 失败路径未零化 |
| `src-tauri/src/crypto/verification.rs` | 75-93 | `unlock_with_password` — 所有路径未零化 |
| `src-tauri/src/crypto/kdf.rs` | 117-129 | `derive_key_with_params` — 中间密钥未零化 |

#### 关键点

```rust
// verification.rs:60-72 — 验证失败时 key 从未零化
pub fn verify_password(
    password: &str,
    verification_data: &VerificationData,
) -> Result<bool, VerificationError> {
    let (key, _) = derive_key_with_params(password, &verification_data.salt, &verification_data.params)
        .map_err(|e| VerificationError::KdfError(e.to_string()))?;
    // key: [u8; 32] 在栈上，从未零化

    match cipher::decrypt(&key, &verification_data.encrypted_header) {
        Ok(decrypted) => Ok(decrypted.as_slice() == VERIFICATION_HEADER),
        // 返回 false 时，'key' 未零化直接丢弃
        Err(_) => Ok(false),
    }
}

// verification.rs:75-93 — unlock 失败路径同理
pub fn unlock_with_password(...) -> Result<bool, VerificationError> {
    let (key, _) = derive_key_with_params(...)?;
    match cipher::decrypt(&key, &verification_data.encrypted_header) {
        Ok(decrypted) => {
            if decrypted.as_slice() == VERIFICATION_HEADER {
                keystore::set_key(key)?;  // 如果 set_key 失败，key 未零化
                return Ok(true);
            }
            Ok(false)  // 错误密码，key 未零化
        }
        Err(_) => Ok(false),  // 所有路径: key 未零化
    }
}
```

#### 修复建议

在所有退出路径上显式调用 `key.zeroize()`：

```rust
use zeroize::Zeroize;

pub fn verify_password(...) -> Result<bool, VerificationError> {
    let (mut key, _) = derive_key_with_params(...)?;
    let result = match cipher::decrypt(&key, &verification_data.encrypted_header) {
        Ok(decrypted) => Ok(decrypted.as_slice() == VERIFICATION_HEADER),
        Err(_) => Ok(false),
    };
    key.zeroize();  // 始终零化
    result
}

pub fn unlock_with_password(...) -> Result<bool, VerificationError> {
    let (mut key, _) = derive_key_with_params(...)?;
    let result = match cipher::decrypt(&key, &verification_data.encrypted_header) {
        Ok(decrypted) => {
            if decrypted.as_slice() == VERIFICATION_HEADER {
                let key_copy = key;
                key.zeroize();
                keystore::set_key(key_copy)?;
                return Ok(true);
            }
            Ok(false)
        }
        Err(_) => Ok(false),
    };
    key.zeroize();
    result
}
```

---

### [FE-CRIT-001] 浏览器扩展将明文密码写入 HTML 属性

#### 漏洞说明

扩展弹窗通过 `innerHTML` 渲染所有 UI。当密码在展开的条目详情中可见时，明文密码被放置在复制按钮的 `data-value` HTML 属性中。这意味着明文密码直接嵌入到 DOM 中，可被同一页面上运行的任何内容脚本（包括第三方扩展或被入侵的脚本）读取。

此外，弹窗在整个 `entryDetails` Map 中无限期缓存完整的 `EntryResponse` 对象（包括明文密码）。此缓存仅在锁定时清除，MV3 service worker 生命周期可能比弹窗更长。

**CWE-312: Cleartext Storage of Sensitive Information; CWE-200: Information Exposure**

#### 漏洞位置

| 文件 | 行号 | 说明 |
|------|------|------|
| `extensions/chrome/src/popup/popup.js` | 666 | 明文密码放入 `data-value` 属性 |
| `extensions/chrome/src/popup/popup.js` | 645-646 | 用户名放入 `data-value` 属性 |
| `extensions/chrome/src/popup/popup.js` | 120-135 | 条目详情无限期缓存 |

#### 关键点

```javascript
// popup.js:636 — 从缓存获取明文密码
const password = details ? details.password : '';

// popup.js:666 — 明文密码直接放入 data-value 属性
<button class="detail-btn" data-action="copy-password"
  data-value="${this.escapeHtml(password || '')}" ...>

// popup.js:120-135 — 条目详情永久缓存
async getEntryDetails(id) {
  if (this.state.entryDetails.has(id)) {
    return this.state.entryDetails.get(id);  // 返回缓存的条目（含密码）
  }
  const entry = await this.sendMessage({ type: 'GET_ENTRY', id });
  if (entry && !entry.error) {
    this.state.entryDetails.set(id, entry);  // 无限期缓存
    return entry;
  }
}
```

#### 修复建议

1. 从所有复制按钮中移除 `data-value` 属性，仅通过 ID 在运行时从内存状态检索密码
2. 考虑在可读性上设置时间限制（例如 5 秒后自动隐藏）
3. 定期或当弹窗关闭时清除 `entryDetails` 缓存

```javascript
// 修复: 不在 DOM 中存储密码，按需从内存检索
case 'copy-password':
  const details = await this.getEntryDetails(btn.dataset.id);
  if (details && details.password) {
    await this.copyToClipboard(details.password, 'Password copied!', true);
  }
  break;
```

---

### [FE-CRIT-002] 内容脚本通过消息通道传输明文凭据

#### 漏洞说明

内容脚本从 background service worker 接收包含 `username` 和 `password` 的明文凭据，作为 Chrome 消息传递载荷。凭据存储在 JavaScript 变量中，并传递给 `autofillLogin()` 和 `showAutoFillPrompt()` 函数。`showAutoFillPrompt` 将完整的 `entry` 对象（包括 `entry.password`）保存在一个闭包中。

恶意脚本可以：
1. 拦截 `chrome.runtime.onMessage` 监听器
2. 代理 `fillField` 函数捕获正在输入的密码
3. 通过监控 DOM `input` 事件检测密码注入

**CWE-319: Cleartext Transmission of Sensitive Information**

#### 漏洞位置

| 文件 | 行号 | 说明 |
|------|------|------|
| `extensions/chrome/src/content.js` | 398-404 | 凭据在闭包中捕获 |
| `extensions/chrome/src/content.js` | 711-728 | 自动填充逻辑 |
| `extensions/chrome/src/background.js` | 178-186 | 通过消息发送明文凭据 |
| `extensions/chrome/src/background.js` | 266-271 | 右键菜单填充 |

#### 关键点

```javascript
// content.js:398-404 — 明文凭据在闭包中
notificationBar.querySelector('#pv-fill').addEventListener('click', async () => {
  hideNotificationBar();
  autofillLogin(entry.username, entry.password); // entry.password 是明文
});

// background.js:178-186 — 通过消息发送明文凭据
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'pwdvault-fill') {
    const entries = await getEntriesForUrl(tab.url);
    if (entries.length > 0) {
      const entry = await getEntry(entries[0].id);
      chrome.tabs.sendMessage(tab.id, {
        type: 'AUTOFILL',
        username: entry.username,
        password: entry.password, // 明文密码通过消息传递
      });
    }
  }
});
```

#### 修复建议

1. 使用 `chrome.scripting.executeScript` 直接注入而非消息传递，减少密码在内容脚本中的暴露时间
2. 自动填充后立即清零本地引用
3. 需要在 manifest 中添加 `scripting` 权限

```javascript
// 修复: 使用 executeScript 直接注入
async function performAutofill(tabId, entryId) {
  const entry = await getEntry(entryId);
  await chrome.scripting.executeScript({
    target: { tabId },
    func: (username, password) => {
      const pwdFields = document.querySelectorAll('input[type="password"]');
      if (pwdFields.length > 0) {
        const nativeSetter = Object.getOwnPropertyDescriptor(
          window.HTMLInputElement.prototype, 'value'
        ).set;
        nativeSetter.call(pwdFields[0], password);
        pwdFields[0].dispatchEvent(new Event('input', { bubbles: true }));
      }
    },
    args: [entry.username, entry.password],
  });
}
```

---

## HIGH 级别漏洞（8个）

---

### [BE-HIGH-001] Nonce/Salt 使用 `thread_rng()` 而非 `OsRng()`

#### 漏洞说明

`cipher.rs` 中的 `generate_nonce()` 和 `kdf.rs` 中的 `generate_salt()` 使用 `rand::thread_rng()` 生成随机值。虽然 `thread_rng()` 默认使用加密安全的生成器（ChaCha），但 `OsRng` 直接从操作系统 CSPRNG 读取，提供更强的安全保证。对于 AES-256-GCM，nonce 唯一性至关重要——如果 nonce 被重用，认证将被破坏。

> 注：密码生成器已更新为使用 `OsRng`（见 CLAUDE.md 历史），但加密模块未同步更新。

**CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src-tauri/src/crypto/cipher.rs` | 63-67 |
| `src-tauri/src/crypto/kdf.rs` | 97-101 |

#### 关键点

```rust
// cipher.rs:63-67
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);  // 应使用 OsRng
    nonce
}

// kdf.rs:97-101
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);  // 应使用 OsRng
    salt
}
```

#### 修复建议

```rust
use rand::rngs::OsRng;

fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
```

---

### [BE-HIGH-002] 密码验证存在时序侧信道

#### 漏洞说明

`verification.rs` 中使用 `==` 比较解密后的验证头与预期常量。标准切片比较在第一个不同字节处短路，创建时序侧信道。具有精确时序测量能力的攻击者（如使用 `RDTSC` 的本地进程）理论上可以利用此漏洞逐字节恢复验证头。

**CWE-208: Observable Timing Discrepancy**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src-tauri/src/crypto/verification.rs` | 69 |
| `src-tauri/src/crypto/verification.rs` | 85 |

#### 关键点

```rust
// verification.rs:69 — 短路比较，存在时序泄露
Ok(decrypted.as_slice() == VERIFICATION_HEADER)

// verification.rs:85 — 同样的问题
if decrypted.as_slice() == VERIFICATION_HEADER {
```

#### 修复建议

使用 `subtle` crate 的常量时间比较（已是 `aes-gcm` 的传递依赖）：

```rust
use subtle::ConstantTimeEq;

// 替换为常量时间比较
Ok(decrypted.as_slice().ct_eq(VERIFICATION_HEADER).into())
```

---

### [BE-HIGH-003] HTTP 请求体无大小限制

#### 漏洞说明

HTTP 服务器读取整个请求体到内存，没有大小限制。攻击者可以发送多 GB 的请求体耗尽内存。由于服务器是单线程同步的，这还会阻塞所有其他请求。

**CWE-400: Uncontrolled Resource Consumption**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src-tauri/src/native_messaging.rs` | 130-135 |

#### 关键点

```rust
// native_messaging.rs:130-135 — 无大小限制
let mut body = String::new();
if let Err(e) = request.as_reader().read_to_string(&mut body) {
    // 攻击者可发送无限数据
    let response = create_error_response(0, format!("Failed to read request: {}", e));
    let _ = request.respond(response);
    return;
}
```

#### 修复建议

```rust
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB

// 使用 .take() 限制读取字节数
let mut body = String::new();
match request.as_reader().take(MAX_REQUEST_BODY_SIZE as u64).read_to_string(&mut body) {
    Ok(_) => {}
    Err(e) => {
        let response = create_error_response(0, "Request body too large".to_string());
        let _ = request.respond(response);
        return;
    }
}
```

---

### [BE-HIGH-004] 所有入口字段无输入长度验证

#### 漏洞说明

`title`、`username`、`notes`、`url`、`tags`、`password` 等字段接受任意长度的字符串，无长度限制。可导致内存耗尽、数据库膨胀、加密/解密超大负载的性能问题。

**CWE-20: Improper Input Validation**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src-tauri/src/native_messaging.rs` | 323-371 (create_entry) |
| `src-tauri/src/native_messaging.rs` | 503-553 (update_entry) |
| `src-tauri/src/lib.rs` | 537-571 (create_entry) |

#### 修复建议

```rust
fn validate_field(value: &str, name: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        Err(format!("{} exceeds maximum length of {} characters", name, max_len))
    } else {
        Ok(())
    }
}

// 建议限制: title=256, username=256, password=1024, notes=10000, url=2048, group_name=128
```

---

### [FE-HIGH-001] HTTP API 明文通信（无 TLS/认证 Token）

#### 漏洞说明

浏览器扩展通过普通未加密的 HTTP 与桌面应用通信（`http://127.0.0.1:17429`）。所有操作（包括通过密码解锁、密码检索、库导出）均在网络上明文传输。虽然 localhost 流量不离开本机，但存在以下风险：

1. 同一机器上的应用程序可读取 localhost 流量
2. 在多用户系统上，其他用户可能嗅探环回流量
3. DNS 重绑定攻击可能允许外部网站向 localhost API 发送请求

**CWE-319: Cleartext Transmission of Sensitive Information**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `extensions/chrome/src/background.js` | 4, 17-21 |
| `src/api/vault.ts` | 12-16 |

#### 关键点

```javascript
// background.js:4 — 纯 HTTP
const API_BASE = 'http://127.0.0.1:17429';

// background.js:17-21 — 明文密码在 body 中
async function sendToApp(command, params = {}) {
  const response = await fetch(`${API_BASE}/api/${command}`, {
    method: 'POST',
    body: JSON.stringify({ id, command, ...params }), // 明文密码
  });
}
```

#### 修复建议

1. 生成临时 API Token 并与扩展共享
2. 每个请求头中包含 Token
3. 将 CORS 限制为特定扩展来源
4. 考虑在 localhost 上使用 HTTPS（自签名证书）

---

### [FE-HIGH-002] 扩展弹窗密码仅用 CSS blur 隐藏而非从 DOM 移除

#### 漏洞说明

当密码"隐藏"时，实际明文密码仍存在于 DOM 中，仅应用了 `filter: blur(4px)` 和 `user-select: none`。这是视觉混淆而非安全保障，任何具有 DOM 访问权限的脚本都可读取。

**CWE-312: Cleartext Storage of Sensitive Information**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `extensions/chrome/src/popup/popup.js` | 636, 656 |
| `extensions/chrome/src/popup/popup.html` | 452-455 (CSS) |

#### 修复建议

1. 当"隐藏"时，渲染 Unicode 圆点字符（`•`）而非真实密码
2. 移除基于 blur 的隐藏机制
3. 添加超时机制，30 秒不活动后重新隐藏密码

---

### [FE-HIGH-003] 主密码提交后未从 React State 中清除

#### 漏洞说明

`SetupScreen.tsx` 和 `UnlockScreen.tsx` 中，主密码存储在 React `useState` 中，通过 API 发送后**从未被清除**。主密码是最敏感的凭证，应立即从内存中清除。

`GeneratorScreen.tsx` 中的生成密码也以同样方式保留在状态中。

**CWE-316: Cleartext Storage of Sensitive Information in Memory**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src/screens/SetupScreen.tsx` | 6, 24-28 |
| `src/screens/UnlockScreen.tsx` | 6, 14-20 |
| `src/screens/GeneratorScreen.tsx` | 12 |

#### 关键点

```tsx
// SetupScreen.tsx:6,24-28 — 提交后未清除
const [password, setPassword] = useState('');
const handleSubmit = async (e: React.FormEvent) => {
  try {
    await actions.initialize(password);
    // password 仍在状态中 — 未调用 setPassword('')
  } catch {
    setLocalError('Failed to initialize vault');
  }
};
```

#### 修复建议

```tsx
const handleSubmit = async (e: React.FormEvent) => {
  // ...
  try {
    await actions.initialize(password);
  } catch {
    setLocalError('Failed to initialize vault');
  } finally {
    setPassword('');        // 立即清除密码
    setConfirmPassword('');
  }
};
```

---

### [FE-HIGH-004] 已解密条目在全局 State 中无限期缓存

#### 漏洞说明

用户查看条目时，完整的 `EntryResponse`（包括明文 `password` 字段）存储在 `AppContext.tsx` 的全局状态中。此状态在用户会话期间持续存在，仅在用户锁定密码库时清除。已解密密码无限期保留在 `selectedEntry` 状态中。

**CWE-316: Cleartext Storage of Sensitive Information in Memory**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src/context/AppContext.tsx` | 70, 243-253 |
| `src/screens/VaultScreen.tsx` | 46-55 |

#### 修复建议

1. 离开编辑屏幕后立即清零 `selectedEntry` 中的敏感字段（password、notes）
2. 复制操作使用不缓存的临时 API 调用
3. 添加 `CLEAR_SELECTED_ENTRY_PASSWORD` action 清零敏感字段

---

## MEDIUM 级别漏洞（7个）

---

### [BE-MED-001] HTTP 响应中密码未零化

#### 漏洞说明

`native_messaging.rs` 中，解密后的密码转换为 `String` 对象（如 `String::from_utf8(password_bytes)`），序列化为 JSON 后未零化。`lib.rs` 的 `export_vault` 已正确实现零化，但 HTTP API 路径未同步。

**CWE-316: Cleartext Storage in Memory**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src-tauri/src/native_messaging.rs` | 410-414 (get_entry) |
| `src-tauri/src/native_messaging.rs` | 687-718 (export) |

#### 修复建议

在构建 JSON 响应后，显式零化密码字符串：

```rust
let mut password = String::from_utf8(password_bytes).map_err(|e| e.to_string())?;
let response = serde_json::json!({ "password": password.as_str(), ... });
unsafe { password.as_bytes_mut() }.zeroize();
```

---

### [BE-MED-002] 错误信息泄露内部实现细节

#### 漏洞说明

HTTP API 返回详细错误信息，包含内部实现细节：
- `"Invalid JSON: missing field 'password' at line 1 column 100"` — 暴露 JSON 结构
- `"Failed to read request: ..."` — 暴露 I/O 层细节
- `"Invalid salt: ..."` / `"Invalid nonce: ..."` — 暴露加密参数期望
- `"Unknown command: <user_input>"` — 反射用户输入

**CWE-209: Generation of Error Message Containing Sensitive Information**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src-tauri/src/native_messaging.rs` | 132-133 |
| `src-tauri/src/native_messaging.rs` | 138-144 |
| `src-tauri/src/native_messaging.rs` | 793-800 |
| `src-tauri/src/native_messaging.rs` | 885 |

#### 修复建议

1. 使用通用错误消息替代详细描述
2. 将详细错误记录到 stderr 供调试
3. 不在错误响应中反射用户输入

```rust
// 修复示例
Err(e) => {
    eprintln!("JSON parse error: {}", e); // 服务器端日志
    let response = create_error_response(0, "Invalid request format".to_string());
}
```

---

### [BE-MED-003] 导入操作非原子性 — 可导致数据丢失

#### 漏洞说明

`import_vault` 先删除所有现有条目和分组，再导入新数据。如果导入中途失败（如第 50 条加密错误），所有原始数据已被删除，仅部分数据被导入，密码库处于不一致状态。

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src-tauri/src/lib.rs` | 1027-1034 |
| `src-tauri/src/native_messaging.rs` | 827-834 |

#### 修复建议

1. 先验证和准备所有数据（解密备份、加密条目），再执行任何破坏性操作
2. 利用 redb 的写事务语义批量删除+插入
3. 考虑添加"导入前自动备份"保障

---

### [FE-MED-001] 剪贴板自动清除机制不可靠

#### 漏洞说明

`clipboard.ts` 使用 `setTimeout` + `navigator.clipboard.readText()` 进行 30 秒自动清除。问题：
1. 用户导航离开时 `setTimeout` 可能不触发
2. `readText()` 需要 Permissions API 授权，可能失败
3. 失败时静默忽略，用户不知道清除失败

**CWE-366: Race Condition within a Concurrent Context**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src/utils/clipboard.ts` | 22-36 |

#### 修复建议

在 Tauri 中使用 native clipboard plugin 获得更可靠的剪贴板操作，清除失败时向用户显示警告。

---

### [FE-MED-002] 内容脚本在所有 URL 上运行

#### 漏洞说明

Chrome 和 Firefox manifest 中内容脚本使用 `"matches": ["<all_urls>"]`，在用户访问的每个页面上注入脚本。扩大了攻击面。

`host_permissions` 也包含 `<all_urls>`，赋予扩展对任何 URL 网络请求的访问权限。

**CWE-1021: Improper Restriction of Rendered UI Layers**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `extensions/chrome/manifest.json` | 22 |
| `extensions/firefox/manifest.json` | 28 |

#### 修复建议

1. `host_permissions` 改为仅 `http://127.0.0.1:17429/*`
2. 内容脚本匹配限制为 `http://*/*` 和 `https://*/*`

---

### [FE-MED-003] 内容脚本使用 innerHTML

#### 漏洞说明

`content.js` 多处使用 `innerHTML` 注入 UI 元素。虽然用户控制值经过 `escapeHtml()` 转义，但第 389 行的图标字符 `${entry.title.charAt(0).toUpperCase()}` **未转义**。`innerHTML` 结合内联 `<style>` 块增加了 XSS 风险面。

**CWE-79: Cross-site Scripting**

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `extensions/chrome/src/content.js` | 308-399 |
| `extensions/chrome/src/content.js` | 389 |
| `extensions/chrome/src/content.js` | 437-598 |

#### 修复建议

1. 对所有用户数据使用 `textContent` 而非 `innerHTML`
2. 通过 `document.createElement` 和 DOM API 构建所有元素

---

### [FE-MED-004] Vault 锁定时状态清理不完整

#### 漏洞说明

`lock()` 操作调度 `RESET` action 替换状态，但旧的 `selectedEntry` 对象（含密码）可能仍被 React 内部或闭包引用。应在 `RESET` 前显式清零敏感字段。

#### 漏洞位置

| 文件 | 行号 |
|------|------|
| `src/context/AppContext.tsx` | 84-85, 184-188 |

#### 修复建议

```tsx
lock: () => {
  dispatch({ type: 'SET_SELECTED_ENTRY', payload: null });
  dispatch({ type: 'SET_ENTRIES', payload: [] });
  api.lockVault();
  dispatch({ type: 'RESET' });
  dispatch({ type: 'SET_SCREEN', payload: 'unlock' });
},
```

---

## LOW 级别漏洞（4个）

---

### [BE-LOW-001] 密码生成器长度参数无边界检查

**CWE-20: Improper Input Validation**

`generate_password()` 接受 `length: usize` 参数无验证。`length = 0` 时返回最小字符，`usize::MAX` 时内存溢出崩溃。

| 文件 | 行号 |
|------|------|
| `src-tauri/src/lib.rs` | 363-418 |
| `src-tauri/src/native_messaging.rs` | 442-501 |

**修复**: 在函数开头 `let length = length.clamp(4, 128);`

---

### [FE-LOW-001] 导出备份密码最低仅 4 个字符

**CWE-521: Weak Password Requirements**

`ImportExportScreen.tsx` 第 32 行要求导出密码至少 4 个字符，而主密码库设置至少需要 8 个字符。

**修复**: 将最低长度从 4 改为 8，与主密码策略一致。

---

### [FE-LOW-002] GeneratorScreen 生产代码中使用 console.error

**CWE-532: Information Disclosure Through Log Files**

`GeneratorScreen.tsx` 第 33 行通过 `console.error` 记录完整错误对象，可能在 DevTools 中暴露内部信息。

**修复**: 使用面向用户的错误状态替代 `console.error`。

---

### [FE-LOW-003] API 路径不一致

**CWE-436: Interpretation Conflict**

`src/api/vault.ts` 第 12 行 HTTP fallback 发送请求到 `http://127.0.0.1:17429`（根路径），而浏览器扩展使用 `http://127.0.0.1:17429/api/${command}`（带 `/api/` 前缀）。

**修复**: 统一为 `http://127.0.0.1:17429/api/${cmd}`。

---

## 依赖安全审查

### Rust 依赖

| 依赖 | 版本 | 状态 | 说明 |
|------|------|------|------|
| aes-gcm | 0.10.3 | 安全 | 无已知 CVE |
| argon2 | 0.5.3 | 安全 | 无已知 CVE |
| redb | 2.x | 安全 | 无已知 CVE |
| bincode | 1.x | **注意** | v1 已停止维护，无已知 CVE 但缺少持续安全审查 |
| tiny_http | 0.12 | **注意** | 无内置 TLS/认证/限流，需自行实现安全层 |
| rand | 0.8 | 安全 | `thread_rng` 是 CSPRNG，但 `OsRng` 更推荐 |
| zeroize | 1.x | 安全 | 无已知 CVE |
| ureq | 3.x | 安全 | 无已知 CVE |
| serde_json | 1.x | 安全 | 无已知 CVE |

### 前端依赖

| 依赖 | 状态 | 说明 |
|------|------|------|
| React 19 | 安全 | 最新主版本 |
| Tauri v2 | 安全 | 当前主版本 |
| fuse.js | 安全 | 确保 lockfile 中使用当前版本 |

---

## 修复优先级总览

### P0 — 立即修复（24小时内）

| ID | 漏洞 | 预估工作量 |
|----|------|------------|
| BE-CRIT-001 | HTTP API 无认证 | 4-8 小时 |
| BE-CRIT-002 | 密钥未零化 | 1 小时 |
| FE-CRIT-001 | 密码写入 DOM 属性 | 1 小时 |
| FE-CRIT-002 | 凭据通过消息通道明文传输 | 3 小时 |

### P1 — 短期修复（一周内）

| ID | 漏洞 | 预估工作量 |
|----|------|------------|
| BE-HIGH-001 | thread_rng → OsRng | 30 分钟 |
| BE-HIGH-002 | 时序侧信道 → 常量时间比较 | 1 小时 |
| BE-HIGH-003 | 请求体大小限制 | 1 小时 |
| BE-HIGH-004 | 输入长度验证 | 2 小时 |
| FE-HIGH-001 | HTTP 明文通信 | 4 小时 |
| FE-HIGH-002 | CSS blur 隐藏密码 | 1 小时 |
| FE-HIGH-003 | 主密码未从 state 清除 | 30 分钟 |
| FE-HIGH-004 | 条目密码无限期缓存 | 1 小时 |

### P2 — 下个版本修复

| ID | 漏洞 | 预估工作量 |
|----|------|------------|
| BE-MED-001 | HTTP 响应密码未零化 | 2 小时 |
| BE-MED-002 | 错误信息泄露 | 2 小时 |
| BE-MED-003 | 导入非原子性 | 4 小时 |
| FE-MED-001 | 剪贴板清除可靠性 | 2 小时 |
| FE-MED-002 | 内容脚本范围过广 | 1 小时 |
| FE-MED-003 | innerHTML 使用 | 3 小时 |
| FE-MED-004 | 锁定时状态清理 | 30 分钟 |
| BE-LOW-001 | 密码生成器长度 | 15 分钟 |
| FE-LOW-001 | 导出密码策略 | 15 分钟 |
| FE-LOW-002 | console.error | 15 分钟 |
| FE-LOW-003 | API 路径不一致 | 15 分钟 |

---

## 长期改进建议

1. **HTTP API 认证机制** — 实现 Bearer Token 认证，生成临时 token 与浏览器扩展共享
2. **TLS on localhost** — 考虑在 localhost HTTP 服务器上使用自签名证书
3. **bincode v1 → v2** — 迁移到积极维护的序列化格式
4. **Zeroizing\<T\> 包装器** — 对所有解密后的密码/备注字符串使用自动零化包装类型
5. **Shadow DOM** — 扩展 UI 使用 Shadow DOM 与页面脚本隔离
6. **`cargo deny check`** — 除 `cargo audit` 外添加许可证合规检查
7. **自动化安全测试** — 为 HTTP API 添加认证、限流和输入验证的集成测试

---

## 正面安全观察

代码库展现了多个良好的安全实践：

1. AES-256-GCM 加密 + 每次加密使用唯一 nonce — 正确实现
2. Argon2id 密钥派生，64MB 内存消耗 + 自适应参数 — 强 KDF 配置
3. 主密码在 `init_vault` 和 `unlock_vault` 中通过 `Zeroize` trait 零化
4. 解锁失败限流（5 次失败 → 60 秒锁定）
5. 可配置超时的自动锁定
6. 剪贴板 30 秒自动清除
7. `tauri.conf.json` 中配置了限制性的 CSP（`script-src 'self'`, `connect-src localhost`）
8. 原子 `lock_vault()` 在同一 mutex 下清除密钥和活动计时器
9. 前端未使用 `dangerouslySetInnerHTML`，toast 使用 `textContent`
10. 53+ Rust 测试 + 17 前端测试，包含安全相关测试用例
11. 密码强度计算器包含常见密码检测和序列模式匹配

---

## 审计方法

- **OWASP Top 10 (2021)** — Web 应用十大安全风险
- **CWE/SANS Top 25** — 最危险软件弱点
- **静态代码分析** — 逐文件阅读全部源代码
- **数据流分析** — 追踪：用户输入 → HTTP 处理器 → 加密 → 数据库 → 响应
- **威胁建模** — 针对密码管理器的特定威胁（密钥泄露、未授权访问、注入攻击、内存取证）

### 审计文件清单

**Rust 后端（9 个文件）：**
- `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`
- `src-tauri/src/main.rs`, `src-tauri/src/lib.rs`, `src-tauri/src/native_messaging.rs`, `src-tauri/src/paths.rs`
- `src-tauri/src/crypto/mod.rs`, `src-tauri/src/crypto/cipher.rs`, `src-tauri/src/crypto/kdf.rs`, `src-tauri/src/crypto/keystore.rs`, `src-tauri/src/crypto/verification.rs`

**前端（18 个文件）：**
- `src/api/vault.ts`, `src/context/AppContext.tsx`, `src/App.tsx`, `src/main.tsx`, `src/types/index.ts`
- `src/screens/*.tsx`（7 个屏幕组件）
- `src/utils/passwordStrength.ts`, `src/utils/clipboard.ts`, `src/utils/toast.ts`, `src/utils/search.ts`
- `src/components/UpdateNotification.tsx`

**浏览器扩展（7 个文件）：**
- `extensions/chrome/manifest.json`, `extensions/chrome/src/background.js`, `extensions/chrome/src/content.js`, `extensions/chrome/src/content.css`
- `extensions/chrome/src/popup/popup.html`, `extensions/chrome/src/popup/popup.js`
- `extensions/firefox/manifest.json`

---

*审计完成日期: 2026-05-06*
*下次建议审计: 重大功能变更后或 v1.1.0 发布前*
