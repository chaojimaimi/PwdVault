# Phase 1 实施方案：密钥基建 — 改主密码 + Touch ID 解锁 + 恢复密钥

> 依据 docs/ROADMAP-2026-09.md Phase 1。三个功能共享 wrap-key 基建，一次成型。
> 流程：本方案 → plan-reviewer 评审 → ds-worker 分两批落地（后端 → 前端）→ code-review 门。

## 0. 安全模型与关键设计决策

### D1 wrap 的对象是 master_key（非 subkey）

条目用 `enc_key`（HKDF subkey）密封、verification header 用 `master_key` 加密
（verification.rs:50）。**wrap blob 里存 master_key**：解锁时 unwrap 出 master_key →
`derive_subkeys(master_key, salt)` 还原 enc/mac → 走与密码 unlock 完全相同的完整性
检查链。verification header（master_key 加密）天然成为 unwrap 结果正确性的校验器。

### D2 解锁态 master_key 不可得 → 启用类操作要求输入主密码

`unlock_with_password` 返回 subkeys 后 master_key 即 zeroize（verification.rs:88-90），
session 只持有 enc/mac。因此 **enable_biometric / enable_recovery 都要求输入当前主
密码**（表单字段，服务端重新派生 master_key）——这也天然构成操作确认。

### D3 recovery 采用单层包装，改密码时要求"重绑定"

`recovery_wrap = EncryptedData(SHA-256(recovery_key_bytes), master_key)`。
恢复密钥是 enable 时随机生成的 32 字节（base64url 43 字符），熵充足，SHA-256 即
AES key，无需 KDF。改密码后 master_key 变化 → recovery_wrap 必须重写，而重写需要
recovery_key 明文（只在 enable 时展示过）→ **改密码表单在恢复功能启用时增加必填的
"恢复密钥"输入**（文案："更新恢复密钥与新主密码的绑定"），输入正确才允许改密码。
Touch ID 已启用的替代路径见 D5。

### D4 存储位置与完整性

wrapped blob 存 `VAULT_TABLE`（与 verification/header 同表）新行：
`"bio_wrap"`、`"recovery_wrap"`。全部经 `VaultStore::write` 事务写入 → HMAC digest
自动覆盖，磁盘篡改在 unlock 的完整性检查中被拒绝（B1 体系）。blob 本身是
AES-GCM 密文（自认证），双保险。密文格式沿用 `EncryptedData::to_bytes/from_bytes`。

### D5 wrap_key 的生命周期与改密码 re-wrap

- **bio**：wrap_key（32B 随机）只存 Keychain。bio 解锁成功后将其缓存进
  `SessionInner::Unlocked` 的 wrap_key 槽位（**新增字段**——republish 自然丢弃、
  锁定自然 zeroize；禁止存为 AppState 独立字段，否则密码派生的新会话会残留
  wrap_key，违背"密码解锁的会话不缓存"）。密码解锁的会话不加载它。
- **改密码时的 re-wrap**（bio 与 recovery 各自处理）：
  - bio blob：session 有缓存 wrap_key → 直接重写；无缓存（本会话经密码解锁）→
    从 Keychain 现读（弹一次 Touch ID，前端须预告文案）。
  - recovery blob：表单必填 recovery_key（D3）→ 重写。
  - 均不存在的自然跳过。

### D8 全量重密封的串行化（评审 P0：防止在途写请求造成静默丢更新或新旧密钥混写锁死）

写服务只持读租约、无全局写互斥（entries.rs:21-62 模式），"全量读→重密封写"跨操作
窗口内若并发提交 `update_entry` 等写事务，会导致 (A) 旧快照整表覆盖静默吞掉并发更新，
或 (B) 旧密钥写事务在换钥后提交 → 新旧密钥混写 + digest 被旧 mac 刷新 → **库永久
锁死**。Touch ID 人机交互（秒级）若落在窗口内会放大暴露。因此 change_password 与
recover_vault 的重密封统一采用**排他清空串行化**：

1. 前置阶段（人机交互与派生，不碰 DB 写）：校验新密码（`validation::master_password`）→
   校验当前密码（`verify_password`）→ 派生新 master/subkeys → **完成全部 Keychain
   交互**（Touch ID 读 wrap_key / recovery key 已在手）——人机交互绝不与任何 DB
   事务重叠；随后**入场取一次租约把旧 enc/mac 拷入 `Zeroizing` 局部变量后立即释放**
   （旧钥来源：会话内拷贝；此后不再持任何租约）；
2. 把旧 enc/mac 拷入 `Zeroizing` 局部变量 → **释放自有租约后**调用
   `session.exclusive_lock_and_clear()`（session.rs:186，排空所有在途租约并拒绝
   新租约；**严禁持租约调用**，同线程死锁，session.rs:330-333 已明示）；
3. 排空后**断言 session 仍处 Locked 态**（防 drain 与 republish 之间被并发
   `unlock_vault` 插入——违例即中止并恢复原态，把静默混写变为干净失败）→ 全量读
   （用旧 enc 拷贝）→ 重密封 → 单 `VaultStore::write(new_mac)` 事务
   （含 verification 行替换 + header 重密封 + re-wrap blob）；
4. 成功 → 一次性 `session.unlock(new_keys)` republish + 菜单/副作用；
   失败 → 事务原子回滚（磁盘不变），`session.unlock(old_keys)` 恢复原解锁态
   （改密码场景）或保持锁定（recover_vault 场景，见 P1.4），向用户报错。

session 换钥窗口（排空→republish，时长随库规模线性增长）内被拒绝的扩展请求会收到
一次可重试的 locked 错误，属可接受的瞬态语义（窗口内无人机交互；并发 unlock_vault
需交互式输入主密码，属合法持密者自竞，且已被步骤 3 的断言转为干净失败）。

### D6 命令面隔离

九个新命令**仅 Tauri IPC**（touch_activity 先例），不进 Native Messaging dispatcher：
`change_password`、`biometric_status`、`enable_biometric`、`disable_biometric`、
`unlock_biometric`、`recovery_status`、`enable_recovery`、`disable_recovery`、
`recover_vault`。
golden_contract.rs 的 tauri 列表与 adapter-only 文档化测试同步更新。

### D7 平台范围

- Touch ID：仅 macOS（`bio.rs` 平台门控；非 macOS `biometric_status.available=false`，
  enable 返回 "not supported"）。Windows Hello 属后续独立项。
- 恢复密钥：**跨平台**（无 Keychain 依赖）。
- 改主密码：跨平台。

## P1.1 wrap 原语（infrastructure/src/crypto/wrap.rs，新文件）

```rust
pub const WRAP_AAD_BIO: &[u8] = b"pwdvault-bio-wrap-v1";
pub const WRAP_AAD_RECOVERY: &[u8] = b"pwdvault-recovery-wrap-v1";
pub fn wrap_secret(wrap_key: &[u8; 32], master_key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, WrapError>;
// EncryptedData::to_bytes 输出；内部 cipher::encrypt_with_aad
pub fn unwrap_secret(wrap_key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<[u8; 32]>, WrapError>;
// cipher::decrypt_with_aad；错误 → WrapError::InvalidBlob（不区分篡改/损坏，防 oracle）
pub fn recovery_wrap_key(recovery_key_paste: &str) -> Result<[u8; 32], WrapError>;
// trim → base64url 解码（43 字符）→ 长度必须 32 → SHA-256；格式错误 → RecoveryKeyInvalid
pub fn generate_recovery_key() -> String; // 32B OsRng → base64url 无填充
```

测试：roundtrip；AAD 篡改拒绝；错误 wrap_key 拒绝；recovery key 格式往返 + 畸形输入拒绝。

## P1.2 VaultStore blob 行（infrastructure/src/database/vault_store.rs 扩展）

- `save_blob_in_txn(txn, key: &str, blob: &[u8])` / `load_blob(db, key) -> Option<Vec<u8>>`
  / `remove_blob_in_txn(txn, key)`（VAULT_TABLE，复用现有表常量；load 为无密钥读——
  blob 是密文，GCM 自认证）。
- `remove_blob` 用于 disable 时随 `VaultStore::write` 事务删除（保 digest 一致）。

## P1.3 SecretStore trait 与 macOS Keychain 实现（infrastructure/src/keychain.rs，新文件）

```rust
pub trait SecretStore: Send + Sync {
    fn available(&self) -> bool;                       // LAContext canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)
    fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError>;
    fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError>;  // 触发 Touch ID
    fn delete(&self, account: &str) -> Result<(), SecretStoreError>;
}
```

- 常量 `SERVICE = "com.pwdvault.desktop"`；account：`"vault-bio-wrap"`。
- macOS 实现：`SecItemAdd/CopyMatching/Delete` + `SecAccessControl
(USER_PRESENCE | BIOMETRY_CURRENTSET)` + `kSecAttrAccessible =
WhenUnlockedThisDeviceOnly` + `kSecUseDataProtectionKeychain = true`。
  security-framework 高层 `passwords` 模块不支持 ACL → 用其 `access_control` 模块
  构造 ACL + `SecItem` 字典路径（必要时 security-framework-sys / core-foundation
  手搭字典，隔离在 keychain.rs 内并注释）。实现时以实际 crate API 为准，优先高层。
  依赖声明按 winreg 先例放
  `[target.'cfg(target_os = "macos")'.dependencies]`（security-framework、
  objc2-local-authentication 0.3，避免 Windows 构建拉入）。
- 错误映射：`errSecItemNotFound → NotFound`；`errSecUserCanceled → UserCancelled`；
  `errSecAuthLocked → LockedOut`；其余 → `Unavailable(String)`。
- `available()`：`objc2-local-authentication` 的 `LAContext
canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`（同步调用，无 block）。
  若该 crate 与依赖树 objc2 版本冲突，退路：`canEvaluatePolicy` 经 msg2 手写（同一结论）。
- `MemorySecretStore`（测试替身，`std::sync::Mutex<HashMap>`）。
- 非 macOS：`available() = false`，set/get/delete → `Unavailable("unsupported platform")`。

## P1.4 服务层（application/src/service/security.rs，新文件）

**公共 helpers（从 unlock_vault 提取，vault.rs:194-323 回归测试守护）**：

- `verify_master_and_integrity(state, master_key) -> Result<(enc, mac), VaultError>`：
  unlock 步骤 3-7 的**只校验不发布**版本——derive_subkeys → header 读取/版本检查 →
  integrity 校验 → settings 加载。legacy 迁移分支（:291-295）改为直接透传传入的
  master_key（不再从 password 重派生）。
- `complete_unlock(state, enc, mac)`：原步骤 8-9（session.unlock + rate limit 重置 +
  auto_lock 应用 + 菜单/活动），仅发布不校验。
- 密码路径 unlock_vault = `unlock_with_password` → `verify_master_and_integrity` →
  `complete_unlock`（行为不变）。

**核心操作（全部遵循 D8 串行化协议）**：

| 函数                                                                                    | 语义                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `change_password(state, current, new: Zeroizing<String>, recovery_key: Option<String>)` | ① 校验 new（`validation::master_password`，P2）→ ② verify current（verify_password）→ ③ `AdaptiveParams::adaptive()` 重新基准新参数（X6 钳制后起点 ≥ 导入底线——改密码是治愈历史弱参数的天然时机，新 verification 行不再永续 16MiB/t=1）+ 新 salt 派生 new_master/subkeys → ④ **前置收集全部 re-wrap 输入**（bio：session 缓存或 Keychain Touch ID；recovery：必填参数校验——逐条 unwrap 验证 recovery_key 正确性，此时不碰 DB）→ ⑤ **.bak 文件备份**（migrate 先例 vault.rs:356-368）→ ⑥ D8 排他清空 → ⑦ 全量读+`reseal_vault` 单事务（新 verification 行 + header 重密封 + re-wrap blob + digest）→ ⑧ republish 新钥；⑦失败 → 事务回滚 + `session.unlock(old)` 恢复原态 + 报错（bio blob 未更新时 Keychain NotFound 的逃生文案："可在设置中先关闭 Touch ID 后重试"）。session 中 wrap_key 缓存随 republish 丢弃（SessionInner::Unlocked 重建） |
| `reseal_vault(db, old_enc, new_enc, new_mac, new_verification, rewrapped_blobs)`        | 内部 helper：参照 migrate_database "读全部→重密封→单事务替换"，**不含** legacy 明文通道；header 经 `save_header_in_txn` 以 new_enc 原样重密封（version/integrity 标志保持）；verification 行替换为本方案新增；blob 行写入/删除在事务内                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `biometric_status(state, store)`                                                        | `{available, enabled}`（enabled = VAULT_TABLE "bio_wrap" 行存在，锁定态可查）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `enable_biometric(state, password, store)`                                              | **无论锁定/解锁均要求当前主密码**（D2 修正：任何会话都拿不到 master_key）→ 派生 master → `store.available()` 检查 → wrap_key=OsRng 32B → `store.set` → wrap → 存行（VaultStore::write）。**legacy 库（无 header 或 integrity_required=false）拒绝启用**（错误提示先完成迁移），否则 bio 解锁会撞迁移分支                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `disable_biometric(state, store)`                                                       | 事务内删 "bio_wrap" 行 + `store.delete`（Keychain 删除失败仅告警）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `unlock_biometric(state, store)`                                                        | ① rate limit 检查 → ② **先查 "bio_wrap" 行存在**（无 blob 不空弹 Touch ID）→ ③ `store.get`（Touch ID）→ ④ unwrap master → ⑤ `verify_master_and_integrity` → ⑥ `complete_unlock` → ⑦ **wrap_key 缓存进 SessionInner::Unlocked**。UserCancelled/LockedOut 透传专用错误（不计 rate limit）；unwrap/header 失败计失败次数                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `recovery_status(state)`                                                                | 行存在性（锁定态可查）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `enable_recovery(state, password) -> String`                                            | 同 enable_biometric 的 D2 密码要求 + **对称的 legacy 库拒绝**（无 header 或 integrity_required=false → 提示先迁移，否则 recover_vault 的校验 helper 会触发迁移写、违反"失败磁盘不变"承诺）→ 派生 master → `generate_recovery_key()` → wrap → 存行 → 返回明文 key（仅此一次）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `disable_recovery(state, current_password: Zeroizing<String>)`                          | verify current → 事务内删 "recovery_wrap" 行（防误触，评审采纳）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `recover_vault(state, recovery_key_paste, new_password)`                                | **三段式（评审 P1：不留"旧钥已解锁"中间态）**：① 校验 new 密码 → `recovery_wrap_key` 派生 → 读 blob → unwrap master → `verify_master_and_integrity`（只校验不发布）→ ② 派生 new_master/subkeys → bio blob 存在时的 Keychain 交互**前置**（锁定态弹 Touch ID 属用户在场，可接受；失败则改走"禁用 bio 并提示重启用"分支）→ .bak 备份 → ③ 排他清空 → reseal 单事务（含 re-wrap）→ **仅此一次** `session.unlock(new)` + 副作用。任一步失败 → 保持锁定、磁盘不变（事务回滚），UI 停留恢复屏。**不执行密码 rate limit**（256-bit 熵，GCM 认证 + header 验证即正确性证明）                                                                                                                                                                                                                                                                            |

错误变体（error.rs，Display + public_message 双 match）：
`BiometricUnavailable`、`BiometricCancelled`、`BiometricLockedOut`、
`WrapBlobCorrupt`、`RecoveryKeyInvalid`、`RecoveryNotEnabled`、
`CurrentPasswordInvalid`、`KeychainError(String)`。

## P1.5 命令层（src-tauri/src/commands.rs，Tauri-only）

九个命令（D6）。密码参数直接收 `Zeroizing<String>`（现有 commands.rs:44-46
unlock_vault 同签名模式）。`AppState` 增加字段
`secret_store: Arc<dyn pwdvault_infrastructure::keychain::SecretStore>`
（Default 按平台装配 macOS 真实现 / 其他平台 Unavailable 桩；测试直接替换字段，
命令零特判）。lib.rs 注册 + golden_contract.rs tauri 列表与 adapter-only 文档更新
（golden_contract.rs:149-164 的精确断言同步）。

## P1.6 前端（第二批落地）

- `src/api/vault.ts`：九个新 invoke 包装 + 类型（`BiometricStatus {available, enabled}`）。
- `SettingsScreen.tsx` 新增 **Security** 区块：
  1. Change Master Password（当前密码 / 新密码 / 确认 / 恢复密钥条件字段——
     `recovery_status` 为 true 时显示必填；bio 启用且本会话无缓存 wrap_key 时预告
     "将请求触控 ID"文案由后端错误/前端 status 提示，简化为通用提示行）
  2. Touch ID 开关（`available=false` 隐藏；enable 表单要求当前主密码；disable 需确认）
  3. Recovery Key（未启用：enable 按钮→密码→一次性展示 key + Copy + Export .txt +
     "我已安全保存"复选后才可关闭；已启用：显示启用状态 + Disable 确认）
- `UnlockScreen.tsx`：`recovery_status` 为 true 显示 "Forgot password?" 链接；
  `biometric_status.enabled && available` 显示 "Use Touch ID" 按钮（调
  `unlock_biometric`，成功后复用现有解锁后的状态刷新路径——AuthContext unlock
  action 抽出共享 `postUnlock()`）。
- 新 `RecoveryScreen.tsx`（recovery key 粘贴 + 新密码 + 确认 + 提交；
  成功 → 正常解锁进入 vault；App.tsx 路由 + AuthContext screen 类型扩展）。
- `AuthContext.tsx`：unlock action 复用；recovery 成功后走与 unlock 相同的
  post-unlock 状态加载（settings/vault load）。

## P1.7 测试矩阵

后端（复用 vault.rs 测试的 `create_modern_vault` 模式 + `MemorySecretStore`）：

1. wrap roundtrip / AAD 篡改拒绝 / 错 key 拒绝 / recovery key 格式往返
2. change_password：旧密码 verify=false、新密码 unlock=true；条目/分组解密内容
   逐一相等；digest 通过；header 可读且 integrity_required 不变；bio/recovery blob
   已 re-wrap（unlock_biometric/recover 用新 key 可解）；recovery_key 缺失时改密码
   被拒（恢复启用场景）；current 密码错误被拒；new 密码未过强度校验被拒
3. **串行化（D8）**：change_password 期间并发写请求（排他窗口内持租约的写入
   尝试）收到 locked/拒绝且**不产生新旧密钥混写**——换钥后 unlock + digest 校验
   必须通过（回归 P0 场景）
4. bio：enable（带密码）→ lock → unlock_biometric 全链路；Keychain 删除后
   unlock_biometric 报错且保持锁定；UserCancelled 不计 rate limit；无 blob 时不
   触发 store.get；legacy 库拒绝 enable
5. recovery：enable → lock → recover_vault(new_password) → 新密码解锁、旧密码拒绝、
   recovery_wrap 已随新 master 重写；错误 recovery key 拒绝且保持锁定；
   **bio+recovery 同时启用**的 recover_vault（两者 re-wrap 同事务）；Keychain
   NotFound 时 change_password 失败路径与逃生文案
6. complete_unlock/verify_master_and_integrity 重构回归：现有 unlock 测试全数通过
7. golden contract：九个新命令在 tauri 列表 + adapter-only 文档，NM 列表不变

前端：vault.ts 包装类型正确（tsc）；Security 区块/Unlock/Recovery 组件测试跟随
现有组件测试模式（条件渲染：bio 不可用隐藏、recovery 启用时表单字段出现）。

手动 QA（人工）：真机 Touch ID 全流程（enable→lock→解锁）；指纹增删后 blob 失效
提示重启用；导出 .txt 恢复密钥文件内容正确；改密码时 Touch ID 弹窗预告与出现；
`kSecUseDataProtectionKeychain` 在未签名本地构建上的行为确认（AGENTS.md 已注明
host 未签名，若有 ACL 授权弹窗属预期）。

## P1.8 验证清单

```bash
cd src-tauri && source ~/.cargo/env && cargo test && cargo test --workspace && cargo clippy --all-targets -- -D warnings
pnpm test && pnpm tsc --noEmit
```

交付：后端批（P1.1-P1.5, P1.7 后端）一个 commit；前端批（P1.6）一个 commit。
CHANGELOG 由主代理收尾统一更新。
