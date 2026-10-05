# PwdVault 代码审计修复方案

**日期**：2026-10-04
**依据**：`code_audit_2026-10-04.md`（五路审计 + 二次独立审查，第七/八节为复核后最终结论）
**对象**：`main @ e7375e2`（v1.1.8）
**性质**：修复方案建议（待批准后实施）

---

## 0. 总体原则与交付结构

1. **fail-closed 不回退**：所有改动保持项目既有的"失败即拒绝"纪律；修复不得引入新的静默降级。
2. **每项带回归测试**：并发类修复必须有交错测试；UI 类修复更新/新增对应测试（注意 CQ-P2a 有旧断言钉死坏行为，必须同步改）。
3. **四个独立 PR**，按依赖与风险排序：

| PR   | 主题                  | 内容                                     | 建议版本                  | 预估工作量              |
| ---- | --------------------- | ---------------------------------------- | ------------------------- | ----------------------- |
| PR-1 | 安全核心 + 唯一 P1    | SEC-M1/M2/M3 + SF-P1                     | v1.1.9（随 updater 分发） | 3–5 人日                |
| PR-2 | 静默失败 + 质量 P2    | SF-P2a~d + CQ-P2a/b                      | v1.1.9 或 v1.2.0          | 2–3 人日                |
| PR-3 | Low 加固 + P3 打磨    | SEC-L1~L5 + SF-P3 组 + CQ-P3 组 + 顺手项 | v1.2.0                    | 3–4 人日（可拆两个 PR） |
| PR-4 | 死代码清理 + 静态收尾 | 修订后死代码清单 + ST-1                  | v1.2.0（独立 chore）      | 0.5–1 人日              |

4. **每个 PR 的验收门（DoD）**：`cargo test --workspace`（src-tauri）+ `cargo clippy/fmt --check` + native-host `cargo test/clippy` + `pnpm tsc --noEmit`（三个 tsconfig）+ `pnpm test` + `pnpm lint` 全绿；PR-1/PR-2 另附手动 QA 清单（见 §6）。所有 `.rs` 文件改动后仍 ≤800 行（commit-gate hook 硬性检查）。

---

## 1. PR-1：安全核心修复（v1.1.9）

### 1.1 SEC-M1 — 解锁路径纳入 D8 互斥（本方案最关键项）

**问题回顾**（经二次审查确认并修正）：`unlock_vault` / `unlock_biometric` 不取 `exclusive_window`，与改密/恢复/同步窗口并发时：① 窗口内插入的写成为**旧密钥孤儿行**（digest 自洽、完整性不报警、读取时才 AEAD 失败）；② 窗口等待后仍可能发布**过期旧密钥**（"已解锁但读写全坏"会话）。

**实现规则（二次审查明确的红线）**：

- ⛔ **严禁**把取窗逻辑放进 `complete_unlock_if`（shared.rs 内层）——`recover_vault` 在已持窗口状态下直接调用它（password.rs:244-247 → :281），同线程重入非重入 Mutex = 必然自死锁。
- ✅ 只改 `complete_unlock` **外层包装**（shared.rs:180 一带）：两个调用方 `unlock_vault`（vault.rs:234）与 `unlock_biometric`（credentials.rs:157）均未持冲突锁；锁序 `exclusive_window → session internals` 与 state.rs:131-133 文档一致；窗口路径的 republish 走 `complete_unlock_if`/`unlock_if`，不经过新包装，无环路。

**推荐设计（双重防线，关闭全部三条交错）**：

```
unlock_vault / unlock_biometric:
  1. 进入时捕获 verification_data 快照 + 其 key_id（新增指纹方法，见下）
  2. Argon2 派生 / wrap key 解包、完整性验证（不变，不持窗——避免窗口期间阻塞桌面解锁 UX）
  3. complete_unlock 外层：
     a. lock state.exclusive_window          ← 新增（序列化：发布永不与 rekey 事务重叠）
     b. 复核 state.verification_data.key_id() == 捕获值  ← 新增（过期密钥防线）
        不一致 → Err(VaultError::VaultLocked 或新增 ConcurrentModification 变体，
        public_message 给"金库状态已变化，请重试"，fail-closed）
     c. 原有发布逻辑（complete_unlock_if 谓词发布）
     d. 释放窗
```

- **key_id 指纹**：给 verification 头类型加 `fn key_id(&self) -> [u8; 8]`（取 Argon2 salt 前 8 字节即可，无需哈希库）。改密/reseal 必然换 salt，指纹必然变化。
- 该设计同时覆盖三条交错：窗口内完成派生的解锁（b 拦截）、窗口后发布的过期密钥（b 拦截）、发布与 rekey 重叠（a 拦截）。

**备选方案（不推荐，留档）**：unlock 全程持窗——实现最简但每次同步合并窗口（数秒）期间桌面解锁完全卡死，UX 不可接受；仅 epoch-bump 不持窗——挡不住"窗口内启动、epoch 已是新值"的解锁。

**测试**（复用 `reseal_window_gate` 测试缝，tests_window.rs 追加）：

1. `unlock_vs_change_password_interleave`：解锁 Argon2 期间注入改密窗口 → 断言解锁 fail-closed 报错（不产生半解锁态）。
2. `unlock_vs_window_write_orphan`：模拟插入写落在快照与 rekey 之间 → 断言插入写被拒（IntegrityMismatch）或条目完整幸存，**不允许孤儿行**（读回逐条 AEAD 解密成功）。
3. `biometric_unlock_vs_window`：生物识别路径同样例 1。
4. 既有 4 个窗口交错测试不回归。

**改动文件**：`crates/application/src/service/security/shared.rs`、`vault.rs`、`credentials.rs`、verification 头类型（infrastructure）、`tests_window.rs`。
**工作量**：M（1–1.5 人日，含测试）。**风险**：并发核心改动，需重点 code review；死锁红线已在设计中规避。

---

### 1.2 SEC-M2 — 文件 IO 下沉 Rust，收回 `$HOME/**` fs 授权

**问题回顾**（二次审查修正后）：webview 持有 `$HOME/**`、`/Volumes/**`、`$TEMP/**` 读写 stat 授权，是 XSS 爆炸半径放大器；文件 IO 实际在前端共**三处**；原方案 `addScopedPath` 在 plugin-fs 2.5.0 中不存在。

**推荐路线：IO 全部下沉 Rust 命令，capabilities 删除三个 fs 显式授权块**。

**新命令**（src-tauri/src/commands.rs + application service 层）：

1. `export_vault_file(path: String) -> Result<(), VaultError>`：复用现有 `export_vault` 的容器生成逻辑（返回前落盘），Rust 侧原子写（tmp + rename，`OpenOptions mode(0o600)` 创建即收紧，借鉴 SF-P2d 方案）。
2. `import_vault_file(path: String) -> Result<ImportSummary, VaultError>`：Rust 读文件（大小上限校验，沿用 X6 资源上限）→ 走现有导入校验链。
3. `enable_recovery` 增加可选参数 `save_path: Option<String>`：提供时由 Rust 写恢复密钥 txt（0600），响应加 `file_saved: bool`——密钥不再二次跨 IPC 传输。

**路径校验（三个命令共用 helper）**：canonicalize 后拒绝 vault 数据库目录（复用 capabilities 里 deny 的两个路径常量化）、拒绝目录、写入前校验父目录存在。dialog 仍在前端（plugin-dialog JS，`dialog:default` 已授权），只把**用户选定的单个路径**传给 Rust——fs 权限从"整个 HOME 常驻"降为"零静态授权 + Rust 侧受控 IO"。

**前端改动**：

- `ImportExportScreen.tsx:75-77 / 109-115`：`writeFile/readFile/stat` 替换为新命令 invoke；删除 `@tauri-apps/plugin-fs` import。
- `SecuritySettingsSection.tsx:237-241`：恢复密钥"保存到文件"改走 `enable_recovery { save_path }`。
- `src-tauri/capabilities/default.json`：删除 `fs:allow-write-file/read-file/stat` 三个对象块（保留 `fs:default` 与既有 M11 clipboard 备案注释；在文件头注释追加一条 M12 备案说明本次收回的理由，延续项目决策文化）。
- 若 `@tauri-apps/plugin-fs` 前端再无其它使用点，从 package.json 移除。

**备选（不推荐）**：Rust 侧 `app.fs_scope().allow_file(path)` 运行时单文件放行——保留前端 IO 代码，但 scope 生命周期管理（何时回收）引入新复杂度，且恢复密钥明文仍经 webview。

**测试**：路径校验 helper 单测（穿越/DB 目录/相对路径拒绝）、原子写单测（写失败不留半文件）、ImportExportScreen 现有测试更新 mock；手动 QA 覆盖 macOS/Windows 双端 dialog 行为差异。

**改动文件**：commands.rs、application/services、capabilities/default.json、两个前端组件、package.json。
**工作量**：M-L（1.5–2 人日）。**风险**：导入导出是用户高频路径，需双平台手动 QA；Windows 路径 canonicalize 行为差异注意。

---

### 1.3 SEC-M3 — sync 明文域 ZeroizeOnDrop 化（按二次审查的 derive 路线）

**问题回顾**：`decrypt_inner` clone 逃逸 + `SyncSecrets/SyncEntry/SyncSnapshot/MergedSnapshot` 层层 clone 的明文 String 不受 zeroize 保护。JSON 序列化缓冲已被覆盖（container.rs 已 zeroize），靶点就是结构体字段及克隆。

**方案**（zeroize 1.8.2 的 derive + serde feature 已核实启用）：

1. 对 `SyncSecrets`、`SyncEntry`、`SyncGroup`、`SyncSnapshot`、`MergedSnapshot`、`LocalRows`（state_io.rs）逐个加 `#[derive(Zeroize, ZeroizeOnDrop)]`——serde/PartialEq/Debug 语义保留，**所有克隆随 drop 自动清零**，比逐字段改 `Zeroizing<String>` 改动更小、覆盖更全（含中途 drop 的 BTreeMap/publish 循环副本）。
2. `decrypt_inner`（state_io.rs:343-352）改为消费式：`match String::from_utf8(plain) { Ok(s) => s, Err(e) => { let mut b = e.into_bytes(); b.zeroize(); return Err(...); } }`——消灭 clone 逃逸点，顺带覆盖 from_utf8 错误分支（错误对象原本携带明文字节裸 drop）。
3. **纪律护栏**：`Zeroizing`/derive 后 Debug 仍转发内值——grep 确认 sync 链路无 `debug!`/`dbg!` 打印快照；在 sync/mod.rs 的 "plaintext-domain" 注释处补一句禁止 debug-log 的提醒。

**测试**：现有 sync 测试全过即证 serde 兼容；新增显式 scrub 测试：构造 `SyncEntry`（已知密码）→ 显式调用 `zeroize()` → 断言字段为空/非原值（derive 同时提供显式 zeroize 方法，可测）。

**改动文件**：`sync/mod.rs`、`sync/state_io.rs`、相关 Cargo.toml（如 derive feature 需显式开启则加）。
**工作量**：S-M（0.5–1 人日）。**风险**：低；derive 对泛型/容器字段的支持已由验证代理核实（String/Option/Vec/i64 均有 impl）。

---

### 1.4 SF-P1 — 扩展空密码假成功（唯一 P1）

**问题回顾**：`getEntry` allSettled 把取密失败降级 `password: ""`；快捷键/右键菜单填空串并弹成功绿条；popup 复制静默无反应；快捷键路径连 entry null 检查都没有。

**方案**（extensions/chrome，全部最小改动）：

1. `background.js getEntry`（:445-456）：secret rejected 时**上抛错误**（各调用方已有错误通道），meta 展示场景改由调用方自行降级——不再在公共 helper 里吞。
2. 右键菜单路径（:581-599）与快捷键路径（:754-779）：发送 AUTOFILL 前守卫 `!entry || !entry.password` → `notifyTab(tab.id, "无法获取密码，请确认桌面端已解锁", "error")`（复用现有通道）；快捷键路径同时补 `!entry` null 检查（当前 `entry.username` 直接 TypeError）。
3. popup 复制按钮（popup.js:1418-1428 及同型 copy-both :1443-1451）：`!details.password` 时 `showToast("获取密码失败", "error")`。
4. content.js `autofillLogin`（:337-361）：防御性空密码短路（`if (!password) { 通知错误; return; }`）——纵深防御，防未来新增调用方重蹈覆辙。

**测试/验证**：background.js 的 chrome API 依赖使单测受限——为 `getEntry` 的降级逻辑补一个可测的纯判断导出（若扩展测试基建允许）；否则以手动 QA 清单覆盖（§6）。

**工作量**：S（0.5 人日内）。

---

## 2. PR-2：静默失败 P2 + 质量 P2

### 2.1 SF-P2a — 扩展剪贴板清除失败反馈（按修正机理）

**机理**（二次审查修正）：manifest 只有 `clipboardWrite` 无 `clipboardRead`，定时器内首个失败的是 `readText()`（需手势 + clipboardRead），内层空 catch 吞掉后，外层带用户提示的 catch 永不触发——清除从不发生且无通知。

**方案（最小修复，本 PR 内做）**：

- content.js:407-409 内层 catch：`console.warn('clipboard auto-clear failed', e)` + `showNotification("剪贴板自动清除失败，请手动清除", "error")`（复用现有通知通道）。
- 顺手：清除成功路径维持静默（不打扰）。

**根治选项（单独评估，不在本 PR）**：复制动作移入 background/offscreen document（offscreen API 可在无手势上下文写剪贴板）——需要权限与 manifest 变更评估，标记为 v1.2.x 跟踪项。

### 2.2 SF-P2b — React ErrorBoundary

- 新建 `src/components/ErrorBoundary.tsx`（class 组件，`componentDidCatch` + `getDerivedStateFromError`；错误上报 `console.error`）。
- fallback UI：错误说明 + **"锁定并重启"按钮**（`lockVault()` + `process.relaunch()`——`process:allow-restart` capability 已在位）+ "仅重启"次按钮。
- `main.tsx`：`<ErrorBoundary><App/></ErrorBoundary>`。
- 测试：前端测试用渲染抛错子组件断言 fallback 出现与按钮回调。

### 2.3 SF-P2c — lock() IPC 失败可见提示

- AuthContext.tsx:200-212 catch 分支：保留既有 RESET/切锁屏（A4 设计取舍不回退），追加 `showToast("锁定指令发送失败，请重试或退出应用", "error")`（toast 工具已存在）。
- 二次审查定级 P2/P3 边界——本项改动极小，随批带走。

### 2.4 SF-P2d — 凭据文件权限从创建即收紧（按修正方案）

- `secret_file_store.rs`（:151-160 一带）：临时文件改 `OpenOptions::new().write(true).create_new(true).mode(0o600)` 创建（Unix；Windows 上 `mode` 为 no-op，且值已 DPAPI 保护——二次审查确认暴露面集中在 Linux），消除"0644 创建 → chmod 收紧"窗口。
- 保留的 `restrict_permissions`（rename 后二次 chmod）失败路径：`let _ =` → `tracing::warn!`（:166）。
- `lib.rs:123` 的 `secure_file` 失败同样补日志（该文件是 native-host.json 扩展 ID，非凭据——日志措辞如实）。
- 测试：Unix 下断言新建凭据文件 mode 为 0600。

### 2.5 CQ-P2a — formatError 统一（含测试解钉）

- 删除 AuthContext.tsx:6-12、VaultContext.tsx:294-302、SettingsContext.tsx:8-12 三份本地实现及 SettingsContext.tsx:241 re-export，统一 `errorMessage(error, '<语境兜底文案>')`。
- **必须同步更新 `AuthContext.test.tsx:77`**——现断言 `toHaveTextContent('RateLimited')` 钉死了坏行为，改为断言 errorMessage 对 RateLimited 的友好文案。
- 修复收益（二次审查扩证）：不止 RateLimited JSON——单元变体（"VaultLocked" 等枚举名原样展示）一并修复；`bootError`/`initialize`/`recover` 路径同享。
- 测试：为 errorMessage 的 serde 外部标签解析补一条单元变体用例（若未有）。

### 2.6 CQ-P2b — import_vault 按阶段拆分

- backup.rs:191-413 拆六段：`validate_backup_envelope` → `decode_and_check_kdf`（X6 floor）→ `derive_import_key` → `decrypt_backup_payload` → `prepare_import_rows`（预加密）→ 事务闭包内联保留。
- **非纯机械注意点**（二次审查）：`lease` 跨阶段使用（:296/:371/:408）改为显式参数传递；`import_password`/`import_key` 的 Zeroizing 随函数边界变化——保持"整个 import 期间存活、结束即清零"语义不变。
- 等价性由现有 backup 测试（backup.rs:415 起）全量回归保证，不改测试。

---

## 3. PR-3：Low 加固 + P3 打磨（可拆"安全 Low"与"杂项 chore"两个 PR）

### 3.1 安全 Low（按性价比排序）

| #      | 项                       | 方案                                                                                                                                                          | 量                       |
| ------ | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| SEC-L1 | native-host token 白名单 | `main.rs` 加 `fn is_valid_token(t) -> bool`（64 位 hex），与 `is_valid_command` 同策略；不匹配拒绝转发并退出。补一条单测                                      | S                        |
| SEC-L3 | OAuth 回调循环丢弃       | `baidu_oauth.rs wait_for_callback`：无 `code` 或 state 不匹配的请求 respond 错误页后**继续循环**直到超时；仅有效回调才返回                                    | S                        |
| SEC-L4 | 恢复密钥返回值           | `enable_recovery` 命令返回 `Zeroizing<String>`（serde 透明）；前端展示组件卸载时置空 state（JS 尽力而为，文档如实声明局限）                                   | S                        |
| SEC-L5 | 自动锁远程语义           | **两阶段**：本 PR 只做文档声明（README 安全节 + AGENTS.md：扩展操作计入活动、等价用户在场）；实现侧（HTTP 路径不 touch 或衰减）留 v1.2.x 决策                 | S（文档）/ M（实现，缓） |
| SEC-L2 | sync 配置加密            | `SyncConfig` 用 enc subkey 加密为 blob（仿 `sync_cek` 模式）+ **明文旧行双读迁移**（仿 LegacySettingsV1 模式：读到明文即加密回写）。涉及迁移，单独小 PR，量 M | M                        |

### 3.2 静默失败 P3 组（一个 chore PR 打包，均为加日志/补分支）

| #      | 项                     | 方案                                                                                                                                  |
| ------ | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| SF-P3a | settings 加载失败      | vault.rs:416-418 改 `match` + `tracing::warn!`（保持默认值行为）                                                                      |
| SF-P3b | sync 凭据删除失败      | engine.rs:428-429 非 NotFound 错误 `tracing::warn!`                                                                                   |
| SF-P3c | 配对码 emit 失败       | dispatcher.rs:66 `tracing::error!`                                                                                                    |
| SF-P3d | token/nonce 持久化失败 | background.js 两处 `.catch` 加 `console.warn`；`pairConfirm` 无 nonce 分支设置 `lastConnectionError = "配对会话丢失，请重新发起配对"` |
| SF-P3e | FileReader onerror     | ImportExportScreen.tsx 浏览器回退路径补 `reader.onerror` + toast（桌面 dialog 路径已处理好，不动）                                    |
| SF-P3f | 同步状态探针第三态     | SyncSettingsSection 加 `"unknown"` 态：首探失败显示"状态未知 + 重试"而非连接表单                                                      |
| 防御项 | entries_to_sync 陷阱   | sync/mod.rs:136 补 debug_assert（secrets map 必须覆盖全部条目 id）+ 注释升级                                                          |

### 3.3 质量 P3 组

| #      | 项                      | 方案                                                                                                                                                                                      |
| ------ | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CQ-P3b | pair 限流竞态           | protocol.rs:121-160 双 Mutex 合并为 `Mutex<(u32, Option<Instant>)>`，单次加锁内完成窗口判定+重置+递增（原死锁顾虑在单锁下自然消失）；补并发计数单测                                       |
| CQ-P3a | revoke 上移 application | 新增 `service::revoke_extension_access(state)`，commands.rs 与 dispatcher.rs 两处改委托；顺带评估 dispatcher 的 `pair`/`pair_confirm` 是否同批上移（二次审查指出它们同样绕过 service 层） |
| CQ-P3c | 错误映射                | state_io.rs:591-594 `EncryptionFailed` → `InternalError`（sync 错误本就不达扩展端，纯排查体验修正）                                                                                       |
| CQ-P3d | EntryScreen 拆分        | 拆出 `TotpSecretField`（含 otpauth 提示）与 `TagsEditor`（纯 props）；`detectChanges` 提为纯函数——注意补 `totpChanged` 参数（:313 现用闭包变量）。行为零变化，现有测试回归                |

### 3.4 加固顺手项（随 PR-3 带走）

- `keychain/macos.rs:340-351`：LegacyGate 分支 gate 失败时 `raw.zeroize()` 后再走错误路径。
- `validate_config`：拒绝 `server_url` 内嵌 userinfo（`user:pass@host` 形态），防与 Basic Auth 双凭据并存未定义行为。
- `docs/` 旧 minisign 公钥文件头部标注 `DEPRECATED`（防手工校验误用）。

---

## 4. PR-4：死代码清理 + 静态收尾（独立 chore）

### 4.1 可删清单（二次审查修订后）

**Rust（连同绑定死亡的整块机制）**

- `delete_group_in_txn`（vault_store.rs:110）
- `ensure_db_dir`（paths.rs:42）
- `get_schema_version` / `set_schema_version`（integrity.rs:42/58）**+ 绑定常量 `SCHEMA_VERSION_KEY`（integrity.rs:15）——整块 schema_version meta 机制同死**
- `is_digest_version_known`（vault_header.rs:132）
- `delete_entry_in_txn`（vault_store.rs:91，仅测试使用——**同步删 vault_store.rs:219 起的测试调用**）
- `is_integrity_required`（vault_header.rs:127，仅测试使用——同步删其单测；顺带更新其过时的"used by the unlock flow"文档注释所涉认知）

**依赖**：domain crate 移除 `serde_json`、`base64`；application crate 移除 `uuid`（连带 rand 依赖链）→ `cargo update -w` 收敛 lockfile，全量构建验证。

**前端**：`isVaultUnlocked`（api/vault.ts:27）、`getEntryCount`（:88）、`DownloadIcon`（Icons.tsx:128）、SettingsContext formatError re-export（:241，随 PR-2 CQ-P2a 一并，若 PR-2 先合则此处只剩确认）。

**CSS**：`.field-group`、`.field-label`（screens.css:116/120）、`.length-value`（:209）。

**扩展**：background.js 8 个死 case（INIT_VAULT:640、CREATE_GROUP:673、UPDATE_GROUP:676、DELETE_GROUP:679、EXPORT_VAULT:688、IMPORT_VAULT:691、CONNECT:715、**UPDATE_SETTINGS:685**——二次审查新发现）+ 6 个死函数成对删除（initVault/createGroup/updateGroup/deleteGroup/exportVault/importVault + **updateSettings**）；content.js:1289 死 case `SHOW_POPUP`。`checkConnection` 保留（GET_STATUS 存活）；`AUTOFILL` case（:694）**保留**（不可达但已文档化刻意留作直发兜底）。

### 4.2 禁删与待决策

- ⛔ `scripts/windows-native-host-smoke.py`——**CI 在用**（quality.yml:179、release.yml:232），二次审查已纠错，任何清理 PR 不得触碰。
- `get_entry_count` 后端链路（commands.rs:139 + lib.rs:319 + dispatcher.rs:214）：前端/扩展零调用但属扩展 HTTP 协议对外 method——**建议保留**（协议稳定性优先），在协议文档标注"预留"；如决定下线需走扩展协议版本协商，另立决策。

### 4.3 ST-1 静态收尾

- 删除 `vite.config.ts:26` 失效的 `@ts-expect-error`（TS2578 唯一编译级错误）。
- `package.json` 的 `typecheck` 脚本追加 `tsc --noEmit -p tsconfig.node.json`，堵住"流水线永远看不到 node 配置错误"的盲区。

### 4.4 PR-4 DoD

全部测试套件绿；`cargo build`/前端构建产物大小对比（依赖回收应略降）；扩展 zip 重新打包确认死 case 删除无副作用（手动加载冒烟）。

---

## 5. 测试补强总表（随各 PR 附带）

| 测试                                                | 随附           | 说明                                                                                   |
| --------------------------------------------------- | -------------- | -------------------------------------------------------------------------------------- |
| 解锁-vs-窗口交错测试 ×3（密码/生物识别/孤儿行断言） | PR-1 / SEC-M1  | 复用 `reseal_window_gate` 测试缝                                                       |
| 路径校验 + 原子写单测                               | PR-1 / SEC-M2  | DB 目录拒绝、穿越拒绝、写失败无半文件                                                  |
| sync zeroize 显式 scrub 测试                        | PR-1 / SEC-M3  | derive 提供的显式 `zeroize()` 可断言                                                   |
| ErrorBoundary 渲染测试                              | PR-2 / SF-P2b  | 抛错子组件 → fallback + 按钮回调                                                       |
| errorMessage 单元变体用例 + AuthContext 断言更新    | PR-2 / CQ-P2a  | 解钉坏行为断言                                                                         |
| pair 限流并发单测                                   | PR-3 / CQ-P3b  | 双线程同分钟边界突发计数不被清零                                                       |
| fuse 配置双端 parity 测试                           | PR-3           | 照搬 password-strength.test.js 模式：扩展测试 import 桌面 `search.ts` 配置做 `toEqual` |
| macOS CI keychain 真实 SecItem 冒烟                 | PR-3（或独立） | runner-gated 写→读→删；**注意 macos/tests.rs 已有 7 个单元测试，本项只补真实 I/O 层**  |
| native-host token 白名单单测                        | PR-3 / SEC-L1  | 64-hex 通过、CRLF/长度不符拒绝                                                         |

---

## 6. 手动 QA 清单（PR-1 / PR-2 合并前）

1. **扩展全路径**（SF-P1/PR-1）：锁定桌面端后用快捷键/右键菜单/ popup 复制 → 应得明确错误提示而非成功绿条/无反应；解锁后正常流回归。
2. **导入导出**（SEC-M2/PR-1）：macOS + Windows 双端 dialog 选路径导出/导入 .pvault；导出到无权限目录得明确报错；恢复密钥"保存到文件"落盘且 0600。
3. **改密并发**（SEC-M1/PR-1，可选压力项）：大库改密期间另一端尝试解锁 → 解锁侧应报"状态已变化，请重试"，改密完成后正常解锁、全部条目可读。
4. **同步回归**（SEC-M3/PR-1）：sync_now 双端各跑一轮，条目/历史快照正常。
5. **渲染崩溃演练**（SF-P2b/PR-2）：dev 模式临时抛错组件 → ErrorBoundary fallback 出现，"锁定并重启"按钮生效。
6. **错误文案**（CQ-P2a/PR-2）：连续 5 次错误解锁 → 显示"尝试过多，60 秒后重试"类文案而非 JSON/枚举名。

---

## 7. 风险登记与回滚

| 风险                              | 概率 | 缓解                                                      | 回滚                                            |
| --------------------------------- | ---- | --------------------------------------------------------- | ----------------------------------------------- |
| SEC-M1 并发改动引入死锁/新竞态    | 中   | 设计已规避重入红线；交错测试 ×3；review 聚焦锁序          | 单 PR revert，无数据格式变更                    |
| SEC-M2 双平台 dialog/路径行为差异 | 中   | 手动 QA §6.2；路径校验单测覆盖                            | revert 后恢复前端 IO（capabilities 同 PR 回滚） |
| SEC-M3 derive 与 serde 边界       | 低   | 验证代理已核实 feature/impl；现有 sync 测试全量回归       | revert                                          |
| CQ-P2b 拆分改变 zeroize 时机      | 低   | 保持"import 全程存活"语义；现有测试等价性验证             | revert                                          |
| 死代码删除破坏隐式引用            | 低   | 二次审查双口径 grep + 宏/路由/动态排除；PR-4 独立小步提交 | 按文件级 commit revert                          |
| UI 文案/交互回归（PR-2）          | 低   | vitest + 手动 QA §6.5/6.6                                 | revert                                          |

所有 PR 均不改磁盘数据格式（SEC-L2 的 sync 配置加密是唯一例外，已设计双读迁移，且独立成 PR）。

---

## 8. 建议决策点（需项目所有者拍板）

1. **SEC-M1 实现路线**：本方案推荐"包装层取窗 + key_id 复核"（§1.1）；若倾向更简单的 epoch-bump 或全程持窗，需重新评估 UX/覆盖面权衡。
2. **SEC-M2 路线**：推荐 IO 下沉（§1.2）；备选 fs_scope 运行时放行（保留前端 IO）。推荐前者，理由：恢复密钥明文不再经 webview、信任边界更清晰。
3. **SEC-L5 自动锁语义**：文档声明优先还是直接实现"HTTP 读操作不续期"？
4. **get_entry_count 协议 method**：保留（推荐，本方案默认保留）还是走版本协商下线？
5. **PR-1 发布节奏**：v1.1.9 仅含 PR-1（最快让安全修复到达用户）还是 PR-1+PR-2 合发？

---

## 附：与审计报告的条目对照

本方案覆盖审计报告第一~~五节全部可执行发现（SEC-M1~~M3、L1~~L6、SF-P1、P2a~~d、P3a~~f、CQ-P2a/b、P3a~~e、ST-1、死代码 P2 全量 + P3 复核新发现），并全部采用二次审查（第七节）修正后的机理与修复路线；SEC-L6（依赖 informational）与 LWW 等设计取舍项按报告结论持续跟踪、不占修复排期；cargo audit 复核动作已由二次审查完成（2026-10-03 新库，0 漏洞），关闭。
