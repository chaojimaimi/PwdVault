# v1.1.9 安全修复实施方案（PR-1 + PR-2 合发）· R2

**日期**：2026-10-05 · **基线**：`main @ e7375e2`（v1.1.8）· **目标版本**：v1.1.9
**上游文档**：`code_audit_2026-10-04.md`（审计+二次审查）、`code_audit_fix_plan_2026-10-04.md`（修复总案）
**修订记录**：R2 按 plan-reviewer 评审意见修订（3 P1 + 4 P2 + 4 P3 全部采纳；评审确认 SEC-M1 无死锁、方向成立）

## 0. 已拍板决策（项目所有者，2026-10-05）

| #   | 决策                                                                                      |
| --- | ----------------------------------------------------------------------------------------- |
| ①   | SEC-M1 双重防线：`complete_unlock` 外层包装取 `exclusive_window` + 取窗后复核验证数据指纹 |
| ②   | SEC-M2 IO 下沉：文件读写移入 Rust 命令，收回 `$HOME/**` fs 授权                           |
| ③   | SEC-L5 本版只做文档声明，实现留 v1.2.x                                                    |
| ④   | `get_entry_count` 保留（v1.2.0 清理批不动）                                               |
| ⑤   | v1.1.9 = PR-1 + PR-2 合发                                                                 |

**不在本版范围**（→ v1.2.0）：SEC-L1~L4/L6、SF-P3 组、CQ-P3 组、死代码清理批、ST-1。

## 1. 工作包总览与波次

| WP   | 内容                                  | 主要文件域                                                                                                                                                                                                                | 波次                     |
| ---- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| WP-1 | SEC-M1 + SEC-M3                       | application/service/security/（shared.rs、credentials.rs 改，password.rs 只读参照）、**service/vault.rs**、sync/（mod.rs、state_io.rs）、tests_window.rs、application/Cargo.toml（评审核实已含 derive feature，预计不动） | Wave 1                   |
| WP-2 | SEC-M2 Rust 侧 + CQ-P2b + SF-P2d      | commands.rs、lib.rs、service/backup.rs、secret_file_store.rs、paths.rs、**tests/golden_contract.rs**                                                                                                                      | Wave 1                   |
| WP-4 | SF-P1 + SF-P2a                        | extensions/chrome/src/**                                                                                                                                                                                                  | Wave 1                   |
| WP-3 | SEC-M2 前端侧 + SF-P2b/c + CQ-P2a     | src/screens、components、context、api、main.tsx、**src-tauri/capabilities/default.json、src-tauri/tests/capability_contract.rs**、package.json                                                                            | Wave 2（契约 §3 已冻结） |
| WP-5 | SEC-L5 文档 + 版本 + CHANGELOG + 发版 | README、AGENTS.md、10 个版本文件                                                                                                                                                                                          | Wave 3（复审通过后）     |

Wave 1 三 WP 文件域互不重叠；cargo 共享 target 锁会串行，属预期。

---

## 2. WP-1：Rust 并发安全（SEC-M1 + SEC-M3）

### 2.1 SEC-M1 双重防线

**已核实的现状**：

- `complete_unlock`（shared.rs:180-186）是薄包装 → `complete_unlock_if(..., |_| true)`；
- 窗口路径不经包装：`recover_vault` 直调 `complete_unlock_if`（password.rs:281），`change_password` 与 sync republish 直调 `state.session.unlock_if`（password.rs:136/156、state_io.rs:513）——三者均绕过 `complete_unlock`，这是无死锁的关键，**不得把它们改经包装**；
- `unlock_vault` 在 vault.rs:207-213 已 clone `verification_data`；`unlock_biometric` 末尾调 `complete_unlock`（credentials.rs:157）。

**改动设计**：

1. `complete_unlock` 签名增加期望验证数据（评审确认 `AdaptiveParams` 未 derive PartialEq——salt 用 `!=`，params 逐字段比较或补 derive PartialEq，实现时择一）：
   ```rust
   pub fn complete_unlock(
       state: &Arc<AppState>,
       enc_key: SecretKey,
       mac_key: SecretKey,
       expected: &VerificationData,   // 调用方在推导前捕获
   ) -> Result<(), VaultError> {
       // ⛔ 文档注释：严禁在持有 exclusive_window 时调用本函数（窗口路径直调 complete_unlock_if / session.unlock_if）
       let _window = state.exclusive_window.lock().expect("window lock poisoned");
       let current = current_verification(state)?;
       if current.salt != expected.salt || !params_equal(&current.params, &expected.params) {
           return Err(VaultError::InvalidInput {
               code: "VAULT_STATE_CHANGED".into(),
               message: "Vault state changed (password change / recovery / sync in progress); retry unlock".into(),
           });
       }
       complete_unlock_if(state, enc_key, mac_key, |_| true).map(|_| ())
   }
   ```
   - salt 非机密，普通比较；错误用现有 `InvalidInput{code,message}`（serde 兼容，`errorMessage` 可提取 message）。
   - 复核逻辑成立性（评审核实）：`derive_new_keys` 每次生成新随机 salt（shared.rs:424），reseal 事务落盘新 verification（shared.rs:387），state 副本在持窗期间更新（password.rs:127-130/272-275）——窗口串行化保证复核无撕裂读；sync republish 不改 verification。
2. `vault.rs unlock_vault`（:234）：传 `&verification_data`（已有 clone）。
3. `credentials.rs unlock_biometric`：在 **Touch ID 弹窗之前**捕获 `let expected = current_verification(state)?;`，末尾传 `&expected`。
4. 锁序（写入注释）：`exclusive_window → database → session internals`，与 state.rs:127-134 文档及 engine.rs:106 先例一致；`lock_vault`/自动锁线程从不取窗口，不成环。

**测试**（tests_window.rs 追加，复用 `reseal_window_gate` 缝；缝位于 drain 之后、`is_unlocked` 检查与 `reseal_vault` 之前——password.rs:102-103）：

- **T1 `unlock_vs_change_password`**：窗口停车期间发起并发 unlock（完成 Argon2 后阻塞在窗口锁）→ 释放缝 → 改密完成 → 断言 unlock 返回 `VAULT_STATE_CHANGED`、无会话发布、新密码可正常解锁。
- **T2 `no_orphan_row_invariant`**（R2 按评审意见改为可落地形态）：窗口停车期间：a) 并发 unlock（应被拒，无会话）；b) 尝试经任何既有句柄写入（drain 后无会话，应被拒）；c) 改密完成 → 断言逐条 AEAD 读回全部条目成功、计数一致、无孤儿行（本修复下窗口内不可能有会话发布 → 孤儿行按构造不可达，测试固化该不变量）。
- **T3 `biometric_unlock_vs_window`**：同 T1 用 MemorySecretStore；`security/tests.rs` 的生物识别夹具为 `pub(super)`——**自建最小夹具或将其提为 `pub(crate)`**（倾向后者便于复用）。
- 既有 4 个窗口测试 + 全 workspace 测试不回归。

### 2.2 SEC-M3 sync 明文域清零（含 E0509 约束——R2 新增）

1. `sync/mod.rs`：`SyncSecrets`、`SyncEntry`、`SyncGroup`、`SyncSnapshot`、`MergedSnapshot` 逐个加 `#[derive(Zeroize, ZeroizeOnDrop)]`（application/Cargo.toml:27 已含 derive+serde feature，评审核实）。
2. **E0509 约束（必须处理）**：`ZeroizeOnDrop` 生成 `impl Drop`，Rust 禁止对 Drop 类型部分移出字段。`sync_to_entry`（sync/mod.rs:154-180）现按值消费并移出 `entry.title/url/username/notes/totp_secret/tags/group_id`——直接加 derive 会编译失败。改造模式：`mem::take(&mut entry.title)` 替代直接移出（borrow 式取出，语义不变：取出的值照常流转，结构体残留空值随 Drop 清零）。实现前 grep 其余按值消费这些结构体字段的点（publish.rs、merge.rs、container.rs、engine.rs）同法处理。
3. `decrypt_inner`（state_io.rs:343-352）消灭 clone 逃逸：
   ```rust
   let plain = match String::from_utf8(plain) {
       Ok(s) => s,
       Err(e) => { let mut b = e.into_bytes(); b.zeroize(); return Err(/* 现有错误类型映射 */); }
   };
   ```
4. 纪律护栏：grep 确认 sync 链路无 `debug!`/`dbg!`/`{:?}` 打印快照；"plaintext-domain" 注释处追加禁 debug-log 提醒。
5. 测试：现有 sync 全量测试回归 + 显式 scrub 测试（构造已知密码 → 显式 `zeroize()` → 断言非原值）。

**WP-1 DoD**：`cargo test --workspace` 全绿（含 T1-T3）、clippy/fmt 0、改动文件 ≤800 行、`grep -rn 'complete_unlock(' --include='*.rs' | grep -v complete_unlock_if` 仅两解锁调用点 + 定义。

---

## 3. WP-2：Rust IO 下沉 + backup 拆分 + 凭据权限（冻结契约 R2）

### 3.1 新命令契约（R2 修订：补 `tauri::AppHandle` 参数）

> 关键修正（评审 P1）：项目 `src/commands.rs:16` 的 `pub type AppHandle = Arc<AppState>`，`State<'_, AppHandle>` 拿不到 dialog 插件——**必须额外注入 `tauri::AppHandle`**（Tauri 自动注入，前端 invoke 参数面不变）。tauri-plugin-dialog 锁定 2.7.0（Cargo.lock:4542），`blocking_save_file`/`blocking_pick_file` 存在；blocking 变体禁止主线程调用——命令体在 `spawn_blocking` 闭包内调用（满足），返回 `Option<FilePath>` 需转 String（按 2.7.0 API 落地）。

```rust
// C1 导出：spawn_blocking 内：blocking_save_file（默认名 pwdvault-backup-YYYY-MM-DD.pvault，
//    filter=["pvault"]）→ 取消返回 Ok(None)；确认后生成容器 → pretty JSON → 原子写 0600 → Ok(Some(所选路径))
#[tauri::command]
pub async fn export_vault_file(
    app: tauri::AppHandle,                    // ← dialog 插件入口
    export_password: Zeroizing<String>,
    state: State<'_, AppHandle>,              // 项目别名 Arc<AppState>
) -> Result<Option<String>, VaultError>;

// C2 读取备份：spawn_blocking 内：blocking_pick_file（filter=["pvault"]）→ 取消 Ok(None)；
//    读取（大小上限 14 MiB —— 对齐前端常量 MAX_BACKUP_FILE_BYTES=14*1024*1024，
//    ImportExportScreen.tsx:14，超限 InvalidInput BACKUP_TOO_LARGE）→ 解析 →
//    envelope 校验（magic+版本，对齐 isSupportedBackup 语义）→ Ok(Some(VaultBackup))
#[tauri::command]
pub async fn read_backup_file(
    app: tauri::AppHandle,
    state: State<'_, AppHandle>,
) -> Result<Option<pwdvault_domain::VaultBackup>, VaultError>;

// C3 恢复密钥：save_path 由前端 dialog 选定传入；Rust 校验（3.2）后写 0600
//    （文案模板从 TS recoveryKeyFileContent 迁移，内容逐字一致）
#[derive(Serialize)] #[serde(rename_all = "camelCase")]
pub struct EnableRecoveryResult { pub key: String, pub file_saved: bool }
#[tauri::command]
pub async fn enable_recovery(
    password: Zeroizing<String>,
    save_path: Option<String>,
    state: State<'_, AppHandle>,
) -> Result<EnableRecoveryResult, VaultError>;
```

- 既有 `export_vault` / `import_vault`（DTO 版）不变；**enable_recovery 原地改签名**（评审核实：IPC-only，HTTP dispatcher 无此路由，无扩展兼容面）。
- `lib.rs` `generate_handler!` 注册 C1/C2。
- **`src-tauri/tests/golden_contract.rs`（R2 新增）**：IPC 清单为手工维护（头注释要求与 lib.rs 同步）；新增 C1/C2 后更新其清单与 `:177-201` 的 ipc_only 期望向量，测试必须同步绿。
- DTO serde 命名遵循 domain 现有约定；JS invoke 参数 camelCase 自动映射。
- **探针先行**：WP-2 开工第一件事写临时探针测试验证 spawn_blocking + blocking dialog 与 Tauri 运行时的实际交互（§8 风险登记）；不通则退化为"前端 dialog 选路径 + 命令收 path"备选（契约去掉 app 参数、加 path 参数，届时同步通知 WP-3）。

### 3.2 路径校验 helper（paths.rs）

`fn validate_user_file_path(path: &Path, for_write: bool) -> Result<(), VaultError>`：

1. 绝对化失败/空 → 拒绝；
2. **拒绝落在 vault 数据目录内**：用 `paths::get_db_path().parent()`（R2 采纳评审 P3：paths.rs:13-39 已按三平台解析，含 Linux `~/.local/share/pwdvault`——勿硬编码两目录）；比较前 canonicalize，Windows 剥 `\\?\` 前缀（手写 trim，不新增依赖）；
3. for_write：父目录存在且为目录；
4. C1/C2 路径来自原生对话框（逐次授权）；C3 的 save_path 为前端 dialog + 本校验 + master password 参数构成第二道门（代码注释说明威胁模型）。

### 3.3 原子写 helper

`fn write_file_atomic_0600(path: &Path, bytes: &[u8]) -> io::Result<()>`：同目录临时文件 `OpenOptions::create_new(true).mode(0o600)`（Unix；Windows no-op）→ 写 → rename 覆盖 → 失败清理。

### 3.4 CQ-P2b import_vault 拆分

`backup.rs:191-413` 拆六段（validate_backup_envelope / decode_and_check_kdf / derive_import_key / decrypt_backup_payload / prepare_import_rows / 事务闭包）；`lease` 改显式参数（:197/:296/:371/:408）；`import_password`/`import_key` Zeroizing 保持"全程存活、结束清零"语义（阶段间移动而非提前 drop）。现有测试不改、全绿即证等价。

### 3.5 SF-P2d 凭据文件权限

`secret_file_store.rs`：写入改 `OpenOptions::write(true).create_new(true).mode(0o600)`（Unix cfg；Windows 分支维持现状——DPAPI 已护）；`restrict_permissions`（:166）失败 `let _ =` → `tracing::warn!`；`lib.rs:123` `secure_file` 失败补 warn（措辞如实：native-host.json 配置）。

**WP-2 DoD**：新命令单测（路径校验各分支、原子写无半文件、enable_recovery save_path 各分支、C2 超限拒绝）+ golden_contract 更新绿 + `cargo test --workspace` 全绿 + clippy/fmt 0 + 文件 ≤800 行。

---

## 4. WP-4：浏览器扩展（SF-P1 + SF-P2a）

### 4.1 SF-P1 空密码假成功

1. `background.js getEntry`（:445-456）：secret rejected 时上抛 `new Error("SECRET_FETCH_FAILED: ...")`（带类型标记的错误消息，供消费方区分文案）。
2. 右键菜单（:581-599）与快捷键（:754-779）：AUTOFILL 前守卫 `if (!entry || !entry.password)` → `notifyTab(..., "无法获取密码（桌面端可能已锁定）", "error")`；**getEntry 上抛后走外层 catch（:607-613）——在 catch 内识别 SECRET_FETCH_FAILED 标记显示同一文案**（R2 采纳评审 P3：守卫覆盖 entry-null，取密失败实际走 catch 分支，文案在 catch 区分）。快捷键路径的 `entry.username` TypeError 由守卫覆盖。
3. `popup.js` 复制两处（:1418-1428、:1443-1451）：`!details?.password` → `showToast("获取密码失败", "error")`（按 popup toast 现有 API 落地）。
4. `content.js autofillLogin`（:337-361）：入口空密码短路 + 错误通知（纵深防御）。

### 4.2 SF-P2a 剪贴板清除失败反馈

`content.js:400-416` 内层 catch：`console.warn("clipboard auto-clear failed", e)` + `showNotification("剪贴板自动清除失败，请手动清除", "error")`（复用现有通道，确认定时器上下文可调用）。**不新增 manifest 权限**（根治方案 background/offscreen 移交记 v1.2.x）。

**WP-4 DoD**：扩展 JS 全部 `node --check` 通过；现有扩展测试不回归；firefox 符号链接与 manifest 不动；手动冒烟（§7）交复审阶段。

---

## 5. WP-3：前端 webview（Wave 2）

### 5.1 SEC-M2 前端侧

1. `src/api/vault.ts`：新增 `exportVaultFile(exportPassword)` / `readBackupFile()` / `enableRecovery(password, savePath?)` wrapper（camelCase 参数）。
2. `ImportExportScreen.tsx`：
   - 导出 Tauri 分支（:70-80）→ `await exportVaultFile(exportPassword)`，成功 toast；浏览器 Blob 回退分支不动；
   - 导入选文件（:105-125）→ `await readBackupFile()`；null（取消）静默；DTO 沿用 `isSupportedBackup` 双保险 + 现有 setSelectedBackup 流；文件名显示改 "Selected backup"；
   - 删除两处 `@tauri-apps/plugin-fs` 动态 import。
3. `SecuritySettingsSection.tsx`（:226-250）：表单加 "Save to file" 复选框——勾选：Enable 点击后先 `save()` 选路径 → `enableRecovery(password, filePath)`（key 不二次过 IPC）；未勾选：`enableRecovery(password, undefined)` 行为同旧。key 展示逻辑不变，toast 按 `file_saved` 分文案。
4. **`src-tauri/capabilities/default.json` + `src-tauri/tests/capability_contract.rs`（R2 成对改，采纳评审 P1）**：删除三个 fs 权限对象块（保留 `fs:default`、`dialog:default`，头注释追加 M12 备案）；capability_contract.rs :29-39 与 :50-83 **反转为断言三个权限已移除、deny scope 不存在、dialog:default/fs:default 保留**。
5. `grep plugin-fs src/ package.json`：前端零引用则移除 JS 依赖并刷 lockfile（Rust 侧 tauri-plugin-fs 保留——`fs:default` 仍需插件在）。

### 5.2 SF-P2b ErrorBoundary

新建 `src/components/ErrorBoundary.tsx`（`getDerivedStateFromError` + `componentDidCatch`→console.error）；fallback：错误说明 + [重启应用]（`relaunch()`——`@tauri-apps/plugin-process` JS 包已装（package.json:22，评审核实）、`process:allow-restart` 已授权；进程重启即等价锁定）+ [复制错误详情]。`main.tsx` 包裹。测试：抛错子组件 → fallback + 按钮（mock relaunch）。

### 5.3 SF-P2c lock 失败提示

`AuthContext.tsx:200-212` catch：保留 RESET/切锁屏（A4 取舍），追加 `showToast("锁定指令发送失败，请重试或退出应用")`。

### 5.4 CQ-P2a formatError 统一

删三份本地 `formatError`（AuthContext.tsx:6-12、VaultContext.tsx:294-302、SettingsContext.tsx:8-12）+ SettingsContext.tsx:241 re-export → 统一 `errorMessage(error, '<语境兜底>')`。**同步更新 `AuthContext.test.tsx:77`**（解钉 RateLimited 断言 → 改断言 errorMessage 文案）；errorMessage 补单元变体解析用例（若未有）。

**WP-3 DoD**：`pnpm tsc --noEmit`（主+test）0 错、`pnpm lint` 0、`pnpm test` 全绿、**`cargo test --workspace` 全绿（capability_contract 反转后）**、`grep plugin-fs src/` 零残留。

---

## 6. WP-5：文档与发版（复审通过后）

1. **SEC-L5 文档**：README 安全节 + AGENTS.md Security Notes 追加"扩展操作刷新自动锁计时（受信端语义），远程不续期增强列 v1.2.x"。
2. **版本**：`bash scripts/bump-version.sh 1.1.9 --changelog`（10 文件；脚本 :192-198 自动刷 native-host lockfile——评审核实）+ `cd src-tauri && cargo update -w`（主 workspace lockfile 对齐，沿 1638997 先例）。
3. **CHANGELOG.md** v1.1.9 条目（Security：SEC-M1/M2/M3、SF-P1；Fixed：SF-P2a-d、CQ-P2a；Internal：CQ-P2b、ErrorBoundary、capability 收回）。
4. **提交**：先处置 commit-gate hook 失效问题（评审 P2：`git config core.hooksPath` 指向旧仓库路径、已不存在）——检查 `.git/hooks/` 是否有 hooks：有则 `git config --unset core.hooksPath` 回落默认；无则明示以人工检查替代（暂存区 .rs 逐个 `wc -l` ≤800 + review 纪律），选择记入提交说明。commit message 沿仓库风格。
5. **发版**：`git tag v1.1.9 && git push origin main --tags` → 观察 release.yml（macOS DMG + Windows + 双扩展 + quality）全绿 → 确认 Release 产物与 updater feed（latest.json 回填，模式同 e7375e2）。
6. **发版后**：AGENTS.md Session Log 追加 v1.1.9 小节；更新记忆。

---

## 7. 全局验收矩阵（主代理复审阶段执行）

| 门禁        | 命令                                                                        | 适用                                                     |
| ----------- | --------------------------------------------------------------------------- | -------------------------------------------------------- |
| Rust 全量   | `cd src-tauri && cargo test --workspace`（243+ 新增）                       | **每波次**（WP-3 含 capability_contract 反转，也必须跑） |
| Rust 静态   | `cargo clippy --workspace --all-targets` + `cargo fmt --check`              | 每波次                                                   |
| native-host | `cd extensions/native-host && cargo test && cargo clippy`（未改动，防波及） | 复审                                                     |
| 前端        | `pnpm tsc --noEmit`（主+test）、`pnpm lint`、`pnpm test`                    | WP-3 后                                                  |
| 扩展        | `find extensions/chrome -name '*.js' -exec node --check {} \;`              | WP-4 后                                                  |
| diff 审查   | 主代理逐文件 review + code-reviewer 子代理独立过 diff                       | 复审                                                     |

**手动 QA 清单**（发版前；macOS 本机必做，Windows 用 CI 产物抽查）：

1. 扩展三路径（快捷键/右键/popup 复制）桌面锁定时得明确错误；解锁后正常。
2. 导出/导入 .pvault 走新命令全流程（含取消对话框）；导出到无权限目录报错干净。
3. 恢复密钥：勾选 Save to file → 选路径 → Enable → 文件 0600、内容含 key；不勾选同旧行为。
4. 连续 5 次错解锁 → 友好限流文案（非 JSON/枚举名）。
5. dev 模式抛错组件 → ErrorBoundary + 重启按钮。
6. 大库改密期间并发解锁 → "状态已变化"报错；改密完成后正常解锁、条目全可读。
7. 同步双端各一轮 sync_now 回归。

**跨平台要点**（复审逐项核对）：

- Windows：路径校验剥 `\\?\`；`mode(0o600)` no-op（DPAPI 已护）；dialog 取消 → None 分支；CI Windows job 与 `windows-native-host-smoke.py` 不受影响（不动 native-host）。
- macOS：Touch ID 路径仅时序入窗，语义不变；未签名构建 keychain 回退不受影响。
- 扩展：chrome/firefox 经符号链接共享 src，改动自动双侧生效；manifest 不动（无新权限）。

## 8. 风险与回滚

| 风险                                          | 缓解                                                                     | 回滚                                                |
| --------------------------------------------- | ------------------------------------------------------------------------ | --------------------------------------------------- |
| SEC-M1 死锁/新竞态                            | 设计规避重入红线（评审核实调用图无死锁）+ T1-T3 + 锁序注释               | 单文件域 revert，无格式变更                         |
| C1/C2 spawn_blocking × blocking dialog 兼容性 | **探针测试先行**；不通则退化"前端 dialog + 命令收 path"（契约同步 WP-3） | 备选路径                                            |
| SEC-M3 E0509（Drop 禁部分移出）               | mem::take 改造模式已定（§2.2.2）；实现前 grep 全部按值消费点             | 退级：仅对不被移出的容器型 derive，其余显式 zeroize |
| enable_recovery 返回结构变化                  | IPC-only（评审核实无 HTTP 面）；WP-3 同波次按契约更新；tsc 兜底          | 同步 revert                                         |
| capability_contract 击穿                      | 与 capabilities 成对改（§5.1.4），WP-3 DoD 强制 cargo test               | 同步 revert                                         |
| 测试并发争用                                  | 接受串行；如实报告                                                       | —                                                   |

## 9. 与修复总案的差异说明

- C3 返回 `EnableRecoveryResult{key, file_saved}`（总案 §1.2 细化）；C2 返回 `Option<VaultBackup>`、导入沿用既有 import_vault(DTO)（避免双入口）；C1/C2 增加 `tauri::AppHandle` 注入参数（R2，评审 P1）。
- SF-P2b fallback 简化为 [重启]+[复制错误]（重启即锁定）。
- R2 新增：golden_contract 同步（WP-2）、capability_contract 反转（WP-3）、E0509 处理（WP-1）、T2 不变量形态改写、hooksPath 处置（WP-5）、14MiB 上限对齐、路径校验用 get_db_path().parent()。
