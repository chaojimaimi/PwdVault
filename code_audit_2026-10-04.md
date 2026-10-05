# PwdVault 全量代码审计报告

**日期**：2026-10-04
**对象**：`main @ e7375e2`（v1.1.8）
**二次审查**：2026-10-04 完成——五个维度全部经独立复核（静态维度由主代理复跑工具，其余四个维度由 4 个全新验证代理在不信任原结论的前提下逐条对照代码裁决），修正了 1 处事实错误、1 处关键误杀（CI 在用脚本）、2 处不可直接落地的修复方案。结论见**第七节**，修订后处理方案见**第八节**（取代第六节）。
**方法**：5 路专项子代理并行审计（安全 / 静默失败 / 代码质量 / 静态检查 / 死代码），全部只读；主代理对头部发现逐条交叉抽验代码后成文。所有 `file:line` 均经实读验证。
**范围**：src-tauri Cargo workspace（domain/infrastructure/application + src 适配层）、React 19 前端（src/）、浏览器扩展（extensions/chrome）、Native Messaging 宿主（extensions/native-host）、CI 与配置文件。

---

## 执行摘要

**未发现 Critical / High 级阻断问题。** 五个维度合计：3 个 Medium（安全边界外延）、1 个 P1（扩展端假成功反馈）、若干 P2/P3 可维护性与加固项。2026-09-18 审计的 4 个 High（含 P0=D8 窗口互斥）**全部确认已正确修复且带回归测试**。

静态基线非常干净：`cargo check/clippy/fmt` 全绿（0 错误 0 警告）、`tsc` 0 错误、ESLint 0 警告、26 个扩展 JS 语法全过、cargo audit 0 漏洞（10 条 informational 依赖告警）；Rust 243 测试 + 前端 237 测试全过。代码库的安全工程成熟度（AAD 全覆盖、常数时间比较、fail-closed 纪律、交错测试文化、错误脱敏）在同类项目中处于头部水平，本次发现集中在**两端边界**（扩展 JS、前端反馈层）与**强基线上的边界外延**（D8 解锁路径、fs capability、sync 明文驻留）。

### 统计总表

| 维度     |                                  Critical/P0                                  | High/P1 | Medium/P2 |   Low/P3   |
| -------- | :---------------------------------------------------------------------------: | :-----: | :-------: | :--------: |
| 安全     |                                       0                                       |    0    |     3     |     6      |
| 静默失败 |                                       0                                       |    1    |     4     |     6      |
| 代码质量 |                                       0                                       |    0    |     2     |     5      |
| 死代码   |                                       —                                       | 0（P1） | 14（P2）  | 9 组（P3） |
| 静态检查 | 1 个编译级错误（TS2578，现有脚本不覆盖故不阻断 CI） + 10 条依赖 informational |         |           |            |

---

## 一、安全审计（0 Critical / 0 High / 3 Medium / 6 Low）

### [SEC-M1] D8 独占窗口不排除密码解锁路径，窗口内插入的写入可能被静默丢弃 — Medium（待确认时序窗口）

`change_password` / `recover_vault` / `run_merge_window` 持有 `exclusive_window` 并 drain 后，并发的 `unlock_vault` **不取该 mutex**（vault.rs:196-236 全程无窗口锁；全仓仅 password.rs:96/245、engine.rs:86 三处持有），可在窗口"post-drain 检查之后、re-seal 事务提交之前"完成 Argon2 派生（约 500ms）并发布旧密钥会话。若该会话的写操作恰好提交在 `reseal_vault` 的快照读取（password.rs:112 → shared.rs:330-344）与 `write_rekey` 事务（shared.rs:368）之间，replace-all 式重密封会静默丢弃该写入——`write_rekey` 的 digest 预校验无法拦截（插入写用同一把旧 mac 刷新了 digest，vault_store.rs:56-68 校验通过）。前提是持有正确主密码，大库（re-seal 数秒）+ 双端并发时可触发；若插入写落在 re-seal 提交之后则 fail-closed 报错。旧 H1 的交错测试（tests_window.rs:75/132/181/218）覆盖窗口-vs-窗口、锁-vs-窗口，**无解锁-vs-窗口用例**。

**修复**：让 `complete_unlock`（shared.rs:180-218）发布前短暂持有 `state.exclusive_window`（锁序 window → session 已兼容），并补一条"改密窗口 vs 并发解锁"交错测试（复用 `reseal_window_gate` 测试缝）。

### [SEC-M2] fs capability 授权 `$HOME/**` 读写，webview 内代码执行即等于全 HOME 文件读写 — Medium（风险面放大器）

`src-tauri/capabilities/default.json` 授予 `fs:allow-read/write/stat` 于 `$HOME/**`、`/Volumes/**`、`$TEMP/**`（deny 仅两个 DB 目录）。React 转义 + CSP `script-src 'self'` + EntrySummary 不含 secret 使 XSS 概率很低，但一旦发生（未来引入渲染 raw HTML 的组件、依赖链投毒），攻击者在 app origin 内可直接读 `~/.ssh/`、浏览器 Cookie DB 等。前端实际只需 dialog 返回的用户选定路径（ImportExportScreen.tsx:69-77）。

**修复**：改用 Tauri v2 dialog 授权路径模式——`save()/open()` 返回后 `addScopedPath()` 把当次选定文件加入临时 scope，capabilities 收回 `fs:default`。把"单点 XSS 爆炸半径"从全 HOME 降回单文件，低成本高收益。

### [SEC-M3] 云同步链路明文密码以非 zeroizing 的 `String`/`Vec` 长驻内存 — Medium（违反项目自身 zeroize 纪律）

每次 `sync_now`/`sync_connect`，`read_local_rows` 解密全部条目到明文域：`decrypt_inner`（state_io.rs:343-352）先 `String::from_utf8(plain.clone())` 再 zeroize 原缓冲——**clone 出的明文 String 不受保护**；随后 `SyncSecrets`/`SyncEntry`/`SyncSnapshot`/`MergedSnapshot` 层层 clone 明文（engine.rs:116-123、publish.rs:110-118、merge.rs:43-59）。对照项目在 `NativeRequest`（protocol.rs:28-68 `Zeroizing<String>`）、`reseal_vault`、backup 上的纪律，这是唯一明文长驻缺口。利用前提是进程内存可读（swap/核心转储/内存抓取）。

**修复**：`SyncEntry` 的 `password`/`notes`/`totp_secret` 改 `Zeroizing<String>`（serde 透明支持，需验证反序列化路径）；或退而求其次，merge/publish 完成后对 merged entries 逐字段 `zeroize()`。

### Low 级发现

| #      | 发现                                                                                                                                             | 位置                                         | 修复建议                                                                                             |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| SEC-L1 | native-host 把 `auth_token` 未校验直接拼入 Authorization 头（CRLF 可注入新 header；可达性仅限扩展自身，纵深防御缺口）                            | native-host/src/main.rs:407-410, 329         | 加 `is_valid_token`（64 位 hex 白名单），与 `is_valid_command` 同策略                                |
| SEC-L2 | `SyncConfig`/`SyncState` 明文存于 vault DB 行，DB 持有者可读同步元数据（server_url、username、remote_dir）                                       | state_io.rs:40-43                            | 用 enc subkey 加密为 blob（与 `sync_cek` 同模式），或至少 username 移入 keychain                     |
| SEC-L3 | 百度 OAuth 回调监听器单请求消费，任意网页 `fetch('http://127.0.0.1:17777/?error=x')` 可打空 pending 授权（DoS；state 128-bit CSPRNG 无注入风险） | baidu_oauth.rs:318-339                       | 循环丢弃无 `code` 或 state 不匹配的请求直到超时                                                      |
| SEC-L4 | `enable_recovery` 以普通 `String` 返回 256-bit 恢复密钥并跨 IPC，两侧驻留副本无清理                                                              | credentials.rs:177-208 + commands.rs:306-315 | 命令侧改 `Zeroizing<String>`，前端展示组件卸载后置空                                                 |
| SEC-L5 | 已配对扩展可经周期性 vault 操作（每次成功操作 `lease.touch_activity()`）无限续期自动锁                                                           | session.rs:325-329                           | 区分桌面输入与远程操作（独立 `last_remote_activity`，自动锁取 max），或文档声明语义                  |
| SEC-L6 | 依赖面：bincode 1.x unmaintained（RUSTSEC-2025-0141，deny.toml 已备案）等 10 条 informational；glib/rand 传递 unsound                            | src-tauri Cargo.lock                         | 保持路线图跟踪 bincode 迁移；网络恢复后重跑 `cargo audit` 复核（本次 advisory-db 为 09-19 本地缓存） |

### 旧报告（2026-09-18）4 High 修复核验

| 旧编号  | 内容                                    | 结论       | 证据                                                                                                                                                             |
| ------- | --------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| H1 (P0) | D8 三窗口互不排斥 + digest 无预校验     | **已修复** | `exclusive_window` 从 drain 前持有到 republish；`lock_epoch` bump + `unlock_if` 同临界区校验；`verify_digest_in_txn` fail-closed；交错测试 ×4。残余边界见 SEC-M1 |
| H2      | 限流提示被 "Invalid password" 覆盖      | **已修复** | UnlockScreen.tsx:31-43/58 state 优先合并                                                                                                                         |
| H3      | 同步完成后列表不刷新                    | **已修复** | SyncSettingsSection.tsx:207-223 并发刷新 + 独立失败 toast                                                                                                        |
| H4      | 缺 eslint-plugin-react-hooks / jsx-a11y | **已修复** | eslint.config.js 两插件在位                                                                                                                                      |

顺带核验：M1（DPAPI）、M2（https-only 含 sync_now 旁路封堵）、M7（popup 填充域校验）均已修复。

### 设计取舍确认（核查后无实际可利用后果，不列为漏洞）

bincode 双读（migration 单点）、D8 sync 变体（generation 双检，比改密路径更严）、坚果云 409=absent、connect 先存凭据、导入 KDF 下限但解锁放行历史参数（`KdfPolicy` 仍有结构下界 + DoS 上界）、ureq 非标准动词 + `max_redirects(0)` 防 Basic Auth 重定向泄露、legacy keychain Touch ID 回退（仅未签名构建可达、tag 前缀 fail-closed）、LWW 固有取舍（tombstone 仲裁 + 指纹 tiebreak + 10 份加密历史快照兜底）。

---

## 二、静默失败审计（0 P0 / 1 P1 / 4 P2 / 6 P3）

Rust 核心链路（解锁/reseal/D8/redb 事务/导入导出/LWW 合并）错误传播纪律良好：fail-closed、单事务回滚、降级路径普遍有日志且为文档化决策。真正的静默失败集中在**扩展端与前端反馈层**。

### [SF-P1] 扩展 `getEntry` 用 allSettled 把秘密获取失败掩盖为空密码，自动填充路径报"成功" — P1

`background.js:445-456`：secret 请求 rejected 时静默降级为 `password: ""`，错误对象完全丢弃（代码注释表明回退是有意的——保住 meta 展示——但下游没有处理空密码）。后果链：

1. 快捷键（background.js:754-779）/右键菜单（:581-599）不校验空密码 → 发送 `AUTOFILL {password: ""}` → content.js:337 照常填空串并弹 **"Credentials filled successfully"**——用户收到主动的错误成功反馈，可能直接提交空密码表单；
2. popup 复制按钮（popup.js:1418-1428）`if (details && details.password)` 判空后**静默无操作**——点"Copy Password"毫无反应；
3. 快捷键路径 `getEntry` 返回 null 时仅 console.error，零用户反馈。

**修复**（最小改动）：`getEntry` 返回 `{entry, secretError}` 或 rejected 时上抛；快捷键/右键路径在空密码时 `notifyTab(..., "error")`（复用现有通道）；popup 复制按钮空密码时 `showToast("Failed to fetch password", "error")`。

### P2 级发现

| #      | 发现                                                | 位置                                  | 后果                                                                                                                                                                      | 修复                                                                       |
| ------ | --------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| SF-P2a | 扩展剪贴板 30s 清除失败两层空 catch，无日志无通知   | content.js:400-416                    | 定时清除不在用户手势上下文，多数站点拒绝 `clipboard.writeText` → 密码**永久留在剪贴板**，而 UI 承诺 30s 自动清除。桌面端 clipboard.ts 有重试+toast（M11），扩展端无等价物 | 对齐 M11：失败 1s 重试一次，仍失败 `showNotification` + console.warn       |
| SF-P2b | React 无错误边界——渲染崩溃即白屏，应用仍托盘运行    | main.tsx（无 ErrorBoundary）          | 白屏无反馈；close-to-tray 下 HTTP 服务继续、用户失去手动锁定入口（最长等 60 分钟自动锁）                                                                                  | App 外包 ErrorBoundary，fallback 提供"锁定并重启"按钮                      |
| SF-P2c | `lock()` IPC 失败时 UI 伪装已锁定，仅 console.error | AuthContext.tsx:200-212               | 后端会话密钥仍在内存、17429 端口 token 仍可读秘密，UI 却显示锁屏——安全语义假成功（触发窗口窄：仅 IPC 层故障）                                                             | 失败分支加可见提示"锁定指令发送失败，请重试或退出应用"或延迟重试           |
| SF-P2d | 凭据文件 chmod 失败被 `let _ =` 静默丢弃            | secret_file_store.rs:166 + lib.rs:123 | 临时文件按 umask（典型 0644）创建后 rename；chmod 失败时 **WebDAV 密码/百度 token 的 base64 明文**以可读权限留在用户目录，多用户机器可读，且零诊断信号                    | chmod 失败 `tracing::error!` 并使 `set()` 返回失败（凭据宁可拒存不可裸存） |

### P3 级发现（摘要）

| #      | 发现                                                                                                                                                  | 位置                           | 要点                                                              |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ----------------------------------------------------------------- |
| SF-P3a | 启动时 settings 加载失败静默回退默认自动锁时长（1→10 分钟，解锁窗口比用户预期长），无日志                                                             | vault.rs:416-418               | 改 match + `tracing::warn!`                                       |
| SF-P3b | `sync_disconnect` 凭据删除失败被忽略，UI 却承诺"forgets its sync credentials"                                                                         | engine.rs:428-429              | 失败 warn；长期在 SyncStatusResponse 如实上报                     |
| SF-P3c | 配对码事件 emit 失败静默——扩展用户陷入无反馈等待                                                                                                      | dispatcher.rs:66               | emit 失败 `tracing::error!`                                       |
| SF-P3d | token/配对 nonce 持久化失败 `.catch(() => {})`——SW 挂起后被迫重新配对，且误诊为"验证码错误"                                                           | background.js:66-71, 45-50     | save 失败 console.warn；无-nonce 分支设置明确 lastConnectionError |
| SF-P3e | ImportExportScreen FileReader 未注册 onerror——读取失败零反馈                                                                                          | ImportExportScreen.tsx:137-158 | 补 `reader.onerror` + toast                                       |
| SF-P3f | 状态探针失败静默降级："已连接"显示为未连接表单（SyncSettingsSection.tsx:97-103）；recovery 探测失败则恢复入口消失（UnlockScreen.tsx:16-30，有意降级） | —                              | SyncSettingsSection 加第三态 "status unknown + retry"             |

**评估后确认无实际后果的项**（kdf benchmark 丢弃、`unwrap_or_default` 于纯字符串 NativeResponse、`entries_to_sync` 回退不可达但属未来调用方陷阱——建议加 debug_assert、migrate 一次性路径有 .bak 兜底等）见审计过程记录，不占修复排期；其中 `sync/mod.rs:136` 值得加防御性注释/debug_assert，防止未来调用方传入不完整 secrets map 时空密码经 LWW 覆盖真实密码。

---

## 三、代码质量审计（0 P0 / 0 P1 / 2 P2 / 5 P3）— 结论 APPROVE

静态验证：`cargo clippy --workspace --all-targets` 0 警告、`pnpm tsc --noEmit` 0 错误、243 Rust 测试 + 237 前端测试全过。分层架构方向干净；`VaultSession` lease/generation 模型、`WindowGate` 测试缝、merge.rs seeded property tests 均为亮点；生产代码 `.unwrap()` 仅 2 处且均有构造性保证。

### [CQ-P2a] 前端三个 Context 重复实现劣化版 `formatError`，序列化 VaultError 会以原始 JSON 展示给用户

AuthContext.tsx:6-12、VaultContext.tsx:294-302、SettingsContext.tsx:8-12 三份逐字相同的本地 `formatError`（`JSON.stringify` 兜底），而 `src/utils/errorMessage.ts:49-66` 已有更强版本（递归提取 message、处理 RateLimited retry 提示、识别 serde 外部标签格式）。后果：连续 5 次解锁失败触发的 60s 锁定提示显示为 `{"RateLimited":{"retry_after_secs":60}}` 而非友好文案（UnlockScreen.tsx:56-68 直接渲染）。**修复**：删除三份本地实现，统一 `errorMessage(error, '...fallback')`（机械替换；顺带消掉死代码 DC-F4 的冗余 re-export）。

### [CQ-P2b] `import_vault`（222 行）/`export_vault`（142 行）4 倍超出项目"函数 ≤50 行"规范

backup.rs:222-413。各阶段本身质量很高（预加密在事务外、失败回滚干净、zeroize 齐全），但单函数承载 envelope 校验→KDF floor→解密→解析→行准备→密封→事务全链路——恰是 import 安全校验（X6 floor、资源上限）所在、最需要可读性的代码。**修复**：按既有阶段注释拆为 `validate_backup_envelope` / `decrypt_backup_payload` / `prepare_import_rows` + 事务闭包，纯机械移动，现有测试可验证等价性。

### P3 级发现（摘要）

| #      | 发现                                                                                                                                                                                                                                                                                                                                                                                                | 位置                                                            |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| CQ-P3a | `revoke_extension_access` 在两处 adapter 重复且绕过 application 层（唯二不委托 service 的命令）                                                                                                                                                                                                                                                                                                     | commands.rs:205-209 + dispatcher.rs:51-55                       |
| CQ-P3b | `enforce_pair_rate_limit` check-then-act 竞态（两个独立 Mutex + 释放后计算），并发下 10/分钟限流被放宽                                                                                                                                                                                                                                                                                              | protocol.rs:121-160；合并为单 `Mutex<(u32, Option<Instant>)>`   |
| CQ-P3c | sync 模块把 JSON 序列化失败误映射为 `VaultError::EncryptionFailed`，误导排查                                                                                                                                                                                                                                                                                                                        | state_io.rs:591-594；改 InternalError                           |
| CQ-P3d | EntryScreen 单组件 752 行六类职责（表单/secret 拉取/TOTP 三态/tags 编辑器/生成器/删除确认）                                                                                                                                                                                                                                                                                                         | EntryScreen.tsx:26-750；优先拆 `TotpSecretField` + `TagsEditor` |
| CQ-P3e | 测试缺口：(a) macOS Keychain 双模式（keychain/macos.rs，456 行。**【二次审查修正：其 `macos/tests.rs`（180 行、7 个测试）实际存在，覆盖错误码映射/模式前缀往返/未知标签 fail-closed/双回退三态——"0 直接测试"为事实错误**；残余缺口仅为真实 SecItem I/O 无自动化覆盖）；(b) fuse.js 搜索配置桌面/扩展双端各一份无一致性测试（popup.js:19-29 vs search.ts:4-14，可仿 password-strength.test.js 先例） | —                                                               |

低优先级备注：类型导入路径不一致（protocol.rs:53 等）、`sync_status` 双重取库、错误措辞 "join error" vs "task join error"、NativeResponse 三字段冗余、tags 比较用 `JSON.stringify`（顺序敏感误判脏）、参数遮蔽（EntryScreen.tsx:240-246）、冗余 debug_assert、HTTP worker 池 8 并发解锁理论 ~512MB Argon2 内存峰值、扩展三文件（popup 1484 行/content 1377 行/background 815 行）超 800 行。

---

## 四、静态检查（全部实跑，未使用任何 --fix）

| 工具                            | 范围                                           |  错误  |       警告       | 结论            |
| ------------------------------- | ---------------------------------------------- | :----: | :--------------: | --------------- |
| cargo check --all-targets       | src-tauri workspace                            |   0    |        0         | ✅              |
| cargo clippy --all-targets      | src-tauri workspace（clean -p 后强制全新检查） |   0    |        0         | ✅              |
| cargo fmt --check               | src-tauri workspace                            |   0    |  0（无 drift）   | ✅              |
| cargo check/clippy/fmt          | native-host（独立 lockfile）                   |   0    |        0         | ✅              |
| tsc --noEmit                    | tsconfig.json + tsconfig.test.json             |   0    |        0         | ✅              |
| tsc -p tsconfig.node.json       | vite.config.ts                                 | **1**  |        0         | ❌              |
| eslint src/                     | 前端                                           |   0    |        0         | ✅              |
| node --check                    | 26 个扩展 JS                                   |   0    |        0         | ✅              |
| jq empty                        | 4 个 JSON 配置                                 |   0    |        0         | ✅              |
| cargo audit（本地缓存库 09-19） | src-tauri（633 deps）                          | 0 漏洞 | 10 informational | ✅（见 SEC-L6） |
| cargo audit                     | native-host（12 deps）                         |   0    |        0         | ✅              |

**[ST-1] 唯一编译级错误**：`vite.config.ts:26` — `error TS2578: Unused '@ts-expect-error' directive.`（项目已装 `@types/node`，`process` 有类型，抑制指令失效）。项目 `typecheck`/`build` 脚本均不检查 `tsconfig.node.json`，故现有流水线永远看不到它。**修复**：删除该行 `@ts-expect-error` 注释；建议把 `tsc -p tsconfig.node.json --noEmit` 加进 `typecheck` 脚本。

**[ST-2] cargo audit 10 条 informational**：8 unmaintained（bincode 1.3.3、fxhash、proc-macro-error、unic-\* ×5）+ 2 unsound（glib 0.18.5、rand 0.7.3，均传递依赖），无实际漏洞；bincode 忽略项在 deny.toml:16 备案。

**环境异常记录**（影响执行方式不影响结论）：并行审计会话争用导致 pnpm 层挂死（回退直跑 `node_modules/.bin/` 二进制，结果等价）；github.com 不可达导致 advisory-db 拉取失败（用 09-19 本地缓存库，存在时效盲区，**建议网络恢复后重跑**）。

---

## 五、死代码审计（0 P1 / 14 P2 / 9 组 P3，可回收 ≈110 行 + 3 个依赖条目）

整体卫生优秀：无任何 `allow(dead_code)` 压制点、npm 依赖全在用（knip 实跑）、39 个 Tauri 命令与 26 条 HTTP 路由注册一致。死代码均为历史重构（useApp facade 移除、扩展 UI 精简、X4 修复）遗留的小颗粒。

### P2 — 确认无用（14 项）

**Rust 死函数（5，~40 行，全工作区唯一命中即定义行，已排除宏/serde/字符串路由隐式引用）**

- `delete_group_in_txn` — vault_store.rs:110
- `ensure_db_dir` — paths.rs:42
- `get_schema_version` / `set_schema_version` — integrity.rs:42 / :58
- `is_digest_version_known` — vault_header.rs:132

**未用依赖（3）**：domain crate 的 `serde_json` + `base64`（仅注释命中）；application crate 的 `uuid`（生成只在 domain）——回收可缩减编译图（uuid v4 连带 rand 链）。

**前端死导出（4，~16 行）**：`isVaultUnlocked`（api/vault.ts:27）、`getEntryCount`（:88）、`DownloadIcon`（Icons.tsx:128，updater 接管后遗留）、`formatError` re-export（SettingsContext.tsx:241——CQ-P2a 修复时顺带）。

**CSS 孤儿类（3，~14 行）**：`.field-group`、`.field-label`（screens.css:116/120）、`.length-value`（screens.css:209，X4 修复遗留）。

**扩展死分支（~40 行）**：background.js 7 个死 case + 6 个死函数（INIT_VAULT:640、CREATE/UPDATE/DELETE_GROUP、EXPORT/IMPORT_VAULT、CONNECT:715 及对应包装函数——v0.3.0 扩展导入导出 UI 移除后的遗留；无 externally_connectable，字面量枚举即完整调用面）；content.js:1289 死 case `SHOW_POPUP`。

### P3 — 疑似待确认（9 组，摘要）

19 个可降级 `pub(crate)` 的过宽导出（其中 `delete_entry`/`count_groups` 仅测试调用）；`get_entry_count` 后端整链路（前端/扩展零调用，仅集成测试消费——对外协议 method，删除属产品决策）；前端冗余双导出（EntryScreen default、ConfirmationModal named、searchEntries 别名）；三个 Context 对象导出无人 import；死类型（`EncryptedData`、`VaultState` @ types/index.ts）；`buildFuseIndex` 仅基准测试用；零引用脚本：`scripts/regenerate-icons.py`（复核确认零引用，可删）、~~`scripts/windows-native-smoke.py`~~（**【二次审查修正：此项为误杀——实际文件名是 `scripts/windows-native-host-smoke.py`，正被 `.github/workflows/quality.yml:179` 与 `release.yml:232` 调用，删除会弄坏 Windows 构建，已从清理清单移除】**）；6 条后端路由仅桌面前端消费（扩展侧调用链已死，路由本身活）；根目录遗留物（CLAUDE.md 旧版指令、历史审计快照、`.conductor/` 空目录——只标注不判死；`latest.json` 是活 updater feed）。

---

## 六、综合修复路线图（跨维度整合，按优先级）

### 第一批：安全边界 + 唯一 P1（建议下一版本前完成）

1. **SF-P1** 扩展空密码假成功三处消费点（autofill 成功提示/复制无反应/快捷键零反馈）
2. **SEC-M1** `complete_unlock` 纳入 `exclusive_window` + 新增解锁-vs-窗口交错测试
3. **SEC-M2** fs capability 收紧为 dialog-scoped 单文件授权（成本最低、爆炸半径收敛最大）
4. **SEC-M3** sync 链路 `SyncEntry` 敏感字段 `Zeroizing` 化

### 第二批：静默失败 P2 + 质量 P2（一个小版本内）

5. **SF-P2a** 扩展剪贴板清除失败重试+通知（对齐桌面端 M11）
6. **SF-P2b** React ErrorBoundary（含"锁定并重启"fallback）
7. **SF-P2c** `lock()` 失败可见提示
8. **SF-P2d** chmod 失败拒绝落盘 + 日志
9. **CQ-P2a** `formatError` 统一到 `errorMessage()`（顺带消 DC-F4）——直接修复用户可见的原始 JSON 错误
10. **CQ-P2b** `import_vault` 按阶段拆函数

### 第三批：Low 加固 + P3 打磨（按机会排期）

- 安全 Low：SEC-L1（token 白名单）→ SEC-L3（OAuth 循环丢弃）→ SEC-L4（恢复密钥 Zeroizing）→ SEC-L2（sync 配置加密）→ SEC-L5（自动锁远程语义，先文档后实现）
- 静默失败 P3：SF-P3a/b/c/d/e/f（多为加日志/补分支的小改动，可合并一个 chore PR）
- 质量 P3：CQ-P3b（pair 限流单锁化）→ CQ-P3a（revoke 上移 application）→ CQ-P3c/d
- 加固顺手项：macos.rs:340-351 gate 失败分支 `raw.zeroize()`；`validate_config` 拒绝 server_url 内嵌 userinfo；docs 旧 minisign 公钥标 DEPRECATED

### 清理批：死代码回收（一个独立 chore PR，≈110 行 + 3 依赖）

- 14 项 P2 全量 + ST-1（删 vite.config.ts:26 失效指令并把 tsconfig.node.json 纳入 typecheck）
- P3 组人工确认后追加（get_entry_count 链路、孤儿脚本、双导出等，再 ≈80-100 行）

### 测试补强（随各批附带）

- 解锁-vs-窗口交错测试（随 SEC-M1）
- macOS CI keychain 真机冒烟（`#[cfg(target_os)]`-gated，随 SEC/M 系列）
- fuse 配置双端一致性测试（仿 password-strength.test.js 先例）
- 网络恢复后重跑 `cargo audit`（在线拉库）+ `pnpm audit --prod` 收尾

---

## 附录：审计方法与声明

- 五路子代理均为只读审计（未修改任何源码文件；工具运行产生的构建缓存属可接受副产物；未使用任何 `--fix`）。
- 主代理对头部发现（SF-P1 allSettled 回退、SEC-M1 unlock 路径无窗口锁、SEC-M2 `$HOME/**`、CQ-P2a 三份 formatError、ST-1 TS2578）逐条重读源码交叉验证，全部属实。
- 严重度口径：安全用 Critical/High/Medium/Low（CVVS 思路），其余维度用 P0-P3；"待确认"标注表示时序/前提狭窄、建议修复但非确定性可利用。
- 依赖扫描基于 2026-09-19 本地 advisory-db 缓存（网络不可达），存在时效盲区，已在路线图标注复核动作。
- 对照基线：AGENTS.md 记录的 v1.1.8 测试基线（243 Rust workspace + 19 native-host + 237 前端）本次全部复跑通过（native-host 测试未在本次复跑范围，仅静态检查）。

---

## 七、二次独立审查结论（2026-10-04）

**方法**：静态维度由主代理本人复跑全部工具；安全 / 静默失败 / 代码质量 / 死代码四个维度由 4 个全新验证代理在**不信任原结论**的前提下逐条对照代码复核（裁决：✅ 确认 / ⚠️ 成立但需修正 / ❌ 不成立）。全部复核只读。

### 7.1 静态检查 — ✅ 全部确认（主代理独立复跑）

clippy（workspace + native-host）0、fmt 无 drift、tsc 主/测试配置 0、tsc node 配置 1（TS2578）、eslint 0——与第四节逐项一致。**补充利好**：安全验证代理以 **2026-10-03 最新 advisory-db** 复跑 cargo audit——**仍 0 漏洞**，第四节"时效盲区"警示解除，路线图中的"网络恢复后重跑"动作可关闭。

### 7.2 安全 — 可信度：高

| 发现      | 裁决      | 修正要点                                                                                                                                                                                                                                                    |
| --------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-M1    | ⚠️        | 三条事实主张全部实证（unlock 无窗口锁、digest 预校验拦不住、无交错测试）；**两处重要修正**见 7.2.1                                                                                                                                                          |
| SEC-M2    | ⚠️        | 授权事实实证；但 `addScopedPath` **在已装的 plugin-fs 2.5.0 中不存在**，原修复方案不可落地；且文件 IO 实际在前端共**三处**（原审计漏了第三处：`SecuritySettingsSection.tsx:237-241` 恢复密钥明文写盘）。修订方案见第八节                                    |
| SEC-M3    | ⚠️ 小修正 | 逃逸点与传播链实证；JSON 序列化缓冲其实**已被 zeroize**（container.rs:170-172/219-222/260-263），靶点确认为结构体 String 字段及克隆；验证代理确认 zeroize 1.8.2 的 serde feature 已启用，并给出**更优修复路线**（derive(Zeroize, ZeroizeOnDrop)，见第八节） |
| SEC-L1~L6 | ✅ ×6     | 全部实证，定级恰当；L6 经 10-03 新库复跑结论强化                                                                                                                                                                                                            |

**7.2.1 SEC-M1 修复方案修正（照原方案实现会出问题）**：

1. **死锁陷阱**：原方案行范围 "shared.rs:180-218" 含糊覆盖了 `complete_unlock_if`（内层）。若实现在内层：`recover_vault` 在**已持窗口**状态下调用它（password.rs:244-247 → :281）＝ 同线程重入非重入 `std::sync::Mutex` ＝ **必然自死锁**。实现必须只改 `complete_unlock` 外层包装（vault.rs:234 与 credentials.rs:157 两个调用方均未持冲突锁，无死锁）。
2. **完整性缺口**：只在发布点取窗并不完全修复——竞争 unlock 的密钥在窗口**之前**从旧 verification_data 推导，窗口释放（rekey 已提交、verification 已换新）后它仍会发布**过期旧密钥**，得到"已解锁但读写全坏"的会话（fail-closed 但状态错误）。增强方案三选一：① 取窗后重验 verification_data 与推导所用 salt/params 一致，不一致拒绝发布；② 窗口开启时 bump `lock_epoch`（顺序必须在窗口自身捕获 epoch **之前**），unlock 侧以 epoch 谓词校验——无需持窗跑 Argon2；③ unlock 全程入窗（窗口以秒计，代价可接受）。
3. **覆盖面**：发现第二发布路径 `unlock_biometric`（credentials.rs:157，同样经 `complete_unlock`）——包装层方案自动覆盖，但测试须覆盖两条路径。
4. **机制表述修正**：插入写不是"被静默丢弃"，而是成为**旧密钥孤儿行**（rekey 只遍历快照 id，新行幸存但密文是旧 enc key；digest 全表重算自洽、完整性校验不报警，直到下次读取 AEAD 解密失败才暴露）——比"丢弃"更隐蔽。

旧 4 High 核验表：H1/H2 证据链经二次实证全部成立。

### 7.3 静默失败 — 可信度：高

| 发现         | 裁决  | 修正要点                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------ | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SF-P1        | ✅    | 四子项全部实证（content.js:337-361 无空串短路、确会弹成功绿条）；补充：快捷键路径**连 entry null 检查都没有**（比原描述更糟）；popup autofill 路径有空密码门控、overlay 路径走 throw 不受影响——原审计影响面判断准确。P1 定级成立                                                                                                                                                                        |
| SF-P2a       | ⚠️    | 后果成立（清除从不发生且无通知）但机理修正：首个失败调用是 `readText`（manifest 只有 clipboardWrite、**无 clipboardRead 权限**）而非 writeText；内层空 catch 吞掉后，外层带用户提示的 catch 永不触发；"永久残留"略夸大（用户下次复制会覆盖，准确表述是"无限期残留直至被覆盖"）。修复需权限层面考量：content script 上下文缺 clipboardRead，最小修复＝失败通知 + console.warn，根治＝复制移入 background |
| SF-P2b       | ✅    | 全仓确认无任何 error boundary                                                                                                                                                                                                                                                                                                                                                                           |
| SF-P2c       | ✅    | 确认；补充这是 A4 文档化设计取舍（防 UI 停留在已解锁界面）+ 后端自动锁线程兜底（≤60 分钟），泄露窗口有界——实际处于 P2/P3 边界                                                                                                                                                                                                                                                                           |
| SF-P2d       | ✅    | 确认；修正两点：① lib.rs:123 那份文件是 `native-host.json`（存扩展 ID，**非凭据**，并入"凭据文件"有拔高）；② FileSecretStore 裸 base64 暴露面实际集中在 **Linux**（macOS 走 Keychain、Windows 全 DPAPI 保护）。更优修复：`OpenOptions::new().mode(0o600)` 创建即收紧，消除 0644 窗口                                                                                                                    |
| SF-P3a       | ⚠️    | 代码确认；后果链高估——settings 持续损坏时解锁同样 fail-closed（shared.rs:172/204），"1→10 分钟"仅在"启动瞬时失败、解锁时已恢复"窄窗口可达                                                                                                                                                                                                                                                               |
| SF-P3b~f     | ✅ ×5 | 全部实证（P3e 限定：浏览器回退路径，桌面 dialog 路径已有 try/catch 处理）                                                                                                                                                                                                                                                                                                                               |
| "无后果"分类 | ✅    | `entries_to_sync` 回退不可达性抽验属实                                                                                                                                                                                                                                                                                                                                                                  |

### 7.4 代码质量 — 可信度：中高

| 发现                      | 裁决            | 修正要点                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CQ-P2a                    | ✅              | **端到端实证**：Rust `Err(VaultError)` 经裸 invoke reject 到达前端为 `{"RateLimited":{"retry_after_secs":60}}` 对象 → 本地 formatError 落 JSON.stringify 分支 → UnlockScreen 文本插值——用户确定看到原始 JSON（不是 [object Object]）。**比原报告更严重**：单元变体（VaultLocked、BiometricUnavailable 等）以字符串到达时被原样显示为枚举名；`AuthContext.test.tsx:77` 的断言**钉死了坏行为**，修复须同步更新该测试 |
| CQ-P2b                    | ✅              | 实测 223/143 行；拆分**非纯机械**——`lease` 跨阶段使用需作参数传递、`import_password`/`import_key` 的 Zeroizing 生命周期随拆分改变清零时机                                                                                                                                                                                                                                                                          |
| CQ-P3a                    | ⚠️              | 重复与绕过属实；"唯二"**不实**——dispatcher 的 `pair`/`pair_confirm`/`handshake` 同样不经 service 层（准确表述：revoke 是唯一在两个适配面重复且绕过服务层的命令）                                                                                                                                                                                                                                                   |
| CQ-P3b                    | ✅              | 竞态实证（双独立 Mutex + 释放后计算 + 8 worker 真并发）；单 Mutex 修复与现有死锁顾虑完全兼容                                                                                                                                                                                                                                                                                                                       |
| CQ-P3c                    | ✅              | 两处引用精确；影响低于原表述（sync 命令不在 HTTP dispatcher 表中，错误到不了扩展端；桌面端 errorMessage 会显示原始字符串）                                                                                                                                                                                                                                                                                         |
| CQ-P3d                    | ✅              | 752 行确认；`detectChanges` 提取时需补 `totpChanged` 参数（313 行用的是闭包变量而非参数）                                                                                                                                                                                                                                                                                                                          |
| CQ-P3e                    | (a) ❌ / (b) ✅ | **(a) 推翻**：`keychain/macos/tests.rs` 存在（180 行 7 个测试）——"0 直接测试"为事实错误，残余缺口仅为真实 SecItem I/O；(b) 完全确认（配置当前逐字段一致、无 parity 测试、password-strength.test.js 先例可照搬）                                                                                                                                                                                                    |
| ".unwrap 仅 2 处"背景声明 | ✅              | 恰 2 处（integrity.rs:173、kdf.rs:69）且构造性保证成立；裸 .expect 为零                                                                                                                                                                                                                                                                                                                                            |

### 7.5 死代码 — 可信度：高（一处关键误杀）

- **14 项 P2 复核结果：1-13 全部 ✅ 确认可删**（独立方法：宽/严双口径 grep + Tauri 命令注册表逐条核对 + 路由字符串对照 + 动态类名/动态 type 排除）；第 14 项 ✅ 且有补充（见下）。
- **❌ 关键误杀（已在第五节原文就地修正）**：`scripts/windows-native-host-smoke.py`（原报告误写为 windows-native-smoke.py）**正被 CI 调用**（`.github/workflows/quality.yml:179`、`release.yml:232`，Windows 构建冒烟）——按原报告删除会直接弄坏 Windows 构建。`regenerate-icons.py` 则确认零引用可删。
- **复核新发现（高置信度，原审计遗漏）**：① 第 8 个死 case `UPDATE_SETTINGS`（background.js:685）及其函数 `updateSettings`；② `delete_entry_in_txn`（vault_store.rs:91）与 `is_integrity_required`（vault_header.rs:127）**仅测试使用**（软删除改造后生产路径不用硬删除；后者文档注释已过时）——删除需同步改各自测试；③ `SCHEMA_VERSION_KEY` 常量与 get/set_schema_version 是**绑定死亡的整块机制**，应整块回收；④ background.js:694 `AUTOFILL` case 不可达但代码注释已声明刻意保留（严格清单应计为 8+1 个死 case）。
- `get_entry_count` "仅测试消费"的限定表述经复核准确（删除属产品决策）。

### 7.6 二次审查净结论

原审计**总体可信**（四维度可信度：安全 高 / 静默失败 高 / 质量 中高 / 死代码 高），无虚构或夸大安全的发现，严重度定级经复核全部恰当。需要修正的问题集中在事实细节与修复方案层：

1. ❌ 事实错误 1 处：keychain/macos.rs 并非"0 直接测试"（tests.rs 有 7 个）；
2. ❌ 关键误杀 1 处：`windows-native-host-smoke.py` 被 CI 引用，不可删；
3. ⚠️ 修复方案不可直接落地 2 处：SEC-M1（内层实现会自死锁 + 发布点取窗不完整，须按 7.2.1 修正）、SEC-M2（`addScopedPath` 在 plugin-fs 2.5.0 不存在，且漏了第三处 IO 调用点）；
4. ⚠️ 机理表述修正若干：SEC-M1 后果实为"旧密钥孤儿行"；SF-P2a 首个失败是 readText（缺 clipboardRead 权限）；SF-P2d 暴露面集中在 Linux 且 lib.rs:123 非凭据；SF-P3a 后果仅在瞬时故障窗口可达；
5. ✅ 利好 2 项：cargo audit 以 10-03 新库复跑仍 0 漏洞（盲区解除）；CQ-P2a 经端到端验证成立且影响面比原报告更大（单元变体枚举名也裸奔 + 测试钉死坏行为）。

---

## 八、修订后建议处理方案（取代第六节）

### 第一批：安全 + 唯一 P1（下一版本前完成）

1. **SF-P1** 扩展空密码假成功（按原方案成立）：`getEntry` secret rejected 时上抛；快捷键/右键路径空密码 `notifyTab` 错误提示（快捷键路径同时补 entry null 检查）；popup 复制按钮空密码 toast。
2. **SEC-M1（按 7.2.1 修正方案）**：在 `complete_unlock` **外层包装**取 `exclusive_window`（严禁实现在 `complete_unlock_if` 内层——recover_vault 重入会死锁）+ 取窗后重验 verification 一致性或 epoch-bump 方案；覆盖 `unlock_biometric` 路径；补解锁-vs-窗口交错测试（密码与生物识别两条）。
3. **SEC-M2（改走 IO 下沉路线）**：三处前端文件 IO（ImportExport 导出/导入 + **SecuritySettingsSection 恢复密钥写盘**）移入 Rust 命令（tauri-plugin-dialog Rust API + `std::fs` + 路径校验），随后从 `capabilities/default.json` 删除三个 fs 显式授权——信任边界更优，且备份明文本就产自 Rust。（若不愿动架构：备选 Rust 侧 `app.fs_scope().allow_file(path)` 运行时单文件放行；`addScopedPath` 在当前 plugin-fs 2.5.0 不可用。）
4. **SEC-M3（改走 derive 路线）**：对 `SyncEntry`/`SyncGroup`/`SyncSnapshot`/`MergedSnapshot`/`SyncSecrets` derive `(Zeroize, ZeroizeOnDrop)`（serde/PartialEq 语义保留，所有克隆随 drop 清零，比逐字段 Zeroizing 改动更小更完整）；`decrypt_inner` 改消费式 `String::from_utf8(plain)`（去掉 clone）并对 from_utf8 错误分支 `e.into_bytes().zeroize()`。注意纪律：Zeroizing 的 Debug 会转发内值，勿 debug-log 快照。

### 第二批：静默失败 P2 + 质量 P2（一个小版本内）

5. **SF-P2a（按修正机理）**：最小修复＝清除失败 `console.warn` + `showNotification`（"剪贴板自动清除失败，请手动清除"）；根治＝复制移入 background/offscreen（需评估 clipboardRead 权限声明，单独评估再做）。
6. **SF-P2b** React ErrorBoundary（fallback 带"锁定并重启"按钮）。
7. **SF-P2c** lock 失败加可见 toast（P2/P3 边界，改动极小）。
8. **SF-P2d（按修正方案）**：`OpenOptions::new().write(true).create_new(true).mode(0o600)` 创建即收紧（消除 0644 窗口，主要惠及 Linux）；保留的 chmod 失败路径补 `tracing::warn`。
9. **CQ-P2a** formatError 统一到 `errorMessage()`（三份全删 + SettingsContext re-export）——**必须同步更新 AuthContext.test.tsx:77 断言**；修复收益扩大到单元变体（不再显示 "VaultLocked" 枚举名）。
10. **CQ-P2b** `import_vault` 六段拆分（校验/解码/KDF/解密/准备记录/事务），注意 lease 参数传递与 Zeroizing 生命周期，测试验证等价。

### 第三批：Low 加固 + P3 打磨（按机会排期）

- 安全 Low：SEC-L1（native-host token 64-hex 白名单，一行）→ SEC-L3（OAuth 循环丢弃无效请求）→ SEC-L4（恢复密钥 Zeroizing）→ SEC-L2（sync 配置加密）→ SEC-L5（自动锁远程语义，先文档后实现）。
- 静默失败 P3：SF-P3a/b/c/d/e/f（多为加日志/补分支，可合并一个 chore PR）。
- 质量 P3：CQ-P3b（pair 限流单 Mutex 化）→ CQ-P3a（revoke 上移 application；顺带评估 pair/pair_confirm 是否同样上移）→ CQ-P3c（错误映射改 InternalError）→ CQ-P3d（EntryScreen 拆分）。
- 加固顺手项：macos.rs:340-351 gate 失败分支 `raw.zeroize()`；`validate_config` 拒绝 server_url 内嵌 userinfo；docs 旧 minisign 公钥标 DEPRECATED。

### 清理批：死代码回收（独立 chore PR，修订后清单）

- **可删**：原 14 项 P2（扣回 windows-native-host-smoke.py——它不在 14 项内，属 P3 G7 误报）+ 复核新发现（UPDATE_SETTINGS case + updateSettings、`delete_entry_in_txn` 及其测试调用、`is_integrity_required` 及其测试、SCHEMA_VERSION_KEY 整块机制）。
- **不可删**：`windows-native-host-smoke.py`（CI 在用）；`get_entry_count` 链路待产品决策。
- ST-1：删 vite.config.ts:26 失效指令 + 把 `tsc -p tsconfig.node.json --noEmit` 纳入 typecheck 脚本。

### 测试补强（随各批附带）

- 解锁-vs-窗口交错测试 ×2（密码路径 + 生物识别路径，随 SEC-M1）。
- keychain 残余缺口 = 真实 SecItem I/O 冒烟（macOS CI runner，标注区分于已有的 7 个单元测试）。
- fuse 配置双端 parity 测试（照搬 password-strength.test.js 模式）。
- ~~网络恢复后重跑 cargo audit~~——已由二次审查以 2026-10-03 新库完成，0 漏洞，动作关闭。
