# v1.2.0 修复实施方案（PR-3 Low 加固 + PR-4 清理批）· R3

**日期**：2026-10-05 · **基线**：`main @ 9aa5f86`（v1.1.9）· **目标版本**：v1.2.0（minor：含 SEC-L5 行为变化与多项加固）
**上游**：`code_audit_fix_plan_2026-10-04.md` 第三/四批 + 二次审查修正 + v1.1.9 复审遗留项
**修订记录**：R2 按 plan-reviewer 意见修订（2 P1 + 3 P2 + 5 P3：SEC-L2 补 re-seal 轮换、WP-B 移 Wave 2、touch 亮线规则、remote 字段入 SessionInner、ST-1 配套、行号校正）；R3 终审 PASS（rewrap 双读复用条款 + legacy 夹具变体 + 20 处计数 + :433 笔误 + WP-C 域补 search.ts）
**流程**：沿 v1.1.9 同一管线（本方案 → plan-reviewer 至 PASS → ds-worker 分波 → 主代理复审 + code-reviewer 独立审查 → 全量门禁 → 发版）

## 0. 范围与决策

**纳入**：SEC-L1/L2/L3/L4/L5、SF-P3a-f 组、CQ-P3a/b/c/d、三个顺手加固项、死代码清理批（修订后清单）、ST-1、依赖回收、keychain CI 冒烟、fuse parity 测试、popup autofill 反馈 rider。

**不纳入（含理由）**：

- ~~export_recovery_key 命令~~——恢复密钥一次性生成不落盘（credentials.rs:204-215 每次 Enable 生成新 key，仅 wrap blob 落盘，不可重放），"事后导出"必须重存密钥、违背一次性语义；重新 Enable 即可再生，v1.1.9 Save-to-file 已覆盖落盘。
- ~~剪贴板清除根治（offscreen 移交）~~——需 manifest 新增权限，触发商店审核面变化，属产品决策；v1.1.9 的"失败通知一次"已消除静默性。再延期并记录。
- ~~CQ-P3a 的 pair/pair_confirm 上移~~——协议握手处理器留在 adapter 可辩护（纯协议应答+限流内聚），本版只上移 revoke。
- ~~SEC-L4 的前端置空~~——JS 无法可靠清零字符串（v1.1.9 复审已确认局限），Rust 侧 Zeroizing 已覆盖可控半段；在上游总案中标注"前端侧不实施（平台局限）"。
- SEC-L6 依赖跟踪（bincode 迁移 deny.toml 备案 2026-12-31 到期前另行处理）。

## 1. 工作包总览（R2 波次重排）

| WP   | 内容                                                                     | 文件域                                                                                                                                                                                                            | 波次                                                                                                       |
| ---- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| WP-A | SEC-L1/L3/L4/L5 + CQ-P3a/b + macos zeroize + SF-P3a/b/c                  | native-host/src/main.rs；application（state.rs、session.rs、service/* 的 touch 站点、baidu_oauth.rs、keychain/macos.rs）；src/commands.rs、lib.rs、native_messaging/{dispatcher,protocol}.rs、domain/constants.rs | Wave 1                                                                                                     |
| WP-C | CQ-P3d EntryScreen 拆分 + SF-P3d/e/f + popup autofill 反馈 + fuse parity | src/screens/**、src/components/**（新组件）、**src/utils/search.ts（仅加 export，R3）**、extensions/chrome/src/{background.js,popup/popup.js}、新测试                                                             | Wave 1                                                                                                     |
| WP-B | SEC-L2（含 re-seal 轮换）+ CQ-P3c + validate_config userinfo             | **{state_io.rs, engine.rs, security/shared.rs, sync/tests_engine.rs}**（R2：load 签名级联 engine.rs 四处调用方 :284/:296-297/:446-447；reseal 集成落 shared.rs）                                                  | **Wave 2**（WP-A 先行合入——A 改 engine.rs touch 站点与 shared.rs 无冲突后 B 再动签名；串行避免同文件并发） |
| WP-D | 死代码清理 + ST-1 + 依赖回收                                             | 全仓死代码点（与 B 域无交集：vault_store/paths/integrity/vault_header/Cargo.toml/前端/扩展）                                                                                                                      | Wave 2                                                                                                     |
| WP-E | keychain 真实 SecItem CI 冒烟                                            | infrastructure 新测试文件 + quality.yml（quality-native-host job）                                                                                                                                                | Wave 2                                                                                                     |
| WP-F | 发版（版本 1.2.0、CHANGELOG、SEC-L5 文案、tag/CI）                       | 10 版本文件 + README/AGENTS                                                                                                                                                                                       | Wave 3（复审后）                                                                                           |

Wave 1：A 与 C 文件域不相交（A 全 Rust+native-host；C 全前端+扩展）。Wave 2：B/D/E 互不相交（B 的四个文件 D/E 均不触碰）。

---

## 2. WP-A：Rust 安全与适配层

### 2.1 SEC-L5 自动锁远程活动宽限（行为变化）

**设计**（R2 修订：字段位置与 touch 规则）：

1. `domain/constants.rs` 新增 `pub const REMOTE_ACTIVITY_GRACE_SECS: u64 = 120;`
2. **`last_remote_activity` 放 `SessionInner::Unlocked` 变体内**（与 `last_activity: Mutex<Instant>` 同生命周期——锁定时随 variant 替换自然清除，无陈旧残影）；`SessionLease` 提供 `touch_remote_activity()`；`AppState` 委托方法供命令层用。
3. **deadline 计算**：`session.rs` 的 `auto_lock_deadline`/`should_auto_lock`（:200-210/:216-229）扩为 `alive while now < max(last_activity + timeout, last_remote + REMOTE_ACTIVITY_GRACE_SECS)`；lib.rs:39-74 自动锁线程轮询结构不变（5s 上限轮询已保证 120s 宽限被及时判定）。
4. **touch 站点亮线规则**（R2：全量清单，替换 v1 的 grep 口径）：
   - **`lease.touch_activity()` 全部 20 处生产站点（backup 1 + entries 7 + groups 4 + credentials 4 + settings 2 + engine 1 + totp 1） → 改 `lease.touch_remote_activity()`**（entries/groups/settings/totp/backup/credentials/engine 各 service；grep 模式 `lease.touch_activity()`）。理由：服务层同时服务桌面 IPC 与 HTTP，无法区分来源；亮线规则可机械验证。在席桌面用户由 UI 心跳维持全窗口（App.tsx:39-66，pointermove/pointerdown/keydown，节流 max(5s, min(60s, timeout/2))）。
   - **`state.touch_activity()` 4 处保留 local 并各加注释**：shared.rs:252（complete_unlock Step 9——解锁即用户在场）、password.rs:140（改密 republish，桌面命令）、engine.rs:134（sync 窗口 republish，sync 为 Tauri-only）、vault.rs:190（create_vault）。四处均为桌面专属"用户在场"路径。
   - **DoD 判据**：`grep -rn 'touch_activity()' crates/application/src` 逐处核对——要么已转 remote、要么带保留注释。
5. **测试**：a) A1 既有测试（commands.rs:600-636）不回归（local touch 推进全窗口）；b) `remote_touch_grants_only_grace`；c) `service_op_touches_remote_not_local`；d) `max_semantics`（remote 晚于 local 取 remote 截止，反之取 local；锁定清零 remote 残影）。

**语义说明（文档/QA 用）**：解锁重置全窗口；桌面输入心跳维持全窗口；任何显式金库操作（含桌面）只给 120s 宽限——解锁后仅用托盘菜单无键鼠输入者，将在 max(解锁+auto_lock, 最后操作+120s) 锁定，符合"无人值守即锁"直觉。

### 2.2 SEC-L1 native-host token 白名单

`native-host/src/main.rs`：`is_valid_command` 旁新增 `fn is_valid_token(t: &str) -> bool { t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) }`（auth.rs:9-20 token 恒 64 hex，已核实）；`extract_auth_header`（:405-410）不匹配即拒绝转发（与命令白名单同错误路径）。单测：合法/CRLF/长度/非 hex 四分支。

### 2.3 SEC-L3 OAuth 回调循环丢弃

`baidu_oauth.rs wait_for_callback`（:318-339）：首个 `Ok(Some(request))` 即返回 → 改**循环**：无 `code` 或 state 回显不匹配（:220-225 校验保留）→ respond 错误页 → continue，至有效回调或总超时。测试：无效请求打不空 pending 会话。

### 2.4 SEC-L4 恢复密钥返回值 Zeroizing

`recovery_file.rs`：`EnableRecoveryResult.key: String` → `Zeroizing<String>`（serde feature 四 crate 已启用，IPC 透明，前端零改动）；写盘分支 `key.as_str()`。更新受影响测试。

### 2.5 CQ-P3a revoke 上移 application

application `service/` 新增 `pub fn revoke_extension_access(state) -> Result<(), VaultError>`（封装 infra auth + pairing::cancel_all_sessions，映射 VaultError）；commands.rs:204-209 与 dispatcher.rs:51-55 改委托。

### 2.6 CQ-P3b pair 限流单锁化 + 顺手项

- `protocol.rs:121-160`：双 Mutex 合并 `Mutex<(u32, Option<Instant>)>`，单锁内窗口判定+重置+检查+递增；10/min 语义与错误文案不变。并发测试（同窗口双线程突发不清零）。
- `keychain/macos.rs:340-351`：LegacyGate gate 失败分支 `raw.zeroize()` 后返回错误。
- `engine.rs:437-438`（SF-P3b）：两处 `let _ = delete(...)` 非 NotFound `tracing::warn!`。
- `dispatcher.rs:66`（SF-P3c）：emit 失败补 `tracing::error!`。
- `vault.rs:416-418`（SF-P3a）：`if let Ok(settings)` 改 match + Err `tracing::warn!`（默认值行为不变）。

**WP-A DoD**：workspace 测试全绿（294 基线 + 新增 ~10）；native-host 测试绿；clippy/fmt 0；≤800 行；A1 不回归；touch 站点 DoD grep 逐处合规。

---

## 3. WP-B：SEC-L2 sync 配置加密（Wave 2，R2 扩域含 re-seal）

### 3.1 设计（六点）

1. `state_io.rs:40-43` 两个明文行 → **加密 blob**：照抄 vault_store sealed-row 模式（vault_store.rs:79 save_entry_in_txn 先例：enc subkey + AES-GCM + AAD 绑定行 key 防行交换）。save 路径已持有 SessionKeys（save_sync_rows :574-623 核实）；**load 路径签名变更**：`load_config`/`load_sync_state`（:544/:556）增加 keys 参数，四个调用方全在 engine.rs（:284/:296-297/:446-447，均在 lease 保护下——sync_status 解锁态限定，前端锁定不可达已核实）。
2. **双读迁移**：读行先按新格式解密；失败/无加密前缀 → legacy 明文 JSON 解析（LegacySettingsV1 先例 database/mod.rs:140/:445）；**读到 legacy 即在本次读取会话内重写为加密格式**（读时迁移，一次事务）。
3. **re-seal 密钥轮换（R2 新增，P1 级）**：`reseal_vault`（shared.rs:356-446）在 SYNC_CEK rewrap（:383-393，`BlobRewrite::Write` 机制）旁，对 sync_config/sync_state 两行做轮换——**必须复用 §3.1.2 的双读 helper 解析（统一覆盖密文与 legacy 明文两种格式）后按新 enc 重加密**，不得照抄 SYNC_CEK 的裸 `unwrap_secret(old_enc)?` 先例（sync_cek 恒为密文而这两行可能是未迁移明文：用户升级后未访问同步设置就改密，裸 unwrap 会 `?` 中断整个 reseal，导致 change_password 对该类用户不可用）；双读两种格式均解析失败才按损坏中止。**测试**：仿 `change_password_rewraps_sync_cek_and_sync_survives`（tests_engine.rs:679）与 `recover_vault_rewraps_sync_cek_and_sync_survives`（:727）补两条"改密/恢复后 sync 配置可读"测试，**各带一个 legacy 明文行夹具变体**（未迁移行 + 改密 → 轮换后仍可读且已是密文）——这是仓库既定标准（sync 必须在改密后存活）。
4. integrity digest：新行自动纳入 VAULT_TABLE 全表扫描（验证 digest 测试）。
5. 测试集：a) 加密往返；b) legacy 明文行 → 读取成功 + 重写密文（断言 DB 行无明文 username）；c) 篡改 → fail-closed；d) digest 回归；e/f) 改密/恢复存活 ×2。
6. 同文件顺手项：**CQ-P3c**（state_io.rs:600-603 `EncryptionFailed` → `InternalError`）；**validate_config**（:228）拒绝 server_url 内嵌 userinfo + 测试。

**回滚风险（如实）**：加密行一旦写入，回滚 v1.1.9 将读不到 sync 配置（旧版无双读）——迁移在读时发生，用户重连 sync 即可恢复；CHANGELOG 注明。

**WP-B DoD**：workspace 测试全绿（+6~8 新增）；clippy/fmt 0；A 波已合入为基线。

---

## 4. WP-C：前端与扩展杂项

### 4.1 CQ-P3d EntryScreen 拆分（纯迁移）

`EntryScreen.tsx`（752 行）拆出 `src/components/TotpSecretField.tsx`（:544-582 现区域）、`src/components/TagsEditor.tsx`（:615-655，纯 props）；`detectChanges`（:240-321）提纯函数并**补 `totpChanged` 参数**（:313 现用闭包变量）。现有测试零回归；新组件各补 1-2 条渲染测试。

### 4.2 SF-P3d 扩展持久化失败反馈

`background.js`：saveToken（:66-71）/savePendingPairNonce（:45-50）`.catch(() => {})` → `.catch(e => console.warn(...))`；`pairConfirm` 无 nonce 分支（:201-202）return 前设 `lastConnectionError = "Pairing session lost — restart pairing"`。

### 4.3 SF-P3e FileReader onerror

`ImportExportScreen.tsx:118-134` 浏览器回退分支补 `reader.onerror` + toast（桌面 dialog 路径不动）。

### 4.4 SF-P3f 同步状态第三态

`SyncSettingsSection.tsx:97-103`：首探失败（status===null 且失败）→ "Status unknown" + [Retry]（调 refreshStatus），不显示连接表单；刷新失败保持旧值（现状）。测试 ×2。

### 4.5 rider：popup autofill 反馈 + fuse parity

- `extensions/chrome/src/popup/popup.js:263-264`：静默 return → `this.showToast("Failed to fetch password")` 后 return。
- **fuse parity**：桌面 `search.ts:4` 的 `fuseOptions` 现为模块私有（R2 核正）——给 `src/utils/search.ts` 加 `export`（最小改动），新扩展测试 import 之并与 popup.js 的 FUSE_SEARCH_OPTIONS 逐字段 `toEqual`（password-strength 先例的桌面 import 模式迁移）；popup.js 配置若不可导入则文本比对兜底。

**WP-C DoD**：tsc（主+test）0、eslint 0、vitest 全绿（243+新增）、扩展三文件 node --check、EntryScreen ≤550 行且现有测试零回归。

---

## 5. WP-D：死代码清理 + ST-1 + 依赖回收（Wave 2）

**Rust**（行号 R2 校正）：`delete_group_in_txn`（vault_store.rs:110）、`ensure_db_dir`（paths.rs:44）、`get/set_schema_version`（integrity.rs:42/58）+ 常量 `SCHEMA_VERSION_KEY`（integrity.rs:15，整块回收）、`is_digest_version_known`（vault_header.rs:132）、`delete_entry_in_txn`（vault_store.rs:91，同步删 mod tests :219 调用）、`is_integrity_required`（vault_header.rs:127，同步删其单测）。
**依赖**：domain 移除 `serde_json`+`base64`；application 移除 `uuid`；构建自动收敛 lockfile。**⛔ 禁 pnpm install / cargo update 其它包**（v1.1.9 版本浮动教训）。
**前端**：`isVaultUnlocked`、`getEntryCount`（vault.ts:88）、`DownloadIcon`（Icons.tsx:128）；SettingsContext formatError re-export（v1.1.9 已删，验证即可）。
**CSS**：`.field-group`/`.field-label`（screens.css:116/120）、`.length-value`（:209）。
**扩展**：background.js 8 死 case（现行号 672/705/708/711/717/720/723/747）+ 死函数成对删（initVault/createGroup/updateGroup/deleteGroup/exportVault/importVault/updateSettings；`checkConnection` 保留）；content.js `SHOW_POPUP`（:1314）。**⛔ 禁删**：windows-native-host-smoke.py、get_entry_count 后端链路（决策④）、AUTOFILL case（文档化保留）。`regenerate-icons.py` 确认零引用**可删**。
**ST-1（R2 含配套）**：删 `vite.config.ts:26` 失效 `@ts-expect-error`；typecheck 脚本追加 node 配置检查——**先本地验证 TS5069**（composite+noEmit 冲突）：若报错则去掉 tsconfig.node.json 的 `"composite": true` 并同步移除 root tsconfig.json 的 `references`（plain tsc 不跟随 references，移除无副作用），再追加 ` && tsc --noEmit -p tsconfig.node.json`。
**DoD**：全量门禁绿；diff 逐文件核对无越界删除。

## 6. WP-E：keychain 真实 SecItem CI 冒烟（Wave 2）

- infrastructure 新增 `#[cfg(all(test, target_os = "macos"))] #[ignore]` 测试 `keychain_secitem_smoke`：**legacy login keychain**（未签名 runner 无 entitlement）write→read→delete 往返，测试专用 account 前缀，自清理。
- `.github/workflows/quality.yml` 的 **quality-native-host job（:142-159，R2 校正——非 :41 的前端 job）**追加 step：`cargo test --manifest-path src-tauri/Cargo.toml -p pwdvault-infrastructure keychain_secitem_smoke -- --ignored --exact`（该 job 已有 Rust 工具链；必要时参照 Linux/Windows job 的缓存模式 :75/:113）。
- 本地默认跳过（ignored）。DoD：本地全量绿；workflow YAML 校验；CI 实跑在发版时验证。

---

## 7. 全局验收与发版（WP-F）

**门禁矩阵**（复审阶段）：workspace 测试/clippy/fmt、native-host 测试/clippy、tsc×3、eslint、vitest 全量、扩展 node --check、主代理逐文件 diff + code-reviewer 独立全 diff。

**手动 QA**：

1. **升级路径（SEC-L2 重点）**：带 v1.1.9 明文 sync 配置的库 → v1.2.0 打开 → sync 状态正常、DB 行已迁移密文；**改密后 sync 配置仍可读可连**（re-seal 轮换）；断开连接日志/文案正常。
2. SEC-L5：解锁后闲置 >max(auto_lock, 120s) 无操作 → 自动锁；期间一次扩展填充 → 续 120s；桌面打字使用不被误锁。
3. EntryScreen 编辑/新建/TOTP/tags 全流程回归。
4. popup autofill 失败有 toast；同步首探失败显示 unknown+Retry。
5. 正常配对回归（SF-P3d 代码审查为主）。

**发版**：`bump-version.sh 1.2.0 --changelog` + `cargo update -w`（仅 workspace 自身）+ CHANGELOG（Security: L1-L5；Fixed: SF-P3 组；Changed: **自动锁远程宽限语义（行为变化，含回滚说明）**+ EntryScreen 拆分；Internal: 死代码回收、依赖移除、keychain CI 冒烟、ST-1）；README/AGENTS SEC-L5 文案更新 + Session Log；commit-gate 标记纪律；**打 tag 前核对四对插件 JS/crate 版本对齐**；tag v1.2.0 → push → CI 监控至绿 → 确认产物与 updater feed。

## 8. 风险与回滚

| 风险                  | 缓解                                                                       | 回滚                                                         |
| --------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------ |
| SEC-L5 误锁在席用户   | 心跳已核实（节流 5-60s）；QA §7.2 必测；宽限常量可调                       | 单域 revert，无格式变更                                      |
| SEC-L2 改密后配置损坏 | **R2：re-seal 轮换 + 存活测试 ×2（仓库既有标准）**；legacy 双读 + 读时迁移 | revert 后旧版可读（加密行回滚不可读→CHANGELOG 注明重连即可） |
| SEC-L3 循环挂死       | 总超时保留；无效请求 respond 后 continue；测试                             | revert                                                       |
| EntryScreen 拆分回归  | 现有测试零改动全回归 + 新组件测试                                          | revert                                                       |
| 死代码误删            | 清单经二次审查 + 独立小步 commit                                           | 文件级 revert                                                |
| ST-1 TS5069           | 配套 composite/references 调整 + 本地先验证                                | 不追加脚本即回滚                                             |
| 插件版本浮动          | WP-D 禁 pnpm install；tag 前四对核对                                       | —                                                            |

## 9. 与修复总案的差异

- SEC-L5 落为具体设计（remote grace 120s + max 语义 + 亮线 touch 规则，字段入 SessionInner::Unlocked）。
- SEC-L2 扩含 re-seal 轮换与存活测试（评审 P1）；WP-B 移 Wave 2（文件域扩为 state_io/engine/shared/tests_engine）。
- 放弃项新增：SEC-L4 前端置空（平台局限）、export_recovery_key（一次性语义）、剪贴板根治（权限面）。
- SF-P3b 行号校正 engine.rs:437-438、CQ-P3c state_io.rs:600-603、SF-P3e ImportExportScreen.tsx:118-134、SHOW_POPUP content.js:1314、ensure_db_dir paths.rs:44、baidu_oauth :318-339、fuse parity 需先 export fuseOptions。
