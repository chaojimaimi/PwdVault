# fix_impl_plan — v1.8.4 批次②：P2×6 加固 + P3 速赢 riders

> 依据：fix_roadmap_2026-11.md §2 + 2026-11-12 recon + plan-reviewer R1（REVISE 全折叠，
> 见 §6）。行号为 recon 时点参考，成批漂移 3-8 行属正常——**实施以符号定位为准，不按
> 行号硬切**。版本裁定：**v1.8.4**（用户 2026-11-12 指令；本批
> 全为修复/加固无 feature，patch 语义成立；roadmap §0/§3.5 的 v1.9.0 标注随 docs 提交
> 改记为 v1.8.4）。
> 批次②缓议项（Zeroizing Debug / NM 1MB 响应上限 / 限流持久化 / native-host ID 交叉
> 校验）**不在本班**，任何 worker 不得顺手实施。

---

## 0. 总则

- **红线（全局）**：entry/sync codec 代际、golden fixtures、AAD 常量、D8 窗口语义、
  unlock_if/unlock/lock_vault/generation 全部零触碰；NM 协议形状不变（error_code 字段
  已存在，本班只是让扩展开始消费它）；**domain-match.js 字节冻结区零触碰**（R1 P0：
  content.js:45 裸标识符调用依赖其声明，永不删除）。
- **测试基线**：Rust 450(+1 ignored) / 前端 717 CI-true (86 files) / native-host 23。
  门禁数字以干净 worktree 实跑为准。
- **实施分波**（三域文件零交集，可并行）：
  - WP-A Rust：P2-6 + P3-8 + P3-9
  - WP-B 前端：P2-3 / P2-4 / P2-5 / P3-2 / P3-3 / P3-4 / P3-5 / P3-6 / P3-7 /
    P3-13（+ P2-6 的前端监听端）/ P3-14
  - WP-C 扩展：P2-1 / P2-2 / P3-10 / P3-11 / P3-12
  - WP-D 文档（主代理）：P3-1 README + roadmap 版本标注 + CHANGELOG（bump 时）
- Worker 纪律：继承树先验证（git status 干净 + 基线测试实跑）；Rust 改完必跑
  `cargo fmt`；逐字拷贝守卫测试注意引号形态（formatter hook 会重排）；不 commit。

---

## 1. P2 修复

### P2-1 扩展更新路径后台域重校验（WP-C）

**现状（recon 已核）**：`updateEntryFromPrompt`
（background-commands.js:208-239）把 content-script 回显的 entry_id 直送
`sendToApp("update_entry", ...)`，零域校验；`checkSaveCredentials`（:163-201）按 digest
验证候选但同样不验域。被攻陷页面可指认任意 entry_id 让扩展改写他站条目。
`getEntryForSender`（:102-116）是正确镜像：先 meta + `entryMatchesSenderUrl` 再取密钥。

**设计**（R1 折叠：wire 名/候选语义/null senderUrl 三处精确化）：

1. 两个入口函数签名追加 `senderUrl` 参数（由 background.js 分派臂传入——
   CHECK_SAVE_CREDENTIALS :266-270 与 SAVE_LOGIN_CONFIRMED update 臂 :278-280，
   senderUrl 来自既有 authorizeMessage 产物，不新增信任源）。
2. 成员校验数据源：**复用 background-commands.js:118-128 已导出的
   `getEntriesForUrl(senderUrl)` helper**（background.js:254 GET_ENTRIES_FOR_URL 分派臂
   的既有用法；注意 GET_ENTRIES_FOR_URL 是扩展内部 runtime 消息类型，桌面侧真实命令
   是 `list_all_entries`——不得把消息类型名当 wire 命令字面发送）。
   `updateEntryFromPrompt`（单 entry_id）：`entries.some(e => e.id === message.entry_id)`
   不成立即 `throw new Error("Entry is not authorized for this site")`（错误文案与
   getEntryForSender 逐字一致）。
3. `checkSaveCredentials`（候选集）：域外候选**静默跳过**（与 getEntriesForUrl 同谓词
   `entryMatchesSenderUrl` 逐个过滤，不整体 throw——与既有候选流语义一致，R1 已核
   候选本就源自同谓词的 GET_ENTRIES_FOR_URL，重推导不破坏合法保存/更新流）。
4. `senderUrl` 为 null/缺失（popup 形态等）→ **全拒**（fail-closed；popup 实际不发
   这两类消息，此为防御性语义声明）。
5. fail-closed：getEntriesForUrl 自身失败（含 "Unknown command"）→ 整个请求拒绝，
   不降级放行。

**测试**（两层，缺一即红）：

- 源码契约层（沿用 background-fill-gate.test.js 范式，零 mock、toContain 源文本）：
  updateEntryFromPrompt 函数体内含 `getEntriesForUrl` 调用 + 拒绝文案；
  checkSaveCredentials 函数体内含同一过滤；background.js 两个分派臂均传 senderUrl
  （不含 senderUrl 实参的旧形态必须消失）。
- **行为层（R1 P1 折叠）**：background-save-prompt.test.js 的 chrome stub 必须增设
  `list_all_entries` 分支（返回 example.com 域内、含既有用例 id（e1/e2）的 fixture，
  sender 为 `https://example.com/login`），否则 fail-closed 门会把该文件四个既有
  verdict/degradation 用例在校验层打红（stub 现走默认分支报 "Unknown command"）；
  SAVE_LOGIN_CONFIRMED update 模式的行为用例一并核对。

### P2-2 sendToApp 按 error_code 分类（WP-C）

**现状（recon 已核，比 roadmap 预估便宜）**：结构化 `error_code` 已全链路透传
（桌面 dispatcher.rs 恒 200 + body 内 REQUEST_REJECTED/COMMAND_FAILED；主机仅对
传输失败标 HOST_TRANSPORT_ERROR 并原样转发桌面 body，main.rs:151-165/:316-390）——
桌面与主机**零改动**。扩展侧 background-native.js:282-306 丢弃 error_code，catch 里
裸 `msg.includes("not found")`（:298 附近）把桌面业务错误 "Entry not found"
（error.rs:136,194）误分类为断连，用户看到"请确认 PwdVault 正在运行"。

**设计**：

1. sendToApp 失败路径：桌面返回的失败体带 `error_code` 字符串时，抛出的 Error 附加
   结构化属性（如 `error.code = data.error_code`），文案仍用 error_message。
2. catch 分类改为两级：
   - 有结构化 code → 唯一断连判定 `code === "HOST_TRANSPORT_ERROR"`；其余
     （COMMAND_FAILED / REQUEST_REJECTED）原样上抛，connectionStatus 不动。
   - 无结构化 code（浏览器运行时 NM 失败，无响应体）→ 走 connection-errors.js 的
     浏览器短语分类器（单一来源）；**删除 background-native.js catch 里的三个裸
     子串判断**（`not found` / `timed out` / `connect`），`native messaging` 一项
     若 connection-errors.js 未覆盖则并入该模块，保持单一分类器出口。
3. connection-errors.js 导出统一的 `isConnectionError(msg)`（若已有等价物则复用），
   供 sendToApp 调用。**短语集必须是旧四子串的超集**（R1 折叠）：浏览器侧枚举文本
   "Specified native messaging host not found" / "Native messaging host timed out"
   已被既有短语覆盖（connection-errors.js:7/:16），`native messaging` 一项若未覆盖
   则并入该模块——迁移后不得丢失任何一种真实传输失败的识别。

**测试**（R1 折叠：分层落位）：

- 纯分类器层（connection-errors.test.js 扩展）：桌面业务错误（message "Entry not
  found"）不被 isConnectionError 判为断连（红：今日 background-native 的
  includes("not found") 误判）；浏览器短语（"Specified native messaging host not
  found" / "timed out"）判为断连。
- **sendToApp 行为层（chrome-stub 范式）**：复用 background-save-prompt.test.js 的
  stub 形态（:17-65）或新建同款文件——connectionStatus 是 background-native.js 的
  模块状态，纯函数测试文件够不着。用例：结构化 COMMAND_FAILED（"Entry not found"）
  → 原样上抛且 connectionStatus 仍 connected；code HOST_TRANSPORT_ERROR → 断连 +
  friendly 文案。

**红线**：协议形状零改动（error_code 消费是纯读）；friendlyConnectionError 文案不动；
background.js 的传输层握手错误处理（host 握手协议）不动。

### P2-3 restoreEntry 刷新失败可见（WP-B）

**现状**：VaultContext.tsx:317-326，`.catch(() => {})` 吞掉 restore 后的 live 重载
失败；loadDeletedEntries 失败则整体 reject（掩盖 restore 成功事实）。

**设计**：照抄 SyncSettingsSection.handleSyncNow（:213-248）的 refreshed-flag 范式：
restore 成功后刷新两列表分别 catch；任一失败 → `showToast("Restored, but refreshing
the list failed")`（toast 工具从 `../utils/toast` 导入，与 SyncSettingsSection 同源）。
restore 自身失败仍照旧上抛给调用方（既有错误通道）。

**测试**：+1（restore 成功 + loadEntries reject → toast 被调用且 restoreEntry 不
reject）。**注意是新文件**：src/context/ 下现无 VaultContext 测试（R1 核实，仅
AuthContext/SettingsContext 有），按 SettingsContext.test.tsx 先例新建。

### P2-4 VaultScreen 排序持久化守卫（WP-B）

**现状**：VaultScreen.tsx:101-110 `handleSortChange` 直接
`updateSettings({...settingsState.settings, sort_mode: mode})`——settings 尚在
loading 时展开 DEFAULT_SETTINGS 落库，覆盖用户真实设置（含自动锁/自动同步等）。
SettingsScreen.tsx:93 是正确镜像：`state.status !== "success"` 短路。

**设计**：handleSortChange 首行加
`if (settingsState.status !== "success") return;`；排序 `<select>` 在
`settingsState.status !== "success"` 时 `disabled`（含 aria 提示或 title，与
SettingsScreen 的禁用形态一致）。

**测试**：VaultScreen 测试 +1（settings 非 success 时 updateSettings 不被调用；
镜像 groupFilter 测试文件的 mock 形态）。

### P2-5 秘密输入属性卫生（WP-B）

**现状（recon 已核）**：EntryScreen username（:500-514）与 password（:520-534）
均无 autoComplete、无 spellCheck。PasswordField 组件已有 `spellCheck={false}` +
autoComplete 透传，但 UnlockScreen（:162）与 SetupScreen（:54/:66）未传 autoComplete。
RecoveryScreen 已正确传值（:93/:104 new-password、:76-77 off）。

**设计**：

- EntryScreen password：`spellCheck={false}` + `autoComplete="new-password"`。
- EntryScreen username：`spellCheck={false}` + `autoComplete="off"`。
- UnlockScreen PasswordField：`autoComplete="current-password"`。
- SetupScreen 两个 PasswordField（密码/确认）：`autoComplete="new-password"`。

**测试**：属性断言 ×3 文件（EntryScreen/UnlockScreen/SetupScreen 各 1 用例，渲染后
`expect(input).toHaveAttribute(...)`）。

### P2-6 trash 清理失败二次可见（WP-A Rust + WP-B 前端）

**现状（recon 已核）**：unlock_effects.rs:24-46 失败仅 tracing::warn，无失败计数；
前端无失败通道（trash-auto-purged 只报成功数）。NM 适配器
（native_messaging/dispatcher.rs:135-145）复用同一 `sweep_trash_and_emit` helper。

**设计**：

1. unlock_effects.rs 新增进程级 `PurgeFailureTracker`（static AtomicU32 承载）+ 纯
   函数决策层，**决策函数取 `&AtomicU32` 参数**（R1 折叠：可注入形态，单测不起全局
   static，避免与未来触碰 sweep 的测试并行脆弱）：`record_purge_failure(&counter)
-> bool`（连续失败计数，恰在第 2 次连续失败返回 true，之后继续失败返回
   false——once-per-run 不重复轰炸）；`note_purge_success(&counter)` 成功即清零
   （瞬时故障恢复后，未来的失败重新值得告知）。
2. sweep_trash_and_emit 的 Err 分支：`record_purge_failure()` 为 true 时
   `app.emit("trash-purge-failed", error.public_message())`（public_message 已净化；
   emit 失败仅日志，不产生新失败路径）。Ok 分支调 `note_purge_success()`。
3. 前端（WP-B，与 P3-13 同文件同提交）：App.tsx 增 listen
   `"trash-purge-failed"` → `showToastWithType(\`Trash auto-purge failed: ${payload}\`,
   "error", 10000)`（对齐 :196-205 既有 server-error 监听形态）。

**不变量**：解锁/恢复永不因清理失败失败（emit 与计数全部 best-effort）；首失败仍仅
日志（不打扰单次瞬时故障）。

**测试**：

- Rust：tracker 决策函数单测（失败×1 false → 失败×2 true → 失败×3 false → 成功清零
  → 失败×1 false → 失败×2 true）。
- 前端：App.tsx 监听器渲染 toast +1 用例（若 App.tsx 测试文件存在 listener 测试范式
  则跟随；无则与 P3-13 一起做渲染断言最小用例）。

---

## 2. P3 riders

| #   | 项                                    | 设计（锚点已 recon 核实）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 测试                                                                                                |
| --- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| 1   | README 状态刷新（WP-D）               | Project Status（:166-168）→ v1.8.4；:151 示例命令去掉陈旧 1.1.7；feature 表补齐现势能力（auto-sync/TOTP/恢复密钥/Touch ID/弱口令检测/回收站/仪表盘）；roadmap 节按当前事实修剪（签名/Hello pending、HIBP/secure notes 搁置）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | 无（docs）                                                                                          |
| 2   | fuse 缓存锁后清理（WP-B）             | search.ts 导出 `clearSearchCache()`（置空模块级 cachedEntries/cachedIndex :29-30）；VaultContext.tsx:166-175 锁过渡 effect 内 RESET 旁调用                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | 无新用例（纯卫生，既有测试保绿）                                                                    |
| 3   | copyWithTimeout 守卫 ×4（WP-B）       | EntryScreen:349、GeneratorScreen:179/:190、TotpCode:90 各自 try/catch → 失败 toast（"Copy failed" 或含 errorMessage，随各文件既有 toast 形态）；不许静默吞                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | clipboard 相关既有测试保绿；+1 TotpCode 失败路径用例（mock copyWithTimeout reject）                 |
| 4   | "Copied" 计时器 ref 化（WP-B）        | VaultScreen:134-136 / GeneratorScreen:178-184：`useRef` 存 timer id，re-arm 前 clearTimeout，unmount effect 清理                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 既有测试保绿                                                                                        |
| 5   | RecoveryScreen 失败清输入（WP-B）     | recover 返回 false 时仅清 recoveryKey 输入（一次性 256-bit 密钥不应残留；密码字段保留——用户可能只需改 confirm 拼写），附注释                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | RecoveryScreen 测试 +1（失败后输入框为空、密码框保留）                                              |
| 6   | Generator tabs 语义（WP-B）           | GeneratorScreen:206-220：去 role="tablist"/role="tab"/aria-selected，改 aria-pressed（group-tabs aria-current 先例）；class 名不动；R1 已核 CSS 无 [role=tab]/[aria-selected] 选择器依赖，可安全移除                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | GeneratorScreen.modes.test.tsx 既有 `getByRole("tab")` 断言（:56/:75/:86/:125）改 aria-pressed 形态 |
| 7   | loadDeletedEntries error 载荷（WP-B） | VaultContext:295-314 catch 分支 payload 增 `error: errorMessage(error, "Failed to load trash")`；state/reducer/类型同步；VaultScreen.tsx:402-416 横幅渲染该文案（Retry 保留）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | VaultScreen.trash 测试 +1（error 载荷出现在横幅）                                                   |
| 8   | integrity.rs ct_eq ×2（WP-A）         | **路径修正**：`database/integrity.rs`（非 crypto/）。:154 `stored == actual` → `stored.ct_eq(&actual).into()`；:316 同改；`use subtle::ConstantTimeEq`（subtle 2.6.1 已在 infrastructure deps，零新依赖）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 正确性等价（既有完整性测试保绿）；无等价用例则补 equal/mismatch 两臂                                |
| 9   | 14MiB/10MiB 对齐（WP-A）              | **择一裁定：升不降**——domain/constants.rs:25 `MAX_BODY_SIZE` 10→14MiB + host main.rs:28 `MAX_MESSAGE_SIZE` 10→14MiB，注释互相指向；MAX_RESPONSE_SIZE(1MiB) 不动（缓议区）；backup 14MiB 与 ImportExportScreen.tsx:22 不动                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 既有 NM 限额测试保绿；改常量若有 pin 测试同步                                                       |
| 10  | ui-bar 悬浮按钮 isTrusted（WP-C）     | content-ui-bar.js:466-469 click 加 `if (!e.isTrusted) return;` + 注释（与 :88-92 fill 按钮门同款措辞）；**补回 roadmap 半项**：shadow-mount 区注释措辞按现状核实修正（不实指即记录无需改动）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | content-is-trusted.test.js +1                                                                       |
| 11  | popup go-to-url 校验（WP-C）          | popup.js:439-449：`new URL(finalUrl)` try/catch 包裹，解析失败直接 return（不开 tab、不关窗）；http(s) 直开规则不变                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | popup 可测函数抽取或 DOM 断言，最小 +1                                                              |
| 12  | eslint 10 warnings 清零（WP-C）       | background-native.js:82 / background.js:102,107 未用 `e` → `_e` 或删参；clipboard-clear.test.js:45 参数改 `_message`、:208 删未用 `runtime` 赋值；content-forms.js:17/:31 两常量**删除**（R1 证实零引用含 popup）；content-ui-bar.js:426 entryCount 为 write-only（:443/:494 两处写入同删）；**domain-match.js:235/:273 两函数不删（R1 P0 撤回）**——content.js:45 以裸标识符调用 `entryMatchesPageUrl`（AUTOFILL 域门，隔离世界共享作用域解析到 domain-match.js 声明），删除即 ReferenceError 全灭 autofill，且击穿 sender-auth.test.js 字节守卫（:657-678 含四函数名）+ content-namespace.test.js FROZEN_NAMES 双断言（:81-90/:92-105）；改用**文件级** `/* eslint-disable no-unused-vars -- 理由 */` 置于 BEGIN 标记**之外**的文件头（:1-8 区域）压掉两条 no-unused-vars——行注释会落入冻结区使 sender-auth.test.js 字节守卫的严格子串包含断裂（R2 指出；eslint-disable 不含 `/* global` 字样，content-namespace.test.js:75-79 禁令不受影响），字节冻结区零触碰 | `pnpm lint` 0 errors **0 warnings** 成为目标门禁                                                    |
| 13  | App.tsx 中文 toast（WP-B）            | :189-191 → `Trash auto-purged ${n} item(s)`；与 P2-6 的 trash-purge-failed 监听器同文件落地                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | 随 P2-6 前端用例                                                                                    |
| 14  | VaultContext 死 try/catch（WP-B）     | :219-227 / :229-237 / :239-253 / :255-270 四处 `catch (error) { throw error; }` 无副作用脚手架拆除（保留体内有意义逻辑）；:195/:216/:313 的 rethrow **不是死的**（前有 dispatch），不动                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | 既有测试保绿                                                                                        |

---

## 3. 测试预算与门禁

- Rust：+2~4（P2-6 tracker、integrity 补臂若缺）→ ~453(+1)。
- 前端：+6~9（P2-3/P2-4/P2-5×3/P2-6+P3-13/P3-5/P3-6改/P3-7）→ ~723+/86+。
- 扩展：+5~7（P2-1×2/P2-2×3/P3-10/P3-11）。
- native-host 23 不变（P3-9 仅常量）。
- 门禁全绿：`cargo fmt --check`、`cargo clippy --workspace -- -D warnings`、
  `cargo test --workspace`、`cargo test`（tauri-app）、`pnpm tsc --noEmit`（三
  tsconfig 经 npm scripts）、`pnpm lint`（0/0）、`pnpm test`、web-ext lint、
  native-host `cargo test`；干净 worktree 复验 + native-host sidecar 预编译。
- **发版**：bump-version.sh → 1.8.4（src-tauri 锁手动重生 + `--locked` 验锁）→
  CHANGELOG [1.8.4] → docs 提交（roadmap 版本标注改记 + AGENTS.md session log +
  qa_manual T61）→ tag + push → 轮询 CI（gh watch 抖动改轮询）。

## 4. QA T61 appended（真机项，jsdom 不可见）

1. EntryScreen/Unlock/Setup 输入属性真机核验（DevTools 看 autocomplete 实际落地 +
   浏览器密码管理器不误触发）。
2. 悬浮按钮合成事件防御：真 Chrome 控制台 `dispatchEvent(new MouseEvent("click"))`
   → overlay 不得打开；真实点击正常。
3. popup go-to-url：恶意 URL（`javascript:`、畸形域）不开 tab；正常 URL 直开。
4. 排序下拉在 settings 加载完成前置灰（冷启动即点，观察 disabled）。

## 5. 依赖与风险

- WP-C 的 P2-2 触碰 background-native.js（sendToApp）——与 WP-C 自身 P2-1 不同文件，
  波内零冲突；与 fill-gate 源码契约测试同文件系，改 sendToApp 需跑全部 background
  契约测试防 toContain 断言失配（formatter 重排风险）。
- P3-9 改 host 常量：host 无依赖变更，锁文件不动；bump-version.sh 照常重生。
- P3-12 domain-match.js 仅加 eslint-disable 注释：diff 审查时逐行核对冻结区无其他
  字节变化（matching 语义零触碰）；sender-auth.test.js 字节守卫必须保持绿。
- WP-C 的 P2-1 同时改 background-commands.js 与 background-save-prompt.test.js
  stub——该文件四个既有用例在门落地后必须全绿，红即 stub 分支缺失（非设计问题）。
- P2-6 事件名 `trash-purge-failed` 为新增监听通道（单向 Rust→前端通知，非 NM 协议）。

---

## 6. R1 评审记录（plan-reviewer REVISE，2026-11-12，全折叠）

| 级  | 发现                                                                                                                                                                                | 折叠落点                                                     |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| P0  | P3-12 domain-match.js 删除前提为假：content.js:45 裸标识符调用 `entryMatchesPageUrl`（AUTOFILL 域门）+ sender-auth.test.js 字节守卫 + content-namespace.test.js FROZEN_NAMES 双断言 | §2 #12 改 eslint-disable 带理由注释；§0 红线升级为"永不删除" |
| P1  | P2-1 门落地即打红 background-save-prompt.test.js 四用例（stub 缺 list_all_entries 分支，fail-closed 在校验层全拒）                                                                  | §1 P2-1 测试节行为层明文要求 stub 增分支 + update 模式核对   |
| P2  | P2-1 "GET_ENTRIES_FOR_URL wire 命令名"措辞会把 worker 引向不存在的桌面命令（真实命令 list_all_entries；消息类型≠wire 命令）                                                         | §1 P2-1 设计第 2 条改指 getEntriesForUrl helper              |
| P2  | P2-1 候选门语义未指定（skip vs throw）+ null senderUrl 形状未声明                                                                                                                   | §1 P2-1 设计第 3/4 条：候选静默跳过、null 全拒               |
| P3  | 行号成批漂移 3-8 行 vs §0 绝对声明                                                                                                                                                  | §0 改"符号定位为准"                                          |
| P3  | P3-10 丢 roadmap 半项 shadow-mount 注释修正                                                                                                                                         | §2 #10 补回                                                  |
| P3  | P2-2 connectionStatus 断言够不着纯函数测试文件 + 短语集超集声明缺失 + typo                                                                                                          | §1 P2-2 设计/测试节（chrome-stub 层 + 超集声明 + 文案修正）  |
| P3  | P2-6 tracker 直操全局 static 的并行脆弱                                                                                                                                             | §1 P2-6 改 `fn(&AtomicU32)` 注入形态                         |
| P3  | P2-3 "+1 测试"实为新文件                                                                                                                                                            | §1 P2-3 注明按 SettingsContext.test.tsx 先例新建             |
| P3  | P3-12 entryCount 是 write-only（连带两处写入）；clipboard-clear.test.js:45 现参名为 message                                                                                         | §2 #12 写明连带删除                                          |

R1 同时核实为真（抽样）：P2-1 门控不破坏合法保存/更新流（候选本就源自同谓词的
GET_ENTRIES_FOR_URL，重推导语义安全）；P2-2 两级重设计不损失真实传输检测且 error.code
不跨 postMessage 边界（同函数 try/catch 内产生消费）；P2-6 NM 路径有 AppHandle
（dispatcher.rs:143-147）；P3-9 升不降方向正确（桌面导入已接受 14MiB，降才制造回归）、
无 10MiB pin 测试；WP 三域文件零交集全量核对成立；无缓议项回流。
