# Phase 0 实施方案：安全与质量收尾（2026-09）

> 依据 docs/ROADMAP-2026-09.md Phase 0。七个小项，均为已定位的遗留问题。
> 验证基线：cargo test / clippy -D warnings / pnpm test / tsc 全绿 + 扩展语法检查。

## X1 扩展握手错误文案区分"连不上"与"版本不匹配"

**位置**：`extensions/chrome/src/background.js`（`sendNativeMessageP` 约 96-127 行、
pairWithApp handshake 分支约 134-146 行）

**现状**：`handshake?.success` 为假或 `protocol_version !== 1` 一律显示 "PwdVault
protocol versions do not match"——端口占用/应用未启动时误导用户（2026-09-15 实测踩中）。

**设计**：三分支：
- 调用抛错或返回 null（host 启动失败/超时/连接拒绝）→ 复用既有
  `friendlyConnectionError`（可构造合成错误走既有映射，避免维护第二份近似文案；
  connection-errors.js:20 已有 "Cannot reach the PwdVault desktop app. Make sure
  it is running." 近似句）
- 响应到达但 `!handshake.success` → 优先展示桌面端返回的
  `handshake.error_message`/`error`（NativeResponse 有这两个顶层字段），
  无则回退现有文案
- 响应到达且 success 但 `protocol_version !== PROTOCOL_VERSION` → 保留现有版本文案

## X2 端口绑定：SO_REUSEADDR + 有界重试

**位置**：`src-tauri/src/native_messaging.rs:125`（`TcpListener::bind(&addr)`）、
`src-tauri/Cargo.toml`（新增 `socket2 = "0.6"`——Cargo.lock 已有传递依赖 0.6.3，
复用同版本避免双副本）

**现状**：std 绑定无 SO_REUSEADDR（Unix），旧实例退出后的 TIME_WAIT 窗口内重绑失败
（2026-09-15 实测：dev 重启后两次 `Address already in use`，扩展服务静默不可用）。

**设计**：
- 用 socket2 构建监听 socket：`Domain::IPV4` + `set_reuse_address(true)` +
  `bind("127.0.0.1:port".parse())` + `listen(queue)` → `TcpListener::from`。
  （Windows 上 std 本就设置 SO_REUSEADDR，socket2 统一三平台行为，无副作用）
- 有界重试：**仅 `ErrorKind::AddrInUse`** 重试（权限类错误立即失败），最多 3 次，
  间隔 1s/2s/4s；仍失败走现有 `native-server-error` emit 路径（B3 已建）。
  已知副作用：`start_server_fails_when_port_is_already_bound` 测试将多耗约 7s
  （持有活跃 listener，SO_REUSEADDR 在 Unix 不会绕过，测试仍通过），接受并在
  测试注释中注明预期耗时。

## X3 AccessibleDialog 非栈序关闭的快照污染

**位置**：`src/components/AccessibleDialog.tsx`（openCount/escapeStack 已在 c557492 引入）

**现状**：每个实例 mount 时各自快照 `#root` 的 aria-hidden 状态；外层先关、内层后关时，
内层 mount 时记录的快照是外层设置的 `"true"`，最终恢复成 `"true"` → 整个应用对
屏幕阅读器不可见（code-review P3-1）。

**设计**：模块级 `snapshot: { ariaHidden: string | null; focused: Element | null } | null`：
- mount 时若 `openCount === 0`（本实例是把背景置 inert 的 owner）→ 记录快照；
- unmount 时若 `openCount` 归零且存在快照 → 恢复并清空；非归零不恢复；
- `previouslyFocused` 焦点恢复同样仅 owner（归零）执行。
- 测试：`AccessibleDialog.test.tsx` 增加乱序关闭用例（打开 A、B，先关 A 再关 B →
  B 关闭后 `#root` 无 `aria-hidden` 残留）。

## X4 popup 生成器 label 用 id 定位

**位置**：`extensions/chrome/src/popup/popup.js:1245`、`:1347`（`.option-row label`
按 DOM 顺序选择，脆弱）。

**设计**：renderGenerator 标记中长度选项的 label 加 `id="gen-length-label"`；两处
`document.querySelector(".option-row label")` 改 `document.getElementById("gen-length-label")`。
（`.strength-label` 是唯一类选择器，不动。）

## X5 Tauri capabilities 收紧 fs scope

**位置**：`src-tauri/capabilities/default.json`、`src-tauri/tests/capability_contract.rs:17-19`

**现状**：`fs:allow-read-file/write-file/stat` 无 scope = webview 可读写全盘
（审计 P3-13）。实际使用仅 ImportExportScreen 的对话框选定路径读写/统计
（`ImportExportScreen.tsx:75,109,115`）。

**设计**：三个 fs 权限改为带 scope 对象：
- allow：`$HOME/**`、`/Volumes/**`、`$TEMP/**`（覆盖用户导出/导入的常规位置）
- deny：`$HOME/Library/Application Support/com.pwdvault.app/**`（macOS 密文库目录）
  **以及 `$LOCALDATA/PwdVault/**`**（Windows 密文库目录，`paths.rs:21-26` 的
  `data_local_dir()/PwdVault`——allow 的 `$HOME/**` 在 Windows 包含 AppData\Local，
  不 deny 则 Windows 版 webview 仍可拖走 vault.db；变量 `$LOCALDATA` 为 Tauri v2
  schema 合法项，多余条目在不匹配平台无害）
- 同步更新 `capability_contract.rs` 对新 JSON 形态的断言（现 `filter_map(as_str)`
  在对象化后必失败，改为读取对象内 `identifier` 字段）。
- 验收（手动 QA）：导出到 ~/Documents 与导入任选路径均成功；**反例**：选择 allow
  范围之外路径（如 macOS 对话框 Cmd+Shift+G 前往 /tmp）→ 得到可理解的失败提示
  （走 ImportExportScreen.tsx:94 既有 catch 的 toast），不得静默或崩溃。

## X6 导入 KDF 下限收紧至 OWASP 底线（评审重写：分层校验，解锁侧豁免）

**位置**：`src-tauri/crates/infrastructure/src/crypto/kdf.rs`（KdfPolicy 约 95-125 行、
`AdaptiveParams::adaptive` 约 54-90 行、`derive_key` 约 143-149 行）、
`crates/application/src/service/backup.rs:236-239`（导入派生前）、
`crates/application/src/fixtures.rs:65-69,303-307`（硬编码 16384/1/1）

**评审纠正的关键事实**：`derive_key` 内部是 `AdaptiveParams::adaptive(500)` 基准，
**起点 m=16384/t=1**，慢机器上会返回低于新下限的参数——直接收紧 `KdfPolicy::validate`
会 (a) 让存量库（verification row 存有 t=1 参数）解锁失败，(b) 慢机器上导出/建库
随机失败。因此采用**分层校验**：

1. `KdfPolicy::validate`（结构边界 16MiB/1..=256MiB/10）**保持不变**——继续服务
   解锁路径（`verification.rs:65/82` 的 `derive_key_with_params` → `to_argon2_params`），
   存量库任何历史参数照常解锁；
2. 新增导入侧产品底线常量 `IMPORT_MIN_MEMORY_KIB = 19*1024`、
   `IMPORT_MIN_ITERATIONS = 2`（OWASP 底线）：`backup.rs` 导入派生（:239）**之前**
   对备份内嵌 params 做校验，不达标返回新错误变体（public message：
   "This backup uses weak KDF parameters and is rejected by the import policy"）。
   **注意用户可见行为变化**：旧版本在慢机器上经 adaptive 产生的 t=1 备份将无法再
   导入（有意的策略性拒绝，缓解路径：库本体解锁不受影响可重新导出；CHANGELOG
   需提及——主代理收尾时统一写入）；
3. `AdaptiveParams::adaptive` 起点钳制到不低于导入底线（19456/2）——保证新生成的
   导出/建库参数永远满足底线，杜绝"自己生成自己拒绝"；
4. fixtures.rs 两处 16384/1/1 **保留**并加注释"代表旧下限时代的存量库"——它们
   恰好成为解锁路径兼容历史参数的回归覆盖；检查是否有导入路径测试依赖低于底线
   的参数期望成功（有则改为期望拒绝）。
5. 测试：导入底线边界用例（恰 19456/2 接受、19455 或 t=1 拒绝）；adaptive 起点钳制
   用例（返回参数 ≥ 底线）。

## X7 AGENTS.md 文档刷新（仅事实修正，不重写风格）

- Current Version/Status：v1.1.5 保留，补一行"2026-09 审计修复 + Phase 0 已落地"；
- 架构段：`AppContext.tsx` 描述改为 **Provider 组合桶（useApp 门面已移除）**，
  状态归属 `AuthContext / SettingsContext / VaultContext` 三 Context；
  目录结构补 `crates/{domain,infrastructure,application}` workspace 与
  `commands.rs / touch_activity`；
- 测试计数：**以 `pnpm test` 实际输出为准回填**（勿硬编码）；Rust 侧 lib 28 +
  capability 1 + golden 2（+ native-host 19）已核验；
- Session Log 追加 2026-09 条目：三路审计 → 核查 → 修复（commits a519ee1/43ae1d3/
  ad5cb61/c557492/1da542b）→ 手动验证 → 本 Phase 0。

## 验证清单

```bash
cd src-tauri && source ~/.cargo/env && cargo test && cargo clippy --all-targets -- -D warnings
pnpm test && pnpm tsc --noEmit
node --check extensions/chrome/src/background.js && node --check extensions/chrome/src/popup/popup.js
```
手动 QA：导出到 ~/Documents 成功、导入任选路径成功（X5）；占用 17429 后启动应用 →
红色告警 toast 仍出现（X2 不改变失败告警语义）。

## 交付

单 commit：`fix(hardening): phase 0 cleanup — bind retry, fs scope, KDF floor, docs`
（CHANGELOG 由主代理收尾统一更新）。
