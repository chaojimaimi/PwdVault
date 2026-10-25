# fix_impl_plan_v1.3.2.md

**版本**: R2.1 · 2026-10-25 · 状态: **plan-reviewer PASS**（R2 复核通过；随附微瑕已并入 WP2.5：Save 在 .entry-actions 外，用 form= 属性关联而非 type=submit）
**范围来源**: 2026-10-25 六路审计的 P1 残留（VaultScreen 异步兜底）+ 全部 P2 批（Rust/React/扩展/CSS/安全）+ 低风险 P3 快赢。核心是 content.js 注入 UI 迁 Shadow DOM 并换现行配色。
**原则**: 改动最小化；两个逐字守卫锚区零触碰；每个 WP 有测试或明确的视觉 QA 项；发版前干净 worktree 全套验证（v1.3.1 教训）。

---

## 背景与现状

v1.3.1 已发布（4 个安全 P1 + 依赖升级）。本版收敛审计剩余项：扩展注入 UI 仍是 v0.2 时代靛蓝配色（`#6366f1` 系，出现在 content.js 6 处）且未隔离（4 个 UI 根全部直接挂 `document.body`，样式/`@keyframes` 全局注入——宿主页可双向污染）；另有 VaultScreen 异步静默失败（审计 React P1）、IPC 错误泄露、UI 对比度不达 AA 等 P2 批。

侦察基线（行号为 2026-10-25 实际值，实施前须复核）：

- content.js 1409 行，4 个 UI 根：通知条 `showAutoFillPrompt` L466-655（`#pwdvault-autofill-bar`，z-index 2147483646）、overlay `createOverlay` L670-851（z-index 2147483647）、toast `showNotification` L1040-1072（每次调用向 head 追加 `<style>`，无限累积）、浮动按钮 `createFloatingButton` L1087-1179。
- 测试锚区（零触碰）：content.js L10-27 `entryMatchesPageUrl` 手抄副本（sender-auth.test.js 逐字节断言）；content-is-trusted.test.js 的守卫串 `if (!e.isTrusted) return;`、4 处站点锚（`#pv-fill`/`#pv-dismiss`/`// Click to fill`/`// Copy button`/keydown 处）与"恰 4 处"计数断言。
- bump-version.sh 管理 5 个 Cargo.toml 但只刷新 native-host 锁——v1.3.1 曾因此挂 Quality Gates。

---

## WP1 — content.js 注入 UI 迁 Shadow DOM + 配色换装（核心，最高风险）

### 设计

1. **四个 UI 根各配一个 host 元素 + closed shadow root**：`host = document.createElement('div')`（host 自带定位：`position:fixed` + 原 z-index 值不变）→ `host.attachShadow({mode:'closed'})` → UI 模板挂进 shadowRoot → `document.body.appendChild(host)`。闭包持有 shadowRoot 引用（closed 模式页面无法触及，content script 自身照常用 `shadowRoot.querySelector`）。jsdom 支持 attachShadow，可测。
2. **样式收编**：现散落的 `<style>` textContent / `cssText` / innerHTML 内联样式块合并为**一份共享 CSS 字符串常量**，每个 shadowRoot 内注入一份 `<style>`。四个全局 `@keyframes`（slideDown/fadeIn/slideIn/fadeInFloat）随样式进 shadow，自动隔离，改名需求消失。**manifest 的 content.css 声明**（chrome manifest:26 / firefox manifest:32）经评审核实该文件为空注释——直接移除两处 `css` 条目，无样式需收编。
3. **配色换装**：CSS 顶部建 `:host` 局部 token 块（镜像桌面 Light 主题：primary `#1E3A5F`、accent `#0D9488`、success `#16A34A`、danger `#DC2626`、bg `#F7F8FA`/surface 白、文本 `#1F2937`/muted `#5B6B80`——以 DESIGN.md 与 themes.css 实际值为准），替换全部 6 处 `#6366f1` 及 `#1e1e2e→#2d2d44` 渐变、浮动按钮 `#8b5cf6` 渐变、toast 背景三色。shadow 内无法用页面 CSS 变量，token 块集中在 `:host` 一处便于未来同步。
4. **顺手修复（迁移中自然解决或一并做）**：toast 每次追加 `<style>` 的累积（收编后消失）；**toast 去重失效修复（评审 P2）**：`showNotification` 用 `document.getElementById("pwdvault-notification")` 去重（content.js:1041），入 shadow 后必失效——改为闭包持有的当前 toast 元素引用；`escapeHtml` 结果再进 `textContent` 的双重转义显示（L880-1030 区域，改纯 textContent）；`background.js` 的 `chrome.runtime.lastError;` no-op 语句（约 L136）删除，并在其早返回回调路径内先读 `lastError` 消除 Unchecked 警告（评审 P3）。
5. **零触碰清单**：L10-27 手抄函数；`if (!e.isTrusted) return;` 守卫串及其 4 处站点锚文本；`#pv-fill`/`#pv-dismiss` 等元素 id；对 background 的消息协议；`autofillLogin`/`insertPassword` 的页面表单注入逻辑（dispatchEvent 部分与 shadow 无关，原样保留）。

### 测试（源码守卫模式，同既有风格）

- 新 `content-shadow.test.js`：① 断言 content.js 中 `attachShadow` 出现恰 4 次（每 UI 根一个）；② 断言无 `document.head.appendChild(<style>)` 式样式注入残留；③ 断言 `#6366f1`/`#8b5cf6`/`#1e1e2e` 零命中、`#1E3A5F`/`#0D9488` 存在；④ 断言 4 个 keyframes 名仅出现在 CSS 字符串内（不再有独立 `<style>keyframes` 注入语句）。
- 既有 content-is-trusted / sender-auth 逐字守卫必须全绿（锚区零触碰的回归证明）。

---

## WP2 — VaultScreen 异步兜底 + React P2 批

1. **P1 残留**：VaultScreen.tsx 四处补 `try/catch` + `showToast(errorMessage(...))`：`handleEntryClick`（L63-69）、`handleCopyUsername`（L78-81）、`handleCopyPassword`（L82-95）、Retry 按钮 `void actions.loadEntries()`（L249-252）。mount 路径（L52-61 allSettled）已有 resource error UI + Retry，核实即可、不强改。
2. **VaultContext actions 稳定化**：把 deleteGroup 的"删中清选中"逻辑下沉进 reducer（`DELETE_GROUP` 同时判定 `deleted === selected` 时重置选中），actions deps 收敛为 `[dispatch]`；删除 VaultScreen.tsx L37-41 与 GroupManager.tsx L28-30 两处 latestRef workaround，恢复直接引用 `actions`。
3. **instanceof Error 残留**：EntryScreen.tsx:346、GeneratorScreen.tsx:47 改 `errorMessage(e, "<缺省文案>")`（核对 import）。
4. **installUpdate 失败可见化**：SettingsContext.tsx L284-288 catch 块补 `console.error` + 新增 `UPDATE_FAILED` phase（reducer + state），Updates 区块对该 phase 显示错误文案并提供重试（复用 manual check 按钮）；**横幅同步（评审 P2）**：`UpdateNotification` 横幅（VaultScreen.tsx:110 消费 phase）在 `UPDATE_FAILED` 下显示「更新下载失败」文案并保留重试入口；补对应测试。
5. **EntryScreen form 语义**：`.entry-content` 区域包 `<form onSubmit={preventDefault + handleSave}>`，Delete/标签等其余按钮显式 `type="button"`；**Save 按钮位于 `.entry-actions`（在 `.entry-content` 之外，PASS 复核微瑕）——不给它 `type="submit"`（不生效），改用 `form="<form 的 id>"` 属性关联提交**（saving 中 disabled 防重）；**TagsEditor 冲突修复（评审 P1）**：`TagsEditor.tsx:55` 的 Enter addTag 无 preventDefault，包 form 后会"加标签 + 隐式提交保存"双触发——补 `e.preventDefault()`；RTL 测试覆盖：Enter 提交保存、标签输入 Enter 只加标签不提交、Delete 不触发提交。

---

## WP3 — Rust P2 批

1. **VaultError IPC 消毒**：error.rs 移除 derive 中的 `Serialize`，手写 `impl Serialize for VaultError`（`serializer.serialize_str(&self.public_message())`），使 IPC 错误形状与 HTTP 路径一致（双通道单一形状）。保留 `Deserialize` derive（若测试/类型需要）。新单元测试：`InternalError("C:\\secret\\path")` 序列化产物不含原始路径、含 public 文案。**前端消费方迁移（评审 P1）**：`TotpCode.tsx:14-21` 用枚举形状判定（`isVaultError && "InvalidInput" in error && code==="TOTP_NOT_CONFIGURED"`）停止轮询——序列化后拒因变纯字符串，必须迁移为对 public_message 的 `startsWith("TOTP_NOT_CONFIGURED")` 判定，并同步改造 `TotpCode.test.tsx:52`、`SyncSettingsSection.test.tsx:294` 等枚举形状 mock；注明 `errorMessage()` 的 RateLimited 分支在 IPC 路径成为死代码（保留不动，无行为影响）。golden/capability 已核实无 VaultError 形状断言。全量 `cargo test --workspace` 必须绿。
2. **MockCloudBackend 入产线收敛**：backend.rs L121 起的 struct 及其 impl 全部加 `#[cfg(test)]`（现有使用全在 crate 内 cfg(test) 模块，编译即验证）。
3. **死依赖清理**：删除 crates/application/Cargo.toml **L26（[dependencies] 段，注释称"为错误类型保留"——评审 P2 更正）** 与根 src-tauri/Cargo.toml L65（[dev-dependencies]）的 bincode 条目，**两处条目的说明注释一并删除**（infrastructure/Cargo.toml L23 的活依赖勿动）。删除后 `cargo test --workspace` + `cargo metadata --locked` 通过（注意锁文件随之更新，一并提交）。

---

## WP4 — 扩展工程质量 + handshake 收敛

1. **扩展纳入 ESLint**：eslint.config.js 增加针对 `extensions/chrome/src/**/*.js` 的配置段（languageOptions.globals 含 chrome/browser/window/document；规则从 recommended 起步，不引入 stylistic 强改）。**必须同时收窄 ignores（评审 P1）**：eslint.config.js:11 的 `"extensions/**"` 从 ignores 移除、改为仅排除 `extensions/firefox/**`（symlink 副本不重复 lint），否则新配置段永不生效、lint 空转绿灯。package.json `lint` 改为 `eslint src extensions/chrome/src`。修掉 lint 报出的全部 error（存量 warning 可暂留但 no-undef 类硬错归零）；CI 无需改动——frontend job 的 `pnpm lint` 自动覆盖。
2. **GET_STATUS 并行化**：background.js L675-682 三个串行 await 改 `Promise.all([checkConnection(), isVaultInitialized().catch(...), isVaultUnlocked().catch(...)])`，语义不变（各自独立 catch）。
3. **handshake 版本收敛**：dispatcher.rs handshake 响应移除 `app_version`（protocol_version/capabilities 保留——协议协商必需）。**评审已核实：extensions/ 全目录 `app_version` 零消费 → 直接删除，无需迁移通道**；handshake 测试（tests.rs:99）不断言 app_version。protocol.rs:222 的豁免列表不变（handshake 仍免 token，但不再泄露版本）。新增 dispatcher 断言：handshake 响应不含 `app_version` 键。

---

## WP5 — 桌面 UI P2/P3 批（纯 CSS/微文案，一次收敛）

1. **对比度（AA）**：themes.css light 增文本级 token：`--color-warning-text:#B45309`、`--color-accent-text:#0F766E`、`--color-success-text:#047857`（dark 侧取既有亮色系对应值），muted light `#64748B→#5B6B80`；强度计标签（EntryScreen/StrengthMeter 小字）改用 *-text token；DESIGN.md L42/L69 muted 值同步为实际值。配对 toast（components.css L546-763 硬编码 hex）改回 var() 引用。
2. **溢出与焦点**：vault.css `.entry-title/.entry-username` 补 `overflow:hidden; text-overflow:ellipsis; white-space:nowrap`；`.entry-actions-inline:focus-within{opacity:1}`；groups.css `.group-create-input:focus` 不再清 outline/box-shadow，改容器 `:focus-within` 高亮（组件实际包裹类名以现地为准）。
3. **动效与状态**：components.css L519-538 两个 keyframes 删除 `translateX(-50%)`；`.modal`/`.confirm-modal` 补 `box-shadow: var(--shadow-card)`；`.btn-secondary/.btn-danger/.btn-icon` hover 补 `:not(:disabled)`；base.css reduced-motion 补 `animation-iteration-count:1 !important`。
4. **细节**：screens.css `.password-preview` 补 `user-select:all`；VaultScreen 空态 L261 "Tap + ..." 改为真按钮（`btn btn-primary`"Add your first password"，onClick=handleAddClick）；"Master password/Master Password" 大小写统一为句首式（grep 三屏）；popup.html `:root` 补 Light 兜底变量（JS 未设主题前不空窗）。

---

## 门禁（全部通过才算完成；在干净 worktree 执行，v1.3.1 教训）

```bash
cd src-tauri && cargo fmt --check && cargo clippy --workspace --all-targets && cargo test --workspace && cargo metadata --locked --format-version 1 > /dev/null
cd extensions/native-host && cargo test && cargo metadata --locked --format-version 1 > /dev/null
cd .. && cargo deny --manifest-path src-tauri/Cargo.toml --config deny.toml check
cargo audit -n --file src-tauri/Cargo.lock && cargo audit -n --file extensions/native-host/Cargo.lock
pnpm typecheck && pnpm lint && pnpm test
bash extensions/chrome/scripts/build.sh && pnpm dlx web-ext@10.5.0 lint --source-dir extensions/firefox/dist --warnings-as-errors
```

## 发版步骤（门禁通过后）

1. CHANGELOG.md `## [1.3.2] - <发布日>`：**Security**（handshake 版本收敛）、**Fixed**（VaultScreen 静默失败、IPC 错误泄露、toast 动画位移、焦点不可见、溢出）、**Changed**（注入 UI Shadow DOM 隔离 + 配色换装、扩展纳入 lint、对比度 token）。
2. `qa_manual_v1.2.0.md` 追加：**T29** 自动填充条真实流（真实点击 Fill 成功填充，样式为 navy/teal 且与宿主样式互不污染）；**T30** overlay 开合/搜索/填充/复制真实流；**T31** Light 主题对比度抽检（placeholder、强度标签）；**T32** 空态 CTA 与 Enter 提交保存。**并注明 T26-T28（剪贴板端到端）须在新版重跑**——content.js 全量重构。
3. `./scripts/bump-version.sh 1.3.2` 后**必须** `cd src-tauri && cargo metadata --locked --format-version 1 > /dev/null` 验锁（v1.3.1 教训），必要时让 cargo 收敛锁并一并提交。
4. 提交序列沿用先例：fix/feat 主体提交 → `release(1.3.2): version sync + changelog` → `docs:` 计划+会话日志。AGENTS.md 更新头部版本、测试基线表、会话日志。
5. 干净 worktree 复跑门禁全套 → `git tag v1.3.2 && git push origin main --tags` → 监控 Release 全 job + Quality Gates + updater feed 提交。

## 非目标（v1.4.0+，明确不做）

EntryScreen useEntryForm 拆分；VaultError 契约代码生成；pair 弹码显示扩展 ID 摘要（涉桌面 UI，挪 minor）；LWW 冲突计数提示；tauri-plugin-updater/zip≥9 升级（2026-12-31 前必须，随 v1.4.x）；产品项（passkey/导入器/安全仪表盘等）。

## 风险与回滚

- WP1 是本版唯一结构性重构：closed shadow root 下事件监听全部在 shadow 内部、消息协议与守卫逻辑不动、逐字锚区零触碰是硬约束；视觉回归靠 T29/T30 真机走查兜底。回滚 = revert 单个提交。
- VaultError 序列化形状变化是跨端契约变更：前端已兼容字符串错误（HTTP 路径同形状），但 golden/capability 测试若钉了旧形状需同步更新（worker 须报告每一处）。
- ESLint 新覆盖可能暴露存量问题：只修 error 级，存量 warning 不强改，避免范围爆炸。
