# fix_impl_plan_v1.3.1.md

**版本**: R2.1 · 2026-10-25 · 状态: **plan-reviewer PASS**（R2 评审通过，R2.1 仅并入评审随附的 P2/P3 非阻塞建议：quality.yml 离线重试分支同改、T28 备选入口）
**范围来源**: 全方位审计报告（2026-10-25，6 路并行审计）的 P1 批次 + 顺手修复的两个门禁/卫生项
**原则**: 只修审计确认的 P1，不做任何新功能；改动最小化；扩展行为变化必须可测试、可手动 QA。

---

## 背景

2026-10-25 六路审计确认 4 个 P1（均已主会话代码复核属实）：

| #    | 发现                                                                                                                                                                                                              | 位置                                           |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| P1-a | 依赖漏洞积压：rustls 0.23.45 命中 RUSTSEC-2026-0346/0347/0348/0349；zip 4.6.1 命中 RUSTSEC-2026-0367/0368/0369（本地 `cargo deny check advisories` 已复现 `advisories FAILED`，CI release 门禁 fail-closed 将红） | `src-tauri/Cargo.lock`                         |
| P1-b | 扩展 popup 剪贴板 30s 自动清除在主路径必然失效（定时器随 popup 销毁消亡；`catch {}` 静默吞错；且无 clipboardRead 权限时 digest 读取本就必败）                                                                     | `extensions/chrome/src/popup/popup.js:221-245` |
| P1-c | content.js 凭据触发事件未校验 `isTrusted`，同域脚本可合成交互取密（全文件 grep isTrusted = 0）                                                                                                                    | `extensions/chrome/src/content.js` 4 处监听    |
| P1-d | `.screen` 居中 + 溢出滚动裁切：内容高于视口时首屏不可达（窗口最小高 500px，Setup/Unlock/Recovery 受影响）                                                                                                         | `src/styles/base.css:76-87`                    |

侦察结论（已核实）：`cargo update -p rustls` 干跑 0.23.45 → 0.23.46 平滑；`cargo update -p tauri-plugin-updater` 会连带 **wry 0.54.4 → 0.57.1**（webview 大版本跳），不适合 patch 版本 → zip 只能走 allowlist。发布流程：github-actions bot 在 release 后自动提交 updater feed（3e38947 先例），本地无需手动做 feed。

---

## WP1 — 依赖升级 + zip advisory 放行（owner: backend）

### 改动

1. `cd src-tauri && cargo update -p rustls -p rustls-webpki -p webpki-roots -p webpki-root-certs -p clipboard-win`
   - 验收：rustls ≥ 0.23.46；webpki 系到达各 advisory 修复版本；clipboard-win 脱离 yanked（5.4.1 → 5.4.x 最新，Windows-only 传递依赖，低风险）。
   - **禁止** `cargo update -p tauri-plugin-updater`（连带 wry 跨版）。
2. zip RUSTSEC-2026-0367/0368/0369 放行，双通道：
   - `deny.toml` `[advisories].ignore` 追加三条，格式仿既有 bincode 条目：`{ id = "RUSTSEC-2026-036x", reason = "..." }`；
   - **新建根目录 `.cargo/audit.toml`**（cargo audit 不读 deny.toml，且只读 **cwd** 的 `.cargo/audit.toml`、不向上搜索父目录）：`[advisories] ignore = ["RUSTSEC-2026-0367","RUSTSEC-2026-0368","RUSTSEC-2026-0369"]`，带注释指向 allowlist 文档。
   - **对齐 quality.yml（评审 P0 + PASS 评审 P2 精化）**：quality.yml:272-277 的两条 cargo audit 目前以 `working-directory: src-tauri` / `extensions/native-host` 且无 `--file` 运行，根目录 audit.toml 覆盖不到它们——真实漏洞下 push 即红。对齐时注意这两步是 `cargo audit || (… && cargo audit -n)` 双命令：**删除 `working-directory:`，且主命令与 `-n` 离线重试都必须带 `--file`**（否则重试在仓库根无锁文件、网络抖动即误红）。精确形态：
     `cargo audit --file src-tauri/Cargo.lock || (echo "::warning::advisory db refresh failed, retrying offline" && cargo audit -n --file src-tauri/Cargo.lock)`；native-host 步同构（`--file extensions/native-host/Cargo.lock`，warning 文案同步）。由此单一 `.cargo/audit.toml` 覆盖两个 workflow；**禁止**在多个目录拷贝 audit.toml（漂移）。
   - `docs/SECURITY-ADVISORY-ALLOWLIST.md` Active allowlist 表追加一行：Reason 必须写明「漏洞代码路径为 tauri-plugin-updater 更新包解压的 symlink 权限逃逸（ZipStreamReader::extract）；利用前提是攻破 minisign 签名链（信任锚已被 golden_contract CI 字节级钉死）或 https 降级；修复需插件大版本升级连带 wry 0.54→0.57，不进 patch」；**Expiry = 2026-12-31**，Owner = backend，触发条件：tauri-plugin-updater 提供 zip ≥9 的版本时必须在下一个 minor（v1.4.x/v1.5.x）完成升级。
   - native-host 锁文件不涉及 zip；`.cargo/audit.toml` 的 ignore 对其无害（无该 crate）。

### 测试/验收

- `cargo audit --file src-tauri/Cargo.lock` 与 `cargo audit --file extensions/native-host/Cargo.lock`（= release.yml 同款命令，quality.yml 对齐后为同一命令）exit 0；
- `cargo deny --manifest-path src-tauri/Cargo.toml --config deny.toml check`（全量，非仅 advisories）exit 0；
- `cargo test --workspace` 全绿；记录升级前后 advisory/warning 计数进 closure 说明。

---

## WP2 — 剪贴板自动清除迁入 background（owner: extension）

### 设计（ digest 校验保留，生命周期不再依赖 popup ）

数据流：popup 复制成功 → `chrome.runtime.sendMessage({type:'CLIPBOARD_ARM_CLEAR', digest, deadline})` → background 存 `storage.session`（key `pwdvault_clipboard_arm`，仿既有 `pwdvault_pair_nonce` 封装模式）+ `chrome.alarms.create('pwdvault-clipboard-clear', {when: deadline})` → `onAlarm` 触发清除。

清除执行分平台：

- **Chrome**：offscreen document（`chrome.offscreen.createDocument`，reason `CLIPBOARD`）内的 `navigator.clipboard.readText()` 做 digest 比对，匹配则 `writeText('')`。background 发 `CLIPBOARD_CLEAR_PING` 给 offscreen（独立 onMessage 监听，runtime.sendMessage 不会回环到 background 自身）；background 收到响应 {cleared, reason}。
- **Firefox**（无 offscreen）：background event page 自身有 DOM——隐藏 `<textarea>` + `document.execCommand('paste')`（需 clipboardRead）读入 → digest 比对 → 清空 textarea 后 `execCommand('copy')` 覆写剪贴板。
- **失败处理**（对齐桌面端 clipboard.ts 的 notify-once）：单次瞬时失败 5s 后重试一次；仍失败 → `storage.session` 记 `pwdvault_clipboard_clear_failed` 标记，**popup 下次打开时消费该标记并 toast 一次「上次剪贴板自动清除失败」**，随后清除标记。禁止空 `catch {}`。
- **重复 arm**：新 arm 覆盖旧 arm（重算 digest、重建 alarm），单一 pending 语义。
- **alarm 唤醒容错**：onAlarm 先读 storage.session 的 arm 记录，`deadline` 已过或 digest 缺失则直接清记录跳过。

### Manifest 变更

- `extensions/chrome/manifest.json`：permissions 追加 `alarms`、`offscreen`、`clipboardRead`；新增 `"minimum_chrome_version": "109"`（offscreen 自 109 起）。
- `extensions/firefox/manifest.json`：permissions 追加 `alarms`、`clipboardRead`；**不加 offscreen**（Firefox 不支持，未声明权限避免 store 告警）。
- 重大取舍（CHANGELOG 与 allowlist 无关，写在 CHANGELOG Security 节）：**新增 clipboardRead 是权限扩张**。理由：digest 校验避免覆写用户新复制的无关内容（盲清 = 数据破坏，对密码管理器更不可接受）；读取范围仅限扩展自身上下文，不涉及页面内容。Bitwarden 采用盲清 + 无 clipboardRead，本方案有意不同。

### popup.js 改动（L221-245）

- `copyToClipboard` 的 autoClear 分支：计算 digest（digestText 保留）→ sendMessage arm → **成功才** toast "...(auto-clears in 30s)"；arm 失败降级为普通 "Password copied!"（不承诺做不到的事）+ console.warn。删除 `activeClearTimer` 本地路径与模块级变量（L9）。
- popup 启动时消费 `pwdvault_clipboard_clear_failed` 标记（见上）。

### background.js 改动

- `handleMessage` switch（L640-732）新增 `CLIPBOARD_ARM_CLEAR`：**纯内部消息，不触发 desktop NM 调用**；sender 白名单（sender-auth.js）登记为 **popup-only**（content script 不得 arm）。
- 新增 `chrome.alarms.onAlarm` 监听 + 平台分支清除器 + offscreen 生命周期管理（创建前查 `chrome.runtime.getContexts`/`clients` 防重复创建）。

### 测试（vitest，仿 token-storage.test.js 的 chrome mock 模式）

新 `clipboard-clear.test.js`：

1. arm 成功 → alarm 以正确 when 创建、storage.session 写入；
2. alarm 触发 + digest 匹配 → 清除执行；
3. digest 不匹配 → 不覆写、记录清空；
4. 清除失败 → 重试一次 → 仍失败写失败标记；
5. popup 打开消费失败标记且只 toast 一次；
6. deadline 已过的孤儿 alarm → 安全跳过。
   content/popup 侧：popup autoClear 分支的 toast 文案分支（arm 成功/失败）测试；sender-auth popup-only 白名单测试更新。所有 chrome API 用 vi.stubGlobal mock；Firefox 分支 mock `document.execCommand`（jsdom 未实现会抛错）。

### 手动 QA（评审 P1：mock 覆盖不了真实浏览器行为，追加至 qa_manual_v1.2.0.md，T 编号顺延）

- **T26 Chrome 端到端**：popup 复制密码 → 立即关闭 popup → 等 30s → 外部粘贴为空；反向用例：复制密码后 10s 内手动复制其他文本 → 30s 到点后用户新内容**不被误清**；
- **T27 Firefox 端到端**：about:debugging 临时加载后重复 T26 两个用例；
- **T28 SW 存活**：复制 arm 后在 chrome://serviceworker-internals 手动 Stop 该 SW（等价入口：chrome://extensions → 「Service Worker」链接，二选一）→ 到点 alarm 唤醒并完成清除；
- 实施备注：offscreen `reasons:['CLIPBOARD']` 有已知 Chromium bug 330570363，若 T26 失败先对照该 issue 现象。

---

## WP3 — content.js 事件 isTrusted 门（owner: extension）

### 改动（4 处，均为处理函数首行 `if (!e.isTrusted) return;`）

1. Fill 按钮点击（L601-637 `#pv-fill` click）——**取密点，最高优先**；
2. overlay 条目点击（L947-951）→ selectEntry 拉取凭据；
3. overlay 条目复制按钮（L954-957 copyBtn → copyEntryPassword）；
4. Ctrl+Shift+L keydown（L1244-1250）。

### 测试

- 新 source-guard 测试（仿 sender-auth.test.js L105-120 的逐字拷贝守卫模式）：断言 4 处 handler 源码含 isTrusted 检查且位于任意 `chrome.runtime.sendMessage`/`copyEntryPassword` 调用之前。
- **回归排查**：grep 既有测试对这 4 个 handler 的 DOM 事件模拟——jsdom 派发的事件 isTrusted 恒为 false，若有既有测试派发 click/key 到这些 handler，测试内用 `Object.defineProperty(ev, 'isTrusted', {value: true})` 注入后断言不变。

---

## WP4 — `.screen` 居中裁切修复（owner: frontend）

### 改动（`src/styles/base.css:76-87`）

- `.screen` 的 `justify-content: center` → `flex-start`；
- 新增 `.screen > :only-child { margin: auto; }`——短内容时 auto margin 吸收自由空间恢复居中；内容超高时 margin 归零、内容从顶部可见可滚动（flexbox auto-margin 语义）。用 `:only-child` 而非 `.card`（评审 P2）：`.screen` 共 5 个消费方，还包括 App.tsx:81（`.loading`）与 App.tsx:92（`.fatal-error`）——后者已自带 margin:auto 不受影响，前者原本靠 justify-content 居中，必须一并覆盖。
- 影响面核对：SetupScreen:37 / UnlockScreen:59 / RecoveryScreen:36（子元素均为 `.card`）+ App.tsx:81/92；screens.css 无 `.screen` 覆写；components.css 的 `.card` 无 margin/overflow 冲突。`.screen-shell`（其余 6 屏）不动。

### 测试/QA

- jsdom 无法断言布局：不写伪测试。
- `qa_manual_v1.2.0.md` 追加（沿用 T 编号，现为 T23）：
  - **T24** 短内容居中回归：Setup/Unlock/Recovery 三屏 + App 启动 loading 态在正常窗口下视觉仍居中；
  - **T25** 溢出可达性：窗口高度拖到最小（500px），打开恢复密钥展示 + 确认输入屏，首屏字段可见、可滚动到顶。

---

## 门禁（全部通过才算完成）

```bash
cd src-tauri && cargo fmt --check && cargo clippy --workspace --all-targets && cargo test --workspace
cd extensions/native-host && cargo test
cd .. && cargo deny --manifest-path src-tauri/Cargo.toml --config deny.toml check
cargo audit --file src-tauri/Cargo.lock && cargo audit --file extensions/native-host/Cargo.lock
pnpm typecheck && pnpm lint && pnpm test
```

## 发版步骤（门禁通过后）

1. CHANGELOG.md 新增 `## [1.3.1] - 2026-10-25`：**Security** 节（rustls 升级、zip allowlist 理由与期限、扩展剪贴板清除重设计 + clipboardRead 权限说明、isTrusted 门）、**Fixed** 节（剪贴板清除失效、屏幕裁切）、**Changed** 节（manifest 权限、minimum_chrome_version）。
2. `./scripts/bump-version.sh 1.3.1`（同步 10 处；**不带 `--changelog`**——脚本会无条件插入 `## [1.3.1]` 标题造成重复（评审 P3），CHANGELOG 条目在第 1 步手写）。
3. 提交：`fix(security): v1.3.1 — clipboard auto-clear moved to background, isTrusted gating, .screen overflow fix, rustls bump`（WP1-4 + CHANGELOG + allowlist 文档 + QA 条目一并列内）；随后 `release(1.3.1): version sync` 版本同步提交（沿 189be2c 先例分开或合并，以 CHANGELOG/版本分离清晰为准）。
4. 仓库另有 CHANGELOG.md 一处未提交的空行删除（遗留），并入本次提交。
5. `git tag v1.3.1 && git push origin main --tags` → CI 构建并自动提交 updater feed（bot 完成，无需手动）。
6. 监控 CI：`gh run watch` 至四 job 全绿，确认 Release 产物与 latest.json feed 提交出现。

## 非目标（明确不做，属 v1.3.2+）

handshake 版本暴露收敛、content.js Shadow DOM 迁移与配色换装、Light 对比度/focus-within/toast 位移等 UI P2 批、VaultError 序列化消毒、扩展 ESLint、tauri-plugin-updater/wry 升级（v1.4.x 跟进）。

## 风险与回滚

- WP2 是唯一行为重设计：Chrome offscreen 与 Firefox event-page 双路径都必须有自动化测试兜底；回滚 = revert 单个 fix commit。
- WP1 的 clipboard-win 升级为 Windows-only 传递依赖，本地无法运行 Windows 测试，靠 CI Windows job 验证。
- zip allowlist 是带期限的显式风险接受，2026-12-31 到期自动 fail，强制在 minor 轨道完成插件升级。
- WP2 已知接受的残余风险（评审 P2，业界同类同病，在 CHANGELOG 说明、不另行处理）：30s 窗口内浏览器整体退出 → alarm 与 session 存储同灭，密码留存剪贴板；复制后 popup 瞬间关闭存在 arm 消息未送达的竞态窗口，此时 toast 未及展示、无承诺被打破。
