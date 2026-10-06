# v1.2.2 实施方案（手动更新检查 + Tags/分组行布局修复）

**日期**：2026-10-06 · **基线**：`main @ 455dca1`（v1.2.1 + feed）· **目标**：v1.2.2（patch：一项功能 + 一项 UI 修复）
**流程**：标准全流程（本方案 → plan-reviewer 至 PASS → ds-worker 实施 → 主代理复审 + code-reviewer → 全量门禁 → 发版）
**修订**：R2（评审 1 P1 + 2 P2 + 2 P3：downloading/ready 守卫、自动路径对称 close、交错策略、select 态波及声明、行号与挂载位修正）；R3（按钮禁用条件同步至 §1.3/测试清单、测试 7 扩 downloading+ready 两态、计数更新）
**内容确认**：用户已确认两项内容；设计决策①（手动检查**不受** "Check on startup" 开关约束，开关只管自动路径）按推荐方案落定。

---

## 1. 功能：设置页手动"Check for updates"

### 1.1 设计要点（沿用已确认设计）

- 解决自动检查三盲区：仅启动一次（长驻托盘等不到）、锁定态不触发、失败静默。
- 手动检查：显式、有反馈、可重试；失败**可见**（与自动路径的静默策略相反，这是本功能核心价值）。
- 隐私不变量保持：设置页仅解锁后可达，天然满足"解锁后才联网"；零后端改动、零新依赖。

### 1.2 SettingsContext.tsx 改动

1. **新状态**（SettingsState 增加字段 + reducer action）：
   ```ts
   manualCheck: {
     phase: 'idle' | 'checking' | 'available' | 'uptodate' | 'error';
     checkedAt: number | null;   // Date.now()，用于 "checked HH:MM" 文案
     version?: string;           // phase==='available' 时携带
   }
   // action: { type: 'SET_MANUAL_CHECK'; payload: 上述对象 }
   ```
   RESET 时归位 `{ phase: 'idle', checkedAt: null }`。
2. **新常量**：`MANUAL_UPDATE_CHECK_TIMEOUT_MS = 15000`（注释：自动 5s 不阻塞启动；手动用户在等，放宽到 15s）。
3. **新 action `checkForUpdates()`**（settingsActions 增加，useMemo 依赖相应补）：
   - 守卫：`phase === 'checking'` 直接 return（防重复触发）；**`updatePhase === 'downloading' || 'ready'` 同样直接 return 并由 UI 禁用按钮**（评审 P1——下载中途重查会 close 在途 Update 句柄、'ready' 态重查会把已就绪安装翻回重下载；手动检查是首个能在下载中触发 close 的路径，必须从守卫层杜绝）；
   - 置 checking → `check({ timeout: MANUAL_UPDATE_CHECK_TIMEOUT_MS })`；
   - **发现更新**：若 `updateRef.current` 存在先 `void old.close()`；`updateRef.current = update`；dispatch SET_UPDATE（复用现有横幅状态与 install/relaunch/dismiss 流）+ SET_MANUAL_CHECK available(version)。**绕过 DISMISSED_UPDATE_KEY**（显式询问给完整答案），且**不写入**该键（自动路径行为不变）；**不动 `checkedThisStartup`**（与自动首查正交）。
   - **无更新（null）**：若 `updateRef.current` 存在 close + 置 null + dispatch SET_UPDATE null（显式检查的最新事实覆盖旧横幅）+ SET_MANUAL_CHECK uptodate。
   - **失败（catch）**：SET_MANUAL_CHECK error（**不清除**已存在的横幅/下载状态——失败只说明本次没查到，不推翻既有事实）。
4. 现有 installUpdate/relaunchApp/dismissUpdate 零改动——除一处对称补丁：**自动检查路径的 `updateRef.current = update` 前同样 close 旧值**（评审 P2——交错下自动后返回会覆盖手动先置的 ref 且不 close，泄漏句柄；单行对称修复，自动路径其余行为不变）。
5. **交错策略声明**（评审 P2）：自动/手动并发时最后写入者胜；手动瞬时失败（null/error）清横幅属可接受语义（用户可再查，显式动作给最新事实）。

### 1.3 SettingsScreen.tsx 改动（Updates 区，现 :187-203）

1. **在 BackHeader 之后、内容 fieldset 之外**挂载现有 `<UpdateNotification>`（`state.update` 存在时，props 与 VaultScreen.tsx:108-115 用法一致）——复用同一安装流，不做第二套 UI。⛔ 不得挂在 Updates section 内部：内容区位于 `disabled={status !== 'success' || saving}` 的 fieldset（SettingsScreen.tsx:116-119）内，横幅按钮会被连带禁用（评审 P3）。
2. Updates 区新增（沿用 option-row/settings 既有类与风格）：
   - **版本行**：`Current version: {ver}`——`useEffect` 内 `import { getVersion } from '@tauri-apps/api/app'` 取一次存 state（动态 import 与仓库现有用法一致；测试 mock）。
   - **按钮**：`[ Check for updates ]`（`btn btn-secondary`），**`manualCheck.phase === 'checking'` 或 `updatePhase === 'downloading' / 'ready'` 时禁用**（与 §1.2.3 守卫同步——下载中/就绪态禁点击而非死点击）、checking 时文案 "Checking…"。
   - **状态行**（`aria-live="polite"`，新 CSS 类 `.update-check-status`，muted 小字）：
     - checking: "Checking for updates…"
     - available: "Update available: vX.Y.Z — use the banner above to install"
     - uptodate: "You're up to date (v{当前版本}) — checked {HH:MM}"
     - error: "Couldn't reach the update server — check your connection and try again"
   - 按钮点击 → `actions.checkForUpdates()`；按钮**不受** `check_updates` 开关禁用（决策①；开关行文案不变）。
3. `settings.css`（或 components.css，按现有归属）：`.update-check-status { font-size: var(--text-label); color: var(--color-text-muted); }` 一条即可。

### 1.4 测试（jsdom；预计 +9~12 条）

- **SettingsContext 层**（现有测试文件追加；mock `@tauri-apps/plugin-updater` 的 `check`，Update 对象带 `close` spy）：
  1. 返回 update → SET_UPDATE 置位 + manualCheck available + 旧 updateRef 被 close；
  2. 返回 null → uptodate + 旧横幅清除 + 旧 ref close；
  3. reject → error 态 + **既有** update 状态不被清除；
  4. checking 期间重复调用被守卫；
  5. 预置 `DISMISSED_UPDATE_KEY='9.9.9'` 且返回 9.9.9 → 横幅仍展示（绕过 dismiss）；
  6. RESET 归位 manualCheck；
  7. `updatePhase === 'downloading'` **与 `'ready'`** 两态各一断言：调用 checkForUpdates 直接 return（check 未被调、manualCheck 仍 idle、ref 未动）；
  8. 交错：先置 ref A（模拟手动已返回）→ 再跑自动检查返回 B → 断言 A 被 close 且 ref 为 B（close-before-overwrite 对称生效）。
- **SettingsScreen 层**：四相状态行渲染 + aria-live 存在 + checking **及 downloading/ready 态按钮禁用**断言 + `state.update` 存在时 UpdateNotification 挂载（mock context）+ 版本行渲染（mock getVersion）。

---

## 2. 修复：Tags/分组行输入框布局塌缩

### 2.1 根因（已诊断，截图+flex 算法证实）

`.btn { width: 100% }`（components.css:36-37，2026-05-01 主题重构引入）在 `.tag-input-row` / `.group-selector-row`（flex 行）内作为按钮基准尺寸吃掉整行 → 输入框 `flex:1`（basis 0）无剩余空间可分 → 塌缩为 padding 宽度胶囊（~50px，占位符被裁）。`group-selector-row`（新建分组内联行，input+Add+Cancel 三个 100% 元素）同族更糟。5 个月老 bug，非近期回归；jsdom 不渲染布局故测试不可见。

### 2.2 修复（纯 CSS，components.css 紧邻现有规则处）

```css
/* Flex rows pairing an input with buttons: .btn's global width:100% acts as
   the flex base size and starves the flex:1 input (basis 0, nothing to grow
   into). Undo it inside these rows — the input owns the space. */
.tag-input-row .btn,
.group-selector-row .btn {
  width: auto;
  flex-shrink: 0;
}

.group-selector-row .form-input {
  flex: 1;
  min-width: 0;
}
```

- 组件零改动；`.tag-input-row .form-input { flex: 1 }` 已存在（:913）不动。
- **声明波及**（评审 P2）：`.group-selector-row` 的 select 态（GroupSelector.tsx:59-67，select + "New" .btn-link 同行）同步受益——select 得 flex:1 占满、"New" 缩为内容宽（现状两者各 ~50% 分行，修复后为改善）；QA 冒烟覆盖两种形态。
- 波及面核查已完成：全仓仅这两处 flex 行内出现 .form-input+.btn 组合（grep 证实）；VaultScreen 齿轮等为 icon-btn 不受影响。
- 视觉验证属人工 QA（方案 §4 清单），jsdom 无法断言布局。

---

## 3. 约束与文件域

| 文件 | 改动 |
|------|------|
| `src/context/SettingsContext.tsx`（+测试文件） | §1.2 |
| `src/screens/SettingsScreen.tsx`（+测试文件，如无则新建 __tests__） | §1.3 |
| `src/styles/components.css` | §1.3 状态行类 + §2.2 三条规则 |
| `qa_manual_v1.2.0.md` | 追加 v1.2.2 验证小节（T21 tags 输入框可见宽度/Add 后 chip、T22 手动检查四态 + 断网 error 态） |

⛔ 禁触：Rust/扩展/manifest/版本文件/其它屏幕。不 commit、不 pnpm install、不新增依赖。文件 ≤400 行为宜（SettingsContext 现约 233 行，增后应 <400）。

## 4. 验收（DoD）

- `./node_modules/.bin/tsc --noEmit` ×2 配置 0 错；`eslint src/` 0；`vitest run` 全绿（253 基线 + 新增）；
- Rust 零改动 → `cargo test --workspace` 复跑一次确认无意外波及（305+1+2 基线不变）；
- 手动冒烟（主代理复审阶段）：`pnpm tauri dev` 起 app —— ① Entries 编辑页 tags 输入框占满行宽、输入实时可见、Add 后 chip 正常；② Group 新建内联行三元素比例正常 + select 态（select 占满 / New 缩为内容宽）；③ 设置页 Updates 区：版本行、Check 按钮、四态文案、发现更新时横幅出现且 Install 流可用（可用本地 mock feed 或对照真 feed 的降级观察 error 态）。

## 5. 发版（v1.2.2）

CHANGELOG（Added: manual update check；Fixed: tags/group input layout collapse）→ `bump-version.sh 1.2.2 --changelog` → `--check` 确认 10 源 → AGENTS.md（头部版本、Session Log、测试表前端计数）→ 四对插件版本核对 → commit（修复 + 版本 + docs 三段式，commit-gate 标记纪律）→ **先 push main 等 Quality 绿 → 再 tag v1.2.2** → Release 六 job 监控（webdav 抖动则 rerun --failed）→ 确认产物与 feed 1.2.2 → 记忆收尾。

## 6. 风险与回滚

| 风险 | 缓解 | 回滚 |
|------|------|------|
| manualCheck 状态与既有 update/updatePhase 状态机互相干扰 | action 设计已定义覆盖规则（available 覆盖、error 不清除）；测试 5 条覆盖交互 | 纯前端 revert |
| Update 资源句柄泄漏（手动重查） | 旧 ref close 语义与 dismissUpdate 一致；测试断言 close 被调 | revert |
| CSS 修复影响其它 .btn 布局 | 选择器限定两行容器内；波及面 grep 已核；QA §4 冒烟两屏 | 单条 CSS revert |
| SettingsScreen 挂横幅导致双屏同显（Vault+Settings） | 两处互斥导航（一次只见一屏），同源 state 无冲突；测试断言挂载条件 | revert |
