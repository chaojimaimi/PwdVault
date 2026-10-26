# v1.5.1 实施方案 — v1.5.0 验收 UI 修补（flex 基准宽陷阱 ×3 + Trash 返回钮）

状态: R3 — plan-reviewer 终审 PASS（R1 REVISE 1×P1 选择器矛盾 → R2 REVISE Fix D 覆盖面 → R3 PASS；sweep 留档 modal-footer 措辞按终审 P3 更正为"稳定等分形态、非显式意图"）
日期: 2026-10-26
范围: 纯前端（VaultScreen.tsx + DashboardScreen.tsx + vault.css/settings.css + 测试）；
无 Rust / 扩展改动

## 1. 背景（真机验收三反馈的判定）

v1.5.0 真机验收（T38/T39 现场）三条反馈：

1. 搜索框与 Recent 宽度不一致 → **设计如此，不改**（`.search-input-wrapper
{ flex: 1 }` + `.sort-select { flex-shrink: 0 }`，vault.css:352-358，搜索优先
   布局，对标 1Password/Bitwarden）。
2. **Security Dashboard summary 排版崩坏（真 bug）**：文字被挤成一列一词、
   Re-run check 按钮冲出右缘。根因 = v1.2.2 老陷阱复发：`.btn { width: 100% }`
   （components.css:37）把 `.dashboard-rerun` 的 flex 基准宽撑到 100% 容器宽，
   中间无 flex 约束的文字 `<div>`（DashboardScreen.tsx:123）被压成 min-content，
   按钮自身溢出（icon + 100% + gap > 容器）。
3. Trash 视图返回路径（交互设计如此，v1.4.1 方案 A：toggle + All 返回）——
   **但截图暴露同款真 bug**：Empty trash 按钮被拉成横贯整行的色块（
   `.trash-header h2 { flex: 1 }` 的 space-between 意图被 `.btn width:100%`
   基准宽击败，h2 只剩一词）。用户两轮验收均点名返回问题 → 本班恢复 Back 钮
   （用户决策权项，主代理代为拍板：跟随用户反馈）。

jsdom 无布局——以上 CSS 陷阱自动化测不出，真机首开现形（v1.2.2 同款教训）。

## 2. 修改内容

### Fix A：Dashboard summary 行（真 bug）

settings.css：

- `.dashboard-rerun` 加 `width: auto;`（scoped 压制全局 `.btn` width:100%，
  v1.2.2 同款修法）；
- 中间文字容器加类名 `dashboard-summary-text`（DashboardScreen.tsx:123 的裸
  `<div>`），规则 `flex: 1; min-width: 0;`——正常吃剩余宽度、可换行、不再被
  挤成一词一列。

### Fix B：Trash header Empty trash 按钮（真 bug）

vault.css：`.trash-header .btn-danger { width: auto; flex-shrink: 0; }`——
**选择器收窄到 .btn-danger（R1 评审 P1 收编）**：原拟的 `.trash-header .btn`
特异度 (0,2,0) 会覆盖 `.btn-icon { width: 40px }`（components.css:86-88，
特异度 0,1,0），推翻 Fix C 的定宽论证。按钮回归内容宽、贴右；h2 保持
`flex: 1`。

### Fix C：恢复 Trash 返回钮（用户决策项）

VaultScreen.tsx trash-header 恢复 v1.4.0 三件套布局：

```jsx
<div className="trash-header">
  <button className="btn btn-icon" onClick={() => setTrashOpen(false)}
          title="Back to passwords" aria-label="Back to passwords">
    <BackIcon />
  </button>
  <h2>Trash</h2>
  <button className="btn btn-danger btn-sm" …>Empty trash</button>
</div>
```

- 替换 v1.4.1 的"no Back button"注释为新说明：tab toggle 仍是返回通路，
  Back 钮是显式可见 affordance（两轮真机验收用户点名）。
- Trash tab 的 toggle 行为**保留不变**（无分组时它仍是唯一返回通路）。
- BackIcon import 恢复。
- `.btn-icon` 的 40px 定宽（components.css:86-88）不受 Fix B 影响（选择器已
  收窄到 .btn-danger），Fix C 的安全性论证成立。

### Fix D：`.security-status-row` 同款陷阱（R1 评审 sweep 实锤，同批修）

settings.css:164-169 `.security-status-row`（flex、无压制）内的按钮同样被
`.btn width:100%` 拉满整行，与本班已判定的 trash-header bug 同构（Settings →
Security 区 "Enabled" badge 与 Disable 钮同行）。**R2 复审指出该类为共享类，
全库 9 处命中，其中 SyncSettingsSection 的三行（:276 单 Retry、:323 Sync Now

- Disconnect、:442）也在选择器作用面内**——它们是同一机制的产物，且"50/50
  等分属有意模式"的说法在代码库中无任何佐证（无注释、无 DESIGN.md 依据）。
  按评审方向 B 统一处理：`.security-status-row .btn { width: auto;
flex-shrink: 0; }` 一条规则覆盖全部命中行，按钮统一回归内容宽（纵向表单
  面板内的标准形态，内容宽合计远小于面板宽，无溢出风险）。

**sweep 其余结论（显式不改，记录在案）**：modal-footer 双钮等分是两枚
basis-100% 按钮等比收缩的**稳定等分形态**（涌现行为，非显式规则意图；
components.css:317-322 仅 flex+gap，不受 Fix D 影响）；`.option-row`
内文字+按钮两侧收缩为可接受形态；`.entry-actions`/`.confirm-modal-actions`
有显式 flex:1 意图（screens.css:50-52 / components.css:468-470）；CSV 导入
按钮用 `btn-full` 属有意全宽——均非活陷阱。

### 权衡说明（为何继续 scoped 压制而非根治）

这是第 5、6 处 `.btn width:100%` 的 scoped 压制（先例 components.css:159-166、
groups.css:69-74/115-121）。根治方案（全局 width 改 opt-in `.btn-full`，类已
存在于 settings.css:70-73）会波及全库每个按钮位，属独立重构——本班取最小
改动，根治记为将来独立事项。

## 3. 测试

- VaultScreen.trash.test.tsx：
  - 新增/恢复 "returns to the main list via the Back button" 用例
    （getByLabelText("Back to passwords") 点击 → 搜索框重现、回收站卸载）；
  - 既有用例全部保持（tab toggle 返回、搜索隐藏断言等不动）。
  - §5 悬问已了结（R1 评审实证）：全库无 "no Back button" 负向断言（唯一负向
    是 `queryByLabelText("Open trash")`，钉旧搜索栏图标钮）；toggle 与 Back
    无逻辑冲突。
- DashboardScreen.test.tsx：三元素共存断言**并入既有首个渲染用例**（R1 评审
  P3 收编——已有 "4 passwords scanned" 与 Re-run 点击断言，不新增独立用例）。
- 布局本身 jsdom 盲区 → qa_manual 追加 T44：仪表盘 summary 单行 sanely 排列
  （图标左、文案中、按钮右不溢出）、Empty trash 内容宽贴右、Security 区
  status 行不再出现满宽按钮、**Cloud Sync 区（Retry / Sync Now + Disconnect）
  按钮回归内容宽后布局正常**、两主题各看一眼。

## 4. 非目标

搜索框/Recent 宽度（设计如此）；dashboard 列表行样式（截图正常）；`.btn`
全局根治重构（记为将来独立事项）；任何 Rust/扩展改动。

## 5. 风险

- `.btn width:100%` 的 scoped 压制只作用于三个窄选择器（`.dashboard-rerun`、
  `.trash-header .btn-danger`、`.security-status-row .btn`）。Fix D 的作用面
  （Security + Cloud Sync 区按钮统一内容宽）是 R2 复审确认后的**有意决策**
  而非误伤；其余 sweep 结论见 §2。
- Back 钮回归后 trash-header 三元素在 400px 窗口内的排布（40 + 文案 + 按钮
  ≈ 200px，余量充足，无饥饿风险——Empty trash 已 width:auto）。

## 6. 门禁与发版

- 本地：`pnpm typecheck` + `pnpm test` + `pnpm lint`（无 Rust/扩展改动）。
- **独立审查（R1 评审 P2 收编，对齐 v1.4.1 先例）**：react-reviewer 审查
  全部 diff，APPROVE 后才进提交。
- 提交：`fix(ui): dashboard summary and trash header flex layout + explicit
trash back button`（含本方案）；commit-gate 两命令仪式。
- 发版：CHANGELOG [1.5.1]（Fixed 三项 + Restored Back）→ bump 1.5.1 + 双锁
  验证 → release 提交 → AGENTS 头部/会话日志一行 + qa_manual T44 → docs
  提交（**Rust/native-host 基线不变，前端计数随新增用例更新**）→ tag v1.5.1
  → push → **盯 Release + Quality Gates + feed**。

## 7. 审查要点（R1 评审已答，留档）

1. 选择器精准性 → Fix B 收窄为 `.btn-danger`；sweep 结论已回写 §2 Fix D。
2. Fix C 与 v1.4.1 决议 → 用户反馈驱动的反转，toggle 保留、无逻辑冲突、
   无测试冲突（评审实证）。
3. 测试钉双通路（Back 返回 + toggle 返回）→ §3。
