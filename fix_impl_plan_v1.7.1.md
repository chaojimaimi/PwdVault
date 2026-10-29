# fix_impl_plan_v1.7.1 — 解锁屏矮窗口提示重叠修复（CSS-only patch）

状态：R2（R1 评审 PASS：1×P2 过时注释同步 + 2×P3 折叠——hint 侧距用 padding 4px 精确复现原 28px、T56 加"探测落定卡片轻微上移属预期"）
日期：2026-10-30
来源：真机 QA（T55 提前触发，用户截图）：锁屏窗口向上拖矮后，底部恢复密钥
提示与 Use Touch ID 按钮重叠。版本 v1.7.1（patch）。

## 0. 根因（两个叠加的布局缺陷，均在 src/styles/auth.css）

- **缺陷 A（重叠的直接原因）**：`.auth-hint` 是 `position: absolute; bottom: 16px`
  （auth.css:381-384），完全脱离文档流。`.auth-screen` 是 `overflow-y: auto`
  的 flex 列，窗口矮于卡片内容时卡片溢出滚动，绝对定位的提示悬浮在卡片内容
  之上 → 与 Touch ID / Forgot 链接重叠。jsdom 全盲（T55 门禁项的原因）。
- **缺陷 B（截图暴露的潜在回归）**：`.auth-screen > :only-child { margin: auto }`
  （auth.css:86-88）是三屏的垂直居中机制。Unlock 屏在探测返回后渲染
  `[.auth-card, .auth-hint]` 两个子元素（UnlockScreen.tsx:71/147/153），`:only-child`
  停止匹配 → 卡片 auto margin 失效 → **正常高度的解锁屏卡片也顶对齐**（不再
  垂直居中）。Setup/Recovery 无提示、单子元素，不受缺陷 B 影响。
- DOM 结构已核实：三屏 error-message 均在 .auth-card 内部（非 screen 子元素）；
  hint 仅 Unlock 渲染，且两态各渲染一个（`null` 探测中不渲染——此时单子元素，
  缺陷 B 同样命中，但窗口短暂无感知）。

## 1. 修复（纯 auth.css，两处；组件 TSX 零改动）

- **替换 auth.css:86-88** `.auth-screen > :only-child { margin: auto }` →
  `.auth-screen > .auth-card { margin: auto }`。语义：单子元素屏（Setup/Recovery）
  行为不变（等价匹配）；双子元素屏（Unlock）卡片 auto margin 在列方向居中，
  剩余空间分配到卡片上下 auto margin → 提示被自然推到真实底部。溢出时 auto
  margin 解析为 0（flexbox auto-margin 安全退化，不会产生 flex 居中裁顶问题），
  内容从顶部开始随 overflow-y: auto 滚动。
- **重写 .auth-hint 定位**（auth.css:380-393）：`position: absolute; bottom/left/right`
  → `position: static; flex: none; align-self: stretch; margin-top: 16px;
padding: 0 28px;`。`align-self: stretch + padding 0 28px` 与原 left/right:28px
  等宽语义一致（内层 flex 的 justify-content: center 继续居中图标+文案组）；
  底部间距由 .auth-screen 既有 padding（--space-xl 24px）承担（原 bottom:16px，
  差 8px 属可接受视觉差）。提示进入文档流后与卡片永不重叠；矮窗口下随内容
  滚动可达。
- **保留**：max-height: 560px 的 11.5px 降级、图标色两态、strong 样式、
  three-state 探测渲染逻辑（TSX 未动）。徽章/卡片/字段样式零改动。

## 2. 验证与发布

- `pnpm typecheck` + `pnpm test`（基线 694/82，纯 CSS 零用例变化）全绿。
- 布局行为 jsdom 不可测 → **QA T56**（qa_manual 追加）：真机两主题 ×
  {正常高度, 最小 500px} × {未启用, 已启用}：卡片垂直居中（缺陷 B 的验收——
  正常高度下 Unlock 卡片应与其他两屏一致居中）、提示位于 Touch ID/Forgot
  下方不重叠、矮窗口可滚动到提示。
- react-reviewer 审查（CSS 语义 + 三屏影响面）；干净 worktree 全量门禁
  （694/82 + Rust 449+1 + native-host 23 + web-ext lint）→ bump v1.7.1 →
  release commit + tag → push → 盯 CI → feed 同步 → 资产验签。
- CHANGELOG 1.7.1 Fixed 条目；AGENTS.md 版本行 + session log 紧凑条目 +
  基线不变说明。
