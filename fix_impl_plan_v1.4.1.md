# v1.4.1 实施方案 — 回收站入口迁入分组 tab 行（方案 A）

状态: R2 — plan-reviewer PASS（附带条件已并入 §4.4）；react-reviewer APPROVE（P2 测试复位 + P3 Virtuoso key 已修，P3 正则换行敏感度备忘不修）
日期: 2026-10-26
范围: 纯前端（VaultScreen.tsx + vault.css + 组件测试）；无 Rust / 扩展改动

## 1. 背景与目标

v1.4.0 QA 反馈：回收站入口是搜索行右侧的纯图标垃圾桶按钮（`VaultScreen.tsx:386-393`），
语义上是"动作"（删除）而非"去处"（视图），与 Bitwarden/1Password/KeePassXC 的
"回收站 = 与分组同级的导航项（图标+文字）"惯例相悖，也与本应用"分组 tab = 列表位置"
的导航语法割裂。

目标：按已批准的方案 A，将回收站入口迁入 group tabs 行，做成右对齐固定簇中的
带文字特殊 tab "🗑 Trash"；回收站视图改为**原位渲染**（tabs 行保持可见，Trash
tab 呈 active 态），彻底消除"删除动作"歧义。

## 2. 现状（代码事实）

- `src/screens/VaultScreen.tsx:45-67` — `trashOpen` 本地 state + 惰性加载 effect（打开才拉已删列表）。
- `VaultScreen.tsx:252-358` — `trashOpen ? <trash-screen> : <>…主视图</>` 整体二选一：
  trash-screen 自带 header（Back + h2 "Trash" + Empty trash）+ 列表 + 两个 danger modal。
- `VaultScreen.tsx:361-394` — search-bar = 搜索框 + sort select + 垃圾桶 icon 按钮（本次删除该按钮）。
- `VaultScreen.tsx:396-438` — group tabs 行**条件渲染**：`groups.length > 0` 时渲染
  `[.group-tabs-scroll(All+分组 tabs)] + [gear 管理]`；`groups.length === 0` 时渲染
  独立的 `group-tabs-empty` 行（仅 "Create group" CTA）；error 时渲染重试行。
- `src/styles/vault.css:77-171` — `.group-tabs`（flex 行）、`.group-tabs-scroll`
  （flex:1 横向滚动）、`.group-tab`（含 flex-shrink:0 / .active 态）、`.group-manage-btn`
  （gear 40px 图标钮）、`.group-tabs-empty` / `.group-manage-first`（空态行）。
- 测试 `src/screens/__tests__/VaultScreen.trash.test.tsx` — 6 用例（5 trash +
  1 sort），其中 **5 处**入口用 `getByLabelText("Open trash")` 定位；断言 trash
  视图无搜索/排序控件。`VaultScreen.groupFilter.test.tsx` 是纯函数测试，不受
  JSX 重排影响。`Phase3ResourceState.test.tsx` 渲染 `groupsStatus: "error"` 的
  本屏（正是 D1 第三态重构对象）——经核对断言（"Could not load passwords."
  文本 + Retry 按钮存在）在重构后预期不变，列入回归观察。
- `Icons.tsx` TrashIcon 接受可选 `size`，currentColor 描边；**但默认
  `className='icon'` 会被 `components.css` 的 `.icon { width:24px; height:24px }`
  覆盖 size 属性**（先例：gear 靠 `vault.css` 的 `.group-manage-btn svg` 规则压到
  14px）——tab 内用 12px 必须配 CSS 覆盖，见 D6。

## 3. 方案（结构变更）

### D1 tabs 行常驻（覆盖 ResourceStatus 全部四态）

unlocked 主视图下 `.group-tabs` 行总是渲染，吸收原 `group-tabs-empty` 分支：
无分组时 "Create group" CTA（保留 `.group-manage-first` 样式，挂载点移入滚动区）
代替独立空态行。`groupsStatus` 四态规格：

- `idle` / `loading`（每次解锁必经的瞬态窗口）：行照常渲染，滚动区为空——
  Trash/gear 立即可达，不因加载闪隐藏。
- `success` 有分组：`[scroll: All + 分组…] [divider] [Trash] [gear]`
- `success` 无分组：`[scroll: Create group CTA] [divider] [Trash] [gear]`
- `error`：`[scroll: 内嵌重试行] [divider] [Trash] [gear]`（gear/Trash 始终可用；
  重试行样式适配见 D6）

### D2 右侧固定簇

新增 `.group-tabs-actions`（flex-shrink:0，gap 4px）包含：`.group-tabs-divider`
（1px 竖线，`--color-border-light`）+ Trash tab + 原 gear 按钮。gear 从 scroll 区
之后移入簇内，行为不变（handleManageGroups 不动）。

### D3 Trash tab

`<button class="group-tab group-tab-trash [active]">` = `<TrashIcon size={12}/> Trash`。

- toggle 行为：`onClick={() => setTrashOpen(v => !v)}`（无分组时没有 All tab，toggle
  是所有状态下都能返回主列表的通路）。
- active 态复用 `.group-tab.active`；`aria-current={trashOpen || undefined}` 与
  兄弟 tab 一致；无 aria-label——可见文本 "Trash" 即 accessible name
  （svg 无 title，不参与命名）。
- **图标尺寸必须 CSS 兜底**：`<TrashIcon size={12}/>` 的 width/height 属性会被
  默认 `.icon` class 的 24px 规则覆盖，故 D6 必须新增
  `.group-tab-trash svg { width:12px; height:12px; }`（与 gear 的既有压制先例同构）。
- 样式：`.group-tab-trash { display:inline-flex; align-items:center; gap:4px; }`。

### D4 导航互斥：分组 tab 与 Trash tab 不同时 active

- All / 分组 tab 的 onClick 包一层 `setTrashOpen(false)` 再 `selectGroup(...)`，
  避免"选中了分组却仍看着回收站"。
- **反向同改**：分组 tab 的 `active` class 与 `aria-current` 增加 `!trashOpen`
  条件（改为 `` `${selectedGroupId === g.id && !trashOpen ? "active" : ""}` ``
  一类），否则回收站视图下"当前分组"与 Trash 同时高亮、双 `aria-current`，
  违背导航互斥语义。All tab 同理。
- gear 无需联动（导航去 groupManager 会卸载本屏，trashOpen 随之重置）；
  selectGroup 全库仅这两个 tab 按钮调用，无遗漏入口。

### D5 回收站内容区原位渲染

外层二选一改为并列：

- search-bar 包 `{!trashOpen && …}`（回收站无搜索/排序的既有保证与测试不变）。
- `trashOpen` 时渲染原 trash-screen 内核（loading/error/empty/list + 两个
  DeleteConfirmModal 原样保留），`.trash-header` 去掉 Back 按钮（tab toggle 即返回），
  保留 `<h2>Trash</h2>` + Empty trash 按钮。
- 主列表分支不变。

### D6 CSS 清理

vault.css 新增：`.group-tabs-actions` / `.group-tabs-divider` / `.group-tab-trash`
（含 **`.group-tab-trash svg { width:12px; height:12px; }`** 图标压制规则）；
error 态重试行内嵌适配——`.group-tabs` 作用域内覆写 `.resource-error-compact`
的 `padding:0` + 左对齐（该类自带居中 padding，嵌进自带 padding 的 tabs 行会双重；
全库仅本屏一处使用，可安全覆写）。

删除：仅 `.group-tabs-empty`（独立空态行容器，被 D1 常驻行取代）。
**保留** `.group-manage-first`（零分组 CTA 样式继续用，仅换挂载点）。

`.trash-header` 移除 Back 相关布局（保持 h2 左、Empty 右的 space-between）。
全部用既有 token（--space-* / --radius-* / --color-*），两主题自动成立。

### D7 明确不做

- 不加已删条目数角标（破坏 v1.4.0 惰性加载设计，打开才拉 deletedEntries）。
- 不改 trash 内部交互（restore/purge/empty 流程与 v1.4.0 一致，T36 已验）。
- 不引入真实 tablist/tab 角色（与既有 group-tab 家族保持同一模式）。
- 扩展不动：回收站是桌面专属功能，NM API 无 trash 端点。

## 4. 测试计划

`VaultScreen.trash.test.tsx`（mock 的 groups=[] 正好覆盖无分组路径）：

1. 既有 6 用例：5 处入口定位 `getByLabelText("Open trash")` →
   `getByRole("button", { name: "Trash" })`；其余断言不变。主视图补**反向断言**
   `queryByLabelText("Open trash")` 为 null（防止旧按钮漏删时新测试静默通过——
   新旧定位器互不冲突，漏删不会被既有断言抓住）。
2. 新增 "trash tab 在零分组时可达且与 Create group 共存"：断言两个按钮同时存在。
3. 新增 "再次点击 Trash tab 返回主列表"：搜索框重现、已删列表卸载。
4. 新增 "有分组时点击分组 tab 退出回收站"：构造带 groups 的渲染变体
   （现有 holder 浅拷贝注入），断言 selectGroup 被调且回到主列表；并断言退出后
   分组 tab 恢复 active / Trash 失去 active（D4 互斥的正反两面）。
   **复审附带条件（必做）**：点击分组 tab **之前**先断言回收站打开期间的互斥——
   分组 tab 无 `active` / 无 `aria-current`（或 Trash 是唯一 active）。只断言
   "退出后恢复"钉不死 D4 反向同改的缺失（漏实现时该测试仍全绿）。
5. 新增 "groupsStatus error 时 Trash tab 与 Retry 共存"（D1 error 态是新行为
   承诺，Phase3ResourceState 只断言 Retry，不覆盖 Trash 可达）。
6. 回归观察（无断言改动预期）：`Phase3ResourceState.test.tsx` 全量通过。

跑全量 `pnpm test` 确认无回归（groupFilter 为纯函数测试，预期不受影响，仍需实跑确认）。

## 5. 风险

- **flex 饥饿**（v1.2.2 教训：`.btn` 全局 width:100% 曾饿死同行输入框）：actions 簇与
  Trash tab 必须 flex-shrink:0；`.group-tab` 已自带，`.group-tabs-actions` 新增显式声明。
- **全局 CSS 压局部标记**（本次评审实证：`.icon` 24px 规则覆盖 size 属性）：新增
  `.group-tab-trash svg` 压制规则（D6），jsdom 测不出尺寸，靠 T38 真机两主题确认。
- **横向滚动隔离**：actions 簇必须在 scroll 区之外（DOM 兄弟节点），分组多时 Trash/gear
  不被滚走。
- **可访问性**：icon+文字按钮的命名来自文本；不新增 aria-label 以免覆盖可见文本；
  导航互斥由 D4 的 `!trashOpen` 条件保证（同一集合不会双 current）。

## 6. 门禁与落地

- 本地：`pnpm typecheck`（覆盖 app + node + 测试 tsconfig；根 tsconfig 不含测试
  文件，`pnpm tsc --noEmit` 查不到测试改动）+ `pnpm test` + `pnpm lint`（无 Rust
  改动，cargo 套件不受影响；发版门禁时照旧全跑）。
- 提交：单提交 `fix(ui): trash entry becomes a pinned Trash tab in the group tabs row`
  （含本方案文档）。commit-gate：react-reviewer APPROVE 后单独 `touch .zcode/review-passed`
  再 commit（两条命令，老规矩）。
- 发版（**时机由用户定**，本方案只落地 main）：CHANGELOG [1.4.1] UI 小节 +
  qa_manual 追加 T38（Trash tab 可发现、零分组可达、toggle 返回、两主题各看一眼）+
  `bump-version.sh 1.4.1` + `cargo metadata --locked` 验锁 + 干净 worktree 全套门禁
  （sidecar 预编译前置）→ tag → CI 盯防。

## 7. 备忘（不在本版做）

- 全局快捷键（App.tsx navigate("vault") 同屏 no-op）在回收站视图下不退出回收站
  ——与现状一致、无回归；未来可让快捷键顺带 `setTrashOpen(false)`。
- 回收站视图存在 tabs 行 + trash-header（h2 "Trash"）双行、文本重复——本版接受；
  未来可把 Empty trash 并入右侧簇省掉 trash-header。

## 8. 审查要点（R1 评审已回答，留档）

1. ~~D1 三态~~ → R2 扩为四态（idle/loading 已规格化：行渲染、滚动区空）。
2. D4 联动入口：selectGroup 全库仅两个 tab 按钮调用，已全覆盖；分组 tab 的
   active/aria-current 同步加 `!trashOpen`。
3. toggle + aria-current 语义成立的前提是互斥（D4 反向同改），已成立。
4. 测试改造含反向断言（旧按钮必须消失）+ error 态可达性用例。
