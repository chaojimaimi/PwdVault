# v1.6.1 实施方案 — v1.6.0 真机验收修补（确认框错误通道 + 字段值懒加载 + 输入卫生）

状态: **R3 — plan-reviewer PASS**（2026-10-27；R1 REVISE 2×P1+2×P2 → R2 REVISE 1×P1 合并残留 + 3×P3 → R3 全部并入后正式 PASS）
日期: 2026-10-27
范围: 纯前端（ConfirmationModal / EntryScreen / useCustomFields / CustomFieldsEditor / components.css + 测试）；**无 Rust 改动**
基线: main @ d5e885c（v1.6.0 已发布）。测试基线：前端 572/75 CI-true / Rust 434+1 / native-host 23。
来源: v1.6.0 真机验收 T45 首轮反馈（3 条发现，已主代理代码级定位）。

---

## 0. 根因（已代码级实证）

- **R1【P1·真 bug】确认框吞错误**：编辑保存被后端校验拒绝（重复/空 label——后端行为正确）时，`onConfirmSave` 把错误写入主表单顶部的 `.error-message`（EntryScreen.tsx:540），而 `ConfirmationModal` **没有 error 显示通道**且失败时保持打开（行为正确）——错误文字在弹窗半透明遮罩后面，用户完全不可见。真机表现为"无法保存成功，也没有任何提示"。
- **R2【设计缺陷】编辑态值不可见引发"没保存"误判**：自定义字段值沿用 notes 的按需加载纪律（打开编辑页不解密进表单，值随主密码眼睛 / Load notes / 保存守卫取值三条既有通道才载入，useCustomFields.ts:118-127）。真机上"重进看到空框"被读成"没保存"。纪律本身有依据（值是密文，自动加载会改变 last_used_at 语义），但缺一个**就近的加载触发**：用户对着 Custom Fields 区域交互时，没有任何路径提示值需要加载；行内眼睛在值未加载时点了只是"空显形"（toggleRevealed 是纯本地状态，CustomFieldsEditor.tsx 的 revealed Set）。
- **R3【P3·样式】**：CustomFieldsEditor 与 GroupSelector/TagsEditor 挤在同一个 `.form-group` div（EntryScreen.tsx:714-723），"Custom Fields" 小节标题紧贴 Tags 行，与其它小节的垂直节奏不一致；value 输入框未关浏览器拼写检查（真机可见 "Safawetsagsa" 的拼写红线，对 token/key 类内容不该开）。

## 1. 修复设计

### F1（P1）ConfirmationModal 错误通道

- `ConfirmationModal` 加 `error?: string | null` prop；渲染位置在 `.confirm-changes-list` 与 `.confirm-modal-footer` 之间：`{error && <div className="error-message confirm-modal-error" role="alert">{error}</div>}`（复用既有 `.error-message` 全局样式——components.css:237，弹窗内复用安全；`confirm-modal-error` 只补 margin）。
- EntryScreen 传 `error={showConfirmation ? error : null}`；**主表单错误横幅同步加抑制**（评审 R1 P2）：`{error && !showConfirmation && (<div className="error-message" …>)}`（EntryScreen.tsx:540）——同一条错误在弹窗打开时只显示在弹窗内，弹窗 Cancel 后回落主表单显示。不存在双显/双 role="alert"。**悬空引用同步门控（评审 R2 P3）**：三处 `aria-describedby={error ? "entry-error" : undefined}`（EntryScreen.tsx:559/618/636）改为同条件 `error && !showConfirmation ? "entry-error" : undefined`，避免横幅被抑制期间引用不存在的节点。
- 失败时弹窗保持打开 = 现状（`setShowConfirmation(false)` 仅在成功路径，EntryScreen.tsx:435），不动；错误可见后用户可 Cancel 回表单修正（checkbox 状态保留）。
- 消费方核实（评审 R1 P3 纠正）：EntryScreen 是 ConfirmationModal 组件的**唯一**组件级消费方；SettingsScreen:519（revoke）、SyncSettingsSection:565（disconnect）等是各自手搭 AccessibleDialog + `.confirm-modal` 类名，不消费该组件——可选 prop 天然零波及。

### F2（P2）校验错误文案端到端可读（传输形状按评审纠正）

- **真实传输形状（评审实证，v1.3.2 起）**：VaultError 手写 Serialize 把**所有变体**序列化为 `public_message()` 字符串（error.rs:66-75，"single shape for every transport"）；`InvalidInput` 的公开文案是 `format!("{}: {}", code, message)`（error.rs:201，有测试钉死该 serde 形状）→ Tauri invoke 拒绝值就是字符串 `"DUPLICATE_CUSTOM_FIELD_LABEL: Duplicate custom field label"`，前端 nestedMessage 对 string 原样返回。R1 方案的对象 mock 是虚构契约，作废。
- **修法（前端窄剥离）**：`errorMessage` 对命中 `/^[A-Z][A-Z0-9_]+: /` 且剩余部分非空的字符串剥掉码前缀（errorMessage.ts 顶层一处，约 4 行）——用户看到 "Duplicate custom field label"。这是对 v1.3.2 以来所有校验类错误显示的全局改进（CQ-P2a"消灭枚举名错误"的收尾）；Display 形状（日志）不动。
- **连带**：worker 跑全量前端套件，若有既有测试钉了带前缀文案 → 属预期改进，更新断言（逐条列出）； errorMessage.test 补剥离正反例（全大写下划线前缀剥/剩余为空不剥/普通大写开头的句子不剥——"Note: this" 不匹配因为 Not 后小写？正则限定全大写+下划线才剥，写清边界）。
- 仍无 Rust 改动。

### F3（P2）字段区域首次交互懒加载已存值

- `useCustomFields` 控制器新增 `loadValues(): void`：编辑态且 `originalCustomFields === null` 且 summary 带已存字段（meta 行 > 0）时，走一次 `get_entry_secret` 并按 mergeLoadedCustomFields 语义填充（fillMissingValues 只填未触碰行，用户已输入的内容绝不被覆盖）。不满足条件时 no-op。
- **失败退避（评审 R1 P3 采纳）**：API 形态 `loadValues(trigger: "focus" | "explicit")`（评审 R2 P3 采纳——避免退避门控误伤意图路径）：取值失败置 `suppressAutoLoad` ref，**仅 "focus" 触发受退避门控**；`"explicit"`（眼睛 F4）与保存守卫不受影响，重进条目即重置。
- **触发点**：EntryScreen 的 Custom Fields 容器 div 加 `onFocusCapture={loadValues}`——点进/Tab 进该区域即触发（不依赖点击聚焦按钮的浏览器差异）。**键盘遍历 posture（评审指出，注释载明接受）**：Tab 途经字段区即解密已存值并 bump last_used_at——与 notes 的显式按钮不对称，但用户此刻已在条目编辑器内、金库已解锁，按需解密比例与 reveal 同级；接受并注释。
- **与保存守卫共享 in-flight**：hook 内 promise ref 承载唯一进行中的取值；`loadValues` 与 `resolveForSave` 守卫分支（:188-193）共用同一条——focus 触发后立刻 Save，`resolveForSave` 返回**同一个** promise，全程恰一次 `getEntrySecret`（不破坏 v1.6.0 busy-lock 测试语义）。
- create 表单天然 no-op（selectedEntry 为 null）。

### F4（P2）行内眼睛先加载再显形

- `CustomFieldsEditor` 加可选 prop `onRevealRequest?: () => void`；行内眼睛 onClick 先调它再 toggleRevealed（EntryScreen 接 `loadValues`）。未加载时点眼睛：框立即解除掩码，值在取值返回后由 fillMissingValues 填入；已加载时行为与现状一致。
- **失败态（评审 R1 P3，明示接受）**：取值失败时框停在"已解掩码 + 空"，错误经 onFetchFailed 落主表单错误区（此时无弹窗遮挡、可见）；用户此时键入的值被保存守卫的整替语义照发（fillMissingValues 不覆盖已输入行）——失败态语义写进编辑器注释，不加 loading 占位（延迟为本地局域网级，占位徒增状态机）。

### F5（P3）输入卫生与布局节奏

- 字段 label/value 输入框加 `spellCheck={false}`（value 是关键；label 顺带）。`autoComplete="off"` 已有。
- CustomFieldsEditor 移出 GroupSelector/TagsEditor 的共享 `.form-group`，独立成 `<div className="form-group">`（EntryScreen.tsx:714-723 一处结构改动），恢复小节间距节奏。目检两主题；TagsEditor 与 GroupSelector 的现有测试不受影响（组件本身不动）。

### F6（P1 配套）EntryScreen 行数预算（评审 R1 P1）

- EntryScreen.tsx 现 799 行顶格，F1/F3/F4/F5 合计约 +6~8 行 → 必超 800 硬上限。
- **抽取预案（现成先例）**：`detectChanges`（EntryScreen.tsx:47-154，约 108 行，已是导出纯函数、有独立测试矩阵）整体 verbatim 移入新模块 `src/screens/entryChanges.ts`，预算一次腾足；消费测试仅**拆分导入行**（合并命名导入 `import { detectChanges, EntryScreen } from "../EntryScreen"` 拆为两条，断言零改动）。禁止 re-export shim（双入口漂移面）。

## 2. 实施与测试

单 worker 实施（表面小）。测试清单：

- **F1**：EntryScreen.customFields.test 增"重复 label 保存被拒 → 错误显示在弹窗内（dialog 内 findByText）、弹窗保持打开、checkbox 保留、主表单横幅在弹窗打开期间不渲染（`!showConfirmation` 抑制）、Cancel 后回落主表单显示"。
- **F2**：同一用例用**真实传输形状** mock——`mockRejectedValue("DUPLICATE_CUSTOM_FIELD_LABEL: Duplicate custom field label")`（字符串，public_message 形状）——断言弹窗显示剥前缀后的 "Duplicate custom field label"。errorMessage.test 补剥离矩阵：全大写下划线前缀剥且剩余非空才剥；剩余为空不剥（整体保留）；普通句子（含冒号空格但前缀非全大写）不剥。既有断言若钉了带前缀文案 → 属预期改进，逐条更新并列出。
- **F3**（防恒真，评审 R1 P2）：用 `fireEvent.focus` **显式**触发（jsdom 的 change/click 不派发 focus，全仓无先例，必须写明）；时序钉死——点 Save **之前**先断言 getEntrySecret 已 calledOnce（证明 focus 触发生效，而非 Save 守卫兜底），再用 v1.6.0 的 fetchGate 手动释放模式：focus 取值卡住 → 点 Save → 断言仍 calledOnce（共享 promise）→ 释放。另盖：无已存字段/已加载/create 表单 → 不发请求；失败一次后后续 focus 不再发（退避）；**失败退避后点眼睛（explicit）仍发请求**（trigger 形态负例，评审 R2 P3）。
- **F4**：未加载条目点行内眼睛 → 触发一次取值 + 框解除掩码 + 值到达后填充。
- **F5**：value 输入 `spellcheck=false` 断言（DOM `input.spellCheck`）；布局目检归 QA。
- **F6**：EntryScreen.tsx ≤800 行硬断言不入测试（行数纪律），worker 汇报实测行数；entryChanges.ts 抽取后 detectChanges 测试矩阵全绿（只改导入路径）。
- 全量 `pnpm typecheck`（**三 tsconfig 脚本**——v1.6.0 的坑 #9）+ `pnpm test`（572/75 基线只增不减）+ `pnpm lint`；Rust/native-host 不动不重跑（干净门禁阶段照常全量）。

## 3. 门禁与发版

干净 worktree 全量门禁（含 native-host sidecar 预构建、web-ext lint、真实 CI-true 计数）→ AGENTS.md/CHANGELOG/qa_manual（T52）→ bump 1.6.1 → 发版序列。**发版等用户明确"发车"指令。**

## 4. 非目标

- 不改整替保存语义与四代链（无 Rust 改动）。
- 不做"打开编辑页自动解密全部值"（posture 变更，维持按需纪律）。
- 不动 diff 确认框的掩码/内容形态（截图三的展示被确认为符合设计：secret 行掩码、非 secret 行明文）。
- CSV 导入、扩展侧不受影响。
