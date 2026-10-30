# fix_impl_plan_v1.8.0 — 锁屏 Touch ID 自动弹出

状态：R3（R2 复审 PASS：1×P2 T57④ 措辞与实际限流契约矛盾 + 3×P3，按评审放行条件全部折叠——T57④ 与 StrictMode 注释两处不得原样落地）
日期：2026-10-30
来源：用户提案 + 主代理可行性分析（已确认：指纹框本质是 Keychain ACL 访问的
系统对话框，程序化触发零新 API；业界常态 1Password/银行 App；无安全回退——
传感器上必须有真人手指）。方案 A 定稿：**启用 Touch ID 时锁屏每次出现自动
弹一次指纹框，取消后不重弹，按钮保留作手动重试入口**。feature → minor v1.8.0。

## 0. 已核实的现状事实

- `unlockBiometric`（AuthContext.tsx:181-199）：入口 SET_LOADING true + 清 error；
  成功 postUnlock；失败分两类——`BiometricCancelled` 静默（:16-18 字符串判定），
  其余 SET_ERROR；finally 清 loading。
- `postUnlock`（:122-126）= SET_UNLOCKED true + SET_SCREEN vault，**幂等**。
- 闭包快照陷阱有案：AuthContext 自注释（:156-162）actions 闭包只看 mount 时
  state——闭包内查 `state.isUnlocked` 是空判断，需要 ref。
- 后端 `unlock_biometric`（credentials.rs:115-170）：限流 → blob 缺失拒绝（不弹框）
  → Keychain 取 wrap key（此处弹系统指纹框）→ unwrap → verify → `complete_unlock`
  → `complete_unlock_if(predicate |_| true)` 无条件发布（shared.rs complete_unlock :205-225）。
  库已解锁时同密钥重复发布无害（同 master → 同子密钥，菜单/限流副作用一致）。
- 密码变更交错时后端返回 `VAULT_STATE_CHANGED`（shared.rs VAULT_STATE_CHANGED 臂 :217-222）——这是
  唯一会产生"迟到失败污染全局 error"的真实路径（见 WP2）。
- 取消/锁定/钥匙串缺失不计限流（credentials.rs 注释原文）；仅 unwrap/header
  失败计。
- UnlockScreen 现状：bioStatus 探测（静默降级）、`showTouchId` 条件、
  `handleTouchId` → actions.unlockBiometric()、按钮 `disabled={state.isLoading}`；
  挂载时自动 focus 密码框（ref-focus-at-commit 模式）。
- initialAuthState.isLoading = true（AuthContext:46）——启动 boot 窗口期 effect
  必须等待，否则探测未回/其他操作进行中就触发。
- **关键拓扑（R1 P0 修正，原方案误判）**：`unlockBiometric` 入口 SET_LOADING true
  → `App.tsx:108-117` 以 Loading 屏**替换整棵认证屏树** → UnlockScreen 卸载。
  指纹框挂起期间密码表单**根本不在渲染树中**——"密码输入与指纹框并存"在现行
  拓扑下不存在；取消后 Loading 退场、锁屏**全新重挂**（该重挂行为是现有手动流
  的既有表现）。因此组件实例内的任何 ref 都会在重挂中销毁——"每片段一次"的
  标志位必须活在 AuthContext（provider 横跨全 App、永不随屏卸载）。
- 锁定路径走 `RESET`（AuthContext.tsx:226-231，`api.lockVault()` 后 dispatch
  RESET → initialAuthState）——reducer 新字段随 RESET 天然按锁定片段清零。
- 测试基建：UnlockScreen.security.test.tsx 以 vi.mock("../api/vault") 模式 mock
  `unlockBiometric`/`biometricStatus`/`recoveryStatus`（mock :18-21、beforeEach
  :23-27、既有取消用例 :69）——**standalone 渲染 + 静态 state mock**，只能覆盖
  组件内逻辑，覆盖不了卸载/重挂循环（R1 P1）。

## 1. WP1 — 一次-每-锁定片段标志（AuthContext）+ 自动弹出（UnlockScreen）

**AuthContext（标志位承载，R1 P0 修复）**：

- `AuthState` 新增 `biometricAutoPrompted: boolean`（initial false）+ 新 action
  `MARK_BIOMETRIC_AUTO_PROMPTED`（reducer 置 true；`RESET` 回 initial → 每次
  锁定片段天然清零——锁路径 :226-231 已核实走 RESET）；
- `unlockBiometric` 入口在 SET_LOADING 的同一批 dispatch 里 MARK（自动与手动
  调用都置位——语义 = "本锁定片段已有过一次指纹尝试"；置位在 effect 触发
  前由状态回流闸住自动重发，无时序竞态）。

**UnlockScreen（自动弹出 effect）**：

- 删除 R1 的组件 ref 方案；effect 依赖
  `[showTouchId, state.isLoading, state.biometricAutoPrompted, actions]`：
  `if (!showTouchId || state.isLoading || state.biometricAutoPrompted) return;
 void actions.unlockBiometric();`
  - 三维门控：探测确认（showTouchId）、无操作进行中（isLoading 覆盖 boot 窗口）、
    本片段未尝试过（reducer 标志位——跨卸载/重挂存活，无需 ref）。StrictMode
    说明（R2 P3 措辞修正，照此写注释）：挂载运行时 showTouchId 恒为 false
    （bioStatus 从 null 起步、探测异步），双触发的首次必然早退，保护来自
    数据流形态而非状态闸——勿写"状态闸住双触发"；
  - 取消后：Loading 退场 → 锁屏重挂 → 探测重跑 → effect 见标志位 true →
    **不重弹**；按钮路径不查标志位（手动重试永远允许）；
  - 下次锁定 → RESET 清零 → 新片段重新自动弹出。

## 2. WP2 — AuthContext 迟到失败守卫（纵深防御，按 R1 P2 改写推演）

- 新增 `const authStateRef = useRef(initialAuthState);` + `useEffect(() => {
authStateRef.current = state; })`（R1 P3 修正：commit 后赋值——渲染期写 ref
  在并发渲染下可能留下超前/回退值，且本守卫失效方向是误吞错误；异步 catch
  读取点必然晚于 commit，一拍滞后无实害）；
- `unlockBiometric` catch 扩为三段：`isBiometricCancelled → 静默`（既有）；
  `authStateRef.current.isUnlocked → 静默`；其余 SET_ERROR；
- **诚实推演（替代 R1 的"净无操作"论断）**：迟到成功/失败在现行拓扑下
  **不可达**——指纹框挂起期间 Loading 屏吞掉全部交互面，密码表单不存在，
  密码解锁无法与之并发；故本守卫是**纵深防御**，非承重墙。但若未来改变
  加载拓扑（认证屏保持挂载，roadmap 候选），两条真实危害立即激活：
  a) 迟到**成功**并非无操作——`complete_unlock_if` 经 `session.unlock_if`
  整体重建 Unlocked 并 **generation+1**（session.rs:140-152）：使在飞的 D8
  lease 失效（session.rs:430）、`last_remote_activity` 归 None（缩短配对扩展
  120s 宽限）、wrap_key 槽清空（biometric 路径随后经 credentials.rs:168 重装恢复，非持久缺失）；且 `postUnlock` 的 `SET_SCREEN "vault"` 会把
  已导航到其他屏的用户**强行拉回金库**（AuthContext.tsx:122-125，导航不幂等）；
  b) 迟到**失败**（如密码变更交错的 VAULT_STATE_CHANGED）写全局 error。
  守卫注释必须完整记载此清单。`unlock`（密码路径）零改动。

## 3. 测试（R1 P1 修正：必须覆盖卸载/重挂循环，不能只测 standalone 拓扑）

- **标志位生命周期（新增 AuthContext/provider 级测试，最关键）**：真实
  AuthProvider（仅 mock ../api/vault）+ 顺序重挂模拟——同一 provider 下两次
  顺序挂载 UnlockScreen（key 变更或 unmount/remount）：第一次挂载自动调用
  恰好 1 次；第二次挂载 **0 次**（标志位跨重挂存活——现状红、修复后绿）；
  然后 dispatch 锁定动作（lock）触发 RESET → 第三次挂载重新自动调用
  （片段分段语义）。若 AppContent 集成挂载成本可行则优先（worker 现场裁量），
  顺序重挂 harness 是下限。
- AuthContext 迟到守卫钉：真实 provider + mock api——先经 unlockVault 成功
  （isUnlocked=true），再 reject 一个非 Cancelled 错误的 unlockBiometric →
  state.error 保持 null；反向对照：未解锁时同样 reject → error 写入。
- UnlockScreen.security.test.tsx 组件级补充（跟随既有静态 mock 模式）：
  探测 available+enabled 且标志位 false → 自动调用 1 次；探测不可用/未启用
  → 不调用；标志位 true（mock state）→ 不调用（取消重挂路径的组件侧投影）。
- 既有用例零回归（探测静默降级/限流文案/错误通道/T56 三态提示/取消静默）。

## 4. 不做的事（边界）

- 不加设置开关（方案分析已裁定）；
- 不改 Loading 屏拓扑（认证屏在指纹框期间保持挂载属体验优化候选，独立
  roadmap 项——本班车不动 AppContent 门控，R1 P0 的修复完全在标志位层）；
- 不动后端/Rust（零命令变更）、不动扩展、Windows Hello 落地时复制本模式；
- 不清 mount 时的既有 error（限流信息必须跨重挂存活——v1.1.9 语义）。

## 5. 风险与验收

| 风险                                              | 缓解                                           |
| ------------------------------------------------- | ---------------------------------------------- |
| ~~取消重弹/无界自旋~~（R1 P0）                    | 标志位入 reducer，跨重挂存活；生命周期测试钉死 |
| 用户想输密码：取消 → 短暂 Loading → 密码表单重现  | 与现有手动流的重挂表现一致；业界常态接受       |
| 未签名构建 legacy keychain 模式（LAContext 门控） | 同为程序化触发；T57 真机覆盖                   |
| 挂载瞬间探测未回 → 弹出延迟一拍 IPC               | 可接受；T57 观察感知延迟                       |
| 迟到失败污染下次锁屏                              | WP2 守卫（纵深防御）+ provider 测试钉          |

- QA T57（按真实拓扑重写，R1 版本中"密码输入与指纹框并存"一条删除——
  现行拓扑下不存在）：
  ①启用态锁屏出现即自动弹指纹框；取消 → 短暂 Loading → 锁屏重现 →
  **不自动重弹**，手动按钮可用；
  ②自动锁定 → 指纹框自动出现（原"先点一下再按指纹"路径消失）；
  ③密码解锁失败后的 Loading/重挂循环**不**触发再自动弹（边界：密码尝试
  不消耗标志位——若密码提交赶在探测返回前失败，自动弹出顺延而非取消）；
  ④连续指纹不匹配：每次显示可操作错误横幅、不重弹（标志位）、**不触发**
  60s 限流——bio 失败经 LA_ERROR_AUTHENTICATION_FAILED → KeychainError，
  发生在 record_failed_attempt 之前，从不计入 5 次计数器（R2 P2 修正：
  原表述"连错 5 指仍限流"与实际契约矛盾）；密码路径 5 错限流不受影响；
  ⑤未签名 dev 构建的 legacy 模式同样自动弹出；
  ⑥T56 回归（矮窗口提示、卡片居中）。
- 流程：react-reviewer 审查（WP1/WP2 前端）→ 干净 worktree 全量门禁 →
  bump v1.8.0 → release + tag → 盯 CI → feed 同步 → 资产验签 →
  CHANGELOG/AGENTS/qa_manual/记忆。
