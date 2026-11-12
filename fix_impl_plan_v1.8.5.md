# fix_impl_plan — v1.8.5 热修：触控 ID 弹窗随窗口最小化/隐藏自动取消

> 依据：2026-11-12 真机反馈（v1.8.4 发布后用户报告：指纹对话框悬留在其他应用正中，
> 不随 app 最小化消失）+ recon（main @ b0cfc93 全量机制钉死，见 §5 recon 摘要）。
> 这是 v1.8.2 修复的另一半——v1.8.2 关掉"注意力不在时主动弹"（windowFocused 门控），
> 本班关掉"弹出后不跟随"（在飞对话框不随窗口可见性撤退）。
> 用户裁定（问题未被应答，按推荐项执行，可随时改判）：触发范围 = **最小化/隐藏**，
> 不含裸焦点丢失；回焦**不重弹**（沿用 v1.8.0 "取消过的片段不重弹"语义）。

---

## 0. 根因（recon 已核）

`crates/infrastructure/src/keychain/biometric_gate.rs:58-103 gate_with_biometrics()`：
未签名 CI 构建 → legacy keychain 模式 → 每次读 wrap key 前创建**函数局部**
`Retained<LAContext>`（:63）并阻塞在 `rx.recv()`（:94）。树内注释（:59-62）已写明
"dropping it invalidates the context and would cancel the pending evaluation
(LAErrorAppCancel)"——但**全树不存在任何 cancel/invalidate 调用路径**，context 是
!Send（objc2 绑定无线程转移），无法移到取消点。对话框因此一旦弹出就永生，直到
用户应答；macOS 系统安全对话框不归属应用窗口，最小化/切走均不跟随。

Frontend 影响：零（取消走 `UserCancelled` → wire 串 "Touch ID was cancelled" →
正好落在 AuthContext `BIOMETRIC_CANCELLED_STRINGS` 静默集合，无红横幅）。

## 1. 修复设计

### F1 取消通道（biometric_gate.rs）

1. **静态与函数落在 keychain/mod.rs 层（R1 P1 折叠）**：biometric_gate 是
   `#[cfg(target_os = "macos")]` 私有模块——若照抄"既有导出形态"（macos 的
   cfg'd pub use），符号仅 macOS 存在，而 lib.rs:386 的 on_window_event 闭包
   **跨平台编译**（CI 出 macOS+Windows 双构建，macOS 本地 cargo check 查不出，
   红在 Windows release CI）。形态：mod.rs 层
   `#[cfg(target_os = "macos")]` 真实现（内部转调 biometric_gate 的静态 +
   置位 fn）+ `#[cfg(not(target_os = "macos"))]` no-op stub 同名函数；
   `keychain` 本就是 pub mod，lib.rs 调用点零 cfg 即可双平台编译。静态
   `BIOMETRIC_CANCEL_REQUESTED: AtomicBool`（Ordering::Relaxed——单标志无依赖
   内存；进程级单提示语义，循 v1.8.4 P2-6 tracker 先例）。
2. **门函数入口处无条件复位标志**（防上一片段的陈旧取消请求杀死下一个提示）；
   复位到 evaluatePolicy 之间的理论损失窗由 v1.8.2 焦点门结构性闭合（窗口已
   最小化时不可能有新提示在飞——自动弹指要求 windowFocused、手动按钮要求窗口
   前置），注释写明即可（R1 P3）。
3. 等待改造：`rx.recv()`（:94）→ 抽出可单测的纯 helper
   `recv_reply_with_cancel<T>(rx: Receiver<T>, cancel: &AtomicBool,
tick: Duration) -> Result<T, SecretStoreError>`（**tick 参数注入，R1 P3**，
   门函数传 200ms）——内部 `recv_timeout(tick)` 轮询 + 每 tick 查标志；标志
   置位 → 立即返回 `Err(UserCancelled)` 并丢弃 context（drop 即 invalidate →
   系统对话框即时消失）。**迟到 reply 安全性已由 R1 定论**：reply block 末尾
   是 `let _ = tx.send(outcome);`（:80）——对已闭信道返回 Err 从不 panic，静默
   忽略，无需保活 sender；提前弃 RcBlock 拷贝安全（framework 自持 Block_copy
   副本）；spawn_blocking 线程 drop Retained 是普通 objc_release，与现状正常
   路径同面。**Disconnected 臂逐字沿用现状**
   `Unavailable("biometric evaluation returned without a reply")`（:97-101，
   R1 P3：隐性 wire 语义漂移禁止）。
4. 取消延迟上界 = 1 个 tick（≤200ms），感知不可辨。

### F2 LAError -9（appCancel）映射加固（同文件）

`LA_ERROR_APP_CANCEL: isize = -9` → `SecretStoreError::UserCancelled`，并入
`la_error_codes_map_to_store_errors`（:113）pin 测试。防御性：任何系统侧发起的
appCancel（非本班取消路径）同样落静默集合，不产生红横幅（**F1 的 drop-
invalidate 触发的正是 appCancel——F1 与 F2 互为必要条件**）。**wire 串不变**
（"Touch ID was cancelled"），前端零改动。**同步修正 :128 注释**（现把
AppCancel 列为落 Unavailable 的例证，映射后失实——stale-comment sweep 规范）。

### F3 窗口事件钩子（src-tauri/src/lib.rs）

既有 `on_window_event` 闭包（:386-392，现只有 CloseRequested→hide 臂）加两臂
（**R1 P1 折叠：两臂守卫不可共用同一失效谓词**——tao 0.37.2 的 macOS delegate
无 windowDidMiniaturize 处理，Focused(false) 仅来自 windowDidResignKey、
Resized 仅来自 windowDidResize，回调时刻 `isMiniaturized` 不保证已翻转 true）：

- `WindowEvent::Focused(false)` → 若 `win.is_minimized() == Ok(true)` → 调
  `cancel_pending_biometric_prompt()`（维持 is_minimized 判，正确排除"系统
  指纹面板抢焦点"的自灭面）。
- `WindowEvent::Resized(PhysicalSize<u32>)` → 若 `is_minimized() == Ok(true)
|| (size.width == 0 && size.height == 0)` → 同上——**零尺寸析取是 belt 的
  实体**：macOS 最小化时 Resized 报 0x0 而 isMiniaturized 翻转时序不可靠是
  生态已知行为（wry #490），0x0 判定独立于翻转时序，保证 T62-1 主场景命中。

**裸 `Focused(false)`（未最小化、未隐藏）不触发取消**——裁定项：避免"对话框
出现时系统面板抢焦点导致提示自灭"的未验证风险；Alt-Tab 场景悬留为已知限制，
T62 观察项收集真机事实后再议。`CloseRequested` 既有臂（hide 前追加取消调用）
覆盖托盘路径。`is_visible` 检查不加（CloseRequested 路径已覆盖 hide；避免
Focused(false)+visible 组合的误杀面）。

### F4 语义保持（零改动声明）

- 回焦不重弹：`biometricAutoPrompted` 片段标志消费逻辑零改动（取消 = 该片段
  已提示过，手动 Use Touch ID 按钮兜底）。
- rate-limit：UserCancelled 路径既有契约不计次（tests_credentials.rs:74 已钉）。
- data-protection 模式（签名构建）：SecItem ACL 系统提示非本进程所有、不可
  取消——本班不动，注释如实声明（当前发布构建全走 legacy，不受影响）。
- `available()` 的瞬态 LAContext（canEvaluatePolicy，无 UI）不需要取消。

## 2. 红线

- session/unlock_if/generation/codec/golden fixtures/AAD 零触碰。
- wire 串 "Touch ID was cancelled" 不变；`BIOMETRIC_CANCELLED_STRINGS` 前端
  零改动；biometric_cancelled_wire_shape_is_pinned（error.rs:286）保持绿。
- unlock_biometric 的 IPC 命令面零变化（golden_contract 命令清单不加新命令——
  取消是 free function 调用，非 IPC）。
- 不新增依赖；objc2/block2 全用既有绑定形态。

## 3. 测试（红→绿）

- `recv_reply_with_cancel` 单测 ×3（纯 helper，普通 mpsc 即可）：①取消置位于
  等待中 → Err(UserCancelled) 且 ≤1 tick+ε 返回；②先到 reply 后到取消 → 返回
  reply（取消请求不影响已完成的评估）；③无取消无 reply → 按超时语义阻塞（用
  短 tick + drop sender 的断开形态断言）。tick 常量注入（测试不过 200ms 真等）。
- `-9 → UserCancelled` 映射并入既有 pin 测试。
- 门函数本身不可单测（objc + 系统对话框）——注释指 QA T62。
- 既有 biometric 相关测试（tests_credentials ×3、error.rs pin、macos tests）全绿。
- 预算：Rust +4~5（helper×3 + 映射×1 ±1）→ ~465(+1)；前端/native-host 不变。

## 4. QA T62 appended（真机项，jsdom/Rust 单测不可达）

1. **最小化取消（核心验收）**：锁屏自动弹指 → 指纹框在场时 Cmd+M 最小化 →
   指纹框 ≤0.5s 内消失；回 app 后锁屏无红色横幅；Use Touch ID 按钮可手动解锁。
2. **托盘隐藏取消**：指纹框在场时点关闭键（hide to tray）→ 同上。
3. **正常流回归**：焦点中自动弹指 → Touch ID 正常解锁；取消按钮静默；错指
   仍出 LockedOut/失败文案。
4. **片段语义**：最小化取消后回焦**不**自动重弹（一次性/片段不变）。
5. **观察项（为未来全焦点丢失方案铺垫）**：指纹框在场时 PwdVault 是否保持
   激活（菜单栏归属/窗口焦点状态）——记录到 qa_manual。
6. **回归**：T57（自动弹、取消静默）、T59（焦点门控矩阵）快速复测。

## 5. recon 摘要（决策依据）

- LAContext 绑定 objc2-local-authentication 0.3.2（LAContext/invalidate 可用）；
  context 函数局部、!Send、阻塞 `rx.recv()`；drop=invalidate 已有树内文档。
- LAError 以裸 isize 匹配（:38-49）：-2→UserCancelled、-8→LockedOut、-1→失败
  文案；**-9（appCancel）现落 `Unavailable("biometric evaluation failed
(LAError -9)")`** → wire "Keychain error: …"，不在静默集合——F2 修的就是
  这个泄漏面。
- lib.rs :386-392 全树唯一 on_window_event（CloseRequested→hide）；tauri
  2.12.5 `WindowEvent::Focused(bool)`/`Resized` 可用；`is_minimized()`/
  `is_visible()` 为 WebviewWindow 方法（主线程闭包内可调）。
- 双调用点共享修复：`gate_with_biometrics` 同时服务解锁（macos.rs:352）与改密
  重封（shared.rs:541 同映射）——取消通道自动覆盖两者。
- 命令链：unlock_biometric（commands.rs:548）→ spawn_blocking → credentials.rs
  :115 → store.get → gate；spawn_blocking 线程上轮询 recv_timeout 无障碍。

## 6. 实施与发布

- 单 ds-worker（Rust 单域，~60-80 行 + 测试）→ rust-reviewer（前端零改动免
  react 评审）→ 干净 worktree 门禁（Rust 侧全量 + 前端 CI-true 复跑钉数）→
  bump 1.8.5 → release → 轮询 CI。QA T62 + AGENTS.md session log + CHANGELOG
  随 docs 提交。
- 发版管线红线全清单沿用（marker 三步、锁重生 --locked 验证、web-ext 对 dist、
  push 后轮询）。

## 7. R1 评审记录（plan-reviewer REVISE，2026-11-12，全折叠）

| 级  | 发现                                                                                                                      | 折叠落点                                                                           |
| --- | ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| P1  | F3 两臂守卫共用可能读 false 的 is_minimized（tao 无 windowDidMiniaturize，两臂可能均在翻转前送达，主场景 T62-1 双双落空） | §1 F3：Resized 臂加 0x0 零尺寸析取（独立于翻转时序）；Focused 臂维持 is_minimized  |
| P1  | cancel fn 照抄 cfg 导出形态仅 macOS 存在，lib.rs 跨平台闭包 → Windows release CI 编译失败（macOS 本地查不出）             | §1 F1：静态+函数落 keychain/mod.rs 层 cfg 对（macOS 真实现 + 非 macOS no-op stub） |
| P3  | helper 签名缺 tick 参数 vs §3 要求 tick 注入                                                                              | §1 F1 第 3 条签名加 tick: Duration                                                 |
| P3  | Disconnected 臂行为未规定                                                                                                 | §1 F1 第 3 条：逐字沿用现有 Unavailable 文案                                       |
| P3  | :128 注释把 AppCancel 列为 Unavailable 例证，F2 落地后失实                                                                | §1 F2 同步修正注释                                                                 |
| P3  | 门入口复位到 evaluatePolicy 之间的理论损失窗                                                                              | §1 F1 第 2 条注释说明（v1.8.2 焦点门闭合）                                         |

R1 同时定论：reply block `let _ = tx.send` 忽略式安全（无需保活 sender）；提前弃
RcBlock/context 线程面与现状同面；zeroize-on-failure 由取消路径自动继承；
UserCancelled 复用使静默集合/rate-limit 豁免/wire 红线三条契约零成本继承；
F1+F2 互为必要（drop-invalidate 回的就是 appCancel）。
