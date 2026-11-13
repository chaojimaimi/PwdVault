# fix_impl_plan — v1.8.6 热修：occlusion 通知驱动的触控 ID 弹窗取消

> 根因（2026-11-12 深度诊断，用户已确认开工）：v1.8.5 的取消触发依赖 Focused/Resized
> 窗口事件，但"对话框在场"场景下事件地形错误——LAContext 认证窗弹出即抢 key →
> PwdVault 窗口在弹出瞬间已发过 Focused(false)（当时 is_minimized=false，守卫正确不
> 取消）；用户 Cmd+M 最小化的是已非 key 窗口 → 无 key 变化 → 无 Focused(false)；
> tao 0.37.2 delegate 无 windowDidMiniaturize 处理（registry 源码实证 ：222/:260 仅有
> windowDidResize/ResignKey）；Resized(0x0)-on-minimize 是陈旧生态报告（wry #490），
> 真机证伪。→ 取消标志从未置位，轮询循环空转，系统对话框永生。
> 本班把取消请求的产生端换成 AppKit 的原生正确信号：**occlusion state 通知**。

---

## 0. 对话框身份与范围（诊断结论，本班不重开）

- 用户活体条目 = 登录钥匙串 legacy 条目（cdat=mdat=2026-09-17；DP 钥匙串 keychain-2.db
  零行）→ 读取走 `gate_with_biometrics` → 对话框 = 我们的 LAContext（标题含原始 reason
  串实证）。v1.8.5 的取消通道（标志 + 200ms 轮询 + drop-invalidate）本身工作正常，
  缺的只是请求产生端。**infrastructure/keychain 本班零改动**。
- 语义升级：occlusion 取消天然覆盖 Cmd+M / Cmd+H / 托盘 hide / **窗口被其他窗口完全
  遮挡**（用户看不见提示 → 取消是正确行为）——比 v1.8.5 三臂更广且统一。

## F1 occlusion 观察者（src-tauri/src/lib.rs）

setup 内、窗口创建后注册（App 生命周期一次性）。**整体（含 use 导入）包在
`#[cfg(target_os = "macos")]` 内**（R1 P1 折叠：`ns_window()` 是 tauri 的
macOS-cfg API、objc2 在非 Apple 目标 `compile_error!`——macOS 本地绿、Windows
release CI 红，v1.8.5 R1-P1 同类缺陷；门禁加 Windows-target check 复跑项）：

1. `window.ns_window()`（tauri 2.12.5，`Result<*mut c_void>`，registry
   webview_window.rs:1952-1956）存为本地 `*mut AnyObject`——窗口永不销毁
   （close=hide，prevent_close），指针 app 生命周期恒有效（注释声明；AppHandle
   捕获备选记录在案，非必需）。
2. `NSNotificationCenter::defaultCenter()` +
   `addObserverForName_object_queue_usingBlock`（R1 实证签名：
   `name: Option<&NSNotificationName>, obj: Option<&AnyObject>,
queue: Option<&NSOperationQueue>, block: &block2::DynBlock<dyn
Fn(NonNull<NSNotification>)> -> Retained<ProtocolObject<dyn
NSObjectProtocol>>`，objc2-foundation 0.3.2 NSNotification.rs:204）：
   - **name** = `NSWindowDidChangeOcclusionStateNotification`（AppKit extern 常量，
     macOS 10.9+；**值==符号名是 AppKit 约定**——注释如实写明，T63-1 真机即其
     真值检验；SDK 头文件核对保留：声明存在 + `NSWindowOcclusionStateVisible =
1UL << 1` + "at least part of the window is visible" 语义原文）。
   - object = nil（单窗口 app；block 内查询我们持有的窗口指针，不解析 notification）。
   - queue = `NSOperationQueue::mainQueue()`（安全方法，主线程串行投递——NSWindow
     主线程访问合规）。
   - block 构造循 biometric_gate.rs:118 的 `RcBlock::new` + DynBlock 先例；
     `msg_send![win_ptr, occlusionState] -> usize`（objc2 0.6.4
     message_receiver.rs:494-495/:529：裸指针接收者合法且官方推荐 `*mut
AnyObject`）；`(state & NSWindowOcclusionStateVisible) == 0` → 调
     `cancel_pending_biometric_prompt()`（既有 infrastructure 导出，零 cfg）；
     否则不动（恢复可见不撤销取消——陈旧标志由 gate 入口既有复位管理）。
3. **依赖落点（R1 P1 折叠）**：F1 代码属 pwdvault crate——其 manifest
   （src-tauri/Cargo.toml）**没有任何 objc2 依赖**（唯一的 objc2-foundation 条目在
   infrastructure，而红线禁改 infrastructure；给 infrastructure 加 feature 不能让
   lib.rs 的 use 编译通过）。改法：src-tauri/Cargo.toml 新增
   `[target.'cfg(target_os = "macos")'.dependencies]` 段：
   `objc2 = "0.6"`、`block2 = "0.6"`、`objc2-foundation = { version = "0.3",
default-features = false, features = ["std", "NSString", "NSNotification",
"NSOperation", "block2"] }`（R1 实证 feature 真名：NSNotificationCenter 归
   `NSNotification` feature、NSOperationQueue 归 `NSOperation`，不存在以控件名命
   名的 feature）。**零新 lockfile 包**——三包全在锁中（objc2 0.6.4/objc2-
   foundation 0.3.2/block2 0.6.2），仅 pwdvault 条目依赖列表变更，属锁重生红线
   覆盖。
4. 观察者 token **有意泄漏**（`std::mem::forget` + 注释：app 生命周期观察者；
   NSNotificationCenter copy block，setup 后本地 RcBlock 可弃）。
5. **自灭安全性论证（注释承载，R1 P3 加桩）**：`NSWindowOcclusionStateVisible`
   语义 = "at least part of the window is visible"（SDK 原文），部分遮挡不丢位；
   宿主窗口强制最小尺寸 **350×500**（tauri.conf.json:19-20），Touch ID 面板几何
   上不可能整盖 → 弹出对话框不触发取消；SDK 另有条款：异形/透明窗口 bounding
   box 落在可见区域仍算 visible——误取消方向风险进一步收敛。完全遮挡（用户看不
   见提示）才取消，语义正确。

## F2 移除两个被证伪/被取代的事件臂

- `Focused(false)+is_minimized` 臂、`Resized+0x0` 臂**删除**：occlusion 严格更广
  （最小化/hide 必然翻转 occlusion——窗口不可见即丢 Visible 位；两臂能命中的场景
  occlusion 必然命中，R1 已核移除安全性）；Resized(0x0) 前提已被真机证伪。
- **连带清扫 v1.8.5 rationale 注释块**（lib.rs:396-413，R1 P2：完整描述被删两臂
  的 wry #490/0x0 论证）——改写为指向 occlusion 机制的简述；残留的 `Focused(false)`
  /`Resized`/`wry #490` 字样会与契约测试断言③的锚点互相干扰。
- `CloseRequested` 臂**保留**（hide 前即时取消，先于 occlusion 通知投递，零害）。
- v1.8.5 的 `recv_reply_with_cancel` 轮询/标志/入口复位/-9 映射/全部测试**零改动**。

## 红线

- infrastructure 零改动；wire 串不变；golden IPC 命令面不变；无新 crate（feature 增补
  除外）；session/codec/golden fixtures/AAD 零触碰。
- include_str 契约测试放**独立 integration test 文件**（v1.8.4 #18③ 自碰撞教训：测试自
  身断言字符串不得与被扫文件共存）。

## 测试

- 新 `src-tauri/tests/biometric_occlusion_wiring.rs`（integration，include_str
  读 lib.rs 源码契约；capability_contract.rs:25 的 include_str 先例）：断言
  ①occlusion 通知名注册存在（**锚 `addObserverForName` 调用形态**，不锚通知名字
  面串——lib.rs 注释里也含该串，R1 预警防碰撞）；②block 内调用
  `cancel_pending_biometric_prompt`；③`Focused(false)`/`Resized` 臂已移除（旧形态必须
  消失，含 rationale 注释清扫）。锚点选结构形态（函数调用形态），防注释碰撞。
- 既有 464(+1) 全绿；预算 +1 → **465(+1)**。lib.rs 实读 505 行（R1 修正），净增
  ~+50/−30 后约 525-555，800 帽无忧。
- **门禁增项（R1 P1）**：Windows-target `cargo check -p pwdvault`（或
  infrastructure 等价目标）复跑——cfg 门的真值检验，v1.8.5 先例。

## QA T63 appended（真机门禁）

1. **Cmd+M 最小化 → 指纹框 ≤0.5s 消失**（核心验收——v1.8.5 失败场景的终审）。
2. Cmd+H 隐藏 → 同上。
3. 托盘/red-button 关闭 → 同上（v1.8.5 已覆盖路径回归）。
4. 正常流：对话框在场、窗口部分被其他窗口遮挡 → **不自取消**（部分遮挡不丢
   Visible 位）；Touch ID 解锁正常；用户取消仍静默。
5. Alt-Tab 至完全遮挡宿主窗口的全屏应用 → 取消（occlusion 语义 bonus，观察项）。
6. 回归：T62 各项。

## 发布

单 ds-worker → rust-reviewer → 干净 worktree 门禁 → bump **1.8.6**（CHANGELOG 手工
管理，不带 --changelog）→ release → 轮询 CI。CHANGELOG/AGENTS.md session log/
qa_manual T63/记忆 gotcha #20（事件地形教训）随 docs 提交。发版红线全清单沿用
（marker 三步、锁重生 --locked、web-ext 对 dist、报完成前再看 git status）。

## 7. R1 评审记录（plan-reviewer REVISE，2026-11-13，全折叠）

| 级  | 发现                                                                                                                                             | 折叠落点                                                                                                                                  |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| P1  | 依赖落点自相矛盾：F1 代码属 pwdvault crate（manifest 零 objc2 依赖），给 infrastructure 加 feature 不能让 lib.rs 编译；红线又禁改 infrastructure | §1 F1.3：src-tauri/Cargo.toml 新增 target-cfg dependencies 段（R1 实证 feature 真名 NSNotification/NSOperation/block2；零新 lockfile 包） |
| P1  | F1 新代码无 cfg 门——ns_window 是 macOS API、objc2 非 Apple 目标 compile_error!（v1.8.5 R1-P1 同类复发）                                          | §1 F1 头部：整体 #[cfg(target_os = "macos")]；门禁加 Windows-target check                                                                 |
| P2  | 被删两臂的 v1.8.5 rationale 注释块未清扫（stale rationale + 干扰契约测试锚点③）                                                                  | §1 F2：注释块一并移除/改写                                                                                                                |
| P3  | feature 名 NSNotificationCenter/NSOperationQueue 不存在                                                                                          | 并入 P1-1 的实证列表                                                                                                                      |
| P3  | "值==符号名"是 AppKit 约定，头文件 grep 证明不了                                                                                                 | §1 F1.2 注释措辞诚实化（约定 + T63 真值检验）                                                                                             |
| P3  | 自灭论证加桩：宿主最小尺寸 350×500 几何不可能整盖 + SDK 异形窗口条款                                                                             | §1 F1.5                                                                                                                                   |
| P3  | lib.rs 实读 505 行（非 ~490）                                                                                                                    | 测试节修正                                                                                                                                |

R1 同时实证为真（全链路）：addObserverForName 签名逐字（NSNotification.rs:204）、
NSOperationQueue::mainQueue 安全方法、msg_send 裸指针接收者合法且推荐 *mut AnyObject
（objc2 0.6.4 message_receiver.rs:494/:529）、通知常量 macOS 10.9+ +
NSWindowOcclusionStateVisible=1UL<<1 + "at least part visible" 语义原文、tao delegate
无 Miniaturize 处理器逐字复核、移除安全性（最小化/hide 必然翻转 occlusion，两臂场景
严格被包含）、线程面（mainQueue 主线程 + Relaxed + 200ms 轮询）、token forget +
close=hide 生命周期、integration include_str 机制（capability_contract.rs:25 先例）、
红线全成立（wire/golden/infra 零触碰在 P1-1 修后可达）。
