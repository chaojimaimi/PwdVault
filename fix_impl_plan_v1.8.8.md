# fix_impl_plan — v1.8.8 热修：显式 invalidate + 抬升宽限期（取消机制层的真正修复）

> 根因（2026-11-13 20:12 第四轮取证闭合，与前三轮根本不同）：前三轮修的都是
> **信号层**（"谁告诉我们取消"），v1.8.7 的信号层已被证明完全正常——文件日志七次
> `biometric prompt cancelled` 打点、轮询按设计返回 UserCancelled。真正死因在
> **机制层**：v1.8.5 起的核心前提 **"drop LAContext = invalidate = 对话框消失"是假
> 命题**——LocalAuthentication 框架在评估在飞期间自行 retain 上下文，Rust 侧
> `Retained` drop 只减一个引用，对象不 dealloc、评估不终止、面板不消失。铁证：
> cid:4 在轮询退出时刻（22.4）无 dealloc 记录，存活 2m26s 后由用户手按 -2 收场，
> 全程零 -9。**机制层死因自 v1.8.5 交付起从未被行使过**（前两轮触发器哑火掩盖了它），
> v1.8.7 触发器响了才现形。
>
> 元教训入档（gotcha #22）：任何"机制 A 则 B"断言未经真机触发一次即未验证。
> **本班发版硬门：本地构建装真机、用户亲眼看到弹窗随切走消失且日志出现 -9 之后，
> 才进入发版管线。**

---

## 0. 取证事实（本班不重开）

1. v1.8.7 进程 33248（20:12:13 启动）信号层全部正常：20:12:22.213 弹窗拉起
   （cid:4）→ 22.262 resign 打点（+49ms）→ 22.4 轮询返回 UserCancelled（标志被
   观察）→ 后续 6 次打点（写无人读的标志）→ 20:14:48 用户手按 -2 才结束。
2. 弹窗拉起后 **~50ms** app 即被面板剥夺 active（resign 打点 +49ms）——v1.8.7
   之前"面板不夺 active"的结论是数分钟后测量推断的，错误。推论：修好机制后若无
   宽限期，面板自身的 raise 副作用会每次自灭弹窗。
3. `LAContext.invalidate`（objc2-local-authentication 0.3.2 LAContext.rs:323，
   `pub unsafe fn invalidate(&self)`）可用；Apple 头文件语义："stops any existing
   authentication interaction ... Use this method to terminate an interaction
   without waiting for the user to act on it" —— 即 Apple 文档化的"终止在飞评估"
   API。invalidate 后 reply 以 LAErrorAppCancel(-9) 触发（map_la_error 已收编
   → UserCancelled 静默；send 落关闭通道 `let _ =` 无害，v1.8.5 R1 已证）。

## F1 显式 invalidate（src-tauri/crates/infrastructure/src/keychain/biometric_gate.rs）

gate_with_biometrics 的等待返回后、函数返回（drop）前：

```rust
let wait_result = recv_reply_with_cancel(...);
if wait_result.is_err() {
    unsafe { context.invalidate(); }
}
match wait_result { ... }
```

- **只覆盖 Err 路径**（UserCancelled = 我们放弃等待 + Disconnected = 框架未回
  reply 的 fail-closed 路径）——Ok 路径评估已由框架终结，无需 invalidate。surgical。
- 线程面：整个 gate 函数在同一 worker 线程执行（Retained `!Send` 结构性保证），
  invalidate 与创建/evaluatePolicy 同线程。
- 注释承载：假命题证伪记录（四轮铁证）+ invalidate 语义 + reply -9 落死通道无害。

## F2 抬升宽限期（同文件，取消轮询 helper 扩展）

**问题**：面板拉起后 ~50ms 内剥夺 active → resign 置标志 → 若直接生效，修好
invalidate 后每次弹窗都会在 200ms 内自灭。**设计**：宽限期内到达的取消请求判为
面板自身 raise 副作用，丢弃（清标志）；宽限期后到达的正常生效。

1. 常量 `CANCEL_GRACE_AFTER_RAISE: Duration = 500ms`（doc 注释：实测面板剥夺
   active 于 +49ms（单机单点），500ms = 10× 余量；盲窗 = 抬升后 0.5s 内的真实
   切换（亚秒极速 cmd-tab 的罕见场景）或宽限内 close-to-tray——被吞后**恢复路径
   = 再次切换/最小化即消失**，此句写入 doc）。
2. `recv_reply_with_cancel` 签名扩展：`raised_at: Instant, grace: Duration`（保持
   纯 helper + 可注入测试形态）。Timeout 臂逻辑：

```rust
if cancel.load(Relaxed) {
    if raised_at.elapsed() >= grace {
        return Err(UserCancelled);
    }
    cancel.store(false, Relaxed);  // 丢弃 + 清标志，防毒害后续 tick
}
```

3. gate 侧：`let raised_at = Instant::now();` 在 evaluatePolicy 返回后捕获
   （面板 ~50ms 后渲染，抬升时刻即此刻）。
4. 附带收益：入口复位到抬升之间的 stale-flag 竞窗也被宽限期吞掉（比 v1.8.2 焦点
   门更硬的封闭），:96-101 的 "exactly the state" 注释按此改写（v1.8.7 记档的
   stale 枚举一并清偿）。

## F3 假命题注释全面清扫（三文件 + 测试头，注释级；R1-P1 补全枚举）

- **biometric_gate.rs**（9 处）：:36-38（const doc "drop-invalidate cancel path"）、
  :41-46（static doc）、:57-62（map_la_error doc 同语）、:78-80（**gate fn doc**——
  R1 纠正：原计划误标为 helper doc）、:96-101（"exactly the state" 枚举 + F2.4
  附带收益改写）、:104-107（SAFETY drop 注释）、:145-152（match 臂注释）、
  :159-173（**真实 helper doc**，"drop its LAContext, dismissing the dialog"）、
  :209-212（测试区注释）——全部改写为 invalidate 真相 + 证伪记录。
- **keychain/mod.rs** :207-212（"drop = invalidate = the panel goes away"）→ 改写。
- **src-tauri/src/lib.rs**（R1 实证：drop-invalidate 措辞零命中；真正被本轮证据
  推翻的是两处假前提注释）：:522-527（"while the prompt is up this app STAYS
  active"——被 +49ms resign 打点直接证伪，F2 宽限期存在的理由恰是它）+
  :535-541（"microsecond window ... the dialog flashes away silently"——F2 落地后
  stale flag 被宽限吞掉、对话框不再闪灭，行为性过时）。清扫条件 =
  drop-invalidate 措辞 ∨ "app stays active" 类已证伪前提。**注释零行为改动**，且
  不得引入 ③ 四禁形 / 通知全名 / 调用形态（v1.8.7 契约锚纪律不变）。
- **tests/biometric_occlusion_wiring.rs** 头部 :3-7（"measured on-device ... the
  app stays active while the prompt is up"）→ 同步证伪改写（断言零触碰）。

## F4 workspace 激活观察者（lib.rs，rust-reviewer P3-3 触发的增量加固）

**动机（P3-3 场景 A 风险）**：若面板在抬升时**永久**剥夺 active（场景 A），用户切换
时不再产生 resign **迁移**（app 已 inactive，DidResignActive 需 active→inactive 迁
移）→ resign 信号在用户核心场景（切走 + 台前调度缩块，无整盖）下可能永不触发，
弹窗继续存活。20:12 取证两次 resign 的时序无法区分场景 A/B——不赌单一信号语义。
**修复**：补状态无关的信号——`NSWorkspaceDidActivateApplicationNotification`：
任何**其他**应用获得激活即触发（不管我们是否还 active），两个场景全覆盖。

1. lib.rs cfg 块内、resign 观察者之后注册第四观察者：center =
   `NSWorkspace::sharedWorkspace().notificationCenter()`（非 defaultCenter）；
   name = 字面量 `"NSWorkspaceDidActivateApplicationNotification"`（同族 AppKit
   值==符号约定）；block **解析通知**（与 occlusion/resign 的不解析不同）：object =
   NSRunningApplication，取 `processIdentifier`（pid_t = i32），**pid != 自己**
   （`std::process::id() as i32`）→ `cancel_pending_biometric_prompt()` +
   `tracing::info!("biometric prompt cancelled: app-switch")`。token forget。
   mainQueue。**置于 resign 注册之后**（文件序第三，保 ⑦ 的 nth(1) 语义）。
2. 语义：对话框在飞期间任何其他应用拿到激活 = 用户注意力已离开 → 取消（与
   v1.8.2 "只在用户在场时弹" 哲学对称）。抬升时面板属主进程激活的副作用落在
   grace 内被吞（与 resign 同）。PwdVault 自己激活（pid 相等）不置标志。
3. 依赖：pwdvault crate target-cfg 段增 `objc2-app-kit = { version = "0.3",
default-features = false, features = ["std", "NSWorkspace", "NSRunningApplication",
"NSString"] }`——**零新 lockfile 包**（tao 传递引入已在锁，13 处引用；0.3.2 的
   三 feature 名已 registry Cargo.toml 实证）。worker 实施时核对 NSRunningApplication
   的 processIdentifier 访问形态（typed 或 msg_send 均可，以编译为准）。
4. resign-active 观察者**保留**（v1.8.7 已交付；双信号同旗标，冗余无害）。

## F5 切回自动重弹（前端 rider，用户裁定并入本班）

**动机**：硬门验证发现——切走取消后切回，弹窗不自动回来（v1.8.0 once-per-episode
设计）。取消语义在 v1.8.8 后变成常态（每次切走都取消），once-per-episode 使自动
弹指的便利在"切走-回来"循环中失效。改为：**注意力回到 PwdVault = 重新武装**。

**设计（关键纪律：rearm 只挂 focus 事件，绝不挂 probe——v1.8.0 P0 同款雷区）**：

1. AuthContext reducer 新增 action `{ type: "REARM_BIOMETRIC_AUTO_PROMPT" }` →
   `biometricAutoPrompted: false`；actions 暴露 `rearmBiometricAutoPrompt()`。
2. UnlockScreen 订阅 effect 的**事件处理器**内（:56-58 处）：闭包局部
   `let wasFocused = false`（R3-P3 边沿检测——精确语义"mount 以来的真实迁移"，
   同时关闭杂散重复 true 事件抹掉 MARK 的缝隙）+ `payload === true && !wasFocused`
   时 `setWindowFocused(true)` 之后追加 `actions.rearmBiometricAutoPrompt()` 并置
   `wasFocused = true`。
   **probe 路径（:69-70，mount 时 eventSeen=false 的初始探测）绝不 rearm**——
   探针对应"mount 时恰好在场"，不是注意力迁移；biometric mismatch 失败路径
   （用户在场、无焦点迁移）走 remount→probe→focused=true，若 probe rearm 就是
   不计限流的无限重试循环（v1.8.0 P0 精确重演；R3 逐行核实：AuthContext :228-256
   catch→SET_ERROR→finally SET_LOADING(false)→remount→probe；biometric 失败不
   计入 5 次限流 → 真无限）。事件才代表真实迁移。
3. 循环安全性论证（逐路径）：
   - **mismatch 环**：raise → 指纹不匹配 → -1 banner → loading=false → remount →
     probe focused=true（无事件）→ 不 rearm → 不重弹 ✓（按钮可用）。
   - **切走-返回环**：raise → 切走 → cancel(-9) → 静默 → remount（away）→ 返回 →
     **focus 事件** → rearm → 重弹 → 标记。每次重弹 = 用户一次主动返回动作，
     非失控环 ✓。
   - **取消按钮环**：用户在场按取消 → 无事件 → 不重弹 ✓（显式取消不骚扰）。
   - **极速返回盲窗**（<0.5s 返回，取消回程未完成时 remount 且错过事件）：不重弹，
     按钮可用，下一个切换-返回周期正常——接受并记录。机制命名（R3-P3）：
     (a) loading 窗口内返回——UnlockScreen 卸载后监听器已被 cleanup（:75-78）拆除，
     事件结构性无人接收，remount probe 见 focused=true 但 probe 不 rearm → 优雅
     错过；(b) remount→异步订阅建立之间的微秒隙事件丢失（v1.8.2 eventSeen 设计
     已承认订阅不回放）——同"不重弹、按钮可用"后果。
4. StrictMode：事件处理器可能双注册（effect 双调），rearm 幂等（flag 已 false），
   双派发无害。
5. 重弹与 Rust grace 的交互：重弹 = 新 gate 入口（复位标志）→ evaluatePolicy →
   若用户 0.5s 内又切走 → grace 吞掉 → 弹窗保留（既有语义）。
6. 文件面：AuthContext.tsx（action + wrapper + 类型）、UnlockScreen.tsx（事件
   处理器一行 + :107-127 段注释更新）、测试。

**测试（R3-P1 修正：两处既有测试腿是对 v1.8.2 刻意钉的反转，必须如实改写）**：

- **改写腿 A**：`AuthContext.biometric.test.tsx:156-163`（v1.8.2 "Blur + refocus
  in the same episode → the flag holds at one"）——末段预期 1→**2**，注释注明
  F5 反转了 v1.8.2 的刻意钉（focus 事件现在突破 episode flag = 重弹语义）。
- **改写腿 B**：`UnlockScreen.security.test.tsx:191-221`（"prompts exactly once
  across focus flips true→false→true"）——末段预期 1→**2** + 同款反转记载。
- 新②：**mismatch 环守卫钉**——失败路径（无焦点事件）不重弹（复用
  AuthContext.biometric.test.tsx:90-116 的 Harness + windowMock：unlockBiometric
  mock reject 非 cancel 消息 → remount → probe true → 断言恰 1 次调用；对
  "probe rearm"变异必红）。
- 新③：取消按钮路径（在场取消）不重弹；负向臂：`payload:false`（blur）不 rearm
  （R3-P3，保留改写腿 A 的"计数不变"中间断言即得）。
- 其余 v1.8.0/v1.8.2 测试零语义改动。
- 预算：前端 758 → **761**（②③ 新块 +3；两腿原地改预期不增数）；Rust 470(+1)
  不变。

## 红线

- ~~信号层零改动~~ **（F4 修订）**：lib.rs 现有三观察者（occlusion/resign）与
  CloseRequested 臂行为零改动；**新增** F4 workspace 观察者是本班唯一信号层增量。
- mod.rs 导出对结构不变（仅 doc 注释改写）；macos.rs / credentials.rs 零触碰
  （UserCancelled → BiometricCancelled 静默链既有）。
- wire 串不变；golden IPC 不变；**无新 lockfile 包**（objc2-app-kit 已在锁，仅
  pwdvault manifest 增 target-cfg 声明，v1.8.6 先例）。
- ~~前端/扩展零改动~~ **（F5 修订）**：扩展零改动；前端限 AuthContext.tsx
  （action/wrapper/类型）+ UnlockScreen.tsx（事件处理器边沿检测 + 注释）+
  两测试文件（改写腿 A/B + 新②③）。

## 测试

- helper 测试改造（biometric_gate.rs tests，注入 tick/grace/raised_at）：
  ① 既有 cancel-mid-wait 改造（setter 延后至 grace 外，断言仍及时）；② 既有
  delivered-reply-wins **零改动语义**（R1 已证：helper 的 `Ok(reply) => return`
  先于一切 flag/grace 逻辑，通道优先于宽限；签名更新但断言不变）；③ 既有
  disconnected 更新签名。新增：④ **宽限期内置位被丢弃、宽限期后二次置位生效**
  （R1-P2 折叠：grace=**100ms** / tick=**10ms** 放宽余量防 CI 调度假红——首次置位
  5ms（≤10× 拉伸仍 <100ms 观察窗内必走丢弃臂）→ 二次置位 150ms → 断言 UserCancelled
  且 elapsed ≥130ms（证明第一次置位没杀掉等待）&& <1000ms）；⑤ 宽限期外置位及时
  生效（setter 150ms / grace 100ms → ~160ms）。
- **invalidate 源码契约钉**（⑦，include_str! 自扫本文件 pre-#[cfg(test)] 区，
  R1-P2 折叠：锚定**全调用形态** `unsafe { context.invalidate(); }` 并断言
  `matches().count() == 1`——裸形态会被 F3 自己的注释掏空（v1.8.1 教训），全形态
  - 恰 1 计数 = 删行即 0 红、注释撞车即 2 红）。
- **F4 契约测试联动（wiring 文件断言修订——本班自己的测试，允许改）**：
  ⑥ 调用形态计数 **2→3**（消息文本同步"three AppKit observers"）；身份+次序链不变
  （occlusion 字面量 < call_sites[0] 仍成立）；⑦ resign 段 nth(1) 不变（workspace
  注册置于文件序第三）。**新增第三测试函数 ⑧**：workspace 名带引号字面量 count==1
  （lib.rs 注释不得复现全名——prose 用 "workspace activation"）、第三调用段切片
  （nth(2) 为终点回溯起点=workspace 字面量）含 `cancel_pending_biometric_prompt`、
  段内含 `processIdentifier`（pid 比对形态锚——没有它观察者无法区分自己与他者）。
- 预算：infrastructure **139**（+3 已落地）；wiring 2→**3**；Rust 合计 **470(+1)**；
  lib.rs 642 → ~685（800 帽无忧）；前端+扩展 758/91、native-host 23 不变。

## 验证-先行-发版协议（本班硬门，顺序不可倒）

1. 实施 + 本地门禁（cargo suite 469(+1) / clippy / fmt / Windows-target
   infrastructure check）。
2. bump 1.8.8（十文件 + src-tauri 锁 `cargo update -w && cargo check --locked`）。
3. **本地构建真机包**：确认 src-tauri/binaries/ 边车存在 →
   `pnpm tauri build --bundles app` → 产物
   `src-tauri/target/release/bundle/macos/PwdVault.app`（版本显示 1.8.8）。
4. **用户真机验证**（退出 1.8.7 → 从 bundle 目录直接启动，不动 /Applications）：
   - 核心：锁库 → 弹指 → 等 ≥2s → 切到别的应用 → **弹窗 ≤0.5s 消失**；
     文件日志新增 `biometric prompt cancelled: resign-active` 且统一日志出现
     `Code=-9`（我读日志取证）。
   - 次项：Cmd+M 最小化 → 消失（occlusion + invalidate 路径）。
   - 观察项：抬升后 0.5s 内极速切换 → 弹窗保留（宽限盲窗，记录即可）→ 再次切换
     → 消失（R1-P3：恢复路径实测）。
   - 观察项（R1-P3）：**连续多次弹指**（≥3 轮锁库-切走循环）——面板 raise→resign
     时延的多轮复验（+49ms 为单机单点，若他机 >500ms 会在宽限外自灭：良性——静默、
     限流豁免、可重试——但需记录实际值供未来校准宽限）。
   - **用户亲眼确认弹窗消失 = 唯一通过标准。**
   - **F5 硬门项（R3-P2 增补——F5 引入新用户可见行为，不验证不发版）**：
     核心 = 切走取消 → **切回 → 弹窗自动重弹**；守卫 = 指纹不匹配（不离开窗口）
     → **无自动重弹**（v1.8.0 P0 防环语义仍活）；取消按钮在场取消 → 不重弹。
     （F1-F4 硬门已于本地构建实测通过：弹窗切走消失 + -9 "Invalidated by client"
     双日志证据。）
5. 通过 → 干净 worktree 门禁 → fix/docs/bump 提交 → tag → release → CI 轮询
   → 记忆（#22 已预写，补发版事实）→ 终报。
6. **不通过** → 带新取证回到诊断（日志此时有七类打点），绝不带病发版。

## 发布

沿用 v1.8.7 全套（marker 三步独立命令、CHANGELOG 手工、AGENTS prepend + 测试表 +
session log、qa_manual T65、feed bot CI 自动、ff-only 同步、完成前 git status）。
CHANGELOG [1.8.8] 条目 + AGENTS Current Version prepend + session log 节随 docs
提交。

## 7. 评审台账（评审后补记）

### R1（plan-reviewer REVISE，2026-11-13 20:4x，全折叠）

| 级  | 发现                                                                                                                                                                                        | 折叠落点                                                                                  |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| P1  | F3 清单不完整：biometric_gate.rs 漏 4 处（:36-38/:57-62/:159-173 真实 helper doc/:209-212）、:78-80 标签错位；lib.rs drop 措辞零命中、真被推翻的是 :522-527 "STAYS active" + wiring 头 :3-7 | §F3 重写（9+1+2+1 处全枚举；lib.rs 腿条件扩展为"假前提类"）                               |
| P2  | ⑦ 锚可被 F3 自己的注释掏空（裸形态 + contains）                                                                                                                                             | §测试⑦：全调用形态 `unsafe { context.invalidate(); }` + count==1（删行 0 红/注释撞 2 红） |
| P2  | 测试④ 时序余量过紧（grace 50ms/tick 20ms，setter 拉伸 >35ms 即假红；v1.8.3 CI 抖动前科）                                                                                                    | §测试④：grace=100ms/tick=10ms，置位/断言阈值同步上调                                      |
| P2  | lib.rs:535-541 行为性过时注释（"dialog flashes away"——F2 后不再发生）未入清扫                                                                                                               | 并入 F3 lib.rs 腿                                                                         |
| P3  | 盲窗"人类不可能"偏强 + 恢复路径未写入 doc                                                                                                                                                   | §F2.1 doc 补恢复路径句；措辞软化                                                          |
| P3  | +49ms 单机单点；他机 >500ms 会在宽限外自灭（良性）                                                                                                                                          | §验证协议补连续 ≥3 轮弹指观察项                                                           |

R1 同时实证为真（file:line / docs.rs）：测试②"零改动语义"（helper :181 `Ok(reply)
=> return` 先于 grace 逻辑）；F2 丢弃语义推演（丢弃按观察时 elapsed 判定，边界带
内置位生效方向正确；store(false) 微窗只吞盲窗置位）；F1 Err 双路径判断 + docs.rs
证实 "invalidate → evaluation fails with LAErrorAppCancel"（-9 链闭合）且
"invalidated automatically when released" 反向佐证根因（drop 引用 ≠ release 对象）；
mod.rs :207-212 清扫点真实；macos.rs :336-359 zeroize 链不受影响；lib.rs 锚纪律
覆盖全部契约锚；objc2 invalidate 签名 docs.rs 核实（本地 registry 无源码，行号
:323 未本地复核——实现时以编译为准）；预算 136+3=139 / 466+3=469(+1)；协议可执行
（tauri build --bundles app 标准路径、sidecar 前置先例、退出 1.8.7 防 17429 冲突、
unsigned 走 LegacyGate = 恰为被修路径）。

### 实施（ds-worker 两轮）+ 复审（rust-reviewer APPROVE ×2）

**第一轮（F1-F3）**：466→469(+1)；lib.rs 577→642；五项验证全绿；变异双红（删
invalidate → ⑦ count 0 红；删宽限 → ④ 红 @11.58ms）。偏差×2：⑦ 锚形态改无分号
尾表达式 `unsafe { context.invalidate() }`（rustfmt 强制展开独立 unsafe 块，单行
字面永失配；三形态实验 E0658/let_unit_value 后定型；过程中意外实测验证 R1-P2 撞车
预言——skip 注释复刻全形态 → ⑦ 红 count==2 → 改 prose 绿）；clippy doc_lazy_
continuation 措辞修。

rust-reviewer **APPROVE**（0 P0-P2 + 4 P3）：invalidate 实证（registry LAContext.rs
:323 + 头文件 "already-invalidated has no effect" 佐证 Disconnected 路径无害）；
沙箱独立变异复证（去宽限红 @11.4ms、**不清标志红 @102.5ms**——store(false) 语义
同样被钉）；①⑤ 假红免疫为不变量级；13 处清扫 grep 零残留。**P3-3 触发 F4**：
场景 A（面板永久剥夺 active → 用户切换无 resign 迁移）下 resign 单信号可能漏覆盖
核心场景 → 补状态无关信号。

**第二轮（F4）**：470(+1)（wiring 2→3）；lib.rs 642→712；Cargo.toml target-cfg 增
objc2-app-kit（零新 lockfile 包，2 行依赖边）；六项验证全绿；变异（删 workspace 段
→ ⑧ count 0 + ⑥ 2 vs 3 红）。偏差×4 全实证：① NSString feature 不存在（0.3.2
顶层 feature 实测清单）→删；② processIdentifier 在 libc feature 门后 →补；
③ Retained::cast 已 deprecated → safe downcast；④ 闭包参数显式注解（E0282——
occlusion/resign 块忽略参数从未触发）。

rust-reviewer 增量 **APPROVE**（0 P0-P2 + 4 P3）：workspace notificationCenter 归属
语义正确（defaultCenter 永远收不到 workspace 通知）；downcast safe API 实证
（retained.rs:325，cast :395 deprecated 必红）；pid 域精确（macOS ≤99998 无回绕）；
fail 方向正确（畸形通知静默跳过=补充观察者不动作）；场景 A 闭合确认（任何他应用
激活 = 状态无关触发，覆盖非整盖切换 + 台前调度）；lock 2 行边零新包逐字属实。
P3 折叠：lib.rs :430 "both observers" 注释诚实化（已折）；worker 偏差×4 + P3-1
Spotlight 观察项 → 发版 docs 提交补录 AGENTS/qa_manual（P3-2 处方）。

**发版硬门协议增补（评审处方）**：真机验证加两观察点——切**非整盖**应用（场景 A
直接验证，F4 存在的理由）+ 弹指期间触发 Spotlight（workspace 信号瞬态激活实测）。

### F5 轮（R3 快审 REVISE→折叠→worker→react-reviewer APPROVE→P3-1 折叠）

R3 聚焦快审（plan-reviewer，只审 F5）：1×P1——"既有测试零语义改动"为假，两条
v1.8.2 测试腿刻意钉了 F5 要反转的行为（AuthContext.biometric.test.tsx:156-163 /
UnlockScreen.security.test.tsx:191-221），须如实反转 1→2 并记载；2×P2（红线矛盾、
验证协议缺 F5 项）；3×P3（盲窗机制命名、MARK-抹除缝 → wasFocused 边沿检测、测试①
负向臂）。全折叠。

worker F5 交付：前端 759/91（+1 = ② mismatch 环守卫钉；③ 并入既有用例、负向臂入
腿 A 中间断言——预算 761→759 差异如实报）；typecheck/lint 干净；变异双红（删
rearm 行 → 两腿红 @expected 2 got 1；probe 加 rearm → ② 红 @expected 1 got 2）。
偏差×4：腿 A/B 与边沿检测结构调和（真实拓扑 blur→cancel→remount 必然发生、remount
重置边沿闭包——腿补 cancel-remount 模拟）；订阅 effect deps []→[actions]
（exhaustive-deps，actions 终身单例语义不变）；腿 B 首跑 ReferenceError 当场补；
预算差异记账。

react-reviewer **APPROVE**（0 P0-P2 + 3 P3）：mismatch 防环结构性闭合（沙盒变异
probe-rearm 双红实证）；worker 偏差 #1 裁定忠实（面板只在 unlockBiometric 在飞期
存在、blur 与 return 之间必然隔着 remount）；测试串与 biometric_gate.rs:75 wire
串逐字节一致。P3-1（边沿守卫无测试钉——沙盒拆守卫 23 用例全绿）主代理折叠：腿 B
中段补"杂散重复 true → 仍 1"断言 + 变异验证红；P3-2（mismatch"无焦点事件"前提在
真机不严格——面板消失可能复 key 产生 Focused(true) 事件输给订阅重建竞速）入 T65
观察参照；P3-3 预算记账 759。

发版期事故：变异验证后用 `git checkout --` 还原 sed 未匹配的文件，把 F5 的
UnlockScreen 实现抹掉（checkout 回退 HEAD 而非撤销编辑——F5 是未提交改动）。
worker 逐字恢复（+36/-3 与原交付一致），759/91 复绿。教训：未提交树上的变异还原
必须用反向编辑或备份回拷，禁用 git checkout。
