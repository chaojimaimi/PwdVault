# fix_impl_plan — v1.8.7 热修：resign-active 驱动的触控 ID 弹窗取消（补全 occlusion 的信号盲区）

> 根因（2026-11-13 四轮活体实锤 + 用户亲口确认场景，无需重开诊断）：v1.8.6 的
> NSWindowDidChangeOcclusionStateNotification 触发器对"切换应用 → 台前调度(Stage
> Manager)收块"结构性无感——缩块仍以缩略形式在屏渲染，occlusion Visible 位不翻转，
> 永不产生通知 → 取消链路零触发（统一日志四轮弹窗零 -9（AppCancel，我们 drop-invalidate
> 路径的唯一特征码），结束码全为用户手按 -2）。机制面探针全部无罪（通知名"值==符号名"
> 本机成立、字面量注册实收通知、bit1 随 Dock 最小化/orderOut 翻转、tao NSApp.run
> 派干 mainQueue、drop→系统侧 Canceling requests 实证），且文件日志
> （~/Library/Application Support/com.pwdvault.app/logs/pwdvault.log.2026-11-13，
> 03:10:10Z 行 = 本地 11:10:10 的 v1.8.6 进程）无 ns_window Err warn——**注册
> 100% 存活**，"注册跳过"假说正式排除。缺的信号是 app 级的"应用失去前台"。
>
> 本班把取消请求的产生端补上这个信号：**NSApplicationDidResignActiveNotification**。
> 取消机制（biometric_gate 的 static AtomicBool + recv_reply_with_cancel 200ms 轮询 +
> drop-invalidate + LAError -9→UserCancelled 静默映射）零改动，全部复用。

---

## 0. 自灭安全性（已活体排除，本班不重开）

2026-11-13 14:57-14:59 系统日志 + System Events 实测：弹窗出现时 PwdVault 保持
active（auto-prompt 的 windowFocused 门通过即证明当时在前台）；用户真实切换
（MailMaster 变 frontmost）后 PwdVault 才 resign 且弹窗照挂 → resign-active 信号
精确对应"用户离开"，不会弹窗即自灭。同时证伪 v1.8.5 的"对话框抢 key"假说（那是从
缺失事件反推的解释，从未实测）——今后不再作为设计依据，相关 stale 措辞如遇直接
冲突一并在注释中修正（不主动大扫除）。

## F1 resign-active 观察者（src-tauri/src/lib.rs）

同一 `#[cfg(target_os = "macos")]` 块内（现 :405-501），**放在 `match
window.ns_window()` 之外、且钉死在 match 之后（cfg 块尾部）**——resign-active 是
app 级通知，不需要窗口指针，注册不依赖 ns_window()（顺带把残余风险对 resign 路径
免疫）。**钉死文件序：occlusion 注册保持 `.addObserverForName_object_queue_usingBlock(`
形态的首个出现（①② 断言的 first-occurrence 锚不得漂移到 resign 观察者上）**。
形态与 occlusion 观察者逐字同族：

1. `NSNotificationCenter::defaultCenter()` +
   `addObserverForName_object_queue_usingBlock(Some(&name), None, Some(&mainQueue),
   &block)`；name = `NSString::from_str("NSApplicationDidResignActiveNotification")`
   （字符串字面量，AppKit 值==符号名约定——与 v1.8.6 window 级同族约定，本机探针已
   实证该约定；注意这是 NSApplication 的通知，投递到同一个 defaultCenter）。queue =
   `NSOperationQueue::mainQueue()`（复用既有 `queue` 绑定即可——注意 occlusion 分支
   的 `queue`/`center` 在 match 内声明；F1 的声明位置要与之协调：把 `center`/`queue`
   的绑定上提到 match 之前，两个观察者共用，避免重复调用 defaultCenter/mainQueue）。
2. block：`RcBlock<dyn Fn(NonNull<NSNotification>)>`，不解析通知，**无条件**调
   `keychain::cancel_pending_biometric_prompt()`（no-eval-in-flight 时置标志无害：
   下一次 gate 入口无条件复位；标志从未被读走即作废）。token `std::mem::forget`
   （app 生命周期观察者，与 occlusion 同款注释）。
3. 注释承载（WHY）：根因一段（台前调度缩块在屏可见 → occlusion 不翻转 → 零通知，
   统一日志四轮零 -9）+ 自灭排除一段（§0 实测）+ 无条件置标志的无害性（gate 入口
   复位 + 复位到 evaluatePolicy 之间的微秒竞窗 fail-closed 良性——弹窗闪现即静默
   取消，rate-limit 豁免，密钥不发布）。
4. 行数预算：lib.rs 现 577；F1 净增约 +45-60 → 约 625-640，800 帽无忧。

## F2 诊断日志 rider

更正（R1 评审实证）：tracing 走**文件日志**而非 stdout（lib.rs:222-231 接
`tracing_appender::rolling::daily`，落盘 vault 同级 `logs/pwdvault.log.YYYY-MM-DD`，
默认 filter `pwdvault=info`，ANSI off）——文件日志可检索（今日核查即靠它排除
ns_window Err）。真机权威验收通道仍是统一日志 LA 子系统的 `-9` 特征码（T64.1）。
红线"无新 crate"禁止引入 os_log 桥（tracing-oslog 等），os_log 集成记为未来独立
item。本班落点：

1. 三个 cancel 产生端各加 `tracing::info!("biometric prompt cancelled: <来源>")`：
   resign 观察者块内、occlusion 观察者块内、CloseRequested 臂（来源字符串区分
   resign-active / occlusion / close-to-tray）——落 `logs/pwdvault.log.*` 可检索。
2. `ns_window()` Err 分支的既有 warn 保持（已是 tracing::warn，落同一文件）。

## 红线

- infrastructure 零改动；wire 串不变；golden IPC 命令面不变；无新 crate（objc2 段
  依赖沿用 v1.8.6，零新 lockfile 包）；session/codec/golden fixtures/AAD 零触碰。
- v1.8.5/v1.8.6 已交付的取消机制、CloseRequested 臂、LAError 映射零改动。**既有
  测试零改动指断言与计数**：tests/biometric_occlusion_wiring.rs doc 注释中
  "the auth dialog steals key status" 一句允许同步修正（§0 证伪的假说），断言
  字符串与计数零触碰；实施者改写 lib.rs 注释时不得引入 ③ 的四禁形
  （`WindowEvent::Focused(false)` / `WindowEvent::Resized` / `is_minimized` /
  `wry #490`）。
- 遗留声明（不在本班）：biometric_gate.rs:96-101 注释的 "exactly the state"
  枚举（minimized/hidden）因新增 resign-active 第三类触发源而变宽——承载不变式
  （prompt 仅在 focused/active 起飞）在 macOS 上仍成立，措辞遗留记档，infrastructure
  零触碰。
- DP-mode（签名构建的 SecItem ACL 对话框）不可取消——声明沿用 v1.8.5/v1.8.6
  （当前发布全为 legacy 路径）。

## 测试

- 扩展 `src-tauri/tests/biometric_occlusion_wiring.rs`（integration、include_str 读
  lib.rs 源码契约；现有单测试函数含 ①occlusion 注册形态锚 ②块内 cancel ③旧形态
  消失 ④CloseRequested 存活）。新增第二个 `#[test] fn`：`resign_active_observer_
  cancels_pending_prompt`：断言 ⑤ `"NSApplicationDidResignActiveNotification"`
  字面量存在于 lib.rs（含引号的字面量形态锚，防注释碰撞——lib.rs 注释若提及该名
  会被撞，要求实现时**注释中不出现该字面量全名**，如需指称用"resign-active"措辞）；
  ⑥ 注册调用形态计数：`addObserverForName_object_queue_usingBlock(`（带前导点形态）
  在 lib.rs 出现**恰 2 次**（注释不得复现该调用形态）；⑦ resign 块内调用
  `cancel_pending_biometric_prompt`（段界锚：resign 字面量行为起点，注册调用行为
  终点——**取该调用形态的第二次出现**（`match_indices().nth(1)` 或 `rfind`，文件序
  钉死后第二次出现必为 resign 注册），保证段界单调递增不与 occlusion 段交叠）。
  现有 ①-④ 断言零改动。
- 预算：+1 测试 → lib 45 不变；集成测试 biometric_occlusion_wiring 1→2（AGENTS 表
  新增表行）；Rust 合计 **466(+1 ignored)**（application 253 / infrastructure 136 /
  domain 26 不变）；前端+扩展 758/91、native-host 23 不变。发布时以 `cargo test`
  实际输出为准填 AGENTS §2 表（counts from actual test output 惯例）。
- **门禁增项（沿用 v1.8.6）**：Windows-target `cargo check -p pwdvault-infrastructure`
  绿即可（pwdvault 包的 ring cc 失败为既有工具链限制）；两观察者整体
  `#[cfg(target_os = "macos")]` 不变，新增代码全部落在既有 cfg 块内。

## QA T64 appended（真机门禁）

1. **切应用取消 ≤0.5s**（核心验收——本轮用户实测场景的终审：弹窗在场 → 切到任意
   应用 → 弹窗消失；系统日志出现 `Code=-9` 特征码即链路通证）。
2. 台前调度收块取消（同上场景的 Stage Manager 形态）。
3. Cmd+M Dock 最小化取消（occlusion 路径回归——v1.8.6 遗留疑点：若对话框持有 key
   导致 Cmd+M 菜单项无效、窗口实际未缩，则属系统行为非本班回归；观察项记录）。
4. Cmd+H 隐藏取消（occlusion 路径）。
5. 托盘/red-button 关闭取消（CloseRequested 路径回归）。
6. 回焦不重弹（once-per-episode 标志回归）。
7. T62/T63 各项回归。
8. 持续观察项：弹窗出现时菜单栏归属仍是 PwdVault（"不夺 active"的持续验证——若
   未来 macOS 版本改变此行为，resign 路径会自灭，T64 每次发版复验）。

## 发布

单 ds-worker → rust-reviewer → 变异验证（删 resign 观察者 → 契约测试⑤⑥⑦红；
删 occlusion 观察者 → ①②红）→ 干净 worktree 门禁（sidecar 预编译 + 全量测试 +
pnpm typecheck + eslint 0 警告 + web-ext 对 dist --warnings-as-errors）→ bump
**1.8.7**（scripts/bump-version.sh 不带 --changelog；CHANGELOG 手工条目；bump 后
手动 `cd src-tauri && cargo update -w && cargo check --locked` 双验证）→ AGENTS.md
头部 Current Version 叙事 prepend + session log 三节 + **§2 测试表刷新（顺带补
v1.8.6 漏记的 occlusion 契约测试行）** + **qa_manual_v1.2.0.md 追加 T64 节** →
commit-gate marker 三步
独立命令 → release → updater feed bot → ff-only 同步 → 轮询 CI（QG 首轮 flake 用
`gh run rerun --failed`）→ 报完成前 `git status --short` 收 formatter 残留 →
记忆更新（gotcha #21 补发版事实 / audit-findings v1.8.7 行 / MEMORY.md 索引）。

## 7. 评审台账（评审后补记）

### R1（plan-reviewer REVISE，2026-11-13 18:0x，全折叠）

| 级  | 发现                                                                                                                               | 折叠落点                                                                                                  |
| --- | ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| P1  | F2 前提错误：tracing 走文件日志（lib.rs:222-231）非 stdout，"零痕迹"不成立                                                          | §F2 重写：落点 logs/pwdvault.log.\*，真机验收通道仍是统一日志 LA -9 特征码；os_log 仍为未来 item           |
| P1  | resign 观察者位置未钉 before/after——置于 match 前会使契约测试 ①② first-occurrence 锚静默重锚、变异期望落空；⑦ 段界未给次序语义     | §F1 钉死"match 之后（cfg 块尾部）、occlusion 保持文件序首个"；§测试 ⑦ 钉"第二次出现（nth(1)/rfind）"       |
| P2  | 测试预算括号自相矛盾（+1 落在 pwdvault 集成测试非 lib 45 不变）+ AGENTS §2 测试表缺 v1.8.6 契约测试行                               | 预算行改"tauri-app 45→46"；§发布补"AGENTS §2 测试表刷新"                                                  |
| P3  | §发布清单缺 qa_manual T64 落档步骤                                                                                                  | §发布补"qa_manual_v1.2.0.md 追加 T64 节"                                                                  |
| P3  | 红线"既有测试零改动"与 §0 stale 措辞修正条款字面冲突                                                                                | 红线补"指断言与计数；doc 注释 'steals key' 句允许修正；不得引入 ③ 四禁形"                                 |
| P3  | biometric_gate.rs "exactly" 枚举将因第三触发源变 stale                                                                              | 红线记遗留：不变式不破、措辞不在本班                                                                      |
| P3  | F2 未覆盖第三个 cancel 产生端（CloseRequested）                                                                                     | §F2.1 补 close-to-tray 来源 info                                                                          |
| P3  | DP 模式不可取消声明未沿用惯例                                                                                                       | 红线补沿用声明                                                                                            |

R1 同时实证为真（file:line）：lib.rs 577 行/cfg 块 :405-501/:410 cfg 门；center/queue
现绑 :434-435（上提可行）；`.addObserverForName_object_queue_usingBlock(` 现恰 1 处
（:480）无注释碰撞；cancel 现有 2 调用点（:399/:472）；cfg 导出对在（keychain/mod.rs
:219-228）红线可达；取消机制零改动主张逐点吻合（biometric_gate.rs :47/:53-55/:102/
:157/:174-194/:39/:65）；objc2 features 覆盖所需符号（Cargo.toml:73-82）零新包；
tauri.conf 350×500 无关项通过。

### R2（plan-reviewer PASS，2026-11-13 18:1x）

8 折叠逐项落位核对通过；新实证句与实文件逐字吻合；唯一残余 P3（预算桶措辞歧义）
已折叠（"lib 45 不变 / wiring 1→2 / 合计 465→466，以 cargo test 实际输出为准填表"）。

### 实施与复审（ds-worker + rust-reviewer，2026-11-13 18:2x）

- worker：lib.rs 577→642（F1 resign 观察者 @cfg 尾部、center/queue 上提 :429-433、
  三 info :403/:481/:543、steals-key 句修正 :386-396）；wiring 测试 1→2；
  466(+1)/clippy/fmt/Windows-target infrastructure 全绿。偏差×4 有档（doc 第二句
  同步、+65 超估算上限、变异归因发现、基线括号勘误）。
- rust-reviewer **APPROVE**（0 P0-P2 + 4 P3）：变异矩阵独立复现（A/B1/B2/C/D/E +
  C+E 复合）；裁定 ①② 漂移容忍可接受（勿显式钉段）；P3-1 折叠（⑥ 次序断言在
  len==2 下恒真、换序 C/C+E 复合可逃逸 → 新测试内加"身份+次序链"：occlusion 带引号
  字面量位置 < call_sites[0]，锚唯一性核实 :452 代码 / :447 反引号注释不撞）。
- P3-1 折叠后 worker 变异复验：C 红于 :172 新链（且为唯一捕获者）、C+E 红于同链、
  正常形态 2/2 绿无误伤、还原后 diff 逐字节一致。
- P3-2/P3-3 记档不折叠（日志措辞未来校准 / ① panic 消息下次触碰时校准）。
