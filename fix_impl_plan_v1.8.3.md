# 实施计划 — v1.8.3 安全 hotfix（批次① P1×4）

> 依据：`fix_roadmap_2026-11.md` §1 + 2026-11-12 二轮对抗性交叉验证（行号基于 main @ 8687c7c）。
> 实施顺序：**WP1(F2+F1) → WP2(F4) → WP3(F3)**——Rust 两包先行（同文件族），扩展收尾。
> 基线：Rust 450(+1) / 前端+扩展 706-84 / native-host 23 / clippy+tsc+eslint(0 err) 全绿。
> 第一步必须实跑钉死基线（v1.8.2 先例）。

---

## 全局红线

- 不触碰：entry/sync codec 代际、golden fixtures、AAD 常量、NM 协议、AuthContext、`sync_disconnect`、`password.rs`（其 epoch 顺序是正确镜像，只允许加注释互指）。
- 全部新测试红→绿：先证明红（改动前失败），改动后绿；每包完成即跑对应套件。
- 注释修正与本包逻辑同 commit；与所在文件注释密度/风格一致（解释 WHY）。

---

## WP1 — sync 窗口安全（F2 + F1，engine.rs + state.rs + tests_window.rs）

### F2：lock_epoch 捕获上移到周期起点

**改动**（`src-tauri/crates/application/src/service/sync/engine.rs`）：

1. `run_merge_window`（:89-155）签名追加参数 `epoch_at_capture: u64`；删除 :98-102 的捕获行
   （"Capture the lock epoch BEFORE the drain" 注释块改写为："captured at cycle start by the
   caller — any lock from cycle start on wins, covering the pre-window network phase
   (fix plan A §2.3; the window itself has no capture point left)"）。
2. `sync_now_with_backend`：在 `SessionKeys::copy`（:431）之后立即捕获
   `let epoch_at_cycle = state.lock_epoch.load(Ordering::Acquire);`，三处
   `run_merge_window(...)` 调用（:486/:493/:502）传入。
3. `sync_connect_with_backend`：在其 `SessionKeys::copy`（:240）之后同样捕获，
   :254 的调用传入（connect 的前置网络阶段 = `pull_or_bootstrap`，:250-253）。
4. 新增 test seam：`state.rs` 的 `#[cfg(test)] pub(crate) network_phase_gate: WindowGate`
   ——加入 struct 字段（:179-181 旁）**并同步加进手写 `Default` impl**（:257-284，
   仿既有两 gate 的 :278-281 显式构造；所有测试以 `..AppState::default()` 构造，
   加字段安全）；engine.rs 在 `sync_now_with_backend` 的 copy（:431）之后、
   `fetch_manifest`（:446）之前停靠 `#[cfg(test)] state.network_phase_gate.wait_if_armed();`。
5. `password.rs` :90-93 注释追加一句互指："the sync merge window instead captures at
   cycle start (earlier than its window) because its pre-window phase includes network
   I/O — see sync/engine.rs"。

**红→绿测试**（`tests_window.rs`，镜像既有 `lock_during_sync_window_is_not_silently_revoked`
:193 的 fixture/线程结构）：

```text
lock_during_network_phase_is_not_silently_revoked
1. device_a.network_phase_gate.arm()
2. spawn 线程跑 sync（经 sync_now_with_backend + cloud.handle()）
3. 等 gate arrival → state.lock_vault() → gate.open()
4. join：断言 result == Err(VaultLocked) 且 !state.session.is_unlocked()
红（现状）：返回 Ok 且 session 已被 republish 复活解锁
```

### F1：自动同步不再刷新完整自动锁窗口

**改动**：

1. engine.rs 新增（模块内）：

   ```rust
   /// Who started this sync cycle — decides which auto-lock window a
   /// successful merge window may refresh (SEC-L5: background cycles are
   /// NOT user presence).
   #[derive(Clone, Copy, PartialEq, Eq)]
   pub(super) enum SyncTrigger {
       /// User-initiated (sync_now command / connect) — full window applies.
       Manual,
       /// Background 30s scheduler tick — extends only the 120s remote grace.
       AutoCycle,
   }
   ```

2. `run_merge_window` 追加参数 `trigger: SyncTrigger`；:144-147 的
   `state.touch_activity()` 与过时注释（"sync window ... is Tauri-only and driven by
   the desktop user"）改为：

   ```rust
   // SEC-L5 presence policy: a Manual cycle is in-person desktop activity
   // and keeps the full auto-lock window; an AutoCycle is a background
   // timer (lib.rs) — it extends only the 120s remote grace, exactly like
   // sync_disconnect's lease touch below. An unattended desktop must lock
   // even while auto-sync keeps succeeding (v1.8.3).
   match trigger {
       SyncTrigger::Manual => state.touch_activity(),
       SyncTrigger::AutoCycle => state.session.touch_remote_activity(),
   }
   ```

   （R1-P3 折叠：remote 触碰在 `VaultSession` 上——session.rs:194 pub，AppState 无委托。）

   注意 :148-154 的 `match (outcome, published)` 在 touch 之后，保持不动（Err 分支的
   warn 行为不变）。

3. 传参链（仅 3 个函数签名变化，**`sync_now_with_backend` 的 pub 签名保持不变**——
   它是 7 个测试文件 ~70 处调用的 seam）：
   - `sync_now_with_backend(state, backend)`（:422，签名不变）body 改为委托
     `sync_now_with_backend_and_trigger(state, backend, SyncTrigger::Manual)`（新私有 fn，
     承接现 body + epoch 捕获 + gate 停靠 + `extend` 传参）。
   - `sync_now_inner`（:329，私有）：签名追加 `trigger: SyncTrigger`；:338 调用
     `sync_now_with_backend_and_trigger`。
   - `sync_now`（:322）→ `sync_now_inner(state, SyncTrigger::Manual)`。
   - `run_sync_cycle_if_due`（:410）→ `sync_now_inner(state, SyncTrigger::AutoCycle)`。
   - `sync_connect_with_backend`（:229）：connect 永远是用户动作 → :254 传
     `SyncTrigger::Manual`（无需参数穿透）。
   - 既有测试调用点（now seam 实测 37 处/5 文件 + connect seam 29 处/8 文件 ≈ 66 处）
     **零改动**；Auto 语义测试走 `run_sync_cycle_if_due`（tests_auto_sync 既有模式）。

**红→绿测试**（`tests_auto_sync.rs` 或 tests_window.rs，断言 touch 目标而非墙钟）：

```text
auto_sync_cycle_extends_only_remote_grace
  connected pair → unlock → run_sync_cycle_if_due 成功跑一轮
  → 断言 session 的 last_remote_activity == Some(_) 且 last_activity 未被本轮刷新
  红（现状）：last_activity 被刷新
manual_sync_extends_full_window
  sync_now_with_backend 跑一轮 → last_activity 被刷新（防回归）
```

（R1-P3 折叠的测试前置：connected_pair 的 connect 会 prime `last_sync_finished`
（engine.rs:200-201）——自动周期测试须先重置 marker + set_interval
（tests_auto_sync.rs:145-146 既有模式）；断言机制用跨模块公开 API 探针而非私有字段：
`auto_lock_deadline` 相等性（session.rs:549-608）+ `should_auto_lock(0)`，即
remote_touch_grants_only_grace 的公开版。connect 路径的 F2 修复无独立 gate 用例
——记为评审观察项（code-review 核对 :240 捕获与 :254 传参）。）

---

## WP2 — 同步失败持久化（F4，engine.rs + lib.rs 注释）

**改动**：

1. engine.rs 新增私有 helper：

   ```rust
   /// Best-effort: persist a sync failure into SyncState so the settings
   /// status line reflects reality (the "Last sync failed" banner was dead
   /// code — last_result was only ever written as "ok"). Runs ONLY while
   /// the session is still unlocked (sealed rows decrypt under the session
   /// key); a locked session (e.g. a lock that fired mid-cycle) skips, and
   /// the next successful cycle naturally refreshes the status. This
   /// function must never produce a new failure path.
   fn persist_sync_failure(state: &Arc<AppState>, error: &VaultError) { ... }
   ```

   实现：`SessionKeys::copy(state)`（失败即 return）→ `get_db` →
   **`load_config(&db, keys.enc_bytes(), keys.mac_bytes())?` → `None ⇒ return`**
   （R1-P2 折叠：save_sync_rows 必须传 &SyncConfig（sealed_rows.rs:184-189）；未配置
   保险库首日就会被踩到——tests_auto_sync.rs:115-125 在未配置 vault 上跑
   run_sync_cycle_if_due 产生 not_configured；取用形状镜像 engine.rs:432-435）→
   `load_sync_state`（sealed_rows.rs:137，read :434 / mutate :534-542 / save :543 的
   既有形状）→ `last_result = Some(bounded(error))` → `save_sync_rows`（:184）全
   `let _ =`/早退。`bounded` = `error.public_message()` 按 chars 截断 160（防超长 DB 行）。

2. 接线两处：`run_sync_cycle_if_due` 错误分支（:415-417，tracing::warn 之外追加）；
   `sync_now`（:322，wrap `sync_now_inner` 结果，Err 时调用）。
   **不接 `sync_connect`**（失败已有 connectError 内联呈现，且未配置保险库无状态行可写）。
3. 注释修正：lib.rs:91-95（"successes and failures alike are recorded..." 改为
   "success writes \"ok\"; a failure best-effort writes the sanitized public message;
   locked-session failures are log-only"）；engine.rs:381-386 同步措辞。

**红→绿测试**（新 `tests_sync_failure.rs` 或并入 tests_engine.rs，镜像既有 backend stub
模式）：

```text
auto_cycle_failure_is_persisted_to_sync_state
  连接好的 pair + 失败 backend stub → run_sync_cycle_if_due
  → 经 sync_status 表面（engine.rs:589，build_status :609 透传）断言
    last_result == Some(<public_message>)
  红（现状）：仍是旧 "ok"
success_overwrites_failure
  失败一轮 → 成功一轮 → last_result == Some("ok")
locked_session_skip_is_silent
  锁定态调 sync_now → wrapper 进入 persist → SessionKeys::copy 失败早退
  → 无 panic、状态行不变
  （R1-P3 折叠：F2 测试驱动的是 now-seam 不经过 persist 接线点，锁定跳过需独立钉死）
```

前端零改动（SyncSettingsSection.tsx:331-335 横幅自动激活）；可选补一条前端
渲染测试（`SyncSettingsSection` 传 `last_result: "Cloud unreachable"` 断言 role="alert"
出现、"ok" 不出现）——若 SyncSettingsSection 既有测试文件则追加，无则不强求。

---

## WP3 — 自动填充可见性过滤（F3，content-forms.js + 新测试文件）

**改动**（`extensions/chrome/src/content-forms.js`）：

1. 新增 `isViewableField(input)`（roadmap §1 F3 的 checkVisibility 主路径 +
   getComputedStyle 兜底；注释说明 jsdom 走兜底、不依赖 rect/offsetParent）。
2. `findLoginForm`（:113-121）：`passwordInputs = Array.from(...).filter(isViewableField)`；
   过滤后为空 → `return null`（fail-safe：报 "No login form detected"）。
3. `selectPasswordField`（:104-111）：**签名与导出不变**（content-save-prompt.js:84 经
   命名空间消费，自动受益）；其内部对 `passwordInputs` 先过滤再选——调用方
   findLoginForm 已过滤，此层过滤是纵深防御（保存提示路径传入的数组未过滤）。
4. `inspectLoginForm` 用户名候选（:160-163）：`usernameCandidates` 过滤追加
   `isViewableField(input)`。
5. 命名空间导出：`globalThis.PwdVaultContent.isViewableField = isViewableField;`
   （:447 附近，v1.6.3 全名引用约定）。
6. 边界注释：`checkOpacity: false` 不拒 opacity:0（避免误伤动画表单）；渲染级蜜罐
   （遮挡/覆盖）超出"未渲染字段"防线——业界 bar 即此。
7. **不碰**：`insertPassword`（activeElement 用户定向路径）、domain-match.js（字节冻结）。
8. **R1-P2 折叠（样式显隐回归）**：findLoginForm 过滤后，"预渲染 display:none、靠
   style/class 切换显隐且无 DOM 插入"的登录层将不再触发悬浮按钮（content.js:143-146
   观察器只配 childList/subtree）。修复：观察器追加
   `attributes: true, attributeFilter: ["style", "class", "hidden"]`（content.js 一行，
   不在全局红线内，与过滤同属 F3 语义）。失败方向安全（更少自动化而非泄漏），
   真机验证进 QA T60。

**红→绿测试**（新文件 `extensions/chrome/src/content-forms.test.js`。R1-P2 折叠：
加载模板**不用** content-save-prompt.test.js（那是 readFileSync 源文本契约测试，无
jsdom）；可行先例是 **clipboard-clear.test.js:1-11**——vite.config.ts:64 全局 jsdom 下
直接 `import` 扩展源文件 + 断言 `globalThis.PwdVaultContent.*`。content-forms.js 顶层
无 DOM 访问、无跨文件裸标识符，单独 import 可行。这是单叶 content 文件的首个行为
测试，不推翻六文件联合体的源文本约定（content-shadow.test.js:6-9）。）：

```text
honeypot hidden-first → visible selected          （红：现状选 [0] 隐藏字段）
hidden + autocomplete=current-password → 仍跳过    （可见性优先于 autocomplete 提示）
all hidden → findLoginForm 返回 null
hidden username candidate → 被跳过
save-prompt：可见字段正常捕获、隐藏字段不捕获       （经 selectPasswordField 间接断言）
```

---

## 测试基线算术（symlink 双计！）

- vitest 同时收集 chrome/ 与 firefox/（symlink）——WP3 新文件按 2 文件计数：
  前端 706/84 → **706 + 2×N(F3) + M(F4 前端) / 86**。N=5、M=1 时预计 **717/86**。
- Rust 450(+1) → **+5~6**（F2 ×1、F1 ×2、F4 ×2-3）≈ **455~456(+1)**；native-host 23 不变。
- 实施第一步实跑钉死精确基线后按此算术验收；任何偏差必须解释归属
  （gotcha：计划清除项必须现场核对归属）。

## 门禁与发布

1. 每包完成即跑：`cd src-tauri && cargo test --workspace`（WP1/WP2）、`pnpm test`（WP3）、
   收尾 `cargo clippy --workspace --all-targets -- -D warnings` + `pnpm typecheck` +
   `pnpm lint`（0 errors）。
2. 双域评审：rust-reviewer（WP1/WP2）+ extension-reviewer 或 react-reviewer（WP3）并行。
3. 干净 worktree 全门禁（gotcha 清单：native-host sidecar 预编译进 src-tauri/binaries/；
   commit-gate 标记分两条命令；web-ext lint；vitest 以 CI-true 计数为准）。
4. bump：`scripts/bump-version.sh`（10 文件）→ `--locked` 验锁（脚本只刷 native-host 锁，
   src-tauri 锁无依赖变化时不动）→ CHANGELOG → commit/tag → push 后盯 CI（轮询）。
5. QA T60 appended（真机）：蜜罐页 Chrome+Firefox 实测 / 开自动同步 5min + 空闲 >10min
   确认锁定 / 过期 WebDAV 凭据 → 失败横幅可见 / **样式显隐登录表单（R1-P2 折叠）：
   display:none→可见切换后悬浮按钮仍出现**。

## R1 评审结论（2026-11-12，plan-reviewer）

**PASS**（0×P0/P1；3×P2 + 6×P3 全部折叠入本 R2：测试模板改 clipboard-clear 先例、
样式显隐回归修复、persist 的 not-configured 分支、`state.session.` 前缀、手写
Default impl、connect 路径记评审观察项、locked-skip 独立用例、行锚/计数修正、
F1 测试用公开 API 探针 + marker 重置）。评审独立证实：66 处测试调用点零改动、
`last_result` 为本地密封行无容器格式影响、TS 类型无联合约束、横幅原样可激活。

## R3 实施期修正（2026-11-12，ds-worker 红相证据 + 主代理复核）

**发现（F1 机制缺口）**：F1 的 touch 分派只堵了两个刷新机制之一。`unlock_if`
（session.rs:140-152）——每次成功 sync 周期 republish 的必经路径——整树重建
`SessionInner::Unlocked` 且 `last_activity = Instant::now()`，**republish 本身就在
刷新完整窗口**（worker 实测：分派就位后 deadline 仍 +23ms ≈ 周期时长）。D8 窗口的
drain（exclusive_lock_and_clear）先销毁时间戳，unlock_if 再以 now 重建——"保留"
必须在窗口两侧成对发生。

**修正机制（快照-恢复，cycle 透明语义）**：

1. `VaultSession` 新增（不改 `unlock`/`unlock_if`/`lock_vault`/generation 规则——
   变体为纯新增；密码/恢复路径继续用现函数，其 la=now 语义正确因用户在场）：
   - `pub fn activity_snapshot(&self) -> (Instant, Option<Instant>)`（真实 pub，
     sync 引擎产码使用，非 cfg(test)）
   - `pub fn unlock_if_restoring(&self, enc, mac, predicate, last_activity,
last_remote_activity) -> bool`——与 unlock_if 同构（同一谓词临界区、
     generation +1、wrap_key: None 不变），唯一差异：以传入时间戳重建而非
     now/None。谓词拒绝时行为与 unlock_if 一致（密钥 zeroize 丢弃、session 原样）。
2. 周期起点（F2 的 epoch 捕获旁，now 与 connect 两路径）一并快照
   `(epoch, last_activity, last_remote_activity)`（打包为 `CycleStartPresence`
   小结构），穿透 `run_merge_window` → `republish_if`（state_io.rs:586 签名透传）→
   republish 改调 `unlock_if_restoring`。
3. F1 的 touch 分派保持（发布后执行：Manual → touch_activity 刷新为 now，用户在场
   语义 ≈ 现状；AutoCycle → 仅 remote grace）。组合效果：**sync 周期对在场状态完全
   透明**——auto 周期后 deadline 不动（锁按计划触发），manual 周期后由 touch 刷新
   （≈现状），F2 锁定场景谓词失败照旧保持锁定。
4. `wrap_key: None` 语义不变（republish 后 Touch ID 重提示 = 现状行为）。

**测试适配**：worker 已写的 grace 探针用例照用；deadline 断言改为"周期前后
auto_lock_deadline 相等"（快照-恢复下可满足——R1 折叠的原始探针复活）；
manual 用例仍断言 touch 刷新（分派在发布后，语义成立）。
**rust-reviewer 必审项**：session.rs 两个新增 API 的状态机正确性（临界区、
Locked/Unlocked 两臂、generation 规则、zeroize 路径）。
