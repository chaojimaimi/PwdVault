# 修复路标方案 — 基于 2026-11-12 五路审查结论

> 依据：`pwdvault-2026-11-audit-findings.md`（记忆档案）+ 本文档。四个 P1 均经二轮对抗性
> 交叉验证确认（机制链零缺口），行号基于 main @ 8687c7c。
> 状态：提案（待用户批准批次①后按既有管线走 mini-plan R1 → plan-reviewer → 实施 → 双域评审）。

---

## 0. 批次总览

| 批次          | 目标版本            | 范围                                                     | 体量                             | 门禁 QA                 |
| ------------- | ------------------- | -------------------------------------------------------- | -------------------------------- | ----------------------- |
| ① 安全 hotfix | **v1.8.3**（patch） | P1×4                                                     | Rust <30 行 + 扩展 ~30 行 + 测试 | T60 真机三项（见 §3.5） |
| ② 加固 + 速赢 | **v1.8.4**（patch；2026-11-12 用户裁定本批改 patch 号，原计划 v1.9.0） | P2×6 + 精选 P3 速赢                                      | M                                | T61 真机项              |
| ③ 战略特性    | v1.10+ 分班车       | passkeys / F1 签名 / Windows Hello / HIBP / secure notes | 各 S–L                           | 每项独立 QA             |
| — 明确不做    | —                   | duress PIN / 邮件深网监控                                | —                                | —                       |

排序理由：①是安全模型回归（SEC-L5 失效 + 蜜罐外泄向量），修复成本极低且全部可红→绿钉死；
②全是纵深防御与诊断性修复，无相互依赖；③每项独立立项，其中 F1 签名最便宜且是其余项的
分发前提，passkeys 需先做可行性 spike。

---

## 1. 批次① — v1.8.3 安全 hotfix（P1×4）

### F1（P1-1）自动同步不再冒充用户在场

**问题**：`run_merge_window` 尾部 `state.touch_activity()`（engine.rs:147）刷新完整自动锁窗口；
v1.6.0 起后台线程（lib.rs:96-101，30s tick）无用户参与调用同一路径 → 开自动同步（5min 档 <
600s 默认锁）的用户，无人值守永不锁。

**设计**：

1. 新增 `enum SyncTrigger { Manual, Auto }`（application crate，sync 模块内即可）。
2. 传参链：`sync_now`/`sync_connect` → `SyncTrigger::Manual`；`run_sync_cycle_if_due` → `Auto`；
   `sync_now_inner` → `sync_now_with_backend` → `run_merge_window` 逐层透传。
3. engine.rs:147 改为按 trigger 分派：`Manual → touch_activity()`，`Auto → touch_remote_activity()`
   （120s 远程宽限——与同模块 `sync_disconnect` engine.rs:573 的既有正确用法对齐）。
4. 同步修正 `:144-147` 过时注释（"sync window is Tauri-only / driven by the desktop user"
   的前提已死）；lib.rs:91-95 的 SILENT BY DESIGN 注释在 F4 一并修正。
5. 失败路径不触碰：merge window 返回 Err 时早退无 touch——方向安全（锁早不锁晚）。

**红线**：手动 sync（用户在场）保持完整窗口语义不变；不改 `sync_disconnect`；不引入新依赖；
`auto_sync_due` 状态机不动。

**测试（红→绿）**：

- `auto_sync_cycle_extends_only_remote_grace`：connected pair fixture，跑一个 Auto 周期成功后
  断言 `last_remote_activity == Some(_)` 且 `last_activity` 未被刷新（红：今日 `last_activity`
  被刷新）。直接断言 touch 目标而非墙钟（Instant 不可伪造，稳定）。
- `manual_sync_extends_full_window`：对称断言 Manual 路径 `last_activity` 被刷新（防回归）。
- 既有 `tests_auto_sync` 状态机测试保持绿。

### F2（P1-2）lock_epoch 捕获上移到周期起点

**问题**：`run_merge_window` 在 `exclusive_window.lock()` **之后**捕获 epoch（engine.rs:94→102），
违反 state.rs:241-244 钉死不变式（password.rs:94-98 是正确镜像）。因 `SessionKeys::copy`
立即 drop lease（state_io.rs:553-565），前置网络阶段（fetch/stat/download，30s 量级）无租约
持有 → 期间锁定瞬时完成（bump epoch + 清钥，`Locked{generation}` 保留 generation）→ 引擎
捕获到 post-bump epoch → republish 谓词 epoch+generation 双匹配 → `unlock_if` 无密码复活。

**设计（两步缺一不可）**：

1. **周期起点捕获**：`sync_now_with_backend` 在 `SessionKeys::copy`（engine.rs:431）旁捕获
   `epoch_at_cycle`，作为参数传入 `run_merge_window`（替换函数内捕获）。只有这一步覆盖
   网络阶段——仅重排 guard 前捕获只堵住 guard→capture 的微小间隙，治不了本报告的实际场景。
2. `run_merge_window` 内删除 `:102` 的捕获行，注释改写为不变式的引用
   （"captured at cycle start — any lock from cycle start on wins, covering the network phase"）。
3. `password.rs` 不动：其 reseal 窗口无网络阶段，guard 前捕获已充分；在两处注释互相指向，
   说明 sync 因下载阶段需要更早捕获（防未来"统一"时误改回去）。
4. republish 被跳过时既有 `Err(VaultLocked)` 可重试语义不变；下一周期 `SessionKeys::copy`
   在锁定态自然失败 → 周期跳过，无自旋。

**红线**：不改 `unlock_if`/`lock_vault`/generation 语义；不改 D8 窗口其余顺序；golden fixtures
零触碰。

**测试（红→绿）**：

- 新增 test seam `network_phase_gate`（仿 `merge_window_gate`，cfg(test) one-shot，停靠点在
  `run_merge_window` 调用之前）。
- `lock_during_network_phase_is_not_silently_revoked`：arm gate → 起同步 → 停靠中 `lock_vault()`
  → 放行 → 断言：同步返回 `Err(VaultLocked)` **且** `state.session.is_unlocked() == false`
  （红：今日返回 Ok 且 session 已被复活解锁）。
- 既有 `lock_during_sync_window_is_not_silently_revoked`（drain 后锁定）保持绿。

### F3（P1-3）自动填充可见性过滤（扩展）

**问题**：`selectPasswordField`（content-forms.js:104-111）`explicit || passwordInputs[0]`、
`findLoginForm`（:113-121）全量收集、`fillField`（:279-305）直写——零可见性过滤。蜜罐页
`<input type="password" style="display:none">` 排首位 → 用户点 Fill 后凭据写入隐形字段被
页面脚本读走。Bitwarden `isViewableField` / KeePassXC-Browser / Firefox LoginManagerContent
均显式防御此向量。

**设计**：

1. 新增谓词（content-forms.js，经 `globalThis.PwdVaultContent` 命名空间约定）：
   ```js
   function isViewableField(input) {
     // Chromium 105+ / Firefox 122+：checkVisibility 覆盖 display:none、
     // visibility:hidden、content-visibility（零面积与 ancestor-hidden 含在内）。
     if (typeof input.checkVisibility === "function") {
       return input.checkVisibility({
         checkVisibilityCSS: true,
         checkOpacity: false,
       });
     }
     // 兜底（含 jsdom 测试环境）：computed style 双查。
     const style = window.getComputedStyle(input);
     return style.display !== "none" && style.visibility !== "hidden";
   }
   ```
   平台核验：Chrome ≥109（manifest 底线）✔、Firefox strict_min_version 142 ✔（checkVisibility
   122+）——两目标全支持，兜底只为 jsdom 与极端旧版。
2. 应用三点：`findLoginForm` 先 `passwordInputs.filter(isViewableField)`（过滤后为空 → 返回
   null，报 "No login form detected"，fail-safe）；用户名候选过滤（:160-163 追加同一谓词，
   修复全零 rect 形同虚设问题）；`content-save-prompt.js` 的 `credentialsInForm` 经
   `selectPasswordField` 自动受益——蜜罐页从"捕获空值静默失效"变为"选到可见字段正常捕获"。
3. 边界声明（注释写明）：`checkOpacity: false` 不拒 opacity:0（避免误伤动画表单）；
   页面用覆盖/遮挡等渲染级蜜罐无法完全防御——业界 bar 是拒绝"未渲染字段"，与本仓库
   eTLD+1 fail-closed 哲学一致。

**红线**：`insertPassword`（activeElement 路径）不动（用户显式定向）；不改 fill 事件派发语义；
domain-match.js 字节冻结区不碰。

**测试（红→绿，新文件 content-forms.test.js）**：

- 蜜罐布局：隐藏 password 字段在前 + 可见字段在后 → 选可见字段（红：今日选 [0] 隐藏字段）。
- 隐藏字段带 `autocomplete="current-password"` → 可见性优先于 autocomplete 提示，仍跳过。
- 全部隐藏 → `findLoginForm` 返回 null → autofill 报 "No login form detected"。
- 用户名隐藏候选被跳过。
- save-prompt：可见字段正常捕获、隐藏字段不捕获。
- jsdom 注意：jsdom 无 checkVisibility → 走 computed-style 兜底，用内联 `style.display="none"`
  断言；不要在测试里依赖 rect/offsetParent（jsdom 全零/全 null，会全拒）。

### F4（P1-4）同步失败写入 SyncState，让失败横幅活过来

**问题**：`last_result` 全树仅两处写入且均为 `Some("ok")`（engine.rs:298、:536）；失败路径 `?`
早退 → 横幅（SyncSettingsSection.tsx:331-335）永假；全树无 sync-failed 事件。云凭据过期后
自动同步持续失败，用户看到的仍是 "ok"，设备静默分叉。lib.rs:91-92 注释对失败一半是假的。

**设计**：

1. 新增 best-effort 持久化 helper（sync 模块内）：
   ```rust
   fn persist_failure(state: &Arc<AppState>, err: &VaultError) {
       // 会话仍解锁时才可解密/重封 PVSYNC1 行；锁定态（如 F2 场景）跳过，
       // 下次成功周期自然会刷新状态。绝不让本函数产生新的失败路径。
       let Ok(db) = get_db(state) else { return; };
       let Ok(mut sync_state) = (|| load_sync_state(&db, ...))() else { return; };
       sync_state.last_result = Some(bounded(err));
       let _ = save_sync_rows(...);
   }
   ```
   `bounded` = `err.public_message()` 截断 160 字符（public_message 已净化，无内部路径；
   行内容本身在加密行内，落盘安全）。
2. 接线两处：`run_sync_cycle_if_due` 错误分支（engine.rs:415-417，tracing 之外追加）；
   手动路径 `sync_now` 失败同样持久化（跨重启可见；UI 内联报错不变）。
3. 注释修正三处：lib.rs:91-95（改为 "success writes ok; failure writes the sanitized
   public message best-effort; locked-session failures are log-only"）；engine.rs:381-386
   同步措辞；sync 顶层文档。
4. 前端零改动：`build_status` 已透传 `last_result`（engine.rs:609），横幅自动激活。

**红线**：失败持久化自身绝不产生新错误（全 `let _ =`/早退）；不新增事件通道（YAGNI，
横幅+日志已闭环）；不改变 "transient jitter must not toast" 的静默哲学（状态行 ≠ 打断）。

**测试（红→绿）**：

- Rust：失败 backend stub → `last_result == Some(<public_message>)`（红：今日仍是旧 "ok"）；
  成功周期覆写回 "ok"；锁定态失败（F2 场景后）→ 无 panic、状态不变。
- 前端：SyncSettingsSection `last_result = "Cloud unreachable"` 渲染 `role="alert"` 横幅
  （今日横幅是死代码、无测试——新增）；"ok" 不渲染。

### 1.5 实施与发布

- 流程：mini-plan（本档 §1 即骨架）→ plan-reviewer R1 → 实施（面积小，可循 v1.5.1 先例由
  主代理直接实施，或单 ds-worker）→ 双域评审（rust-reviewer + extension-reviewer）→
  干净 worktree 门禁 → release。
- 发布管线红线（记忆 gotchas 全清单）：commit-gate 标记分两条命令；干净 worktree 验证
  （含 native-host sidecar 预编译进 src-tauri/binaries/）；bump-version.sh 后 `--locked` 验锁
  （脚本只刷 native-host 锁）；web-ext lint；push main 必盯 CI（轮询，gh watch 遇网络抖动改
  轮询）；守卫正则引号无关。
- 测试基线预算：Rust 450(+1) → **~457(+1)**（+6±1）；前端 706/84 → **~712/85+**（F3 新测试
  文件 + F4 前端用例）；native-host 23 不变。typecheck 三 tsconfig、clippy -D warnings、
  eslint 0 errors 全绿。
- QA T60 appended（真机，jsdom 不可见项）：
  1. 蜜罐页真机验证（Chrome + Firefox 各一：真实 checkVisibility 路径）
  2. 开自动同步 5min + 空闲 >10min → 真机确认锁定发生（v1.8.2 同款场景矩阵思路）
  3. 过期 WebDAV 凭据 → 设置页失败横幅真机可见

---

## 2. 批次② — v1.9.0 加固 + 速赢（P2×6 + P3 速赢）

### P2 修复

| #    | 修复                         | 设计要点                                                                                                                                                                                                          | 测试                                                            |
| ---- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| P2-1 | 扩展更新路径后台域重校验     | `updateEntryFromPrompt` 与 `CHECK_SAVE_CREDENTIALS` 在 sendToApp 前用 `authorizeMessage` 的 senderUrl 调 `GET_ENTRIES_FOR_URL`，校验 `entry_id` ∈ 结果集，否则 throw（与 getEntryForSender :102-116 对称）        | background-fill-gate 同款新用例 ×2                              |
| P2-2 | sendToApp 按 error_code 分类 | **recon 前置**：核主机 `HOST_TRANSPORT_ERROR`（main.rs:160）是否透传桌面业务错误码；若桌面 HTTP 错误体无 code，主机对非传输失败统一标 `DESKTOP_ERROR`。扩展 catch 改按结构化 code 判 disconnected，删三个子串匹配 | connection-errors.test.js 扩展（含 "Entry not found" 不再误判） |
| P2-3 | restoreEntry 刷新失败可见    | 照抄 SyncSettingsSection.handleSyncNow 范式："Restored, but refreshing the list failed" toast                                                                                                                     | VaultContext 相关测试 +1                                        |
| P2-4 | VaultScreen 排序守卫         | `settingsState.status !== "success"` 短路 + select disabled（镜像 SettingsScreen.tsx:93）                                                                                                                         | VaultScreen.groupFilter 同款 +1                                 |
| P2-5 | 秘密输入属性卫生             | EntryScreen password `spellCheck={false} autoComplete="new-password"`、username `autoComplete="off"`；Unlock/Setup 经 PasswordField 传 autoComplete                                                               | 属性断言 ×3 文件                                                |
| P2-6 | trash 清理失败二次可见       | 连续第二次失败后 once-per-run toast（保持"解锁永不因清理失败"不变量）；首失败仍仅日志                                                                                                                             | unlock_effects 单测（可测 fail 计数器）                         |

### P3 速赢 rider（S 尺寸，与 P2 同班车）

1. **README 状态刷新**（仍写 v1.1.9 / auto-sync 列 pending）——公开仓库第一印象。
2. **fuse 缓存锁后清理**：`clearSearchCache()` 导出，挂 VaultContext 锁过渡（与 RESET 同点）。
3. **copyWithTimeout 守卫 ×3**（TotpCode/EntryScreen/GeneratorScreen）：try/catch + 现有
   toast 范式（App.tsx:248-251 的既有约定）。
4. **"Copied" 计时器 ref 化**（VaultScreen:136 / GeneratorScreen:182）：clear 后 re-arm。
5. **RecoveryScreen 失败清输入**（或加"重试 UX"注释，与主密码 finally 对齐）。
6. **Generator tabs 语义**：role="tab" → `aria-pressed` 按钮（group-tabs 的 aria-current 先例），
   消解 APG 方向键承诺。
7. **loadDeletedEntries error 载荷**：补 `error: errorMessage(...)`，trash 横幅可显示原因。
8. **integrity.rs 常量时间比较 ×2**（:154、:316，`subtle::ConstantTimeEq`——查 subtle 是否
   已在依赖树，是则零新依赖）。
9. **14MiB/10MiB 上限对齐**：`MAX_BACKUP_FILE_BYTES` 降 10MiB 或 HTTP cap 升 14MiB（择一，
   与 native-host 常量同步）。
10. **ui-bar 悬浮按钮 isTrusted 门控**（content-ui-bar.js:466-469 一行）+ shadow-mount 注释
    措辞修正。
11. **popup go-to-url 方案白名单**（popup.js:440-445）：仅 `^https?://` 直开，否则补
    https:// 前缀，`new URL()` 二次校验失败即拒绝。
12. **eslint 10 warnings 清零**（`entryMatchesSenderUrl`/`entryMatchesSenderUrl` 死导出先核
    sender-auth 测试引用再删；PASSWORD_* 常量核 popup 引用）。
13. **App.tsx:190 中文 toast → 英文**（或标记 i18n 待办）。
14. **VaultContext 死 try/catch 脚手架移除**（:220-269 四处）。

### 批次②缓议（单独立项，不挤本班车）

- **Zeroizing Debug 转发明文**（M）：DTO 面广，建议新类型 `SecretString`（仿 SecretKey 的
  redacted Debug）分类型逐步换——独立班车。
- **NM 主机 1MB 响应上限**：升 4MB 需 native-host 重建 + 金样回归；与 P2-2 的主机改动合并
  考虑，或单独。
- **解锁限流持久化 / keychain Vec 清零 / WebDAV 凭据串 Zeroizing**：清零卫生类，随任意
  Rust 班车搭车。
- **native-host ID 交叉校验**：纵深防御，随 NM 相关班车。

---

## 3. 批次③ — 战略特性（版本规划见 §3.5；2026-11-12 用户决策：③-4/③-5 搁置）

### 3.1 项 1：macOS 签名 + 公证 + Windows Authenticode（含 native-host 签名捆绑）

**macOS 最优路径**（Tauri 官方流程成熟，低风险）：

- Apple Developer Program（$99/yr）→ `Developer ID Application` 证书。
- Tauri v2 bundler 原生支持：`APPLE_SIGNING_IDENTITY` + 公证凭据二选一——`APPLE_ID` +
  `APPLE_PASSWORD`（app-specific password）或 App Store Connect API key（官方推荐项）。
  `tauri build` 时 bundler 自动签名 → notarytool → staple。
- Notarization 强制 hardened runtime：核对现有 entitlements（keychain-access-groups 是
  data-protection Keychain 的前提，另核 webview 的 JIT/allow-jit 需求项）。
- CI：证书 base64 + 密码进 GitHub Secrets，release.yml 加证书导入步骤；密钥红线：只进
  Secrets + 本地 Keychain，绝不进 repo（gitleaks 已有门禁兜底）。
- **隐藏收益（顺带落地）**：签名后 Touch ID 栈可从 legacy login keychain 升级到
  data-protection Keychain（当前 unsigned 构建被 -34018 限制只能走 legacy 路径）；
  updater 的 macOS 更新安装路径也随公证打通。
- **时序红线**：签名必须在下一个 release 生效前完成——首个签名版本发布后，后续所有
  update 都按已签名 app 的路径安装，不能再回退未签名构建。

**Windows 最优路径**（存在地区限制风险，需申请验证）：

1. 首选 **Azure Artifact Signing**（原 Trusted Signing）：$9.99/月 Basic（5,000 签名/月），
   微软现推荐的官方签名服务，云托管无硬件 token，Tauri v2 支持对接。
   **风险**：individual 开发者通道为 public preview 且初限 **美国/加拿大身份**——中国大陆
   身份能否注册需实际申请验证；不可用则降级方案 2。
2. 备选 **OV/EV 代码签名证书**：EV（~$300-500/yr，硬件 token）即时 SmartScreen 信誉；
   OV 便宜但信誉需下载量积累（新证书仍会看到 "Windows protected your PC"）。
3. native-host 签名捆绑（roadmap 既有项）与主程序同一证书。

- SmartScreen 预期管理：任何新证书都有信誉积累期，首个签名版本仍可能有短暂警告期。

### 3.2 项 2：passkeys（spike 先行，实施在后）

**关键外部事实（2026-11-12 调研）**：扩展接入浏览器原生 passkey UI 的机制在 W3C 仍属讨论
中的 spec 议题（webauthn#1976），Chrome 未开放通用的第三方 provider API——正规 provider
通道是 Bitwarden/1Password 级的审批制合作，PwdVault 不应把方案押在浏览器厂商审批上。

**最优路径：KeePassXC 式 content-script intercept 为主方案**（KeePassXC 2.7.7+ 已生态验证，
不依赖厂商审批）：

- content script 拦截 `navigator.credentials.create/get` 的 passkey 调用 → 经既有信任边界
  （isTrusted + eTLD+1 域匹配）转发扩展 → vault 中的私钥在扩展侧做 assertion 签名
  （密码管理器本质是"软 authenticator"，与 KeePassXC 同构）。
- 数据面：第五代 entry codec（passkey 条目：rpId/credentialId/userHandle/私钥）+
  sync container v4——四代解码链与容器版本门禁均有成熟先例。
- 并行动作：仍向 Chrome 提交正规 provider 申请（若获批可平滑切换到浏览器托管 UI）。
- **Phase 0 spike（1 周，v1.11.0 门槛）**：验证 intercept 在 isTrusted/iframe/conditional
  mediation 下的行为边界 + Chrome Web Store passkey 声明合规要求。
- **降级方案**：spike 失败则做"passkey 存档"（保存/查看/导出，不含签名），完整支持延后
  重估。

### 3.3 项 3：Windows Hello（M，随 v1.10.0 平台班车）

**最优路径（v1）：DPAPI 保险箱 + Hello presence gate，镜像 Touch ID 语义**：

- wrap key 用 DPAPI（CryptProtectData）加密落盘——**infrastructure 的 DPAPI credential
  路径已存在**（Windows CI 已覆盖），零新依赖底座。
- 解锁流程：`UserConsentVerifier.RequestVerificationAsync`（WinRT，`windows` crate 开
  feature）弹 Hello/生物/PIN → 通过后 DPAPI 解出 wrap key → 走现有 wrap 解封链
  （与 Touch ID 的"Keychain wrap + biometric ACL"完全对称）。
- **dual-mode 降级**（镜像 Touch ID dual-mode 先例）：无 Hello/无生物硬件的机器不启用
  该功能（UI 不出现），不静默降级为纯 DPAPI。
- **安全 caveat（必读）**：已有公开研究（Clément Notin 2019）证明纯 UI gate 类 Hello
  集成可被绕过——**v1 明确定位为便捷解锁（与 Touch ID 同级的威胁模型），master
  password 仍是根防线；v2 升级路径 = KeyCredentialManager（TPM-backed，challenge 签名
  验签后才解 wrap key，私钥不出 TPM）**。注意 KeyCredentialManager 在无生物硬件的
  PC 上也会成功（cppwinrt#999）——严格生物强制做不到，dual-mode 判定要用生物硬件
  枚举而非 API 成功与否。

### 3.4 待重启区（2026-11-12 用户决策搁置）

- **HIBP 双轨**（opt-in k-匿名 + 离线 dump）——重启门槛：隐私立场拍板
- **Secure notes + 密码历史**——重启门槛：下一个 feature 班车排期时顺带评估
  （history 是 S 尺寸搭车项，届时别忘）
- Watchtower-lite / Linux 打包 / 移动端：维持原位（未受本次决策影响）

### 明确不做（记录在案）

- **duress PIN / self-destruct**：三巨头（1Password/Bitwarden/KeePassXC）均无，社区共识是
  FDE/travel mode 替代。
- **邮件深网监控**（Proton/Dashlane 式）：需把邮箱交给第三方，冲突本地-first；最多做
  手动单次查询。

### 3.5 版本规划总表

| 版本        | 主题          | 内容                                                                                                        | 体量/周期                | 前置条件                                                                      |
| ----------- | ------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------------- |
| **v1.8.3**  | 安全 hotfix   | 批次① P1×4（§1）                                                                                            | <1 周                    | 无                                                                            |
| **v1.8.4**  | 加固 + 速赢   | 批次② P2×6 + P3 riders（§2）——2026-11-12 实际发版号（用户裁定 patch；原计划 v1.9.0）                        | ~1 周                    | 无（可与 ① 尾部并行准备）                                                     |
| **v1.10.0** | 平台信任班车  | macOS 签名公证 + Windows Authenticode + native-host 签名 + Windows Hello v1 + data-protection Keychain 切换 | 2–3 周                   | **2026-11-12 备案：方案定稿但暂缓实施，待用户重启**（§3.1–§3.3 设计保留有效） |
| **v1.11.0** | passkeys 班车 | Phase 0 spike → 第五代 codec + sync v4 + 扩展 intercept + 桌面 UI                                           | spike 1 周 + 实施 4–6 周 | spike 结论；建议在 v1.10 之后（发布节奏错峰）                                 |
| 待重启      | —             | HIBP / secure notes / history / Watchtower-lite                                                             | —                        | 用户重启                                                                      |

排序理由：签名（3.1）是"其余一切的安装前提"且最便宜；Hello 与签名同班车构成统一的
"平台信任"主题（README 安装表两行同时落地）；passkeys 体量最大且技术路径依赖 spike
结论，压轴。v1.8.3 → v1.9.0 快速连续出货消化安全债，v1.10 起进入 feature 节奏。

---

## 4. 决策请求（用户拍板项）

1. 批次① 是否立即开工（建议：是——P1-1/P1-2 是安全模型回归，修复 <1 天）。**→ 待确认**
2. F1 的 Apple Developer 账号采购 + Windows 签名通道申请验证（Azure Artifact Signing
   先行，地区限制风险需实测；EV 备选）——**v1.10.0 的硬前提，建议 v1.9.0 期间并行启动**。
3. ~~HIBP 隐私立场~~ → **2026-11-12 决策：搁置**（待重启区）。
4. ~~passkeys 是否进 roadmap~~ → **2026-11-12 决策：不做首批**，passkeys 落 v1.11.0 压轴
   （spike 先行）；HIBP/secure notes 进待重启区。

---

## 5. 依赖与风险索引

- ①内 F2 与 F4 有交互（F2 场景=锁定态失败 → F4 的锁定态跳过分支被 F2 的测试顺带覆盖）。
- ②P2-2 依赖主机 error_code 透传 recon；若需改 native-host，注意其 Cargo.lock 需手动重生
  （bump-version.sh 只刷自己那份）。
- 所有改动不触碰：entry/sync codec 代际、golden fixtures、AAD 常量、NM 协议形状（error_code
  是新增可选字段，serde/前端均向后兼容）。
- 全部红→绿测试先行钉死，实施顺序建议 F2 → F1 → F4 → F3（Rust 三连后扩展收尾，评审两域并行）。
