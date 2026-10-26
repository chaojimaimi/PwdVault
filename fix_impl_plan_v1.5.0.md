# v1.5.0 实施方案 — M 档产品批次第一班（仪表盘 + 导入器 + 三搭车件）

状态: R3 — plan-reviewer 终审 PASS（R1 REVISE 1×P0+4×P1 → R2 REVISE 机理更正 → R3 PASS，评审链路留档供 WP4 复盘）
日期: 2026-10-26
范围: Rust（domain/infrastructure/application/tauri-app）+ 前端三屏 + 扩展匹配门；
NM 命令数不变（无新增 NM command），全部新命令 Tauri-only
调研: 三路 Explore 核实 + plan-reviewer R1 轮复核，引用 文件:行号 为当前 HEAD 实证

## 0. 背景与非目标

审计整改 M 档拆两班（用户已批准路线图）：本班 = 安全仪表盘 + 第三方 CSV 导入器 +
回收站自动清理 + 每条目 URL 匹配覆盖 + pair 弹码扩展 ID 摘要。**非目标（留给 v1.6.0
或更远）**：自定义字段、扩展保存/更新提示、同步冲突提示与定时同步、LWW 冲突计数、
HIBP 泄露查询（外发哈希需单独产品决策）、完整 PSL、生成历史持久化。

## WP1 安全仪表盘（Security Dashboard）

### 设计

- **Rust 侧聚合，不送明文出进程**。新 Tauri-only 命令 `security_report`：
  复用同步域的全量解密形态（`state_io.rs:385-433` read_local_rows 的
  `decrypt_inner:369-382` 模式），只读扫描全部活条目，返回
  `SecurityReport { generated_at, total, weak: Vec<{id, score}>,
reused: Vec<Vec<id>>, stale: Vec<id> }`——**响应不含任何密码/notes/totp 明文**。
  严禁复用 `get_entry_secret`（它有 last_used_at 60s 节流 bump，entries.rs:152-164，
  逐条拉取会污染"最近使用"排序并双倍暴露明文）。
- **明文治理同 SEC-M3 纪律**：解密出的密码 String 一律 `Zeroizing`，重复检测
  的桶 map 存 SHA-256 摘要、绝不存明文，map 用后即弃（评审 P2 收编）。
- **Rust 侧强度评分**：把前端 `getPasswordStrength`（passwordStrength.ts:80-145，
  0-100 启发式）忠实移植为 Rust `strength::score_password`，双端共享 ≥10 条
  固定测试向量（同分断言）保证一致；弱密码阈值 score≤40（Very Weak/Weak，
  passwordStrength.ts:131-142 同源）。
- **重复检测**：对解密后密码的 SHA-256 摘要分桶，≥2 同桶为一组。
- **陈旧检测**：`updated_at` 距今 >365 天（阈值 v1 固定，不做设置项）。
  **文案必须写"超过一年未修改"**——updated_at 是内容修改时间，不是使用时间
  （last_used_at 刻意不 bump updated_at，entries.rs:143-149）；不得写"未使用"。
- **前端**：新 `DashboardScreen`（AppScreen union + App.tsx case +
  VaultScreen `.header-actions` 入口按钮，先例 VaultScreen.tsx:222-231）。
  布局复用 `generator-screen screen-shell` + `settings-section` 卡片族；
  新 ShieldIcon（Icons.tsx 现无此图标）。三张清单行点击 → `selectEntry(id)` +
  `navigate("entry")` 跳编辑；空清单显示健康文案；重跑按钮。报告纯只读，
  无自动修复行为。

### 触面补充（评审 P2 收编）

`src-tauri/tests/golden_contract.rs` 的 `tauri_ipc_commands` 手写清单与
`adapter_only_commands_are_documented` 断言（:51-119, 164-226）必须随本 WP
提交同步加入 `security_report`（WP2 同理加两个 CSV 命令）——该清单不是只有
NM 侧漂移，Tauri 侧也需要维护。

### 测试

- Rust：strength 向量一致性、reused 分桶、stale 边界（365 天 ±1）、tombstone
  排除、锁定态调用报错、明文 Zeroizing 编译期强制（裸 String 无法进入聚合 fn）；
  `security_report` 注册进 lib.rs invoke_handler + golden_contract 清单同步。
- 前端：DashboardScreen.test.tsx（holder 注入 + api mock）：渲染三清单、
  跳转回调、空态；api/vault.ts 命令封装测试（既有 vault.test.ts 模式）。

## WP2 第三方 CSV 导入器

### 设计

- **格式**：Bitwarden / 1Password / Chrome / KeePassXC 四家 CSV 预设，按表头
  签名自动识别（如 `login_uri`+`login_username` → Bitwarden）；无法识别 → 报错
  并列出各预设期望表头（v1 不做自定义映射 UI，记为后续）。列映射：
  title/username/url/password/notes/totp(登录OTP列)/group(folder/Group 列)。
  **解析规范（评审 P2 收编）**：strip UTF-8 BOM（1Password/Chrome 导出常带）、
  CRLF/CR/LF 统一、RFC4180 引号转义与引号内嵌换行支持——表头签名识别必须在
  BOM 剥离之后做。
- **SEC-M2 全程原生对话框，明文不落 webview**：
  - `import_csv_open`（Tauri-only）：原生打开对话框 → 读盘（cap 10MiB、
    ≤5000 行、字段长度走 domain validation）→ 解析+校验 → **暂存进 AppState**
    （明文行结构派生 Zeroize/ZeroizeOnDrop，锁定/退出即弃，仿 pairing session
    生命周期）→ 返回**预览**（不含密码列，密码列仅显示"有/无"）。
  - `import_csv_commit`：**预 seal 全部行 + 单事务批量写 + 单次 digest 刷新**
    （backup.rs:452-508 先例；empty_trash 批量版 entries.rs:367-374 同构）。
    **禁止按条循环 create_entry**——每次 store.write 都伴随整库 digest 刷新
    （entries.rs:60-65），5000 行逐条提交 = 5000 次全库 digest 的 O(n²) 写放大
    （评审 P1 收编）。create_entry 只借鉴"加密前置"一点。group 列存在的先建组
    （**组名 trim 后精确匹配去重**，暂存行间与现库均去重），全部成功后清暂存；
    返回 `{ created_entries, created_groups, skipped_rows }`。
  - 预览到提交之间文件可变：commit 以暂存为准（文档化，不做二次校验）。
- **重复策略**：预览时对暂存行 vs 现库做 `username+url` 相等统计，预览区显示
  "约 N 条疑似重复"；**仍然全部作为新条目导入**（对标 Bitwarden 导入语义，
  不做合并/跳过 UI——记为后续）。
- **前端**：ImportExportScreen 第二个 divider 后新增 settings-section；预览用
  新建轻量表格（项目内无 table 先例，screens.css/settings.css 新增样式，
  全 token 化）；浏览器 fallback：`<input type="file">` 读文本走同一对命令的
  bytes 入口（与 .pvault 的 fallback 先例 ImportExportScreen.tsx:108-139 同构，
  此时预览明文经 webview——fallback 仅非 Tauri 环境，风险接受并注释）。

### 触面补充

golden_contract.rs `tauri_ipc_commands` 清单 + adapter-only 断言随本 WP 同步
（加入 import_csv_open / import_csv_commit）。

### 测试

- Rust：四家表头识别（**含 BOM 前缀/错列序/多余列/CRLF/引号内换行**）、cap 拒绝、
  暂存 Zeroize（drop 断言）+ **锁定即弃暂存用例**（评审 P3 收编）、commit 建条目数/
  组数/组名去重（评审 P3 收编）、单事务断言（digest 刷新一次）、疑似重复统计、
  锁定态拒绝。
- 前端：ImportExportScreen CSV 分区交互测试（识别失败/预览渲染/提交调用）。

## WP3 回收站自动清理

### 设计

- 设置项 `trash_auto_purge_days: u32`，**默认 0=关**（永久删除必须显式 opt-in，
  比 Bitwarden 的默认 30 天保守——本地优先产品的取向，评审可挑战）；
  选项 0/7/30/90。全链路：Rust Settings（`#[serde(default)]`，JSON 写侧即兼容
  旧行）+ Settings golden 两个 hex 常量重捕（bincode_golden.rs:66-70，bincode
  布局变了，v1.4.0 同款手工更新）+ types/index.ts + DEFAULT_SETTINGS +
  SettingsScreen 新 option-row（放 Auto-Lock 分区之后，仿 AUTO_LOCK_OPTIONS）。
- **扫描时机：仅解锁后**（deleted_at 在加密 blob 内，锁定态无法扫描——调研
  实证）。**已知局限明示（评审 P3 收编）**：长期不锁的库不会触发扫描、改设置
  也要等下次解锁生效——写入用户文案与本文档。
- **事件管道（评审 P1 收编）**：application 层无 emit 能力——新服务纯函数
  `run_trash_auto_purge(state, now) -> Result<usize>`（**独立模块** service/
  trash_sweep.rs，entries.rs 已 1011 行超 800 帽不再追加），返回清理数；由
  **持有 emit 能力的适配器**在解锁成功后调用并 emit `trash-auto-purged(count)`
  （count=0 不发）：Tauri `unlock_vault` / `unlock_biometric` 命令（AppHandle
  可得）、NM dispatcher unlock 臂（handle 已有，pair-request 同款管道）。
- **执行位置与批量上限（评审 P1 收编）**：在 complete_unlock **发布密钥之后**
  调用（不在 D8 exclusive window 内），单事务批量"删行+ledger 记录"
  （empty_trash 批量先例 entries.rs:367-374；purge 同事务模式 entries.rs:331-340
  语义——否则下轮同步把远端 tombstone 拉回回收站），**单批 ≤500 且每次解锁
  最多清一批，余额留待下次解锁**（"解锁阻塞有界"严格成立；= MAX_PURGED_LEDGER
  上限）。**路径覆盖明示**：三适配器 = Tauri `unlock_vault` / `unlock_biometric`
  - NM dispatcher unlock 臂；`recover_vault` / `change_password` 虽同走
    complete_unlock_if 但**不触发扫描**，下次解锁补上。

### 触面补充

无新 Tauri 命令，golden_contract 清单无需变动；Settings 字段变更按上文触面走。

### 测试

- Rust：days=0 不扫；到期/未到期边界；同事务 ledger 断言（purge 后远端回放
  不复活）；锁定态不扫；活条目永不入扫描；500 批量上限；返回计数正确性。
- 前端：Settings 分区渲染与保存；toast 事件监听测试。

## WP4 每条目 URL 匹配覆盖（本班触面最大，排最后实施）

### 设计

- **新枚举** `UrlMatchMode { Auto, Exact, Domain }`，`Auto` 为
  `#[serde(default)]`+`#[default]`（先例 GeneratorMode, protocol.rs:82-127）。
  语义（收敛在既有两门之上，扩展侧 exact=hostname 全等、domain=registeredDomain、
  auto=现状 v1.4.0 eTLD+1）。

### P0 收编：条目编解码三代链（R1 的双读方案会灭掉现存条目）

现 PasswordEntry 为 **13 字段**（entities.rs:12-44），LegacyEntryV2 只覆盖
11 字段的 pre-v1.1.5 布局（entry_codec.rs:38-50），bincode 位置编码、双读仅
两代。直接加第 14 字段会让 v1.1.5–v1.4.1 写入的 13 字段 blob 在新旧两个结构上
双双 EOF/trailing-bytes 失败——**现存全部条目不可读**；且若照 R1 重捕两个条目
fixture，golden 全绿恰好把回归洗白。修订：

- ① domain/entities.rs PasswordEntry 加字段（第 14 个）；
- ② **新增只读 `LegacyEntryV3`**（精确映射现 13 字段布局，deserialize-only），
  LegacyEntryV2 保留给 11 字段代；`decode_entry_plain` 变**三代链**：
  当前 14 字段 → LegacyEntryV3（13，新字段补 `UrlMatchMode::Auto`）→
  LegacyEntryV2（11，同理）；
- ③ golden fixture 分两类：现有两个条目 fixture（bincode_golden.rs:44,48）
  重捕为 14 字段布局（bincode 换血 tripwire 职能不变）；**新增第 3 个永久
  fixture 钉死 13 字段真实 blob 的可读性（NEVER RECAPTURE 注释）**——生成
  方式沿用 entry_codec.rs:163-194 的 test-only `Serialize` fixture 模式
  （现行 11 字段字节即产于此），**不手拼 hex**；
- ④ dto.rs EntrySummary/CreateEntryRequest/UpdateEntryRequest；
- ⑤ **SyncEntry 与容器版本（R2 复审机理更正）**：SyncEntry 加字段 +
  entries_to_sync + sync_to_entry（mem::take 纪律）；**新字段必须带
  `#[serde(default)]`——这是读侧 v1 容器兼容的承重措施**：容器快照 payload
  是 **serde_json**（解密后 `serde_json::from_slice::<SyncSnapshot>`，
  container.rs:170；写侧 to_vec + SNAPSHOT_AAD 重封 :219-230），JSON 缺字段
  由 serde default 容忍，**不需要 legacy 结构**（bincode 只用于 LWW
  fingerprint，:233-241）。**CONTAINER_FORMAT_VERSION 1→2**：写侧恒 v2、
  **AAD 常量沿用现有 SNAPSHOT_AAD / WRAP_AAD_CONTAINER 不升版本**（防止
  弄死 v1 读）。bump 的真实理由：不 bump 则旧设备 serde_json **静默忽略**
  未知的 match_mode 并在合并/重发布时把它剥掉（静默数据丢失），且两设备
  fingerprint 输入分歧（container.rs:233-236 注释明言两设备须同容器版本）；
  bump 后旧设备在版本门（container.rs:155-156，先于任何密钥推导）得到干净的
  UnsupportedVersion。**新增永久 fixture：v1 容器真实字节可读
  （NEVER RECAPTURE）**；container.rs 2 个 SyncEntry fixture（:564,:568）
  重捕为含新字段的 fingerprint 输入布局，**2 个 SyncGroup fixture
  （:571,:576）不动**（全班 golden 重捕共 6 个常量 = settings×2 + entry×2 +
  sync_entry×2，另新增 2 个永久 fixture）；
- ⑥ NM protocol.rs NativeRequest 透传字段（`#[serde(default)]`）；
- ⑦ update/create 服务透传。

### 扩展触面（评审 P1 收编：AUTOFILL 消息共 4 个构造点）

- 两门签名改造——`entryMatchesSenderUrl(entry, url)` 已持 entry；
  `entryMatchesPageUrl(entryUrl, pageUrl)` 改收 entry（调用点 popup.js:313、
  content.js:1597 都持完整对象）。
- **AUTOFILL 消息 4 个构造点全部补 match_mode**：background.js:640-648、
  background.js:851-858、**popup.js:318-324（popup 直发 tabs.sendMessage、
  不经 background——R1 遗漏点）**、及 background.js:735-755 的 dead-code 臂
  （其自注释 2026-09 已验证死代码）——同款补 match_mode 转发一行并更新该
  注释（若选择显式跳过则必须改注释说明，两者取其一写死，不留"实施时再定"）。
  **content 侧缺字段回退语义 = auto**（`message.match_mode || "auto"`），
  不是报错。
- **VERBATIM 块纪律**：sender-auth.js:48-293 与 content.js:4-249 逐字同步
  （守卫 sender-auth.test.js:242-261 会红），改动两处同提交；background 禁止
  旁路主机名比较（background-fill-gate 守卫），exact/domain 分支写在两门
  函数体内。

### 前端触面

types/index.ts 三处 + EntryScreen URL 组内 select（auto/exact/domain，
带 hint 文案）+ `detectChanges` 三处跟进（ChangeItem 分支 / metadataDirty /
pendingChanges patch，EntryScreen.tsx:45-127,216-235,304-315）。

### 测试

- Rust：编解码三代链（**13 字段真实 blob 可读** + 11 字段 + 14 字段 round-trip）、
  sync LWW 带 match_mode、v1 容器可读 + v2 round-trip、golden 重捕 6 常量 +
  2 永久 fixture 全绿、NM serde 缺字段默认 auto。
- 扩展：两门三模式行为矩阵（auto/exact/domain × strict/wide 门 ×
  **空 entryUrl（三模式均保持 strict 拒绝——评审 P3 收编）**）、popup 路径
  AUTOFILL 消息含 match_mode 断言、verbatim 守卫双侧同步、popup/content
  调用点透传、content 缺字段回退 auto。
- 前端：EntryScreen select 与 detectChanges 纯函数矩阵。

## WP5 pair 弹码扩展 ID 摘要

### 设计

- dispatcher `pair` 臂（dispatcher.rs:60-77）emit payload 从裸 code 改为
  `{ code, caller }`（caller 已在 protocol.rs:223-227 解析好，native host 与
  协议零改动）；前端 App.tsx:163-168 toast 增加一行"请求方：…"——Chrome 显示
  32 位 ID 的 `前4…后4` 截断（用户可与 chrome://extensions 比对），Firefox
  固定 ID `pwdvault@pwdvault.app` 原样显示。
- **安全定位写进代码注释与用户文案**：`X-PwdVault-Caller` 在 loopback 可被
  本机进程伪造（protocol.rs:257-260 自认），摘要仅为核对提示，不是认证。

### 测试

- dispatcher payload 单测；前端 toast 渲染（含截断格式化函数单测）。

## WP6（搭车）golden_contract NM 清单去漂移

调研发现 `src-tauri/tests/golden_contract.rs:17-47` 手写的 NM 命令集合已与
dispatcher 实际（dispatcher.rs:40-284）漂移（`is_initialized`/`get_entry` 等
旧名），且该测试自比自、永不红。修复：清单更新为与 dispatcher 一致 + 注释
指明维护责任（与 dispatcher.rs 同步改）；不加反射机制（超范围）。updater
公钥 pin 断言（:236-294）不动。WP1/WP2 的新 Tauri 命令进 `tauri_ipc_commands`
清单（见各 WP 触面补充）。

## 模块放置纪律

entries.rs 已 1011 行（超 AGENTS 800 行帽，历史遗留）——本班新增服务一律
独立模块：`service/security_report.rs`（WP1）、`service/csv_import.rs`（WP2）、
`service/trash_sweep.rs`（WP3）、strength 移植放 domain（WP1）。严禁向
entries.rs / backup.rs 继续追加。

## 测试基线预期

前端 391 → 约 +25；Rust +30 上下（三代链与容器 fixture、strength 向量、
report、CSV 双命令、自动清理、dispatcher payload）。发版时以干净 worktree
实测数更新 AGENTS.md。

## 风险

- **WP4 触面最大且动三代编解码 + 容器版本**：排最后实施、独立提交单元；
  两个永久 fixture（13 字段条目 blob、v1 容器）是本班的回归保险丝，任何
  "让测试变绿"的重捕都是禁忌。评审重点拷问 exact 语义与 hostname 全等的
  IDN/端口/大小写规范化（`new URL().hostname` 已含大小写折叠与 IDN→punycode，
  端口不入比较——需在测试钉死）。
- **WP2 明文治理**：暂存 Zeroize、10MiB/5000 行 cap、预览无密码列、单事务
  批量提交、日志禁明文；fallback 路径的明文过 webview 为已知接受项（注释钉死）。
- **WP3 默认值取向**：默认关闭永久删除 vs 对标 Bitwarden 默认 30 天——本方案
  取保守；解锁后执行 + 500 批量上限使解锁路径阻塞有界；仅解锁时扫描的局限
  明示。
- **golden 重捕共 6 常量 + 新增 2 永久 fixture** 必须与结构变更同提交；无
  脚本，手工更新后跑三套 golden 测试确认。
- 仪表盘强度评分若 Rust 移植与前端启发式漂移，两处 UI 会给不同结论——共享
  测试向量钉死，注释互指。

## 门禁与发版

- 本地全套：`pnpm typecheck` / `pnpm test` / `pnpm lint` / 扩展 build+web-ext
  lint / `cargo test --workspace` / native-host test——干净 worktree 复跑后发版。
- 提交序列：WP 各自独立提交单元（WP4 最后）→ release(bump 1.5.0 + 双锁验证
  - CHANGELOG) → docs(AGENTS 头部/基线/会话日志) → tag v1.5.0 → push →
    **盯 Release + Quality Gates + feed**（7 号坑：style 提交也盯）。
- QA 清单：qa_manual 追加 T39-T43（仪表盘真实数据、四家 CSV 实导、自动清理
  到期触发、三模式真站匹配、配对弹码摘要）。

## 审查要点（R1 已答，留档 + 复审新焦点）

1. ~~security_report 攻击面~~ → 响应无明文 + Zeroizing 纪律 + 锁定态拒绝。
2. ~~CSV 暂存 vs bytes-IPC~~ → 暂存制保留；commit 以暂存为准已文档化。
3. ~~D8 窗阻塞~~ → 发布后执行 + 500 批量上限 + 三适配器 emit 管道。
4. **复审焦点**：三代编解码链与 LegacyEntryV3 设计、容器版本 1→2 决策
   （R3 已按 JSON 机理更正 + serde(default) 承重 + AAD 不升级）、
   AUTOFILL 第 4 构造点已写死为 background.js:735-755 dead-code 臂。
5. **复审焦点**：fixture 账目（重捕 6 + 永久 2）是否准确完整。
