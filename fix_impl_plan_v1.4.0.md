# fix_impl_plan_v1.4.0.md

**版本**: R3 · 2026-10-25 · 状态: 待终审（R2 复核：八项修订全落位，仅 1×P1 新矛盾——purge 记账吞合法复活——已修正 + P2/P3 采纳）
**范围来源**: 审计功能对标 Top10 中的四个 S 级件 + tauri-plugin-updater/wry 现代化（zip 债务的现实处理，见 WP1 背景重大修正）。
**原则**: 产品件贴既有模式（settings/service/dispatcher 既有分层）；安全敏感处（URL 匹配、last_used_at 同步语义）逐条写死设计；wry 大版本跳跃必须配真机更新流 QA。

---

## ⚠️ WP1 背景重大修正（对既定计划的偏离，已向用户报告）

既定目标"升级 tauri-plugin-updater 以获得 zip ≥9、清零三条 RUSTSEC"**经 2026-10-25 crates.io 核实不成立**：tauri-plugin-updater 全系版本（含 2026-10-14 发布的 3.0.0-alpha.3）的 zip 依赖仍为 `^4`；`cargo update -p tauri-plugin-updater` 干跑显示 zip 完全不动。zip ≥9 在插件生态中当前不存在，修复不可达。
**修正后方案**：v1.4.0 将插件在 2.x 线内升到最新（连带 wry 0.54→0.57 及传递依赖现代化，本次干跑已确认 wry 0.57.1/brotli 9 等），并以此为契机完成更新流全面 QA；zip 三条 ignore **续期至 2027-06-30**，理由更新为上述 upstream 事实（附核实日期与版本证据），触发条件改为"Tauri 任一版本线提供 zip ≥9 时的下一个 minor 必须跟进"。强制到期机制保持。此偏离已在计划评审前报告用户。

---

## WP1 — tauri-plugin-updater 2.x 最新 + wry 现代化 + zip 放行续期

1. `cargo update -p tauri-plugin-updater`（2.x 线内最新，干跑显示 wry 0.54.4→0.57.1、brotli 9、windows-future 等一大批传递更新）；npm 侧 `@tauri-apps/plugin-updater` 升到与插件匹配的 2.x 最新（package.json ^2.11.0 → 实际最新 2.x；JS API 在 2.x 线内兼容，SettingsContext 的 check/downloadAndInstall 调用面不变，typecheck 验证）。
2. **allowlist 续期与改写**：deny.toml、.cargo/audit.toml、docs/SECURITY-ADVISORY-ALLOWLIST.md 三处 zip 条目的 expiry `2026-12-31 → 2027-06-30`，reason 增补："2026-10-25 crates.io 核实：tauri-plugin-updater 最新版（含 3.0.0-alpha.3）zip 依赖均为 ^4，zip ≥9 在插件生态不存在；本放行待 Tauri 任一版本线提供 zip ≥9 后于下一个 minor 移除"。allowlist 文档表格同步。
3. **wry 0.57 回归 QA 面**（真机，写入 qa_manual）：自动更新完整流（检查→下载→安装→重启）+ 手动检查 + 托盘/窗口基础行为；macOS 与 Windows 各一遍。CI 产物作为 QA 载体。
4. 验收：`cargo test --workspace` 全绿；`cargo audit -n` 后 rustls/zip 状态不变（zip 三条仍在 allowlist、其余无新增漏洞）；`pnpm typecheck` 过。

## WP2 — 自动填充匹配放宽 eTLD+1

### 设计（安全敏感，逐条写死）

1. **语义**：匹配键从"完整 hostname（剥 www）相等"放宽为 **eTLD+1（注册域）相等**：`accounts.example.com` 与 `example.com` 互相匹配；`example.co.uk` 必须按三段计（多段公共后缀不得把 `evil.co.uk` 误判为同站）。空 entryUrl 放行、空 pageUrl 拒绝、scheme-less 补 https、大小写归一、剥 www——既有语义全部保留。
2. **多段后缀表 + fail-closed 退化（评审 P0 修正）**：不引入完整 PSL（250KB 依赖不划算），内嵌一份**精选多段公共后缀常量**（约 120 条：co.uk/org.uk/ac.uk/gov.uk/co.jp/ne.jp/or.jp/com.au/net.au/org.au/co.nz/com.br/com.mx/co.in/co.za/com.sg/com.hk/com.tw/com.cn/gov.cn/net.cn/org.cn 等，取 Mozilla PSL ICANN 段常用项）；`registeredDomain(host)`：取末 2 段；**若末 2 段命中后缀表 → 取末 3 段；若末段为 2 字母 ccTLD 且末 2 段不在表内 → 回退完整 hostname 精确匹配（fail-closed：漏表时宁漏报不泄密，否则 `login.site.co.xx` 与攻击者可注册的 `evil.co.xx` 会被同化为同一"注册域"）**；**标签不足边角（R2 复核 P3）**：host 本身即为表内后缀（如 `co.uk` 两段取"末 3 段"标签不足）→ 回退完整 hostname 精确匹配，测试钉住；单标签 ccTLD 集（tv/io/me 等 ~250 条）列为可选增强不进本版。表常量注明"精选非全集、出处 Mozilla PSL ICANN 段、2026-10-25 摘录"。单测覆盖：表内命中/未命中/ccTLD fail-closed/标签不足/大小写。
3. **实现收敛：两门五处归一（评审 P1-1/P1-2 修正）**：匹配实际有**两个门，语义不同，都必须升级且不得互相 unify**——① **宽门 `entryMatchesPageUrl`**（空 entryUrl 放行的泛型语义，sender-auth.js:87 注释明言与严门 "Do NOT unify"）：真源在 sender-auth.js，content.js 逐字副本 + popup.js import 调用跟随；② **严门 `entryMatchesSenderUrl`**（sender-auth.js:56-73，要求 entry.url 非空，background.js:487 GET_ENTRY 填充门消费）：**升级为同一注册域语义**（共用升级后的 normalizedDomain/registeredDomain），且 **background.js getEntriesForUrl（L499-508）删除第三处独立实现、改 import 严门**——不得改用宽门（其空 entryUrl=true 会把泛型条目放进任意页的自动填充列表，破坏 background.js:505-506 与 L631-634/L842-844 注释依赖的"空 entryUrl 拒绝"不变量）。content.js 的 `normalizedDomain` 副本（L29-35）与新增后缀表常量、`registeredDomain` 助手一并逐字节同步。
4. **测试**：sender-auth.test.js 既有 6 用例中"sub.example.com 被拒"（L71）改断言新语义（接受）；新增：宽门/严门各自的 eTLD+1 跨子域接受、多段后缀（co.uk）不跨站、**ccTLD fail-closed 用例（不在表内的 `co.xx` 下两站互不匹配）**、既有语义回归（空 entryUrl 宽门放行/严门拒绝、scheme-less、www）；**getEntriesForUrl 回归：泛型条目（空 URL）永不出现**；逐字守卫扩展：sender-auth ↔ content 的同步断言范围扩至 `normalizedDomain` + 后缀表常量 + `registeredDomain`（守卫测试同步升级；注意提取正则 `[\s\S]*?\n\}` 遇函数内列 0 闭括号会截断——新函数保持扁平不嵌顶层闭括号，或改用计数提取）。content-shadow/content-is-trusted 守卫全绿。

## WP3 — 生成器 passphrase / PIN + 会话历史

1. **Rust 算法**（application/service/utils.rs，桌面与扩展共用链路）：新增 `generate_passphrase(words: u8, separator: &str, capitalize: bool, append_number: bool)` 与 `generate_pin(len: u8)`；词表 **EFF short list（1296 词）以 `include_str!` 内嵌**（可 diff EFF 原文；附完整性测试：恰 1296 词、全 ASCII 小写、无重复）；选择用 OsRng + **无模偏差采样（评审 P2 精确化）**：抽 `u16`，接受域 = 1296 在 2^16 下最大整数倍 **64800**（`v < 64800` 接受，否则重抽），`index = v % 1296`；append_number 用 OsRng 0-99。validation（domain/generator.rs）加对应参数校验（words 3-10、pin 4-16 等）。
2. **命令面**：`generate_password` 命令与 dispatcher 的 `generate_password` 增加 `mode` 参数（`"password"|"passphrase"|"pin"`，**`#[serde(default)]`** 缺省 `"password"` 向后兼容——旧扩展/旧调用零破坏）；透传各模式参数。dispatcher 默认值同步。**契约测试（评审 P2）**：新增"无 mode 的旧载荷"反序列化回归用例。
3. **前端**：GeneratorScreen 加模式切换（三段 tab）；passphrase 模式选项（词数 3-10/分隔符/首字母大写/追加数字）、PIN 模式（长度 4-16）；StrengthMeter 支持模式感知熵（passwordStrength.ts 加入口：passphrase = words×log2(1296)+number 位贡献；pin = len×log2(10)——Rust 侧不算强度，前端独有，无 parity 问题）；**会话生成历史**：GeneratorScreen state 保留最近 10 条（时间+值，点击复制），**不持久化**（写明理由：生成值落盘扩大攻击面，会话级已满足"找回刚生成的密码"诉求）。
4. **测试**：Rust 单测（passphrase 词数/分隔/大小写/数字、pin 长度与字符域、无模偏差统计粗检、校验边界）；前端模式切换与历史列表测试；popup 模式透传冒烟（popup UI 加同款模式 select，走既有 NM 链路）。

## WP4 — 最近使用排序 + 回收站

### last_used_at 写入路径（同步语义敏感，逐条写死）

1. 恢复写入 + **节流（评审 P1：§5.1.2 当年因写放大移除——每次取密=条目重封+全摘要刷新）**：`get_entry_secret`（service 层，桌面复制与扩展复制/填充的共同必经点）成功取密后，**仅当 `now - 已存 last_used_at > 60s` 才落盘 bump**（读现值即可判断，无额外状态）；bump **显式不 bump `updated_at`**——last_used_at 定位为**设备本地元数据**：评审已核实 SyncEntry 不含该字段（sync/mod.rs:74-93）、指纹/anti-echo 天然无涉、save_entry upsert 仅在 update/remove 显式赋 updated_at（entries.rs:206/273）→ 纯 bump 不触发同步推送；合并时随胜者 payload 覆盖属可接受行为（注释写明）。
2. 移除/修正 native_messaging/tests.rs L356 "persistence removed" 断言（语义反转，改为断言 bump 生效 + 60s 内第二次取密不落盘）。
3. summary DTO（列表接口）补 `last_used_at` 字段供排序（评审已核实 dto.rs:84-93 现缺；entry_codec/golden 已含该字段，格式无变化）。

### UI

4. **排序控件**：VaultScreen 搜索区（L170-208）加排序下拉（`Recent`（last_used_at 降序，空值沉底）/ `Recently updated`（updated_at 降序）/ `A–Z`），VaultContext 加 `sortMode` state（入 settings 持久化，默认 Recent——worker 按既有 settings 模式加字段）；排序在 filteredEntries 末端 useMemo 应用。
5. **回收站**：service 新增 `list_deleted_entries`（复用 tombstone 行）、`restore_entry`（deleted_at=None + **updated_at bump**——必须胜过远端 tombstone，走既有 merge 复活规则 L113-131）、`purge_entry`/`empty_trash`（物理删行）。**purge 回流对策（评审 P1 + R2 复核 P1 修正）**：物理删本地行后，远端容器的 tombstone 会在下次同步经 merge 规则 1（单侧存在→原样采纳）+ upsert（vault_store.rs:88）**重插本行，回收站被回填、"清空"自我撤销**——对策：本地 `purged_entry_ids` 记账（redb 独立小表，**仅本地不同步**，FIFO 上限 500）；**过滤必须限定 tombstone 行（`deleted_at.is_some()`）——live 行即使 id 在账也放行并顺带出账**（对端离线编辑按 merge 复活规则胜过本端 tombstone 时，pull 到的是 live 行，无差别过滤会静默吞掉合法复活并每次同步重演 = 数据丢失）；`list_deleted_entries` 同样过滤已记账 tombstone。FIFO 溢出后果注明为已知取舍：最老 id 出账后其 tombstone 会重新出现在回收站，用户可再次 purge。测试钉两个方向："purge → 远端 tombstone 回流 → 仍不出现"与"purge → 远端 live 复活行 → 正常入库且出账"。VaultScreen 加"回收站"入口（分组 tab 行尾部图标或筛选下拉，worker 按现地交互选最贴切者）：已删条目列表（标题+删除时间）+ 单条恢复/永久删除/清空回收站，永久删除走既有 DeleteConfirmModal 危险确认。回收站列表**不参与搜索索引与排序**（独立简单列表）。扩展不暴露回收站。
6. **测试**：Rust（60s 节流双取密单次落盘、bump 不动 updated_at、restore 复活语义、purge 后 tombstone 回流不复活、purge 幂等、deleted 不出现在 list）；前端（排序三态、回收站操作流转、空态）。golden 测试若钉 summary DTO 需同步（worker 报告每一处）。

## WP5 — 全局快捷键

1. **插件**：加 `tauri-plugin-global-shortcut`（v2）依赖 + lib.rs 注册 + capabilities 加 `global-shortcut:allow-register/unregister/is-registered`（最小集，权限名已经评审对照官方文档核实）。
2. **行为**：默认快捷键 `CmdOrCtrl+Shift+Space`（可配置，设置页改键）——动作 = 显示主窗口 + set_focus（复用托盘 show 分支逻辑）+ 路由到 vault 屏 + 聚焦搜索框；注册失败（冲突/无效串）→ 设置页显式红字提示并回退禁用态。设置项：`global_shortcut_enabled: bool`（默认 true）+ `global_shortcut: String`（默认上述）；Rust Settings 结构、infrastructure load/save、types/index.ts、SettingsContext、SettingsScreen Security/General 区块各按既有模式加字段；**改键/开关走 Rust 命令重注册（`register_global_shortcut` command，评审 P3：Rust API 注册则 capabilities 权限语义清晰，避免前端 JS API 与 capability 的错配）**，校验失败保留旧值并提示。已知上游问题备注：macOS 回调可能双触发（tauri#10025），写入 T37 观察项。
3. **测试**：Rust 注册/注销与回调分发单测（mock 不可行处至少测配置解析与校验）；前端设置项读写测试。

---

## 门禁（全部通过才算完成；最终在干净 worktree 执行，含边车前置步——v1.3.2 教训）

```bash
cd src-tauri && cargo fmt --check && cargo clippy --workspace --all-targets && cargo test --workspace && cargo metadata --locked --format-version 1 > /dev/null
grep -A1 'name = "wry"' src-tauri/Cargo.lock   # 评审 P3：断言 wry 已到 0.57.x
cd extensions/native-host && cargo test && cargo metadata --locked --format-version 1 > /dev/null
cd .. && cargo deny --manifest-path src-tauri/Cargo.toml --config deny.toml check
cargo audit -n --file src-tauri/Cargo.lock && cargo audit -n --file extensions/native-host/Cargo.lock
pnpm typecheck && pnpm lint && pnpm test
bash extensions/chrome/scripts/build.sh && pnpm dlx web-ext@10.5.0 lint --source-dir extensions/firefox/dist --warnings-as-errors
```

## 发版步骤（门禁通过后）

1. CHANGELOG `## [1.4.0] - <发布日>`：**Added**（eTLD+1、passphrase/PIN+历史、最近使用排序、回收站、全局快捷键）、**Security**（updater 插件/wry 现代化；zip 放行续期的 upstream 事实与期限）、**Fixed/Changed** 视实现。
2. `qa_manual` 追加 T33-T37：**T33** updater 真机端到端（v1.3.2→1.4.0 自动更新全流程，macOS+Windows 各一遍——wry 跳跃的 QA 主体）；**T34** eTLD+1 匹配真站（accounts.example.com 类子域站点 + 一个 co.uk 站点不跨站）；**T35** passphrase/PIN 生成与历史；**T36** 回收站全流程（删→列出→恢复→永久删→清空）；**T37** 全局快捷键（默认键、改键、冲突提示）。
3. `./scripts/bump-version.sh 1.4.0` 后必须 `cargo metadata --locked` 验锁（v1.3.1 教训）。
4. 提交序列沿用先例（feat 主体 → release → docs+会话日志）；AGENTS.md 头部/基线/会话日志更新。
5. 干净 worktree 复跑全套门禁 → `git tag v1.4.0 && git push origin main --tags` → 监控 Release + Quality Gates + feed。

## 非目标（v1.5.0+）

每条目 URL 覆盖开关；完整 PSL；生成历史持久化；回收站自动清理策略；passkey/导入器/安全仪表盘（对标清单的 M/L 件）；pair 弹码扩展 ID 摘要；LWW 冲突计数。

## 风险与回滚

- **wry 0.54→0.57** 是本版最大不确定性：覆盖面是全部窗口/托盘/更新行为，靠 T33 真机端到端兜底；CI 双平台构建先行暴露编译/打包层问题。回滚 = revert 提交（锁与依赖同 revert）。
- **eTLD+1 是安全语义放宽**：错放 = 凭据进错误域名。fail-closed 退化规则（ccTLD 不在表内 → 回退精确匹配）+ 攻击面用例 + 两门归一 + 三路审查重点；"宁漏报不泄密"取向写进代码注释。
- **last_used_at 同步语义**：设计为本地元数据（不 bump updated_at、不推同步），与 merge 覆盖行为的交互已有注释与测试；若 review 发现指纹/codec 隐患，按 review 意见调整。
- 四个产品件各自独立成提交单元，回滚互不牵连。
