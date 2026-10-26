# v1.6.0 实施方案 — M 档"动内核"批次：自定义字段（四代编解码链）+ 扩展保存/更新提示 + 同步冲突计数/定时同步 + `.btn` 行内陷阱收编

状态: **R3 — plan-reviewer PASS**（2026-10-26；R1 REVISE 1×P0+2×P1 → R2 REVISE 1×P1（口径自纠）→ R3 PASS，仅余 1×P3 措辞已修）
日期: 2026-10-26
范围: Rust workspace（domain/infrastructure/application + tauri-app 层）、React 前端、浏览器扩展（Chrome/Firefox 共享源）、桌面 HTTP/NM 表面
基线: main @ 9accf5d（v1.5.1 收尾 style 提交，CI 绿）。测试基线：Rust 391（+1 ignored）/ native-host 23 / 前端记录值 464–465（68 文件；AGENTS 头表 464、v1.5.1 session log 465，**以干净 checkout 实跑为准**）。

---

## 0. 调研结论（方案的事实底座，全部已主代理复核；评审再核）

- `PasswordEntry` 现为 14 字段（entities.rs:46-86），bincode **位置编码**，`#[serde(default)]` 对 bincode 完全失效。加第 15 个字段必须扩 `decode_entry_plain` 世代链，否则 ≤v1.5.x 写下的每一条 entry blob 都读不出来（entry_codec.rs:13-32 模块文档明文警告，v1.5.0 plan review 的 P0 原案）。
- `ENTRY_RECORD_FORMAT_VERSION=2` 只跟踪加密信封通道（v1 无 AAD / v2 有 AAD），**内层布局变更不 bump**（v1.5.0 先例）。AAD 常量不变。
- golden fixture 两类纪律（v1.5.0 先例）：6 个随结构变更**同 commit 重捕**（entry×2、settings×2、sync_entry×2）；2 个 **NEVER RECAPTURE** 永久 fixture（13 字段 entry blob、v1 容器），均由 test-only Serialize fixture 结构生成真实字节，绝不手拼 hex。
- 同步容器 snapshot 是 **serde_json**（读兼容靠 serde default），fingerprint 是 **bincode** `SHA-256(bc_serialize(SyncEntry))`（container.rs:252-256）。SyncEntry 加字段 → 跨版本 fingerprint 分歧 + 旧设备 republish 静默 strip → 必须按 v1.5.0 先例 bump `CONTAINER_FORMAT_VERSION` 2→3，`SUPPORTED_READ_VERSIONS`（`[u32; 2]` 数组）扩容为 `[1, 2, 3]`，SNAPSHOT_AAD 保持不变。
- `SyncConfig`/`SyncState` 密封行（PVSYNC1）内层是 **serde_json**（state_io.rs:629/755）——加字段带 `#[serde(default)]` 即可读旧行，无需 legacy 结构降级。
- LWW 结构（merge.rs:112-165）：`lww` 按 updated_at 取大、相等时 fingerprint 字典序 tiebreak（对称）；墓碑不变式 `deleted_at == updated_at`（`remove_entry` 写入即如此，merge 三分支均保持）。**评审纠正**：复活分支（winner.deleted_at < loser.updated_at）在该不变式下仅损坏/外来数据可触达；真实的"一端删、一端改"按时间戳走 `>=`（删除胜）或 None（改胜）分支。冲突计数口径据此修订（D5）。
- **并发结构（评审纠正）**：`exclusive_window`（state.rs:145）仅覆盖 `run_merge_window`（engine.rs:88-91）；手动 sync_now 的网络阶段（manifest/pull/publish）**设计上在窗外执行**（engine.rs:14-16 模块文档）。不存在"整周期同步互斥体"——D6 新增叶级 `sync_cycle` 锁（评审建议采纳）。
- 备份链路（评审纠正后的正确模型）：`.pvault` 是**明文载荷**——`ExportEntry`（dto.rs:137-150）的 password/notes 为 `Zeroizing<String>` **明文**；导出路径逐条**解密成明文**（backup.rs:80-125），导入路径**明文→encrypt 重封**（backup.rs:361-399 `encrypt_import_entries`，跨 vault/换密恢复可移植）。`ExportEntry` 现缺 `url_match_mode`/TOTP/custom_fields——TOTP 用户备份即丢（实证为真的既有缺口），本批次以**明文载荷**方式补齐（D8）。
- 定时器模板：`start_auto_lock_thread`（lib.rs:43-78，std::thread + ≤5s 醒醒）；"后台动作通知前端"唯一先例是 `app.emit("trash-auto-purged")`。`sync_now` 要求解锁态 + 合并窗走 `exclusive_window`。
- 扩展侧：content script 目前只允许发 `GET_ENTRIES_FOR_URL`/`GET_ENTRY`（sender-auth.js `CONTENT_SCRIPT_COMMANDS`，在 verbatim 块外）；`CREATE_ENTRY` 事实上 popup-only；background **没有** updateEntry 包装。全部 UI 必须走 v1.3.2 closed shadow root 模式（`mountShadowHost`，`content-shadow.test.js` 钉 `UI_ROOTS=4`）；isTrusted 守卫现有 4 处（`content-is-trusted.test.js` 钉计数）。content script 无 `<form>` 时不触发 submit 事件；无 `all_frames`（iframe 明示不支持）；纯 http 页 `crypto.subtle` 为 undefined（secure-context 限制）——摘要计算需 feature-detect（D7）。
- 扩展拿旧密码明文做比对违背 B4 deferred-fetch 姿态（v0.9 audit 先例）——"密码是否变化"的判定必须放在桌面侧，content 只持有用户新键入的明文（本就在页面上）。

## 1. 目标与非目标

**目标（本批次交付）**

1. 条目自定义字段（label + value + secret 标志，随条目加密存储、进同步、进备份）。
2. 扩展"保存/更新提示"：网页提交登录/注册表单后，经桌面侧摘要比对判定 新建/更新/无变化，页面内 shadow-root 提示条，用户点击才落库。
3. 同步：LWW 冲突自动解决的计数与展示（状态行 + 同步 toast）；定时自动同步（默认关闭，Settings 单字段 `auto_sync_interval_min`，0=关闭）。
4. 备份保真修复：`ExportEntry` 以明文载荷补 `url_match_mode`/`totp_secret`/`custom_fields`，导入路径重封还原。
5. Rider：`.btn` 行内陷阱收编——引入 `.btn-inline` 工具类，迁移 v1.4.1/v1.5.1 的 scoped 压制规则，清扫残余陷阱行。

**非目标（显式排除，预留决策）**

- HIBP 泄露监测（外部哈希上报是产品决策，留给用户）。
- 完整 PSL 后缀表（等真实误匹配证据）。
- 生成器历史持久化（隐私）。
- Windows Hello / 生物解锁。
- iframe 内表单检测（无 `all_frames`，本批次明示不支持）。
- CSV 导入自定义字段（4 家 CSV 源格式不一，v1.6.0 导入忽略该列，文档注明）。
- 搜索索引纳入自定义字段 label（涉及桌面/扩展 search-parity 双端同步，留后续）。
- 冲突的三方合并/基线比对（需要快照基线，改动量大；本批次只做 D5 口径内的计数）。

## 2. 设计决策

### D1. 自定义字段数据模型

```rust
// domain/src/entities.rs（新类型）
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct CustomField {
    pub label: String,    // 明文（外层 blob 加密覆盖），可进摘要
    pub value: Vec<u8>,   // 内层密文原始字节：bc_serialize(EncryptedData)，与 encrypted_notes 同模式
    #[serde(default)]     // JSON 面（NM/备份）读兼容；bincode 位置编码下恒存在
    pub secret: bool,     // 仅控制 UI 掩码显示；存储层一律加密
}
```

- `value: Vec<u8>`（评审 P2 采纳）：与 `encrypted_notes: Option<Vec<u8>>` 真正同模式，原始密文字节，无编码歧义。空 vec 合法（占位行）。
- `PasswordEntry` 追加第 15 个字段 `pub custom_fields: Vec<CustomField>`，**置于字段表末尾**（url_match_mode 之后）。bincode 位置编码：旧 blob 少一段 → 反序列化失败 → 世代链降级读取。
- value 一律内层加密（不区分 secret 标志）：与 notes/password 的披露纪律一致——值只经 `get_entry_secret` 离开 vault（SEC-M3/B4 姿态延续）。`secret=false` 只意味着 UI 明文显示。
- 同步域单独建 `SyncCustomField { label, value /*明文 String*/, secret }`（mod.rs），派生 `Zeroize, ZeroizeOnDrop`（SEC-M3 明文域纪律）；`SyncEntry` 追加 `#[serde(default)] pub custom_fields: Vec<SyncCustomField>`（v1/v2 容器 JSON 读兼容的 load-bearing 属性，与 url_match_mode 同位注释）。`SyncSecrets`（sync/mod.rs:129-133）同步增加 custom-field 明文值通道（id 缺失 → 空 vec 回退，评审 P3 采纳）。
- DTO：`CreateEntryRequest.custom_fields: Vec<CustomFieldInput{label, value /*明文*/, secret}>`（明文提交，服务端加密）；`UpdateEntryRequest.custom_fields: Option<Vec<...>>`（None=不动，Some=整替——tags/url_match_mode 的 metadata 整替语义，避开按需加载复杂度）；`EntrySummary.custom_fields: Vec<CustomFieldMeta{label, secret}>`（**只含 label+secret，绝不含 value**——桌面列表、NM list_all_entries/get_entry_meta 三条出口自动带 label）；`EntrySecretResponse.custom_fields: Vec<CustomFieldValue{label, value, secret}>`（明文值，get_entry_secret 一次性解出，Zeroizing 纪律照 password/notes 现状）。
- `EntrySummary::From<PasswordEntry>`（dto.rs:119-135）逐字段拷贝——**漏拷 custom_fields 则三条出口一起静默丢**，测试钉住。

### D2. 校验（validation.rs，照 tags 样板 L163-178）

- **全部在明文层校验**（评审 P3 采纳：密文长度校验属封印点内部实现，不进校验层）：常量 `MAX_CUSTOM_FIELDS=32`、`MAX_CUSTOM_LABEL_BYTES=256`、明文 value ≤ `MAX_FIELD_LENGTH`(4096)。
- label：trim 后非空、字节上限；**label 重复拒绝**（稳定错误码，VaultError 变体命名照 `DUPLICATE_TAG` 惯例）；value 允许空；secret 无约束。
- 校验入口：`entry_fields` / `entry_update` / `backup_payload` 逐字段复用形态（validation.rs:84-143、316-326）。CSV 导入不产自定义字段（非目标），无校验面。

### D3. 四代编解码链（本批次最高风险项）

`entry_codec.rs`（现 438 行，无行数压力）：

- 新增 `LegacyEntryV4`（Deserialize-only，字段 = 现 14 字段布局的精确镜像，含 `url_match_mode`）。
- `decode_entry_plain` 降级链：`PasswordEntry(15)` → `LegacyEntryV4(14)`（custom_fields=vec![]）→ `LegacyEntryV3(13)` → `LegacyEntryV2(11)`，newest-first 逐级降级，映射照抄现链。
- `seal_entry`/`open_entry`/`entry_aad`/`ENTRY_RECORD_FORMAT_VERSION=2` 全部不动（信封版本 ≠ 内层布局）。
- 降级后果如实记录：≤v1.5.x 版本读不了 v1.6.0 写的 entry blob（与 v1.1.5/v1.5.0 历次字段追加同性质，updater 使其在实践中非问题）。

**fixture 纪律（同 commit 完成，缺一即 P0）**：

- 重捕 2 个：`PASSWORD_ENTRY_MINIMAL_HEX`/`PASSWORD_ENTRY_FULL_UTF8_HEX`（15 字段；FULL 的 `url_match_mode=Exact` 哨兵保留，另设 custom_fields 非空哨兵）。
- 新增 1 个永久 NEVER RECAPTURE：`PASSWORD_ENTRY_V4_14_FIELD_HEX` + 测试 `password_entry_v4_14_field_blob_still_reads`——先断言 15 字段 `bc_deserialize::<PasswordEntry>` 对 14 字段 blob **必须失败**，再走真实 `decode_entry_plain` 路径断言读出且 custom_fields 为空。生成方式照 13 字段先例：**test-only Serialize 结构**（14 字段镜像）产真实字节，绝不手拼。同步更新 `bincode_golden.rs:250` 现测试的过时失败消息（"current 14-field layout" → 15 字段表述；断言本身 13≠15 自然成立）。
- `password_entry_v3_13_field_blob_still_reads` 的"当前结构必须失败"断言原样保留（13≠15 自然成立）。
- 同 commit 重捕 `SYNC_ENTRY_MINIMAL/FULL_HEX`（SyncEntry 14 字段，custom_fields 哨兵）。

### D4. 同步容器 v2→v3

- `CONTAINER_FORMAT_VERSION=3`、`SUPPORTED_READ_VERSIONS` 扩容为 `[1, 2, 3]`、`SNAPSHOT_AAD` 不变（v1 永久 fixture 继续通过）。版本门（parse_envelope）外旧设备拿 `SYNC_CONTAINER_VERSION` 可读错误——fingerprint 分歧与静默 strip 在版本门处截断。
- 新增永久 NEVER RECAPTURE：`V2_CONTAINER_HEX` + 测试 `v2_container_real_bytes_still_open`，**落独立测试文件 `sync/tests_container_v2_fixture.rs`**（container.rs 现 758 行近顶）。生成机制（评审 P3 采纳的准确表述）：`entry_fingerprint` 具型于 `&SyncEntry` 不能作用于 test-only 结构——测试内**内联复刻** fingerprint 两行（`Sha256(bc_serialize(...))`，以 test-only 13 字段 SyncEntry 结构为输入）产 snapshot JSON 与 fingerprint，并在测试内**手工复刻 seal 步骤**（模块内 weak-params 助手已示范全部内部件用法）封装版本钉 2 的 envelope；断言 v3 代码读出后 custom_fields 为空（serde default 生效）。
- fingerprint 跨版本一致性模块文档（container.rs:620-633）同步更新至三版本表述。

### D5. LWW 冲突计数（口径按评审 P1 修订）

**计数口径（写进 merge.rs 模块文档；R2 复审 P1 修订）**——一次 entry/group pair 合并计为冲突，当且仅当：

1. **删后修改**：一端墓碑、一端存活，**且存活侧 `updated_at` > 墓碑侧 `deleted_at`**（删除之后对端发生了修改——LWW 裁决丢弃了真编辑或复活了真删除）。关键：不能简单用"状态相异 XOR"——`remove_entry` 写墓碑时**覆写** `updated_at = deleted_at`（entries.rs:484-488），对端**陈旧存活副本**（updated_at ≤ 删除时刻）经 `>=` 分支正常传播删除，XOR 会把每次常规删除传播误计为冲突（trash 批量清理一次可报数百假冲突）。`updated_at > deleted_at` 恰好区分"陈旧副本"与"真编辑"，并天然涵盖复活分支。
2. **时间戳撞车且内容分歧**：`updated_at` 相等且 fingerprint 不同（tiebreak 被迫裁决的真歧义）。

不计：双端均存活的时间戳先后编辑（LWW 设计内行为）；fingerprint 相同的幂等重复添加；双端均删除；**陈旧副本的删除传播**（存活侧 updated_at ≤ 墓碑侧 deleted_at——正常同步语义，非冲突）。
**已知盲区（如实入档）**："修改先于删除"（编辑更早、删除更晚胜出，编辑被 LWW 丢弃）在无三方基线的 2-way 合并下与常规删除传播**不可辨识**，不计数——三方基线比对已列非目标。

- 实现：`merge_entry_pair`/`merge_group_pair` 返回 `(SyncEntry, bool /*conflict*/)`（或等价 MergeOutcome）；`merge_entries`/`merge_groups` 聚合计数；`MergedSnapshot` 加 `pub conflicts: u32`（Zeroize derive 对 u32 成立，ZeroizeOnDrop 链不断）。
- 持久化：`SyncState.last_conflict_count: u32` + `#[serde(default)]`（密封行内层是 JSON，读旧行平滑）。`SyncStatusResponse` 加 `conflict_count: u32`（Serialize-only，旧前端忽略新键无害）。
- UI 文案钉死 "automatically resolved (last-write-wins)"（R7）。首次双 vault 合并若时间戳撞车或存在删后修改，会计数——语义正确（真歧义/真分叉被裁决），文档注明。

### D6. 定时自动同步（锁结构按评审 P1 修订）

- **存储**：`Settings` 加单字段 `#[serde(default)] pub auto_sync_interval_min: u32`（0=关闭，默认 0——严格 opt-in，照 trash_auto_purge_days 语义；UI 选项 0/5/15/30/60）。**归位理由（评审 P3 采纳）**：auto-sync 间隔是设备本地偏好（Settings 已收纳同类 trash_auto_purge_days），SyncConfig 是云连接配置——语义分层，而非密封行成本考量（D5 对 SyncState 加字段证明后者同样便宜）。
- **周期级互斥（新增叶级锁）**：AppState 加 `sync_cycle: Mutex<()>`。`app::sync_now`（手动）、`sync_connect`（评审 R2 P2 采纳：connect 同样跑完整周期，engine.rs:226-250）与定时 tick 都**持它跑完整周期**（网络阶段 + 合并窗），在获取 `exclusive_window` 之前获取（锁序平凡无环：sync_cycle → exclusive_window，换密码/恢复/revoke 只取 exclusive_window 从不取 sync_cycle，无反向获取点）。**取锁模式二分**：定时 tick 用 **`try_lock`**——拿不到 = 有周期在跑 → 本 tick 跳过，绝不排队；手动 sync_now/connect 用**阻塞 `lock()`**——用户显式动作必须完成并回报（SF-P* 立场），至多等一个有界的自动周期（评审建议采纳）。这修正 R1 的两处错误：exclusive_window 只护合并窗、网络 IO 设计在窗外——"无新锁"约束删除（R6 同步更新）。
- **定时器**：tauri setup 里 spawn `start_auto_sync_thread(state)`（照 auto_lock 线程模板，≤30s 醒醒）。每 tick：未解锁 → 静默跳过；`auto_sync_interval_min==0` → 跳过；距上次同步完成（AppState 内存 `Instant` 标记，手动 sync_now 同样刷新它；启动时=进程启动时刻）≥ interval → 触发。定时线程直接调阻塞周期（线程本身即后台；评审 P3 措辞采纳——Tauri 命令路径照旧 spawn_blocking）。
- **失败处理**：结果照常写 `SyncState.last_result`（Settings 里可见）；**不发 toast、不 emit 事件**——后台定时器对瞬时网络抖动弹窗是骚扰，静默失败经状态行兜底（设计取舍，文档注明；区别于 SF-P* 修复的"用户动作无反馈"场景）。
- NM/HTTP 无新面：定时同步是桌面 Tauri-only 行为。
- SETTINGS_DEFAULT/EXTREMES_HEX **第三次重捕**（先例注释 L85-96 更新）。

### D7. 扩展保存/更新提示（安全模型先行）

**原则**：这是页面上下文代码首次触达"写操作"路径，白名单扩容必须有显式论证；旧密码明文**永不**进 content script。

- **捕获（content.js）**：submit 时刻（三路 isTrusted-gated：`form` submit 事件、提交按钮 click、密码框 Enter——覆盖无 `<form>` 容器），提取 username + password；**明文封死在捕获闭包里**，页面真实导航即随 content script 销毁。SPA 软导航无碍；entry URL 钉住**提交时刻**的 `location.href`（不是确认时刻）。
- **摘要与 secure-context 降级（评审 P2 采纳）**：新密码 SHA-256 经 WebCrypto 计算；`crypto.subtle` 在纯 http 页为 undefined——feature-detect 失败即**静默跳过提示**（保守：http 页多为内网/设备页，误报打扰大于漏报便利；不把明文代理进 background 换取覆盖）。
- **判定（桌面侧，无明文穿越）**：content 用缓存的 `GET_ENTRIES_FOR_URL` 摘要按 username 本地匹配候选；新 NM/HTTP 命令 `verify_entry_password { id, password_sha256 } -> { matches: bool }`（桌面解密存储密码、SHA-256 比对、常量时间比较；**不返回明文**）。
  - username 无匹配 → `save`；有匹配且存在 `matches=false` → `update`（带该条目 title）；全部 `matches=true` → **无提示**（啥都没变，防提示疲劳；天然覆盖"其它密码管理器自动填充旧密码→用户真实提交"场景——matches=true 静默）；表单无 username 可提取 → **跳过**（保守，防误报；文档注明）。
  - `verify_entry_password` 的威胁面：只回布尔、loopback + Bearer token + content 白名单 + 用户 submit 手势链路触发；不加新限流（现服务器仅 unlock 限流，文档记录该决策）。
- **确认（两段式，MV3-safe）**：CHECK 是无状态请求/响应、CONFIRMED 携带全部落库所需状态——两者之间 SW 挂起无影响（background 不持任何待定状态）。content → background 仅两新消息类型，均入 `CONTENT_SCRIPT_COMMANDS` 白名单：
  1. `CHECK_SAVE_CREDENTIALS { entry_ids, password_sha256 }` → background 转发 NM verify（≤候选数个调用）→ 回 `{action: "none"|"save"|"update", entry_title?}`。**background 不持有明文**。
  2. `SAVE_LOGIN_CONFIRMED { mode, entry_id?, url, username, password }` → background 立即调 NM `create_entry`/`update_entry`（update 用整替式 UpdateEntryRequest，username/title 沿用原条目）→ toast 回执 → **立即丢弃明文**。用户点"Not now"、60s 超时、页面导航 → content 闭包销毁，什么都不留。`CREATE_ENTRY`/`UPDATE_ENTRY` 保持 popup-class 不动——content 只能发语义受限的专用类型。
  - 明文驻留窗：捕获闭包（页面侧，用户键入处）至确认点击，最长 60s——对"用户明示要保存的刚键入凭据"这一场景成立，写进代码注释与文档。
  - vault 锁定：NM 调用失败按现有 VAULT_LOCKED 处理（无提示、不保存——v1 边界，文档注明）。
  - 旧桌面（无 verify 命令）：background 收到未知命令错误 → **静默禁用提示特性**（降级，不弹错）。新扩展 + 旧桌面组合显式兼容。
- **UI（第 5 个 closed shadow root）**：底部居中提示条（与顶部 autofill bar、右下 toast 错位），文案 "Save this login to PwdVault?" / "Update password for {title}?"，[Save/Update] [Not now]；60s 自毁（照 autofill bar 的页面内 setTimeout 先例）；`UI_ROOTS` 4→5、新样式入 `SHADOW_CSS`（暗色延后——现 4 个 root 均只镜像 Light，一致）；每次每 tab 至多一个待确认提示（in-flight 守卫，content 侧闭包标记）。
- **无新 manifest 权限**（submit 检测在已注入 content script 内；`chrome.notifications` 明确不加，照 background.js:576 先例）。Firefox 走符号链接共享源，天然同步。change-password 表单（`CHANGE_PASSWORD_PATTERNS` 已识别）与登录同一判定流（有 username 时）。

### D8. 备份保真修复（明文载荷模型——R1 P0 纠偏后重写）

**载荷模型**（评审实证）：`.pvault` 备份是**明文载荷**——导出时逐条解密（backup.rs:80-125），导入时明文重新 `encrypt()` 封进目标 vault（backup.rs:361-399）；跨 vault/换主密码恢复因此可移植。新增字段一律**明文**进 `ExportEntry`：

- `ExportEntry` 加三字段，全部 `#[serde(default)]`：
  - `url_match_mode: UrlMatchMode`（明文元数据，serde lowercase）；
  - `totp_secret: Option<Zeroizing<String>>`（明文，Zeroizing 纪律照现有 password/notes 字段）；
  - `custom_fields: Vec<ExportCustomField { label: String, value: Zeroizing<String>, secret: bool }>`（明文值）。
- 导出侧：现有逐条解密循环（backup.rs:80-125）内增解 TOTP 与 custom field 值（随 entry 已解出的上下文一并解）。
- 导入侧：`encrypt_import_entries`（backup.rs:361-399）现有明文→encrypt 路径上补三字段的加密与还原（custom value 加密进 `CustomField.value: Vec<u8>`，secret 标志与 label 明文随结构走）。
- **空值占位行对称规则（评审 R2 P2 采纳）**：导出侧空密文 vec 特判为空明文（空 vec 不能 `bc_deserialize::<EncryptedData>`——照 backup.rs:92-93 notes 空 bytes → None 同型先例）；导入侧空明文跳过 encrypt、还原为空 vec。往返不变性进 WP1 round-trip 测试。
- 校验：`backup_payload` 校验（明文层）扩展覆盖 custom_fields 限值（D2）。
- 兼容性（方向性如实声明）：
  - 旧备份（无新键）→ 新版导入：`#[serde(default)]` 落默认，平滑；
  - 新备份 → **旧版**导入：serde_json 忽略未知键，新字段静默丢——**单向损耗，CHANGELOG/文档明示**，迁移指引为"两端都升级后再做备份迁移"。

### D9. Rider：`.btn` 行内陷阱收编（`.btn-inline` 工具类）

**决策依据**：调研实测 ~73 处依赖 `.btn { width:100% }` 默认全宽，其中绝大多数是设计意图（表单/卡片下通栏按钮）；陷阱只在"flex 行内与 `flex:1` 兄弟并存"时咬人（v1.2.2 tags、v1.5.1 ×3 同一机制）。全局摘除 width:100% 波及 73 处且 jsdom 无法验证布局，回归面不成比例；flex 算法内无 CSS 解（basis:100%W 是问题的根，`flex-basis:0` 会让按钮塌缩）。

- 新增工具类 `.btn-inline { width: auto; flex-shrink: 0; }`（components.css，注释说明陷阱机制与使用时机："按钮与 flex:1 输入同行时必须使用"）。
- 迁移现存 scoped 压制到统一类：settings.css:171-178（security-status-row）、settings.css:277-280（dashboard-rerun 的 width:auto 部分）、vault.css:382-386（trash-header .btn-danger）、components.css:159-166（tag/group-selector 行）、groups.css:70/117——替换为模板上加 `btn-inline` 类，删除对应 CSS 压制块（flex-shrink 语义并入工具类）。
- 清扫残余陷阱行：grep 所有含 `.btn` 且兄弟带 `flex:1` 的 flex 容器（EntryScreen 生成器 modal-footer、UnsavedChangesModal、update-notification 行等——调研第 8 条已列候选），逐行确认后加类。`.btn` 全局规则、`.btn-full`、`.confirm-modal-actions .btn{flex:1}`、`.entry-actions button{flex:1}` 均不动。
- 验收：受影响行在 QA（T51）双主题人工过目；不新增全局 width 语义。

## 3. 工作包与波次

```
W1: WP1(Rust 自定义字段核心) ∥ WP2(React 自定义字段 UI)
W2: WP3(Rust 同步 v3+冲突计数+定时+verify 命令) ∥ WP4(扩展保存/更新提示)
W3: WP5(React 同步 UI + 定时同步开关 + rider 收编)
每波 worker 上任先核实继承树（v1.3.0/v1.5.0 铁律）。
```

- **WP1（Rust 自定义字段核心）**：domain（CustomField、字段 15、DTO 四件套、校验、PasswordEntry::new）；infra 编解码（LegacyEntryV4 四代链、D3 全部 fixture 纪律 + 过时断言消息更新）；服务层触点（entries.rs、security_report.rs 编译面、native_messaging dispatcher 的 create/update 组装）；同步域最小映射（SyncEntry + SyncCustomField + SyncSecrets 通道 + entry_to_sync/sync_to_entry，容器版本 bump 留 WP3）；备份保真（D8 全部：ExportEntry 三字段 + 导出解密 + 导入重封 + backup_payload 校验）；CSV 导入忽略自定义字段注释。测试：四代链矩阵、fixture 三件套、校验边界、EntrySummary 三出口含 label、备份往返（含 TOTP/custom_fields 还原 + 旧备份兼容）——新测试落独立测试文件。
- **WP2（React 自定义字段 UI）**：types 全套（对齐 D1 形状）；`CustomFieldsEditor`（TagsEditor 模式：受控数组、行增删、secret 掩码切换、Enter preventDefault）；EntryScreen 集成（编辑态经 get_entry_secret 一次取值——与 password 同通道、metadataDirty 加 `sameCustomFields`（按 label 多重集匹配、顺序不敏感、reorder 不脏）、detectChanges 扩展（key=`custom:<label>`，secret 行用 password 掩码 valueType）、pendingChanges 整替组装）；`EntrySecretResponse` 类型扩展。测试：编辑器增删改掩码、sameCustomFields 矩阵（照 sameTags）、detectChanges custom 分支、旧 mock 兼容（5 个 EntryScreen 测试脚手架同步）。
- **WP3（Rust 同步 + verify 命令）**：容器 v3 + `V2_CONTAINER_HEX` 永久 fixture 落 `sync/tests_container_v2_fixture.rs`（D4）；冲突计数贯通（D5：两 merge 函数 → MergedSnapshot → engine 聚合 → SyncState 持久化 → SyncStatusResponse）；定时同步（D6：Settings 字段 + SETTINGS fixture 第三次重捕 + `sync_cycle` 叶级锁 + 线程 + try-lock + AppState Instant 标记）；`verify_entry_password`（DTO + application service + HTTP 路由 + NM dispatcher 路由，常量时间比较，测试覆盖命中/未命中/锁定拒绝/不返回明文）。测试：容器三版本门矩阵、冲突口径测试矩阵——正例（删后修改计、撞车计）+ **负例防回归钉（评审 R2 P3 采纳：双端均删除不计、陈旧副本删除传播不计、先后编辑不计）**、定时器状态机（解锁/关闭/间隔/并发跳过）。**行数纪律**：container.rs 758 / state_io.rs 781 / commands.rs 762 均近 800 顶——新测试一律独立 tests_*.rs，新命令逻辑尽量沉 application 层。
- **WP4（扩展保存/更新提示）**：content.js 三路 isTrusted 捕获 + 闭包明文 + crypto.subtle feature-detect + 摘要计算 + 候选匹配 + 第 5 shadow root 提示条 + 确认/放弃流；background 两个新消息 case + verify/create/update NM 编排 + 旧桌面降级；sender-auth 白名单 +2（注释写明扩容论证）；两 manifest 无权限变更。测试：`content-save-prompt.test.js`（源文本契约：守卫序、白名单、闭包不落 background 中间态）+ `UI_ROOTS` 5 + `GUARDED_SITES` 计数更新 + 降级路径。
- **WP5（React 同步/设置 UI + rider）**：SyncSettingsSection 冲突状态行（>0 红字 + "resolved automatically" 文案）+ sync_now toast 带计数；SettingsScreen Auto-Sync option-row（照 trash-purge 模式，hint 注明需先连接同步）；rider D9 全部（工具类 + 迁移 + 清扫）。测试：照 SyncSettingsSection.test / SettingsScreen.trashPurge.test 脚手架。

## 4. 测试与门禁

- 全量：`cd src-tauri && cargo test --workspace`（Rust 预期 ≥ +45）、`pnpm test`（前端+扩展预期 ≥ +55）、`cd extensions/native-host && cargo test`（23 不变——host 无业务改动，透传新命令无需白名单变更）。
- `pnpm tsc --noEmit` 三 tsconfig；`cargo clippy`；`cargo fmt --check`。
- verbatim 守卫：本批次**不动** sender-auth.js/content.js 的域匹配 verbatim 块（保存提示不触碰匹配语义——候选匹配复用 GET_ENTRIES_FOR_URL 结果；`CONTENT_SCRIPT_COMMANDS` 集合在 verbatim 块外，扩容不触守卫）。
- commit-gate：近顶文件为 **container.rs(758) / state_io.rs(781) / commands.rs(762)**（评审实测；entry_codec 438、entries 521 无压力）——新测试一律独立测试文件，新命令逻辑沉 application 层；若必须触碰近顶文件且超限，commit 前拆测试模块（v1.5.0 playbook：verbatim 搬移 + dedent + `pub(super)` 助手）。
- 干净 worktree 全量门禁（native-host sidecar 预构建进 src-tauri/binaries/）在发版前执行——本地跑数会因 dist/ 副本虚高，测试基线以干净 checkout 实跑为准（v1.3.1 教训；464/465 漂移届时校准并回写 AGENTS.md）。

## 5. 风险登记（评审重点）

| #   | 风险                                                                   | 缓解                                                                                                                                                                               |
| --- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1  | 第 15 字段破坏存量 vault 读取（bincode 位置编码，serde(default) 失效） | D3 四代链 + 永久 14 字段 fixture 先断言"必须失败再降级读出"；评审重点核对 decode 顺序与 fixture 生成方式                                                                           |
| R2  | golden 重捕洗白回归                                                    | V4 fixture 与 v2 容器 fixture 均为 test-only 结构产字节、永久冻结；重捕与新增同 commit                                                                                             |
| R3  | 同步静默 strip / fingerprint 分歧                                      | 容器 bump v3 + 版本门外旧设备干净失败；AAD 不变保 v1 fixture                                                                                                                       |
| R4  | 备份单向损耗（新备份→旧版导入丢字段）                                  | 明文载荷 + serde(default) 双向读兼容中"新→旧"方向不可救；CHANGELOG/文档明示 + 迁移指引                                                                                             |
| R5  | 扩展白名单扩容 = 页面上下文首次触达写路径                              | 专用受限类型（非开放 CREATE/UPDATE）、isTrusted 手势链、确认点击才落库、background 不持明文、旧桌面降级、crypto.subtle 降级；安全评审重点                                          |
| R6  | 定时同步与手动/connect 并发周期                                        | `sync_cycle` 叶级锁整周期持有（先于 exclusive_window，锁序无环）；tick try_lock 跳过、手动阻塞等待（用户动作必完成）；正确性兜底另有 D4 etag/If-Match 重试环（publish.rs:101-111） |
| R7  | 冲突计数口径被误解为"丢数据"                                           | 口径钉死（删后修改 + 撞车分歧两类），文案 "automatically resolved (last-write-wins)"，merge.rs 模块文档写明口径、不计数形态与盲区                                                  |
| R8  | rider 波及面失控                                                       | 不动全局 width 语义，只加工具类与迁移；QA 人工过目受影响行                                                                                                                         |
| R9  | `NativeRequest.request: Option<PasswordEntry>` 死字段的反序列化面      | PasswordEntry.custom_fields 带 `#[serde(default)]`（JSON 面读兼容，bincode 面恒存在），死字段本批次不清理（避免无谓面变化）                                                        |

## 6. 手动 QA 追加（qa_manual_v1.2.0.md，T45 起）

- T45 自定义字段 CRUD：增删改掩码行、diff 确认框、保存后重进、双主题。
- T46 旧库升级：v1.5.1 真实 vault 原地打开（四代链实读），旧条目 custom_fields 显示为空。
- T47 备份往返：含 TOTP + 自定义字段的条目导出→（新版本）导入还原无损；v1.5.1 备份导入新版本平滑；换密码后同备份恢复可解（明文载荷模型验证）。
- T48 扩展提示（真浏览器，Chrome+Firefox）：新站注册→Save 提示→落库；同站改密→Update 提示；同凭据重复登录→无提示；锁 vault 提交→无提示；纯 http 页→无提示（subtle 降级）；旧桌面降级路径。
- T49 定时同步：连 WebDAV 后开 5min 档，观察自动触发与状态行；关闭档位验证不触发；自动周期进行中触发手动 sync_now → 手动**等自动周期完成后执行**并正常回报（阻塞语义验证）。
- T50 冲突计数：双设备造 equal-updated_at 冲突与**删后修改**冲突（B 在 A 删除后编辑），验证状态行红字 + toast 计数；纯先后编辑、常规删除传播（A 删、B 未改）不计数。
- T51 rider：tags 行、security/sync 状态行、dashboard、trash header、生成器 modal-footer、更新通知横幅——双主题目检。

## 7. 发版序列（评审通过、实施、审查、干净门禁全绿后）

CHANGELOG → `scripts/bump-version.sh 1.6.0` → `--locked` 验锁 → 分批提交（feat: WP 序列 / fix / docs / release(1.6.0) version sync + changelog）→ tag v1.6.0 → push origin main --tags → 盯 Release 6 job + Quality Gates + CodeQL → feed bot 提交 rebase 确认 → push 后必盯 CI（v1.4.1 教训）。
