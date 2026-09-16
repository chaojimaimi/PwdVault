# Phase 2+3 实施方案：数据格式 v3 与多设备云同步

> 依据 docs/ROADMAP-2026-09.md。范围收敛说明：**安全笔记已存在**（`encrypted_notes`
>
> - EntryScreen/`update_notes`），Phase 2 实际为 tombstone 软删除 + TOTP；Phase 3 为
>   云盘哑存储 + 加密快照容器 + 客户端合并的多设备同步。完成后 bump v1.1.6 打包。
>   流程：本方案 → plan-reviewer → ds-worker 分五批落地 → 收尾打包。

## 0. 核心架构决策

### D1 同步 = 云盘哑存储 + 加密快照容器 + 客户端合并

无服务器、无账户。每台设备维护本地 redb 工作副本；云端只有一个**自包含加密容器**
（E2E，网盘只见密文）；同步 = 下载容器 → 域对象合并 → 写本地 + 上传。
业界先例：KeePass 系（kdbx + 网盘 + merge）、Enpass（无账户 + 自选云 + 合并）。

### D2 容器自包含 KDF 与 container key（cek）——两种凭据（评审重写）

**容器密码与设备本地主密码是两种独立凭据**：容器 KDF 用容器密码派生 kdf_key；
每设备本地库用自己的主密码（可不同）。

```
container v1（pwdvault-sync.pwsync）= {
  version: 1,
  kdf: { salt, params },                        # 容器密码派生（adaptive，起点 ≥ X6 导入底线）
  wrapped_cek: EncryptedData(kdf_key, cek),     # cek = 32B 随机容器密钥，创建后不变
  snapshot: EncryptedData(cek, json)            # 全量域快照（明文等价对象，容器即 E2E 边界）
}
snapshot = { rev: u64, device_id, generated_at, entries: [SyncEntry], groups: [SyncGroup] }
SyncEntry/SyncGroup = 域字段明文（含 password/notes/totp_secret 明文）+ deleted_at
```

- **本地持久化（定案）**：cek 用 **enc_key 包裹**存 `VAULT_TABLE["sync_cek"]`。
  理由：读侧 sync_now 需在会话内解 cek，而 master_key 解锁后即 zeroize（session
  只有 enc/mac）——enc_key 包裹使同步免密；**重包裹下沉到 `reseal_vault` 内部**：
  行存在即 `load_blob → unwrap(old_enc, WRAP_AAD_SYNC) → wrap(new_enc) →
save_blob_in_txn`（old_enc/new_enc 均已在 reseal 签名内）——change_password 与
  recover_vault 两条换 enc 的 D8 流程自动继承，无调用方各自维护；新增独立 AAD
  常量 `WRAP_AAD_SYNC = b"pwdvault-sync-cek-v1"`（防跨 blob 挪用，先例
  WRAP_AAD_BIO/RECOVERY）。**unwrap 失败 → 整个 reseal 中止回滚**（fail-closed，
  与内层字段重加密策略一致；该场景被 digest 覆盖近乎排除）。bio/recovery 维持
  master 包裹管道不变（二者只在有密码/Touch ID 的交互路径 unwrap）。
- **引导（每设备一次，要求解锁会话）**：设置页"连接云同步"→ 输入**容器密码**
  （首台设备默认与其主密码相同，可自定；后接设备输入创建者设定的容器密码）→
  下载容器（远端无容器 → 本地上传初始容器，cek=OsRng；**创建语义**：WebDAV 用
  If-None-Match:*；百度侧后续解包失败 → 清本地 sync_cek 重新引导，评审采纳）→
  解 cek → 解 snapshot → D8 排他清空下合并写本地 → 存 sync_cek（enc 包裹，
  并入 reseal 管道）+ sync_config → 上传合并结果（若 changed）。
  **空库新机器**：先走 SetupScreen 建本地库（任意本地密码）→ 解锁 → 同上引导
  （合并结果 = 容器全量）。未初始化机器不提供引导入口（评审 P1：get_db 无句柄）。
- 改主密码 / 恢复主密码：二者均轮换 enc_key，`reseal_vault` 内部的 sync_cek
  重包裹自动继承（见上），容器与远端无感。
- `cek` 永不落容器外明文；unwrap 结果用 SecretKey/Zeroizing。

### D3 合并语义：2-way LWW + tombstone 裁决（不做 3-way）

- 按 UUID 并集；单侧存在（含 tombstone）→ 直接收下。
- 双侧存在：`updated_at` 大者胜；**相等时以内容 SHA-256（SyncEntry 的 bincode
  序列化——两设备必须同 form 定死）字典序大者胜**（对称确定性裁决，保证交换律
  ——评审 P1：参数位置 tiebreak 会破坏 merge(a,b)=merge(b,a)）；`deleted_at`
  存在且 ≥ 对侧 `updated_at` → 删除胜，否则修改胜（清除 deleted_at 复活）。
- 不做 3-way/base 的原因：LWW+时间戳是 KeePass 系验证二十年的语义，免 base 存储；
  误覆盖场景由**版本轮换**兜底（历史快照可人工找回）。
- 收敛性性质（测试硬断言）：交换律 merge(a,b)=merge(b,a)、幂等 merge(x,x)=x、
  并集无损（两侧任意非删除条目必出现在结果或其 tombstone 中）。
- GC：v1 不做（tombstone 永久保留；密码条目量级小；文档注明未来可加 90 天 GC）。

### D4 云端布局与条件写入

```
<remote_dir>/
  pwdvault-sync.pwsync            # 当前容器
  pwdvault-sync.manifest.json     # {rev, device_id, sha256, ts}
  history/pwdvault-sync-r<rev>-<device>-<ts>.pwsync   # 滚动版本，保留最近 10 份
```

- WebDAV：PUT + If-Match(ETag)，412 → Conflict → 重拉重合并重试（≤3 次）；
  PROPFIND Depth:0 取 ETag/size；MKCOL 忽略 405。
- 百度网盘：无 If-Match → 上传前 stat manifest 比对 rev（不一致 → Conflict），
  上传后复核；历史版本用唯一文件名天然无冲突。

### D5 触发模型（v1）

手动 Sync now 按钮 + 解锁后自动同步一次。**定时轮询不做**（避免新增常驻线程；
作为后续项）。同步要求解锁态（需要 cek 与本地密钥）。

### D6 命令面

新增 **Tauri-only** 命令（touch_activity 先例，扩展桥不暴露），共 **七个**：
`totp_code(id)`、`sync_status()`、`sync_connect(config, container_password)`、
`sync_disconnect()`、`sync_now()`、`baidu_start_auth() -> {auth_url}`、
`baidu_complete_auth(code)`。golden_contract 的 tauri 列表与 adapter-only
文档同步更新，NM dispatcher 不变。

## P2 数据层（格式 v3，无表结构迁移）

### P2.1 实体扩展（domain/entities.rs）——双读兼容（评审 P0 重写）

**评审纠正的关键事实**：bincode 1.x **不支持**尾部字段 serde(default)（上游
bincode#179；代码库自身 `database/mod.rs:126-150` 的 `LegacySettingsV1` 双读先例
即为此而生）。真实行为：新代码读旧 blob（缺尾部字段）→ EOF 错误；旧代码读新
blob → "成功"但回写会静默丢新字段。因此：

- `PasswordEntry` 尾部追加 `pub deleted_at: Option<i64>`、
  `pub encrypted_totp_secret: Option<Vec<u8>>`；`Group` 尾部追加
  `pub deleted_at: Option<i64>`（不加 serde(default)，靠双读兼容）。
- **entry_codec::open_entry / group_codec::open_group 双读**（照抄
  LegacySettingsV1 模式）：先按当前结构反序列化；失败则按
  `LegacyEntryV2`/`LegacyGroupV2`（旧字段集）反序列化并转换（新字段 = None）。
  **抽取统一 helper 替换 open_entry 全部三个内层反序列化点**（v2 AAD / v1 /
  plaintext 迁移通道——legacy 通道读的也是旧字段集记录，均需双读）。
  新代码由此可读全部历史 blob。
- 旧版本应用读新 blob"成功但回写丢字段"的跨版本降级风险由 (a) 容器 version
  字段（跨机同步仅允许同容器版本互操作）与 (b) 发布说明（禁止用旧版本打开
  同一库）承担。
- VAULT_FORMAT_VERSION 与 digest 版本均不 bump（无记录格式切换——双读已覆盖；
  digest 的 v3 先例是完整性算法变化，本次未改算法）。

### P2.2 软删除改造（过滤层次按评审写死）

- **infra 层保持 raw 语义**：`list_entries`/`list_groups`/`load_entry`/
  `load_group`/`list_all_entries_bulk`/`count_entries`/`count_groups` 一律不过滤
  （tombstone 原样返回/计数）——`reseal_vault`（security/shared.rs）依赖裸全量
  读写，改其语义会让 tombstone 行变成旧钥死行（下次 bulk 解密即炸）。
- **service 层过滤**：`list_entries`/`list_all_entries`/`list_groups`/
  `list_all_groups`/`get_entry`（已删除 → NotFound）/`get_entry_count`/
  `get_entry_count_group`（解密后计数，修扩展命令失真——评审 P2）。
- **remove_entry/remove_group 改软删除**（置 deleted_at=now 落库）；
  **remove_group 现有级联清空 group_id 的代码删除**（groups.rs:95-111，与
  "组 tombstone 不级联、group_id 悬挂允许"一致，悬挂 UI 显示未分组）。
- 周边语义：`update_entry` 作用于已删除条目 → NotFound（不复活）；合并"修改胜"
  清除 deleted_at（复活语义）；backup 导出默认排除 tombstone（文档注明恢复旧
  备份可能以新 ID 复活已删条目）。
- bulk 读取（含 tombstone）供合并/reseal 使用，保持现状即可。

### P2.3 TOTP（infrastructure/src/totp.rs，新文件）

- RFC 6238：HMAC-SHA1（默认）与 HMAC-SHA256，30s 步长，6 位，动态截断；
  `totp_code(secret: &[u8], algo, digits: u8, period: u32, at: i64) -> String`。
- otpauth:// URI 解析：`otpauth::parse(uri) -> {secret, algo, digits, period,
label}`（支持 percent-decoding secret base32；标准 base32 解码需引入/手写
  base32——手写 ~30 行，避免新依赖；hmac 0.12 已在树，sha1 需新增 `sha1 = "0.10"`）。
- 测试：RFC 6238 附录 B 官方测试向量（SHA1/SHA256）；base32 往返；otpauth 解析。

### P2.4 TOTP 接线

- `update_entry` 请求扩展 `totp_secret: Option<String>`（update 模式同
  update_notes：None=不动、Some("")=清除、Some(x)=设置；infra 层加密为
  encrypted_totp_secret）。domain 的 UpdateEntryRequest（dto.rs）加字段 +
  validation（长度上限）。
- 新命令 `totp_code(id) -> {code, seconds_remaining}`：读条目 → 解密
  totp_secret → 生成当前码。get_entry_secret 不变（避免扩展侧变化）。

## P3.1 合并引擎（application/src/service/sync/merge.rs，新）

```rust
pub struct SyncEntry { pub id, title, url, username, password: Option<String>,
  notes: Option<String>, totp_secret: Option<String>, tags, group_id,
  created_at, updated_at, deleted_at: Option<i64> }
pub struct SyncGroup { id, name, created_at, updated_at, deleted_at }
pub fn merge_snapshots(local: Vec<SyncEntry>, remote: Vec<SyncEntry>, ...)
  -> (Vec<SyncEntry>, Vec<SyncGroup>, changed: bool)
```

- 本地侧从 redb 解密构造（新 helper：entries → SyncEntry，解密
  password/notes/totp_secret），远端侧从容器解出；合并结果写回：单
  `VaultStore::write` 事务（upsert 变化条目——重加密 with 本地 enc_key）。
- `changed` 标志：合并结果与远端快照不同才上传（防回声）。**比较规范化**：
  按 id 排序 + 结构体字段级 PartialEq（禁止依赖序列化字节，评审 P3）。
- **与本地写入的串行化（D8 复用的精确时序，评审 P2）**：取租约拷贝本地
  enc/mac 入 Zeroizing → drop 租约 → `exclusive_lock_and_clear()`（排空在途写；
  严禁持租约调用）→ 排他窗口内：全量读 + 合并 + 单事务写回 + republish
  （`session.unlock(拷贝的 enc/mac)`——同步不换钥，勿照抄 change_password 的
  新钥先例）→ **网络上传在排他窗口之外**（含 ≤3 次冲突重试，窗口不随网络 I/O
  拉长）。锁定态调用 `exclusive_lock_and_clear` 为无害 no-op（session.rs:203-206）。
- 测试：交换律/幂等/并集无损三条性质测试（伪随机序列，含 updated_at 相等的
  tiebreak 用例）；指定用例：双端同改不同条目、同条目先后改、一端删一端改
  （双向）、组删除不级联（group_id 悬挂允许，UI 显示"未分组"）。

## P3.2 CloudBackend trait + WebDAV（sync/backend.rs、sync/webdav.rs）

```rust
pub enum BackendError { Conflict, Auth(String), Network(String), NotConfigured }
pub struct RemoteStat { pub etag: Option<String>, pub size: u64 }
pub trait CloudBackend: Send + Sync {
    fn stat(&self, path: &str) -> Result<Option<RemoteStat>, BackendError>;
    fn download(&self, path: &str) -> Result<Vec<u8>, BackendError>;
    // Precondition::IfMatch(etag) → PUT If-Match；Precondition::IfAbsent →
    // If-None-Match:*（初始容器"不存在才创建"语义，评审 P3）
    fn upload(&self, path: &str, body: &[u8], precondition: Precondition) -> Result<(), BackendError>;
    fn upload_unique(&self, path: &str, body: &[u8]) -> Result<(), BackendError>;  // 历史版本，唯一名无冲突
}
pub enum Precondition { IfMatch(String), IfAbsent }
```

- **WebDAV**（application 层，ureq 3 + Basic Auth）：PROPFIND（Depth:0，解析
  getetag/getcontentlength——手写最小 XML 提取，避免引 XML 解析器）、GET、
  PUT+If-Match（412→Conflict）、MKCOL（405 忽略）、upload_unique 直接 PUT 唯一名。
  ureq 3 无任意动词便捷 API：`http::Request`（`Method::from_str("PROPFIND")`，
  http 1.4 已在树）+ `Agent::run`（评审 P3）。
- 凭据存储（评审 P2：bio store 全 item 挂 Touch ID ACL，不可复用）：
  - macOS：新增**非交互 Keychain store**（无 SecAccessControl 的独立实现，账户
    前缀 `sync-`，与 bio 交互 store 分离）——同步凭据读取不得弹 Touch ID；
  - 非 macOS：`FileSecretStore`（0600 JSON，api_token 文件先例；Phase 1 只建了
    Unavailable 桩，本批新增实现）。
    账户名：`sync-webdav-password`、`sync-baidu-token`。
- **MockCloudBackend**（测试替身）：内存 KV + 注入式冲突调度。

## P3.3 同步引擎（sync/engine.rs）

- **SyncConfig**（VAULT_TABLE 行 `"sync_config"`，明文 JSON）：enabled、backend
  （webdav|baidu）、server_url（WebDAV）、remote_dir、username（WebDAV 用户名
  非敏感入此）；WebDAV 密码/百度 token 入非交互 SecretStore（见 P3.2）。
- `sync_connect(state, config, container_password)`：引导（D2，要求解锁会话）——
  下载容器（远端无容器则本地上传初始容器，cek=OsRng，创建语义
  `Precondition::IfAbsent`）→ 派生 → unwrap cek → 解 snapshot → D8 排他清空下
  合并写本地 → 存 sync_cek（enc_key 包裹）+ sync_config → 上传合并结果
  （若 changed）。
- `sync_now(state)`：解锁态 → 读 sync_cek（**enc_key 包裹，session enc_key 直接
  解包**，见 D2 定案）→ stat manifest → rev 变化才下载容器 → 解 snapshot →
  D8 排他清空下合并写本地 → changed 则**在排他窗口之外**上传（If-Match/rev 检查；
  Conflict → 重拉合并重试 ≤3）→ 轮换历史（保留 10）→ 更新 `last_sync` 状态行
  （VAULT_TABLE `"sync_state"`：last_sync_at、last_result、remote_rev）。
  （D8 时序中 republish 的是**拷贝的原会话 enc/mac**——同步不换钥，评审 P3。）
- `sync_disconnect(state)`：事务删 sync_cek/sync_config/sync_state（云端文件保留，
  文档注明）。
- `sync_status(state) -> {enabled, backend, last_sync_at, last_result, remote_rev}`。

## P3.4 百度网盘适配器（sync/baidu.rs）

- OAuth2 授权码（**无 PKCE**——百度开放平台不支持且 SecretKey 内嵌本无机密性，
  评审 P2）：`baidu_start_auth() -> {auth_url}` → **固定 loopback 回调端口**
  （`127.0.0.1:17777`，避开 17429；开放平台 redirect_uri 要求含端口精确匹配，
  端口写入 `docs/BAIDU-SETUP.md` 注册指引）→ 用户浏览器授权后回调 →
  `baidu_complete_auth(code)` → token 存非交互 SecretStore。
  **AppKey/SecretKey 为编译期配置占位**（`domain/constants.rs` 占位常量；未配置
  → BackendError::NotConfigured，前端显示引导文案）+ `docs/BAIDU-SETUP.md`
  指导注册开放平台应用。
- 文件 API：stat = `filemetas`（dlink/size/md5）；download = dlink（带 User-Agent
  头）；upload = 预创建 + superfile 分片（4MB 单片足够）；manifest rev 比对替代
  If-Match（D4）。
- token 过期/401 → refresh 一次重试；refresh 失败 → Auth 错误（前端引导重新授权）。

## P3.5 前端（最后一批）

- SettingsScreen 新 **Sync** 区块：未配置 → 后端选择（WebDAV/百度网盘）+ 表单
  （WebDAV：URL/目录/用户名/密码；百度：授权按钮——NotConfigured 时显示
  BAIDU-SETUP 引导）+ "Connect"（要求输入**容器密码**引导）+ Disconnect；
  已连接 → 状态行（last sync/remote rev）+ Sync now + Disconnect。
- EntryScreen：TOTP 字段（文本框，支持粘贴 `otpauth://` URI 自动解析填充；
  清空 = 移除）。
- VaultScreen/EntryScreen：TOTP 码徽标（调 `totp_code`，30s 前端 tick 刷新，
  秒数进度显示；仅未删除条目）。
- vault.ts：**七个**新命令包装 + 类型；toast 错误呈现复用现有模式。

## P3.6 测试矩阵

1. P2：**双读兼容**（旧 blob 无新字段 → Legacy 结构转换后字段 None；新 blob 新旧
   代码行为各按评审结论）；TOTP RFC 6238 附录 B 向量（SHA1/SHA256、多时刻）；
   base32 往返；otpauth 解析（含畸形输入）；软删除后 list 过滤 + get 404 +
   count 不含 tombstone；update_entry 的 totp 设置/清除路径；update 作用于已
   删除条目 → NotFound；remove_group 不再级联清 group_id
2. 3.1：merge 交换律/幂等/并集无损性质测试（伪随机 100 序列）；六个指定冲突用例
   （含双向删改裁决、updated_at 相等的哈希 tiebreak 对称性）；防回声规范化比较
3. 容器：roundtrip；错误容器密码拒绝；篡改拒绝（GCM）；cek 引导 unwrap
4. 3.3：MockCloudBackend 全流程（引导→两设备交替修改→同步收敛断言——
   两 AppState 模拟）；Conflict → 重拉重合并；上传重试 ≤3；未引导时报错；
   排他窗口内写请求被拒且换钥后一致性成立（复用 Phase 1 D8 测试模式）
5. 3.2：手写 tiny_http WebDAV stub 测 PROPFIND/PUT/If-Match 412/MKCOL
6. golden contract：七个新命令 tauri 列表 + adapter-only，NM 不变
7. 回归：现有全部测试通过（尤其 entries 软删除改造后 remove/patch 相关断言更新；
   **recover_vault 与 change_password 换 enc 后 sync_cek 均已自动重包裹**——
   reseal_vault 内部继承断言）

## P3.7 里程碑与批次

| 批   | 内容                                                      | 当量    |
| ---- | --------------------------------------------------------- | ------- |
| 1    | P2 数据层 + TOTP 后端 + 测试                              | ~1 天   |
| 2    | 3.1 合并引擎 + 容器格式 + 测试                            | ~1.5 天 |
| 3    | 3.2 backend trait + WebDAV + 3.3 同步引擎 + 命令 + golden | ~2 天   |
| 4    | 3.4 百度适配器                                            | ~1 天   |
| 5    | 3.5 前端                                                  | ~1 天   |
| 收尾 | 版本 bump 1.1.6 + CHANGELOG + 打包（主代理）              | —       |

## P3.8 风险与注记

- **百度 AppKey 需注册**：无 AppKey 时适配器返回 NotConfigured（不阻塞构建与其他
  后端）；docs/BAIDU-SETUP.md 指导。
- LWW 语义预期：版本轮换（10 份历史）兜底误覆盖找回。
- 每设备引导需输一次**容器密码**（cek 建立后免密）。
- 旧版本应用打开新版库："成功"但回写会丢新字段（bincode legacy 忽略尾部）——
  容器 version 字段挡跨版本同步（v1 只允许同容器版本互同步），发布说明注明
  禁止降级运行。
- WebDAV 服务器 ETag 差异：坚果云/Nextcloud 支持；无 ETag 服务器降级 manifest rev。
- 前置条件：**打包前用户需 `sudo xcodebuild -license accept`**（Xcode 许可，本次
  构建阻塞项）。
