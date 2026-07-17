# PwdVault 综合优化实施方案

> **适用版本**：v1.0.5（本地工作区）  
> **文档日期**：2026-07-16  
> **文档状态**：待评审  
> **实施目标**：在不扩张产品功能边界的前提下，将 PwdVault 从“功能完整的个人项目”提升为“具备稳定数据一致性、安全边界、可访问 UI 和可信发布流程的本地密码管理器”。

---

## 1. 执行摘要

PwdVault 已具备较完整的产品基础：

- Tauri v2 + React 19 的桌面架构；
- Rust service 层复用 Tauri IPC 与浏览器扩展入口；
- redb 嵌入式数据库；
- AES-256-GCM、Argon2id、HKDF 子密钥、内存密钥清理；
- 条目元数据整体加密、数据库 HMAC 完整性摘要；
- Chrome/Firefox 扩展和 Native Messaging 桥接；
- Light/Dark 双主题及紧凑桌面布局；
- 前端、Rust 主应用和 native host 的基础测试。

当前最主要的问题不是缺少功能，而是下列产品化闭环尚未完成：

1. 业务数据写入与完整性摘要更新不在同一事务中，正常崩溃可能让合法数据库在下次解锁时被误判为篡改。
2. 完整性摘要可以通过删除 digest 或修改版本信息触发“旧库迁移”并重建基线，存在降级绕过。
3. 解锁流程在完整性验证完成前发布密钥，部分错误路径可能形成“接口返回失败但内存中已经解锁”的状态。
4. vault 和备份中的 Argon2 参数缺少产品级上限，恶意输入可能造成内存或 CPU 资源耗尽。
5. Firefox/Windows Native Messaging 注册和 Firefox 发布包存在兼容性错误。
6. 前端加载失败会被伪装为空库，更新检查没有真正遵守用户隐私开关。
7. UI 在最小窗口、键盘操作、屏幕阅读器、对比度和扩展端一致性方面仍有缺口。
8. CI/CD 没有把测试、格式、Clippy、版本一致性和产物签名作为稳定版发布门禁。

因此，在完成本文 P0 范围前，不建议将当前 v1.0.5 作为稳定安全版本发布。可以继续生成 development/nightly 产物用于验证。

---

## 2. 当前质量基线

### 2.1 已验证结果

| 检查项 | 当前结果 |
|---|---|
| TypeScript 类型检查 | 通过 |
| 前端生产构建 | 通过；存在动态/静态 import 混用警告 |
| 前端测试 | 7 个测试文件，27 项通过 |
| Rust 主应用测试 | 81 项通过 |
| Native host 测试 | 14 项通过 |
| `cargo fmt --check` | 失败 |
| `cargo clippy --all-targets -- -D warnings` | 失败 |
| 400×600 启动页 | 实机浏览器预览布局正常 |
| 350×500 最小窗口 | Settings/Backup/Generator 存在内容裁切风险 |

### 2.2 成熟度判断

| 维度 | 当前判断 | 说明 |
|---|---|---|
| 整体架构 | 良好 | service 层方向正确，但状态、事务和 adapter 边界尚未完全收口 |
| 密码学原语 | 良好 | AES-GCM、Argon2id、HKDF 选型正确，风险主要在生命周期和调用边界 |
| 数据一致性 | 需优先整改 | digest 与业务写入非原子，完整性基线可降级 |
| 桌面前端 | 视觉良好、状态不足 | 缺 resource state、错误恢复、完整可访问性和细粒度订阅 |
| 浏览器扩展 | 功能较完整、维护性偏弱 | popup 单体化，状态、设计 token 和算法与桌面端漂移 |
| 测试 | 基础良好、关键场景不足 | 缺故障注入、并发、历史数据库 fixture、权限和浏览器 E2E |
| 发布工程 | 未达到稳定密码管理器标准 | 缺硬性质量门禁、正式签名、版本与产物一致性检查 |

---

## 3. 优化原则与实施边界

### 3.1 优化原则

1. **先保证数据可信，再优化体验和性能。**
2. **安全不变量放在 service/application 层，不能只依赖前端或 HTTP adapter。**
3. **所有格式变更必须可迁移、可回滚、可用历史 fixture 验证。**
4. **非法数据应拒绝，不应静默修正或覆盖。**
5. **完整性检查失败必须 fail closed，不能自动刷新基线。**
6. **不通过扩大 CSP、放宽浏览器权限或增加遥测来换取便利。**
7. **性能优化必须有基准数据，避免过早引入高复杂度结构。**

### 3.2 本轮包含范围

- vault session、auto-lock 和并发模型；
- redb 写事务和数据库完整性机制；
- 数据库迁移、备份格式与输入验证；
- 密钥及明文生命周期；
- Native Messaging 注册、配对、传输和发布打包；
- React 状态、错误恢复、隐私设置、响应式和可访问性；
- 浏览器扩展 UI 一致性和 sender 授权；
- 性能基准、模块化和 CI/CD；
- README、AGENTS、CHANGELOG、安全威胁模型和发布文档同步。

### 3.3 明确不包含范围

- 云同步、多设备同步和账户系统；
- 生物识别、TOTP、泄露监控、移动端等新功能；
- 替换 AES-GCM、Argon2id、HKDF、redb、Tauri 或 React；
- 整体品牌重设计或新增主题体系；
- 引入 Redux、React Query 或重量级 UI 组件库；
- 在本轮实现跨平台整库快照回滚检测。

### 3.4 安全能力边界

完成本方案后，产品应明确承诺：

- 保护 vault 静态文件被复制后的机密性；
- 检测没有合法密钥时对数据库内容的离线修改、删除或记录替换；
- 限制浏览器网页直接访问密码库；
- 在锁定后清理应用持有的加密密钥和敏感业务状态。

本轮仍不承诺防御：

- 已完全控制当前用户会话的恶意软件；
- 键盘记录器、管理员/调试器、进程内存转储；
- 数据和 digest 一起恢复的完整旧版 `vault.db` 快照回滚。

如果未来必须检测整库快照回滚，需要使用 OS Keychain、DPAPI 或 Secret Service 保存数据库外部的可信 root/counter，并单独进行跨平台安全设计。

---

## 4. 优先级矩阵

| 编号 | 优化项 | 优先级 | 风险类型 | 预计工作量 |
|---|---|---|---|---|
| P0-1 | 业务写入与 digest 原子事务 | P0 | 数据损坏/可用性 | 3～4 人日 |
| P0-2 | 完整性防降级与严格迁移 | P0 | 安全边界 | 3～4 人日 |
| P0-3 | 两阶段解锁和会话原子发布 | P0 | 锁状态/密钥泄露 | 2～3 人日 |
| P0-4 | KDF 参数上限与文件权限 | P0 | 本地 DoS/离线破解 | 1～2 人日 |
| P0-5 | 发布质量门禁与稳定版冻结 | P0 | 供应链/发布可信度 | 2～3 人日 |
| P1-1 | 统一 ValidationPolicy | P1 | 输入安全/数据质量 | 2～3 人日 |
| P1-2 | 备份 v2 与导入资源限制 | P1 | 备份安全/兼容性 | 3～4 人日 |
| P1-3 | 前端 resource state 和隐私开关 | P1 | 数据可信度/隐私 | 2～3 人日 |
| P1-4 | 最小窗口、主题和无障碍 | P1 | 可用性/合规性 | 4～6 人日 |
| P1-5 | Native Messaging 跨浏览器修复 | P1 | 扩展可用性/信任边界 | 4～6 人日 |
| P2-1 | 上下文订阅、搜索和批量读取优化 | P2 | 性能/维护性 | 3～5 人日 |
| P2-2 | 模块边界与协议版本化 | P2 | 演进能力 | 3～5 人日 |

---

## 5. 分阶段实施方案

## 阶段 0：发布冻结与回归基线

**预计工作量：1～2 人日**

### 5.0.1 优化内容

1. 暂停稳定版发布，仅允许 development/nightly 产物。
2. 收集并固化 v1.0.0～v1.0.5 的真实数据库和备份 fixture。
3. 新增测试基础设施：
   - redb 故障注入；
   - 并发 barrier；
   - 文件权限验证；
   - Chrome/Firefox 打包产物检查；
   - UI 多窗口尺寸测试。
4. 建立安全威胁模型和格式演进说明。
5. 保存当前性能基线：100、1,000、5,000、10,000 条目。

### 5.0.2 实施边界

- 不修改数据库格式；
- 不调整用户功能；
- 只建立后续整改所需的回归保护。

### 5.0.3 验收标准

- 每个已发布数据库格式至少有一个 fixture；
- fixture 不包含真实用户凭据；
- 当前测试和性能结果可在 CI 中重复执行；
- 威胁模型明确描述支持和不支持的攻击场景；
- 当前 stable release 流程被显式阻止，nightly 不被误标为稳定版。

---

## 阶段 1：事务、会话与完整性闭环

**预计工作量：5～8 人日**  
**要求：实施完成后进行独立安全审查。**

### 5.1.1 建立统一 VaultSession

当前 AppState 将数据库、enc key、MAC key、活动时间、auto-lock、HTTP 限流、托盘回调等状态混合存放。HTTP adapter 额外持有 `op_lock`，但 Tauri IPC 和 auto-lock 没有遵循同一并发模型。

建议引入：

```text
VaultSession
├── Locked
└── Unlocked
    ├── enc_key
    ├── mac_key
    ├── last_activity
    └── session_generation
```

所有需要访问 vault 的 service 操作取得 operation/session lease；auto-lock 取得排他 lease，等待正在执行的操作结束后再清理密钥。

### 5.1.2 建立 VaultWriteTxn

新增统一数据库写事务接口，例如：

```rust
vault_store.write(|txn, session| {
    // 1. 修改 entries/groups/settings
    // 2. 在同一个 write txn 内重算 digest
    // 3. 写入 digest/version
    // 4. 一次 commit
})
```

必须迁移的操作：

- create/update/delete entry；
- secret access 的 `last_used_at`；
- create/update/delete group 和 cascade；
- update settings；
- import vault；
- legacy database migration；
- 所有未来数据库 mutation。

如果 `last_used_at` 不影响核心功能，优先考虑移除 secret fetch 的持久化副作用，减少写放大和摘要重算。

### 5.1.3 两阶段解锁

新解锁顺序：

1. 检查速率限制；
2. 在局部 `Zeroizing<DerivedKeys>` 中验证密码；
3. 强制取得数据库；
4. 读取并验证受认证的 vault header；
5. 验证 digest；
6. 必要时执行经过验证的 migration；
7. 加载并验证 settings；
8. 最后一步原子发布 `UnlockedSession`；
9. 重置速率限制并启动 activity timer。

任何错误都必须保持 Locked 状态。

### 5.1.4 完整性防降级

新增受 AEAD 认证的 vault header，至少包含：

- `vault_format_version`；
- `schema_version`；
- `record_format_version`；
- `digest_algorithm_version`；
- `integrity_required`；
- migration generation/marker。

新格式一旦设置 `integrity_required=true`：

- digest 缺失必须拒绝解锁；
- 未知 digest version 必须拒绝；
- 不允许自动刷新基线；
- migration 必须由明确 legacy 特征触发；
- migration 前生成不可覆盖的原库副本。

entry/group 的 AES-GCM 加密增加 AAD：

```text
table_name || record_id || record_format_version
```

### 5.1.5 密钥和明文生命周期

- 将裸 `[u8; 32]` 封装为不可 Copy、`ZeroizeOnDrop` 的 `SecretKey`；
- KeyStore 使用 `with_key` 闭包借用，避免到处复制密钥；
- master key、subkey、迁移 plaintext、codec 序列化缓冲全部使用 Zeroizing；
- notes、HTTP body、native host frame 中的敏感内容同样缩短生命周期；
- 错误和日志不得包含密钥、密码、token、解密 notes 或完整文件路径。

### 5.1.6 实施边界

- 保留现有 AES-GCM、Argon2id、HKDF 和 redb；
- 保留现有前端和扩展 command 名称；
- 不在本阶段增加云同步或新用户功能；
- 不实现整库快照回滚检测。

### 5.1.7 验收标准

1. 业务修改、digest 计算和 digest 写入处于同一 redb write transaction。
2. 故障注入在任意步骤终止进程后，重启只能看到完整旧状态或完整新状态。
3. 删除 digest、修改 digest version、删除记录、交换两条 blob 后，新格式 vault 必须解锁失败。
4. v1.0.0～v1.0.5 fixture 可一次迁移，二次启动不得重复迁移。
5. DB IO 错误、digest 损坏、migration 第 N 条失败时：
   - `is_unlocked=false`；
   - enc/mac key 均为空；
   - activity timer 为空；
   - 原数据库保持可恢复。
6. IPC、HTTP、auto-lock 并发执行 1,000 次，无死锁、丢更新和陈旧 digest。
7. 所有 mutation 代码中不再出现“先业务 commit、后 refresh_digest”的调用序列。

---

## 阶段 2：统一输入边界与备份安全

**预计工作量：3～5 人日**

### 5.2.1 ValidationPolicy

新增共享 validation 模块，Tauri、HTTP、Native Messaging、import 必须调用同一套策略。建议至少验证：

| 数据 | 建议约束 |
|---|---|
| 主密码 | 至少 8 字符；建议增加强度提示，不强制复杂字符规则 |
| 导出密码 | 至少 8 字符 |
| title/username/url | 非法空值和最大字节长度 |
| password | 非空、最大字节长度 |
| notes | 最大字节长度 |
| group name | trim 后非空、最大长度、重复名称策略 |
| tags | 最大数量、单 tag 最大长度、去重策略 |
| group_id | 格式合法且引用存在 |
| entries/groups | 单个 vault 和单个备份最大数量 |
| settings | auto-lock、generator length、charset 不变量 |
| generator | 至少一种字符集为 true |

前端校验仅用于即时 UX，不能替代后端 validation。

### 5.2.2 KdfPolicy

所有 vault 和 backup KDF 参数在进入 Argon2 之前统一校验。建议初始范围：

- memory：16～256 MiB；
- iterations：1～10；
- parallelism：1～8；
- 增加组合成本上限，防止多个合法上限组合造成不可接受延迟；
- 已发布合法参数通过 fixture 白名单验证。

非法值必须立即返回 `InvalidParams`，不得先尝试分配。

### 5.2.3 备份 v2

定义稳定的 v2 envelope：

```text
magic
format_version
kdf_name + validated params
cipher_name
salt
nonce
created_at
ciphertext
```

除 ciphertext 外的规范化 header 作为 AES-GCM AAD。新版本：

- v1 备份只读导入；
- 新导出全部使用 v2；
- 导入顺序为：文件大小检查 → envelope 检查 → KDF 参数检查 → Base64/二进制长度检查 → KDF → 解密 → payload 数量/字段检查 → 预加密 → 单事务替换。

### 5.2.4 数据库格式演进

- 使用 `RecordEnvelope { format_version, ciphertext }`；
- 明确定义 `StoredEntryV1/V2` 和 `StoredGroupV1/V2`；
- 建立 migration registry：`vN -> vN+1`；
- 未知 future version 只读失败，不得写库；
- settings 记录不存在时才返回默认值；记录存在但解析失败时返回 CorruptData。

### 5.2.5 文件权限

- macOS/Linux 数据目录、日志目录：`0700`；
- vault、native-host config、日志：`0600`；
- 启动时修复已有宽权限；
- Windows 使用仅当前用户可读 ACL；
- 文件创建应使用安全 OpenOptions/ACL，避免先以宽权限创建后再 chmod 的窗口。

### 5.2.6 实施边界

- v1 备份保持只读兼容；
- 非法值拒绝而不是 clamp；
- 任一导入验证失败不得产生数据库写入。

### 5.2.7 验收标准

1. Tauri、HTTP、import 对相同非法输入返回相同稳定错误码。
2. 空或过短主密码无法通过任一入口创建 vault。
3. `m_cost=u32::MAX`、极端 t/p 参数在 50 ms 量级内被拒绝，无明显 RSS 增长。
4. 任一 v2 header、ciphertext、nonce 位被修改均导入失败。
5. 超大文件、超多记录、超长字段和无效 settings 在数据库首次写入前拒绝。
6. v1 fixture 可读，v2 round-trip 通过。
7. macOS/Linux 权限自动化测试通过；Windows ACL 验证通过。

---

## 阶段 3：前端数据可信度与隐私

**预计工作量：3～4 人日**

### 5.3.1 Resource State

为 entries、groups、settings 增加：

```text
idle | loading | success | error
```

禁止使用空数组同时表示“尚未加载、加载失败、确实为空”。

Vault 页面要求：

- loading：显示 skeleton/spinner；
- error：显示明确错误和 Retry；
- success + empty：显示真正的空库状态；
- error 时不得显示“No passwords saved yet”。

Settings 加载失败时：

- 显示错误和 Retry；
- 禁止使用默认值保存；
- 不得覆盖真实后端设置。

### 5.3.2 更新检查隐私

更新检查只能在：

1. vault 解锁；
2. settings 加载成功；
3. `check_updates=true`；
4. 当前启动尚未检查过；

四个条件同时满足时执行。

如果 GitHub 仓库仍为 private，未认证的 Releases API 不适合作为更新源。可选择：

- 发布公开、签名的 update metadata；或
- 在仓库公开前关闭自动更新；或
- 使用未来的正式 Tauri updater 和签名 manifest。

不得把 GitHub token 打包进客户端。

### 5.3.3 Group 状态一致性

- GroupSelector 使用 VaultContext 的 groups/actions；
- Entry 中创建组后全局 group tabs 立即更新；
- 删除当前筛选组后 selectedGroupId 自动清空；
- 删除组后的 entry group_id cascade 在前端立即刷新。

### 5.3.4 Secret 最小暴露

- 后端增加 patch update，未修改密码时不要求提交旧密码；
- 编辑页默认不拉取 password/notes；
- reveal/copy 时按需获取，并在短期状态中使用；
- 原生剪贴板负责定时清理，使用 pasteboard sequence/change count 判断内容是否仍为本应用写入；
- JS timer 不再闭包持有明文密码 30 秒。

### 5.3.5 表单一致性

- 至少选择一种 generator charset；
- 最后一个 charset 不允许取消，或显示内联错误并禁用 Generate/Save；
- Entry、Settings、扩展 Create 页面增加 dirty guard；
- 保存/创建期间按钮 disabled，并通过 pending state 防止重复提交；
- boot/setup 失败使用 fatal boot error + Retry，不显示成首次创建 vault。

### 5.3.6 实施边界

- 不引入新的全局状态库；
- 保留当前页面结构和主要导航；
- 不改变密码管理器核心工作流。

### 5.3.7 验收标准

1. 加载错误绝不显示为空库。
2. settings 加载失败时 Save disabled。
3. `check_updates=false` 时 update API 调用次数为 0；true 时每次启动最多一次。
4. 仅修改 title/username/url/tags/group 时不调用 `get_entry_secret`。
5. Entry 内创建组后回到 Vault，组立即可见。
6. 删除当前筛选组后自动返回 All。
7. 所有 charset false 时无法生成或保存无效默认设置。
8. 有未保存修改时返回会提示；未修改时不提示。

---

## 阶段 4：UI、设计系统与可访问性

**预计工作量：4～6 人日**

### 5.4.1 清理主题遗留

- 删除 index.html 中 Classic/Cyber/Hybrid 的遗留默认主题；
- 删除远程 Google Fonts 和 CSP 不允许的内联 script/style；
- 使用本地字体资产或系统回退；
- 保留 DESIGN.md 定义的 Inter/JetBrains Mono token；
- 首帧 theme bootstrap 放入受 CSP 允许的本地 module；
- 支持 System/Light/Dark；
- System 模式订阅 `matchMedia('(prefers-color-scheme: dark)')` 变化。

### 5.4.2 统一 ScreenShell

桌面屏幕统一使用：

```css
height: 100dvh;
display: flex;
flex-direction: column;
```

内容区统一：

```css
flex: 1;
min-height: 0;
overflow-y: auto;
```

应用于 Vault、Entry、Generator、Settings、Groups、Backup/Restore。

### 5.4.3 语义颜色和对比度

新增：

- `--color-on-primary`；
- `--color-on-danger`；
- 必要时增加 `--color-on-success`；
- 不直接假设所有主题下品牌色都能使用白字。

交互目标：

- 普通桌面按钮至少 36～40 px；
- 核心和触摸操作至少 44 px；
- theme-dot 不得只有 12×12 可点击区域；
- muted text、placeholder、danger/primary button 满足 WCAG AA 对比度。

### 5.4.4 Strength Meter

改为 track + fill：

```text
strength-track
└── strength-fill width = score%
```

增加：

- `role="meter"` 或 progressbar；
- `aria-valuemin=0`；
- `aria-valuemax=100`；
- `aria-valuenow=score`；
- 标签与颜色双重表达，不能只依赖颜色。

### 5.4.5 AccessibleDialog

统一替换 Confirmation、Delete、Restore、Generator modal：

- `role="dialog"`、`aria-modal="true"`；
- `aria-labelledby`/`aria-describedby`；
- 打开时设置初始焦点；
- Tab/Shift+Tab focus trap；
- Escape 关闭；
- 关闭后恢复触发元素焦点；
- 背景 inert；
- 危险 restore 可增加 typed confirmation，例如 `RESTORE`。

### 5.4.6 表单和列表语义

- Backup 密码框增加 label/id；
- Vault search 增加可访问名；
- GroupSelector select/input 与 label 关联；
- tag 删除从 clickable span 改为 button；
- entry listitem 内使用独立主按钮和复制按钮；
- 支持 Enter 和 Space；
- 错误信息使用 `aria-invalid`、`aria-describedby`；
- Toast Provider 使用 `role=status`/`role=alert` 和 `aria-live`。

### 5.4.7 实施边界

- 保留 DESIGN.md 的 Trust & Security 方向；
- 保留 Light/Dark 色彩体系和 400×600 紧凑布局；
- 不进行品牌或信息架构重设计。

### 5.4.8 验收标准

1. 350×500、400×600、800×700 无横向溢出和底部操作裁切。
2. 100%、125%、200% 缩放下可完成全部核心流程。
3. 键盘可完成 setup、unlock、CRUD、generator、settings、backup/restore。
4. axe 扫描无 serious/critical。
5. modal 焦点圈闭、Escape 和焦点恢复测试通过。
6. 离线启动无外域字体请求，首帧主题正确。
7. 20/50/100 分强度填充约为 20%/50%/100%。
8. Light/Dark/System 在 OS 主题变化时表现一致。

---

## 阶段 5：浏览器扩展和 Native Messaging

**预计工作量：4～6 人日**

### 5.5.1 跨浏览器 manifest

Chrome native host manifest：

```json
{
  "allowed_origins": ["chrome-extension://<id>/"]
}
```

Firefox native host manifest：

```json
{
  "allowed_extensions": ["pwdvault@pwdvault.app"]
}
```

不得用同一个字段和 URL 格式生成两种 manifest。

Windows 下：

- Chrome 和 Firefox 使用独立 manifest 文件；
- 两个 registry key 指向各自文件；
- 后注册的浏览器不得覆盖前一个 manifest。

### 5.5.2 Firefox 自包含打包

发布时不能使用 `zip --symlinks` 保留指向 `../chrome` 的链接。使用 staging：

1. 创建临时 staging 目录；
2. 复制 Firefox manifest；
3. resolve/copy chrome 共享的 src/icons；
4. 验证所有 manifest 引用存在；
5. 将普通文件打包为 zip/xpi；
6. 执行 `web-ext lint` 和安装 smoke test。

### 5.5.3 配对和 caller 绑定

- native host 读取浏览器启动参数中的真实 caller ID/origin；
- host 不再自行伪造固定 Origin；
- PairSession 绑定 caller + session nonce + TTL + attempt count；
- A caller 创建的 code 不能由 B caller confirm；
- 错误 code 不应无限尝试，也不能让任意本地进程持续抢占合法 session；
- token 保持 constant-time 比较；
- UI 增加撤销 extension access/重新配对。

### 5.5.4 传输和资源限制

短期：

- HTTP 使用固定 worker pool 或有界队列；
- 限制并发连接、body size、读取时间；
- 严格检查 POST、path、content-type、content-length；
- 响应增加 `Cache-Control: no-store`；
- Origin 只作为标签，不能描述为认证边界；
- 移除扩展不再需要的 loopback host permissions 和 CORS。

中期：

- macOS/Linux 使用 Unix domain socket；
- Windows 使用 named pipe；
- socket/pipe 使用当前用户 ACL；
- 关闭 127.0.0.1:17429；
- 移除相关 CSP connect-src。

### 5.5.5 协议版本

Native Messaging 请求增加：

- `protocol_version`；
- typed/tagged command DTO；
- 稳定错误结构：`code/message/retry_after`；
- app/host/extension capability handshake；
- 不支持的协议版本应返回明确升级提示。

### 5.5.6 扩展 sender 授权

background 根据 sender 类型分权：

- popup：允许显式查看、复制和管理；
- content script：只允许当前 `sender.tab.url` 域名匹配的 entry；
- content script 不得传入任意 URL 代替 sender.tab.url；
- `GET_ENTRY` 不能只凭任意 ID 返回 secret；
- token storage 设置为 trusted contexts；
- 锁定时清理 popup secret cache、visible password 和 content-script 临时状态。

### 5.5.7 扩展 UI 模块化

不要求立即重写为 React，先拆分：

```text
popup/
├── state.js
├── api.js
├── actions.js
├── screens/
├── accessibility.js
├── popup.css
└── popup.js
```

- 桌面与扩展共享 canonical design tokens；
- 密码强度使用共享测试向量；
- loading/error/empty 分离；
- entry header 支持 Enter/Space 和 `aria-expanded`；
- Toast 增加 live region；
- 支持 reduced-motion、focus-visible 和 200% 缩放；
- form pending 防重复提交；
- Create 页面增加 dirty guard。

### 5.5.8 实施边界

- 保留 Native Messaging 主流程和 host name；
- 不强制引入 React/Preact；
- socket/pipe 可以在短期修复完成后作为独立小版本交付。

### 5.5.9 验收标准

1. macOS/Windows 上 Chrome、Firefox `sendNativeMessage` smoke E2E 通过。
2. 解压发布包后所有 manifest 引用都是存在的普通文件。
3. Chrome/Firefox manifest lint 和浏览器加载通过。
4. Windows 两个 registry key 指向不同且正确的 manifest。
5. A caller 的 code 不能由 B caller confirm；过期、重放和超次数请求被拒绝。
6. 1,000 个慢/畸形连接下线程和内存有明确上限，UI 和 auto-lock 仍正常。
7. content script 请求其他域 entry ID 被拒绝。
8. token 不可从 content script 的 storage API 读取。
9. Chrome/Firefox 均覆盖 disconnected、pairing、locked、loading、error、empty、unlocked。

---

## 阶段 6：性能、模块化与发布工程

**预计工作量：3～5 人日**

### 5.6.1 前端性能

- AppContent 只订阅 AuthContext；
- 页面直接使用 `useAuth/useVault/useSettings`；
- 逐步删除组合 `useApp()` 和 `any` dispatch facade；
- Fuse 索引按 entries 变化缓存，不在每次 query 时重建；
- 搜索使用 `useDeferredValue`；
- GroupManager 一次构造 group count Map，避免每组 filter 全 entries；
- 未使用的 `useEntries` 删除或正式接入。

### 5.6.2 后端性能

- list entries/groups 使用单个 read transaction bulk scan；
- 避免先 list IDs 再逐条开启 transaction；
- 为 100/1k/5k/10k 数据量记录 list、search、mutation p50/p95；
- Argon2、import/export、大文件处理放入 blocking worker；
- update check 可取消且不阻塞 UI/托盘；
- digest 如果在大库 mutation 中超出预算，再评估增量认证结构或 Merkle tree，不提前引入。

### 5.6.3 模块边界

渐进拆分为：

```text
domain
├── Entry / Group / Settings
├── validation policy
└── stable error codes

application
├── vault lifecycle
├── CRUD use cases
├── backup use cases
└── session/transaction policy

infrastructure
├── redb repository
├── crypto
├── filesystem
└── update source

adapters
├── Tauri IPC
└── Native Messaging
```

domain 不得依赖 Tauri 或 redb；两个 adapter 应通过 golden contract tests 返回一致结果。

### 5.6.4 CI/CD 目标流水线

#### quality-frontend

- 固定 Node 和 pnpm 版本；
- `pnpm install --frozen-lockfile`；
- TypeScript build；
- Vitest；
- ESLint；
- axe/component accessibility tests。

#### quality-rust

主应用和 native host 分别执行：

- `cargo fmt --check`；
- `cargo clippy --all-targets -- -D warnings`；
- `cargo test --locked`。

#### security

- audit 两个 Cargo.lock；
- `pnpm audit`；
- secret scan；
- CodeQL/SAST；
- 许可证策略；
- 对无法立即修复的 RUSTSEC warning 建立包含理由和到期日的 allowlist。

#### package

- 仅依赖全部 quality/security job 成功后执行；
- 版本脚本检查 VERSION、app Cargo、host Cargo、Tauri config、package.json、Chrome、Firefox、tag；
- Firefox 使用自包含 staging；
- 对产物执行安装/启动 smoke test。

#### sign-and-verify

- macOS Developer ID、notarization、staple；
- Windows Authenticode；
- 浏览器扩展按平台要求签名；
- 上传前执行签名验证。

#### provenance

- SHA-256 清单；
- CycloneDX SBOM；
- GitHub artifact attestation；
- Actions pin 到 commit SHA。

### 5.6.5 版本一致性

- 修复 native host 仍为 1.0.3、其他组件为 1.0.5 的漂移；
- `bump-version.sh` 更新并校验所有版本源；
- 产品版本与 `protocol_version` 分离；
- host 不一定每次与产品版本相同，但任何差异必须被显式声明和 CI 校验；
- 本地 HEAD、origin、release tag 和 CHANGELOG 状态纳入发布检查。

### 5.6.6 验收标准

1. 10,000 条目搜索输入响应目标小于 100 ms，主线程长任务小于 50 ms。
2. `list_all_entries` 只使用一个 read transaction。
3. 5,000 条目 list/mutation p95 有可重复基准；相对基线退化不超过 20%。
4. KDF、10 MB import 和 5 秒更新超时期间，窗口、托盘和 auto-lock 仍响应。
5. PR 和 release 必须通过 fmt、Clippy、全部测试、审计和版本检查。
6. macOS `codesign --verify --deep --strict`、`spctl`、stapler validate 通过。
7. Windows `Get-AuthenticodeSignature` 为 `Valid`。
8. 没有正式签名证书时，只允许 development/nightly 发布。

---

## 6. 测试与验收矩阵

| 类别 | 场景 | 通过标准 |
|---|---|---|
| 数据事务 | create/update/delete/group/settings/import 故障注入 | 只能看到完整旧状态或完整新状态 |
| 完整性 | 删除 digest、改版本、删记录、交换 blob | 新格式 vault 拒绝解锁且不写新基线 |
| 解锁 | DB IO、坏 digest、migration 失败 | 保持 Locked，密钥和活动时间为空 |
| 并发 | IPC + HTTP + auto-lock 1,000 次 | 无死锁、丢更新、陈旧 digest |
| KDF | 极端 m/t/p 参数 | 快速拒绝，不 OOM |
| 备份 | v1 fixture、v2 round-trip、损坏 header/ciphertext | 合法可读，任一篡改失败 |
| 输入 | 非法 settings、超长字段、超多记录 | 首次写库前拒绝 |
| 权限 | macOS/Linux/Windows 数据文件 | 仅当前用户可读 |
| 前端状态 | loading/error/empty | 错误绝不伪装为空库 |
| 隐私 | `check_updates=false` | update API 0 次调用 |
| Secret | 非敏感字段编辑 | 不调用 secret API |
| 窗口 | 350×500、400×600、800×700 | 无横向溢出和操作裁切 |
| 可访问性 | 键盘、focus、screen reader、axe | 核心流程可完成；无 serious/critical |
| 主题 | System/Light/Dark、离线启动 | 首帧正确，无外域字体请求 |
| 扩展 | Chrome/Firefox 各业务状态 | 真机 smoke E2E 通过 |
| Sender 授权 | content script 请求其他域凭据 | 拒绝 |
| 性能 | 10k 搜索、5k 列表和 mutation | 达到既定 p95 和交互预算 |
| 发布 | 测试、审计、版本、签名、SBOM | 全部通过后才允许 stable release |

---

## 7. 实施依赖与建议排期

### 7.1 依赖关系

```text
阶段 0：基线
  └── 阶段 1：事务/会话/完整性
        └── 阶段 2：Validation/备份/格式演进

阶段 0
  └── 阶段 3：前端数据可信度
        └── 阶段 4：UI/可访问性

阶段 0
  └── 阶段 5：扩展/Native Messaging

阶段 1～5
  └── 阶段 6：性能/模块化/稳定发布
```

### 7.2 推荐排期

| 周期 | 主要内容 | 可交付结果 |
|---|---|---|
| 第 1 周 | 阶段 0 + 阶段 1 前半 | fixture、故障注入、VaultSession、事务框架 |
| 第 2 周 | 阶段 1 后半 + 阶段 2 | 完整性防降级、两阶段解锁、Validation、备份 v2 |
| 第 3 周 | 阶段 3 + 阶段 4 | resource state、隐私开关、最小窗口和可访问性 |
| 第 4 周 | 阶段 5 | Chrome/Firefox NM、sender 授权、自包含打包 |
| 第 5 周 | 阶段 6 | 性能、模块边界、CI、版本和签名验证 |
| 第 6～7 周 | 缓冲与安全回归 | 真机 E2E、迁移验证、发布候选版 |

总体预计：

- 单人实施：约 22～34 人日，建议预留 5～7 周；
- 后端/安全与前端/扩展两人并行：约 3～4 周；
- 阶段 1、2、5 完成后分别进行安全/兼容性复审。

---

## 8. 风险与回滚策略

### 8.1 数据库格式变更风险

控制措施：

- migration 前自动备份原数据库；
- 原库备份使用唯一时间戳，不覆盖；
- migration 单事务、幂等；
- fixture 覆盖所有已发布格式；
- migration 失败不发布 key、不更新 marker、不删除原库。

### 8.2 完整性误报风险

控制措施：

- 业务数据与 digest 同事务；
- 不再 best-effort 刷新摘要；
- legacy 检测使用明确、受验证的格式信号；
- 不将未知格式当成旧格式自动迁移。

### 8.3 跨浏览器差异风险

控制措施：

- Chrome/Firefox 使用独立 manifest builder；
- macOS/Windows 真机矩阵；
- 发布包解压后静态验证；
- `web-ext lint`、Chrome load unpacked 和真实 NM smoke test。

### 8.4 UI 回归风险

控制措施：

- 保持现有品牌和信息架构；
- 多尺寸视觉回归；
- 键盘和 axe 自动测试；
- Light/Dark/System 分别验证；
- 扩展和桌面共享 token/test vectors。

### 8.5 进度风险

如果需要压缩范围，最低可发布集合必须包含：

1. 阶段 0；
2. 阶段 1 全部；
3. 阶段 2 的 KDF/Validation/权限；
4. 阶段 3 的错误状态和更新隐私；
5. 阶段 5 的 Firefox/Windows manifest、自包含包和 sender 授权；
6. 阶段 6 的测试、版本和签名门禁。

视觉细节优化、性能深度优化和 socket/pipe 可在后续小版本继续，但不能跳过数据一致性与发布门禁。

---

## 9. Definition of Done

本轮优化只有在以下条件全部满足时才可标记完成：

- [ ] 所有业务 mutation 与完整性摘要同事务提交；
- [ ] 解锁在全部验证完成后才发布密钥；
- [ ] 新数据库格式无法通过删除 digest 或修改版本降级；
- [ ] 极端 KDF、超大备份和非法字段在写库前快速拒绝；
- [ ] 文件权限/ACL 仅允许当前用户读取；
- [ ] v1.0.0～v1.0.5 数据库 fixture 可安全迁移；
- [ ] v1 backup 可读，新导出为受 AAD 保护的 v2；
- [ ] 前端 loading/error/empty 状态严格区分；
- [ ] `check_updates=false` 时完全不联网检查；
- [ ] 非敏感 entry 编辑不读取旧 password/notes；
- [ ] 350×500 至 800×700 无操作裁切；
- [ ] 键盘可完成全部核心流程，axe 无 serious/critical；
- [ ] Chrome/Firefox Native Messaging 真机 E2E 通过；
- [ ] content script 无法越权读取其他域凭据；
- [ ] 10k 搜索和 5k 列表达到性能预算；
- [ ] frontend、Rust app、native host 的测试/fmt/clippy/audit 全部成为 CI 门禁；
- [ ] 所有产品版本和 protocol version 通过一致性检查；
- [ ] 稳定版产物通过 macOS/Windows 签名验证；
- [ ] README、AGENTS、CHANGELOG、架构、安全边界和发布文档与代码一致。

---

## 10. 最终建议

实施顺序应固定为：

1. 建立回归和 fixture；
2. 修复事务、会话、完整性和 KDF 边界；
3. 完成输入、备份和权限加固；
4. 修复前端数据可信度与隐私；
5. 完成 UI/可访问性；
6. 修复浏览器扩展和 Native Messaging 跨平台问题；
7. 最后进行性能、模块化和稳定发布收口。

不建议在上述工作完成前加入生物识别、TOTP、云同步等新功能。PwdVault 当前最有价值的优化不是扩大功能面，而是确保现有密码库在崩溃、升级、篡改、异常输入、跨浏览器和发布流程中都能保持可验证、可恢复和一致。
