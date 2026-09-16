# PwdVault 审计修复方案（2026-09）

> 依据：2026-09-15 三路审计（后端 / 前端+扩展 / 业界对比）+ 三路独立核查代理逐条验证。
> 本文所有行号经核查代理二次确认，为当前工作区真实行号。
> 状态：待 plan-reviewer 评审。

---

## 0. 核查结论与范围裁定

### 0.1 确认修复（本期范围）

| ID  | 问题                                                                                     | 核查结论                                                                | 批次 |
| --- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---- |
| B1  | 删除 vault header 一行即绕过完整性校验（fail-open 到 legacy 迁移，可注入明文钓鱼条目）   | CONFIRMED（digest 在 META_TABLE 非 header；迁移会静默重建 digest 基线） | 1    |
| B2  | `init_vault` 防重只查内存态，理论上可覆盖既有 vault                                      | PARTIAL 降级 P3（扩展侧 INIT_VAULT 为休眠代码），机制性修复             | 1    |
| B3  | HTTP 端口 17429 bind 失败静默；先占者可截获主密码明文与 Bearer token                     | CONFIRMED 且加重                                                        | 1    |
| B4  | bincode 在 AEAD 验证前反序列化磁盘字节，无长度限制                                       | CONFIRMED 降级 P3（受 digest 保护），顺手修                             | 1    |
| D1  | `keystore.rs` 死代码且 `get_key()` 返回未擦除副本                                        | CONFIRMED                                                               | 1    |
| D2  | `paths.rs` `current_dir().unwrap()` 启动期 panic 点                                      | CONFIRMED                                                               | 1    |
| D3  | `lib.rs:211` `default_window_icon().unwrap()`                                            | CONFIRMED                                                               | 1    |
| D4  | native host `extract_command` 无字符白名单（CRLF 注入防御深度）                          | CONFIRMED（现实注入≈0，防御深度修复）                                   | 1    |
| D5  | 更新检查 `read_to_string` 无响应体上限                                                   | CONFIRMED                                                               | 1    |
| D6  | pairing code 比较非常时时间                                                              | CONFIRMED（理论性，低成本修复）                                         | 1    |
| F1  | 扩展单匹配页面加载即预取明文密码进 content script 闭包                                   | CONFIRMED（密码在 isolated world，页面 JS 不可读；违反最小化/延迟解密） | 2    |
| F2  | 授权 URL 用 `sender.tab.url`（顶层），忽略 frame URL                                     | PARTIAL：当前 manifest 无 `all_frames:true` 不可利用，属潜伏缺陷+加固   | 2    |
| F3  | `findLoginForm` 第一个密码字段即返回；`detectFormType` 是死输出                          | CONFIRMED 且更重（`DETECT_FORM` 消息无任何发送方）                      | 2    |
| F4  | 浮动按钮 fixed 定位混入 `window.scrollY`；无移除路径                                     | CONFIRMED                                                               | 2    |
| F5  | popup 滑块 `oninput` 逐像素触发 `sendNativeMessage`（每条消息 spawn 一个 host 进程）     | CONFIRMED                                                               | 2    |
| F6  | 配对码输错后自动重发 `pair`，作废桌面端正在显示的码；nonce 仅存 SW 内存                  | CONFIRMED                                                               | 2    |
| A1  | auto-lock 活动只由 vault API 推进，纯本地输入不续期；到期直接 reload                     | CONFIRMED（beforeunload 在 macOS WKWebView 不渲染确认框）               | 3    |
| A3  | 剪贴板三处实现：同内容重复复制被旧定时器提前清空；popup/content 定时器随文档销毁永不清空 | CONFIRMED 且加重                                                        | 3    |
| A4  | `AuthContext.lock()` 无 try/finally，异常时 UI 与后端脱节                                | CONFIRMED（结构性防御缺口）                                             | 3    |
| A5  | EntryScreen 快速生成器硬编码 `length:16`，无视 Settings 默认值                           | CONFIRMED                                                               | 3    |
| A6  | `passwordStrength.ts` 的 `color` 字段死代码（硬编码 hex 绕过主题）                       | CONFIRMED                                                               | 3    |
| A7  | Restore 确认按钮 disabled 不含 `importing`                                               | PARTIAL（双击路径当前不可达，一行加固）                                 | 3    |
| A8  | `AccessibleDialog` inert 无引用计数 + Escape 无栈协调（潜伏缺陷，当前 UI 无叠加路径）    | CONFIRMED                                                               | 3    |

### 0.2 明确不做（记录理由）

| 项                                   | 理由                                                                 |
| ------------------------------------ | -------------------------------------------------------------------- |
| iframe `all_frames:true` 功能化      | 功能决策而非缺陷修复；F2 修复后前置条件已备齐，单独立项              |
| UDS / named pipe 替代 TCP 17429      | 架构级改造（原生 Stage 3 规划），B3 告警先行缓解                     |
| token lock 时轮换                    | 需改扩展配对协议与存储语义，影响面大，单独设计                       |
| 全局限流改按主体                     | 本地单用户威胁模型下收益低                                           |
| `remove_group` 读-写事务 TOCTOU      | 单用户 UI 概率极低                                                   |
| Tauri capabilities `fs:scope` 收窄   | 需配合 dialog 流程回归测试，单独做                                   |
| Windows 文件 ACL                     | 纵深防御，继承用户 profile 目录已有保护                              |
| 锁定前 dirty 双向协商                | A1 活动上报已把触发概率降到极低；完整协商需前后端协议设计，单独立项  |
| popup/content 剪贴板"文档销毁不清空" | MV3 popup/页面生命周期固有限制；桌面端（主场景）webview 常驻不受影响 |
| TOTP / 安全笔记等功能项              | 功能路线图，非本缺陷修复范围                                         |

---

## 批次 1：后端修复（src-tauri + extensions/native-host）

### B1 完整性 fail-open → fail-closed

**位置**：`src-tauri/crates/application/src/service/vault.rs:190-237`（unlock）、`crates/infrastructure/src/database/integrity.rs:12-13`（digest 存于 `META_TABLE["db_digest"]`）、`crates/infrastructure/src/database/entry_codec.rs:66-67`（明文 bincode 回退）

**根因**：`integrity_required` 完全由 header 行存在性决定（`vault_header.rs:126-128` `header.is_some_and(...)`）。header 缺失 → 走 legacy 迁移分支 → 不校验 digest 且经 `VaultStore::write` 静默重建 digest 基线。攻击者（已持 vault.db 写权限）删 header 一行 + 篡改/注入条目 → 下次 unlock 被当作 legacy 库干净迁移。`entry_codec.rs:66-67` 的明文 bincode 回退允许注入攻击者构造的钓鱼条目。

**设计**（迁移兼容性依据：v1.0.5（2026-05）起所有升级路径均自动写入 header，当前（2026-09）存量用户库已全部带 header；fail-closed 实际影响面≈0）：

```
unlock 时读取 header：
  Some(h) && h.integrity_required  → 现有 fail-closed digest 校验（不变）
  Some(h) && !h.integrity_required → legacy 一次性迁移，但迁移前：
      若 META_TABLE 已存 digest → 先 verify_integrity，不匹配即拒绝迁移
      （防"从旧 .bak 回插 integrity_required=false header 洗白注入条目"）
  None                             → 一律返回错误，不再自动迁移：
      VaultError::LegacyVaultRequiresMigration
      public_message: "Vault database is missing its integrity header. If this vault
                       was created by an older version of PwdVault (pre-1.0.5),
                       please migrate it using PwdVault 1.1.4 first, or restore from
                       a backup."
```

- 删除 unlock 中 `header == None → migrate_database` 的自动触发调用；`migrate_database` 保留但成为非 test 构建下的 dead code，须标注 `#[cfg_attr(not(test), allow(dead_code))]` + 注释说明"仅测试与未来显式迁移工具使用"，否则 `cargo clippy -D warnings` 验收门必挂。
- 错误变体进入 `public_message()` 脱敏映射（`crates/application/src/error.rs`）。
- **明文 bincode 回退收窄到迁移路径**（评审补充的残余链：攻击者删 header+verification+digest 三行 → 用户重建设置 → init 重建 → 运行态明文钓鱼条目仍可被 `open_entry` 回退收编）。**调用链事实（复审核实）**：`open_entry` 仅被 `load_entry`（mod.rs:223）与 `list_all_entries_bulk`（mod.rs:273）调用；`open_group` 仅被 `load_group`（mod.rs:312）与 `list_all_groups_bulk`（mod.rs:356）调用；`migrate_database` 经 `load_entry`（vault.rs:300）与 `load_group`（vault.rs:340）访问数据，与运行态共用这两层。因此：
  - `open_entry` / `open_group` 增加 `allow_plaintext: bool` 参数，**透传** `load_entry` / `load_group`（entry 与 group 两侧都要，`group_codec.rs:59` 有同样的明文回退）；
  - `migrate_database` 走 true 通道（或拆出 `load_entry_legacy` / `load_group_legacy` 专用包装）；其余全部运行态调用方（entries.rs:74,89,179、groups.rs:70、native_messaging.rs:1208、backup.rs）走 false；
  - `list_all_entries_bulk` / `list_all_groups_bulk` 固定 false（其内联调用的 open_* 不透传参数）；
  - 运行态（false 通道）遇到明文 blob 返回解码错误（该条目按"损坏/不支持格式"跳过或报错，不得静默解析）。
- 残余风险如实记录：若攻击者同时精确删除 header+digest 两行且库为真 legacy 明文库，仍可伪装；该场景等同攻击者重写全库，危害不高于"攻击者已有文件写权限"，接受。

**测试**（`vault.rs` 测试模块，仿既有 fixtures 测试模式）：

1. 建库（生成 header+digest）→ 直接从 redb 删除 `VAULT_TABLE["header"]` 行 → unlock 必须失败，错误为 LegacyVaultRequiresMigration。
2. 同场景下条目未被篡改确认：失败后不发生 digest 重写（META digest 值不变）。
3. 真 legacy fixture（无 header 无 digest，明文 blob）→ 走显式 `migrate_database` 调用 → 迁移成功、unlock 成功（保留对迁移函数本身的覆盖）。
4. 回插伪造 header（integrity_required=false）+ 篡改条目 + META 仍存原 digest → 迁移前 verify_integrity 失败 → 拒绝。
5. 运行态（false 通道）：`load_entry`/`list_all_entries_bulk` 对明文 bincode blob 一律返回错误（不走回退，与 header 状态无关）；
6. `cargo clippy --all-targets -- -D warnings` 下 `migrate_database` 不触发 dead_code。

**验收**：`cargo test -p pwdvault-application` 全绿；删 header 场景 fail-closed。

### B2 init_vault 磁盘级防重

**位置**：`vault.rs:85-99`（init_vault）、`vault.rs:73-79`（is_vault_initialized）

**设计**：

- `init_vault` 开头，在内存检查之后增加磁盘检查：`paths::get_db_path` 存在 → `Database::open` + `load_verification_data` → 若 `Ok(Some(_))` 返回**既有的** `VaultError::VaultAlreadyExists`（error.rs:18，Display 与 public_message 均已存在，不新增变体）。避免覆盖既有 verification row。
- `is_vault_initialized`：内存 `verification_data.is_some()` 时返回 true；否则若 db 文件存在则查磁盘 verification row（复用 setup_vault 的加载逻辑，失败按 false 处理并记 tracing::warn）。
- 扩展侧无需改动（休眠代码）。

**测试**：磁盘已有 verification 行时调 `init_vault` → 返回错误且原 verification row 字节不变（读前后对比）。

### B3 端口 bind 失败 UI 告警

**位置**：`src-tauri/src/lib.rs:173-180`（spawn 内 `if let Err(e) ... tracing::error!`）

**设计**：

- bind 失败时除日志外：`app_handle.emit("native-server-error", format!("Browser extension server failed to start: {error}"))`（注意 error 已是后端内部错误字符串，需确认不含敏感路径——`start_server` 返回的错误信息检查一遍，含端口即可）。
- 前端 `src/App.tsx`（或 `src/context/AuthContext.tsx` 挂载处）`listen('native-server-error')` → 用 `utils/toast.ts` 显示长时 toast（type=error，不自动消失或 10s）。
- 不做自动重试（避免与抢占者端口拉锯）；用户重启应用即可。

**测试**：Rust 侧新增单元测试：占用端口后调 `start_server` 断言返回 Err（若 start_server 不易单测则测错误构造路径）；前端以手动验收为准（`pnpm tsc --noEmit` + 现有测试不回归）。

### B4 bincode 反序列化长度上限

**位置**：`crates/infrastructure/src/database/entry_codec.rs:54,67,72`（含 `is_encrypted` 的 deserialize）、`group_codec.rs:46,59`、`vault_header.rs:86`、`database/mod.rs:186,393,395`（含 `LegacySettingsV1` 回退）。**以 `grep -rn "bincode::deserialize" crates/` 全量核对为准**，列举仅供定位，勿只改列表处。

**设计**：`database/mod.rs`（或 codec 模块顶部）新增常量 `MAX_ENCODED_BLOB: usize = 1 * 1024 * 1024`（正常 EncryptedData blob 数百字节级，1MB 充裕）。所有"磁盘字节 → bincode::deserialize"调用点前加 `if blob.len() > MAX_ENCODED_BLOB { return Err(...) }`，错误走各文件现有 CodecError/Error 变体（新增 `BlobTooLarge` 或复用 decode error）。

**测试**：构造 1MB+1 假 blob → open_entry / open_group / VaultHeader::open / load_verification_data 均返回错误而非尝试分配。

### D1 删除 keystore.rs 死代码

**位置**：`crates/infrastructure/src/crypto/keystore.rs`（129 行）、`crypto/mod.rs:19`（pub use）、`crates/application/src/error.rs:45-49`（`From<KeyStoreError>`）

**设计**：删除三处 + `session.rs:259` 附近提及 keystore 的过时注释清理。删除后 `cargo build` 全 workspace 确认无悬空引用（keystore 自身测试一并删除）。

### D2 paths.rs 去 unwrap

**位置**：`crates/infrastructure/src/paths.rs:15,21,27,32`

**设计**：`current_dir().unwrap()` → `current_dir().unwrap_or_else(|_| std::env::temp_dir())`。四平台分支同改。

**测试**：现有 paths 测试不回归（不构造 cwd 被删场景，属平台极限）。

### D3 窗口图标 unwrap

**位置**：`src-tauri/src/lib.rs:211`

**设计**：`app.default_window_icon().unwrap().clone()` → `match`/`if let Some(icon) ... Some(icon.clone()) else None`（查 tray builder 的 API 是否接受 Option；若必须非 Option 则 `.expect("embedded window icon missing")`）。

### D4 native host command 白名单

**位置**：`extensions/native-host/src/main.rs:379-382`（extract_command）

**设计**：`extract_command` 返回前校验 `command.chars().all(|c| c.is_ascii_lowercase() || c == '_')`，不满足则向 stdout 写协议错误响应（沿用该文件现有错误响应路径）并以非零退出（与既有"畸形消息即退出"策略一致）。

**测试**：native-host 若有测试模块则加 2 例（合法 command / 含 CRLF command）；无测试模块则以 cargo build 通过 + 人工复核为准。

### D5 更新响应体上限

**位置**：`crates/application/src/service/update.rs:44-47`

**设计**：项目用 **ureq 3**（application/Cargo.toml:35，`Response` 无 `into_reader()`），现有代码为 `response.body_mut().read_to_string()`。改为 `response.body_mut().take(1024 * 1024).read_to_string()`（导入 `std::io::Read`；`Body` 实现 Read）。超限截断导致 JSON 解析失败 → 走既有解析错误分支（更新检查静默失败可接受）。

### D6 pairing code 常时比较

**位置**：`crates/infrastructure/src/pairing.rs:67-70`

**设计**：`session.code != code` 与 `session.nonce != nonce` → `subtle::ConstantTimeEq`（`ct_eq().into()`；`subtle = "2"` 已在 infrastructure 依赖）。长度不等时先短路返回 false（保持现有行为）。

**测试**：现有 pairing 测试不回归。

### 批次 1 验证

```bash
cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings
pnpm tsc --noEmit   # 前端未被批次1修改，防交叉确认
```

---

## 批次 2：浏览器扩展修复（extensions/chrome/src，firefox 经 symlink 自动生效）

### F1 提示条延迟取密（最小化/延迟解密）

**位置**：`extensions/chrome/src/content.js:981-1007`（checkForAutoFillPrompt）、`:303-445`（showAutoFillPrompt）、`background.js:345-359`（GET_ENTRY 门禁，保持不变）

**设计**：

- `checkForAutoFillPrompt` 单匹配分支：**不再** `sendMessage({type:'GET_ENTRY', id})`；直接用 `entries[0]`（`GET_ENTRIES_FOR_URL` 返回的 EntrySummary，含 title/username，无 password）调用 `showAutoFillPrompt(entrySummary)`。
- `showAutoFillPrompt`：渲染逻辑不变（只用 title/username）；Fill 按钮 click handler 改为 async：先 `chrome.runtime.sendMessage({type:'GET_ENTRY', id: entry.id})` 取 meta+secret（复用 background 既有 URL 门禁），成功后 `autofillLogin(entry.username, entry.password)`；失败（含 vault locked）在提示条内显示错误文案并保留提示条。
- Fill 点击后 secret 用完即弃（闭包内不长期持有；保持现状的局部使用）。
- 锁定态：GET_ENTRY 失败路径给 "Vault is locked — unlock PwdVault and try again" 文案。

**影响**：单匹配页面加载仅走 list 接口（本来就要调），不再取明文；用户点击 Fill 才取 secret。

### F2 授权基准改为 frame URL

**位置**：`extensions/chrome/src/sender-auth.js:22-27`、`background.js:482-490`（保持不动）、`background.js:364,369`（域名归一化统一）

**设计**：

- `sender-auth.js`：`senderUrl: sender.url || sender.tab.url`（`sender.url` 是消息发起 frame 的文档 URL；顶层 frame 下与 `tab.url` 相同，行为兼容；未来开 `all_frames` 时授权自动落在正确 frame）。
- 统一域名归一化：`background.js:364,369` 的 `.replace('www.', '')` 改为与 `sender-auth.js:33` 一致的 `/^www\./` 锚定正则 `.replace(/^www\./, '')`。
- 不改 manifest（不开 all_frames）。

### F3 表单检测消费 + 多密码字段

**位置**：`content.js:41-52`（patterns/detectFormType）、`:54-107`（findLoginForm）、`:233-257`（autofillLogin）、`:1032`（DETECT_FORM 死消息）

**设计**：

- `findLoginForm`：收集表单（或文档）内**全部** password input：
  1. 优先选 `autocomplete="current-password"` 的字段；
  2. 若无，且密码字段数 === 1 → 该字段；
  3. 若无，且密码字段数 > 1（疑似 register/changePassword）→ 选第一个并依赖 formType 门禁（见下）决定是否自动填。
     username 候选逻辑保持（所选 password 字段上方邻域）。
- `detectFormType` 返回值真正消费。**门禁位置（复审二次澄清）**：`autofillLogin` 有三类调用方——①自动提示条 Fill 按钮（:430-433）；②overlay 显式选择条目（selectEntry→:781）；③`AUTOFILL` 消息（:1015-1016，来自 popup 显式填充与右键菜单）。register 门禁**只约束自动路径，放行全部用户显式动作**：
  - **浮动按钮门禁设在 `createFloatingButton` 内部**（:867 已调用 `findLoginForm()`，formType 现成）：`formType === 'register'` 时直接 `return` 不创建。必须放这里——`createFloatingButton` 有三个调用点（checkForAutoFillPrompt :1003、init ready 回调 :1061、MutationObserver 回调 :1079），只改 checkForAutoFillPrompt 挡不住后两处。
  - **提示条门禁设在 `checkForAutoFillPrompt`**（:982 的 `findLoginForm()` 结果含 formType）：register 时不调 `showAutoFillPrompt`。
  - `login`/`changePassword` 的自动提示行为不变；`autofillLogin` 本体不改行为（overlay 选择、popup 填充、右键菜单均直通）。QA 对应项："register 页不弹自动提示条、不显示浮动按钮，但 popup 显式填充仍可用"。
- 删除 `DETECT_FORM` 消息响应（`content.js:1032` 附近）——已核实全扩展无发送方。
- `REGISTER_PATTERNS` 中 `/create/i`、`/join/i` 收紧为仅匹配按钮/表单文本场景有限收紧（如 `/create\s+(an\s+)?account/i`、`/join\s+now/i`），降低误判。

### F4 浮动按钮定位与生命周期

**位置**：`content.js:876-877,928-931`（创建/定位）、`:1073-1083`（MutationObserver）

**设计**：

- 定位：`top = rect.top - 50`（去掉 `window.scrollY`，fixed 用视口坐标），`right: 20px` 不变。
- 新增 `positionFloatingButton()`：重查 `findLoginForm()` → 找到则更新 top；找不到 → `removeFloatingButton()`。
- 新增 `removeFloatingButton()`：`floatingButton?.remove(); floatingButton = null`。
- `window.addEventListener('scroll', throttle(positionFloatingButton, 200), {passive:true})` 与 `resize` 同理（节流用简单时间戳实现，避免引库）。
- MutationObserver 回调（现有 debounce 1076）：`floatingButton` 存在时也调 `positionFloatingButton()`（覆盖 SPA 表单消失场景）。

### F5 生成器滑块 debounce

**位置**：`extensions/chrome/src/popup/popup.js:1155-1161`

**设计**：`lengthSlider.oninput` 仅更新数值显示与 state；`lengthSlider.onchange`（松手）才 `handleGenerate()`。不引库、不加定时器（change 事件语义已足够）。同文件 `:383` 的初始 `handleGenerate()` 不动。

### F6 配对码状态机

**位置**：`popup.js:390-400`（render pairing 分支）、`:840-858`（PAIR_CONFIRM 失败）、`:879-902`（startPairing）、`background.js:24,96-126`（nonce 内存）

**设计**（单变量方案，评审采纳）：

- popup 失败路径：`pairingStarted` **保持 true、不再复位**（:856 删除该复位行）。render pairing 分支的自动 `startPairing()` 守卫 `!pairingStarted`（:397）由此单独成立——失败后仅显示错误 + 既有 "Get New Code" 按钮（`new-code-btn`，:864）显式重发，不新增标志位（避免与 `pairingStarted` 职责重叠、Get New Code 路径漏复位）。
- background nonce 持久化：`pendingPairNonce` 写入/读出 `chrome.storage.session`（仿 token-storage.js 模式新增 pair-nonce 存取函数；SW 被杀后 `pairConfirm` 仍能取到 nonce）。保留内存变量作缓存。
- 测试：仿 `token-storage.test.js` 为 nonce 存取新增 `extensions/chrome/src/pair-nonce-storage.test.js`（写读、缺失返回 null）；`sender-auth.test.js` 补一例"sender.url 存在时优先于 tab.url"（与现有断言兼容已核实）。

### 批次 2 验证

```bash
pnpm test                      # 扩展的 *.test.js 由 vitest 收集（含新增 sender-auth/pair-nonce 用例），确认不回归
node --check extensions/chrome/src/content.js   # 语法级校验（无构建型检查时的底线）
node --check extensions/chrome/src/background.js
node --check extensions/chrome/src/popup/popup.js
node --check extensions/chrome/src/sender-auth.js
bash extensions/chrome/scripts/build.sh        # 打包脚本跑通（路径已核实）
```

手动 QA 清单（写入 PR 描述）：配对失败显示 Get New Code 而非自动换码；单匹配页面加载后 DevTools Network/NM 无 get_entry_secret 调用，点击 Fill 后才出现；register 页不弹自动提示条但 popup 显式填充仍可用；滚动页面浮动按钮跟随；滑块拖动松手才生成。

---

## 批次 3：桌面端修复（src/ + 少量 src-tauri 命令注册；在批次 1 之后串行执行）

### A1 auto-lock 活动上报

**后端**：`src-tauri/src/commands.rs` 新增（注意类型别名：`pub type AppHandle = Arc<AppState>`，commands.rs:16，`.manage()` 注册的是 `Arc<AppState>`——不要用 `State<AppState>`，无法解析到被管理类型）：

```rust
#[tauri::command]
pub fn touch_activity(state: State<'_, AppHandle>) { state.inner().touch_activity(); }
```

`lib.rs` invoke_handler（:268-293）注册 `commands::touch_activity`（批次 1 已动 lib.rs，本批次串行避免冲突）。`AppState::touch_activity` 已存在且 pub（state.rs:52）。

**前端**：`src/api/vault.ts` 加 `touchActivity(): Promise<void>`（invoke 包装）；`src/App.tsx` 新增 `useEffect`：`isUnlocked === true` 时挂 `window` 级 `pointermove`/`pointerdown`/`keydown` 监听（`capture:true, passive:true`），以 `useRef` 时间戳节流（60s 内最多一次）调用 `vaultApi.touchActivity().catch(() => {})`（静默失败合理：锁定后调用会失败）。锁定（isUnlocked 变 false）时移除监听。

**测试**：仿 `src/screens/__tests__/hooksSanity.test.tsx` 模式新增轻量测试（touchActivity mock 被调用/节流生效）；Rust 侧仿现有 command 测试补 touch_activity 一例。

### A3 剪贴板定时器句柄

**位置**：`src/utils/clipboard.ts:16-38`、`extensions/chrome/src/popup/popup.js:190-213`、`extensions/chrome/src/content.js:276-295`

**设计**：三处同改——模块级 `let activeClearTimer = null`；`copyWithTimeout` 开头 `if (activeClearTimer) clearTimeout(activeClearTimer)`；setTimeout 句柄存入。效果：新复制重置 30s 窗口（最后复制起算）。

- `content.js:283` 的明文 `current === text` 比较改为与 popup.js 一致的 SHA-256 digest 比较（`crypto.subtle`，content script 可用），消除 secret 明文闭包驻留。
- 已知限制记录：popup/content 的定时器随文档销毁失效（MV3 固有），桌面端不受影响。

**测试**：`src/utils/__tests__/` 新增 clipboard 测试（fake timers：两次复制同内容，第一次 timer 被 clear，30s 从第二次起算）。popup/content 无自动化框架，语法校验 + 手动 QA。

### A4 lock() try/finally

**位置**：`src/context/AuthContext.tsx:137-141`、`src/screens/VaultScreen.tsx:136-143`

**设计**：`lock()` 改为：

```ts
try {
  await api.lockVault();
} catch (error) {
  console.error("lock failed", error);
} finally {
  dispatch({ type: "RESET" });
  dispatch({ type: "SET_SCREEN", payload: "unlock" });
}
```

后端 lock 幂等（session.rs:186-206），finally 无条件回锁屏安全。`VaultScreen.tsx:138` 改 `onClick={() => { void authActions.lock().catch(() => {}); }}`（void + 兜底 catch 消除 unhandled rejection；grep 其他 lock() 调用点同步处理）。

### A5 快速生成器读默认值

**位置**：`src/screens/EntryScreen.tsx:328-341`

**设计**：生成器 options 初始化对齐 `GeneratorScreen.tsx:14-20` 模式：`useSettings()` 的 `default_length` / `default_include_*` 作为初值（替代硬编码 16/全字符集）。

### A6 删除 passwordStrength color 死代码

**位置**：`src/utils/passwordStrength.ts:73-89`（color 计算）、`:91`（返回值）；`src/utils/__tests__/passwordStrength.test.ts` 若断言 color 则同步删除断言；`src/components/StrengthMeter.test.tsx:5` 的 mock 中的 color 字段一并清理。

### A7 Restore 按钮加固

**位置**：`src/screens/ImportExportScreen.tsx:315`

**设计**：`disabled={restoreConfirmation !== "RESTORE"}` → `disabled={importing || restoreConfirmation !== "RESTORE"}`（一行）。

### A8 AccessibleDialog inert 引用计数 + Escape 栈

**位置**：`src/components/AccessibleDialog.tsx:43-44,56-63,81,86`

**设计**：模块级 `let openCount = 0` 与 `const escapeStack: symbol[] = []`。

- mount：`openCount === 0` 时才对 `#root` 设 inert/aria-hidden；`openCount++`。
- unmount：`openCount--`；`previousAriaHidden` 快照恢复（:87-88）与 inert 移除**仅在 openCount 归零时执行**（叠加场景下内层关闭不得恢复背景可交互）。
- Escape：handler 检查本实例是否为栈顶（最后注册者）才 onClose；unmount 时出栈。
- 新建 `src/components/AccessibleDialog.test.tsx`（仿同目录 `StrengthMeter.test.tsx` 模式；项目无 `__tests__/` 组件测试目录惯例），用例：连续打开两个 → 关内层 → `#root` 仍 inert；Escape 一次只关栈顶。

### 批次 3 验证

```bash
pnpm test && pnpm tsc --noEmit
cd src-tauri && cargo test
```

---

## 执行顺序与交付

1. **批次 1**（后端）→ cargo test/clippy 全绿
2. **批次 3**（桌面前端 + A1 命令注册，依赖批次 1 的 lib.rs 改动先行）→ pnpm test + tsc + cargo test 全绿
3. **批次 2**（扩展，独立目录）→ pnpm test + node --check
4. 每批次独立 commit（conventional commits：fix(backend)/fix(extension)/fix(desktop)）
5. 全部完成后更新 CHANGELOG.md（Unreleased 段落）——由主代理执行，不在 ds-worker 范围

## 回归风险与回滚

- B1 影响"极老版本直升"用户（pre-1.0.5 未迁移库）：错误信息已给迁移指引；发布说明中注明。
- F1/F3 改变扩展自动填充行为（register 页不再提示）：属安全向行为修正，QA 清单覆盖。
- 其余均为局部防御性修复，行为兼容。
