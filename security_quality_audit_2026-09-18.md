# PwdVault 全套代码安全与质量审计报告

**日期**: 2026-09-18 · **版本**: v1.1.7 · **分支**: main
**方式**: 6 个并行专项审计（Rust 后端安全 / 扩展+Native Host 安全 / Rust 质量 / React 前端 / TS-JS 质量 / CI-供应链），全部发现经主会话二次读码复核。

---

## 总体结论

**未发现 Critical 级别问题。** 加密核心、会话/配对设计、扩展纵深防御、CI 供应链管控均明显高于同规模项目平均水平，且测试文化出色（256 Rust + 213 前端全绿，fmt/clippy/tsc 干净，cargo/pnpm audit 0 漏洞，无泄密）。

共确认 **4 个 High**（1 后端并发缺陷 + 3 前端/工程缺陷）、约 10 个 Medium、20+ Low/Info。最重要的单项是 **D8 独占窗口互不排斥** 的并发缺陷，可导致改密码后锁库或静默丢数据，建议尽快修复。

---

## High（已逐一人工复核）

### H1 [后端·并发] 三个 D8 独占窗口互不排斥，可并发打开

- 位置: `src-tauri/crates/application/src/service/sync/engine.rs:66-106`、`src-tauri/crates/application/src/service/security/password.rs:73-95`、`src-tauri/crates/infrastructure/src/database/vault_store.rs:31-39`
- 证据: 每个窗口都是 `exclusive_lock_and_clear()` → `is_unlocked()` 检查 → **不持任何锁**完成工作 → `republish`。`sync_now` 在网络阶段即释放 lease（engine.rs:223-225），窗口本身也不取 lease；`AppState`（state.rs）无窗口专用互斥锁；`VaultStore::write` 用调用方 mac 直接 `refresh_digest_in_txn`，**不校验旧 digest**。
- 交错后果:
  - a) 改密码 reseal 提交后，sync 合并窗口用**旧密钥**封裝的行 + 旧 mac 刷新 digest → 下次用新密码解锁时完整性校验失败（锁库，需 .bak/恢复密钥救回）；
  - b) reseal 用其旧快照后提交 → 远端合并进来的行被静默删除。
- 测试缺口: 现有测试只覆盖「lease 持有者 vs 窗口」与「窗口后的陈旧键写入」，**没有窗口-vs-窗口交错**（tests_engine.rs:574 的测试停在 republish 之后）。
- 修复建议: `AppState` 增加专用 `Mutex<()>`，从 drain 到 republish 全程持有以串行化所有窗口；并让 `VaultStore::write` 先验证当前 digest 再刷新（不匹配则 fail-closed）。

### H2 [前端·UX/安全] 限流锁定提示被覆盖为 "Invalid password"

- 位置: `src/screens/UnlockScreen.tsx:38-40,56` + `src/context/AuthContext.tsx:145-147`
- 证据: `if (!success) setLocalError("Invalid password")`，而 `const error = localError || state.error` 中 localError 优先。5 次失败触发 `VaultError::RateLimited` 后，第 6 次起即使输入正确密码也显示 "Invalid password"。
- 影响: 锁定状态被掩盖，用户盲目重试。
- 修复: 仅在 `state.error === null` 时设置 localError，或对 RateLimited 单独展示。

### H3 [前端·数据] 云同步完成后 vault 列表不刷新

- 位置: `src/components/SyncSettingsSection.tsx:199-210`、`src/screens/VaultScreen.tsx:33-39`
- 证据: `handleSyncNow` 只 `setStatus(await syncNow())` + toast，从不触发 VaultContext 重载；VaultScreen 仅在 `[authState.isUnlocked]` 变化时加载。
- 影响: 拉取的远端新增/更新/软删除在界面上不可见，直到重新锁定或发生 CRUD。
- 修复: syncNow 成功后调用 loadEntries/loadGroups，或让 VaultContext 订阅同步完成事件。

### H4 [前端·工程] 未配置 eslint-plugin-react-hooks / jsx-a11y

- 位置: `eslint.config.js:5-17`、`package.json` devDependencies
- 证据: 仅 `js.configs.recommended` + `tseslint.recommended`；已存在的依赖数组遗漏（`VaultScreen.tsx:39`、`GroupManager.tsx:29`、`SecuritySettingsSection.tsx:99`）无法被自动捕获。
- 修复: 加入两个插件（exhaustive-deps: warn）并在 CI 跑 `pnpm lint`。

---

## Medium

### 后端安全

| #   | 发现                               | 位置                                                 | 要点                                                                                                                              |
| --- | ---------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| M1  | 非 macOS 云同步凭据明文落盘        | `infrastructure/src/secret_file_store.rs:86-96`      | `restrict_permissions` 在 non-unix 是 no-op；`sync-secrets.json` 中 WebDAV 密码/百度 token 为 base64 明文 → Windows 用 DPAPI 包装 |
| M2  | WebDAV 接受 `http://` 明文         | `service/sync/backend.rs:307-311`                    | Basic Auth 可被网络嗅探（容器本身 E2E 加密，但账号密码泄露=整个网盘沦陷）→ 默认强制 https，http 需显式确认                        |
| M3  | 百度 OAuth 固定端口 17777、无 PKCE | `service/sync/baidu_oauth.rs:136`、`constants.rs:85` | 本地进程抢绑可截获授权码（默认构建 AppKey 为空已缓解、绑失败会报错）→ 授权前检测端口占用并在文档标注残余风险                      |

### 后端质量

| #   | 发现                   | 位置                                                                                                           | 要点                                                                             |
| --- | ---------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| M4  | 无窗口-vs-窗口交错测试 | `service/sync/tests_engine.rs:574`                                                                             | H1 对测试套件不可见                                                              |
| M5  | 历史快照轮转逻辑未测   | `service/sync/publish.rs:224-251`                                                                              | 滚动 10 快照保证无回归保护                                                       |
| M6  | 巨型函数               | `dispatcher.rs:26`(244行)、`backup.rs:191`(223)、`lib.rs:151`(190)、`engine.rs:231`(112)、`server.rs:175`(112) | dispatcher 重复 17 次 `serde_json::to_value().expect()`，建议抽 `ok_json` helper |

### 扩展

| #   | 发现                            | 位置                                                                    | 要点                                                                                                                                                |
| --- | ------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| M7  | **Popup「自动填充」无域名校验** | `extensions/chrome/src/popup/popup.js:241-247` → `content.js:1221-1223` | 其他填充路径全部域匹配门控，唯 popup 直发任意条目凭据到当前标签页 → 钓鱼页可被填入无关条目密码。建议复用 `normalizedDomain` 比对，不匹配时警告/阻止 |

### CI / 供应链

| #   | 发现                                       | 位置                                       | 要点                                                                       |
| --- | ------------------------------------------ | ------------------------------------------ | -------------------------------------------------------------------------- |
| M8  | 大多数 CI job 缺 `permissions:` 最小权限块 | `quality.yml` 全部、`release.yml` 多数 job | 继承 repo 默认 token 权限；建议顶层 `permissions: {}` + 按 job 授予        |
| M9  | CodeQL 结果无处呈现（SAST 形同虚设）       | `codeql.yml:32-36`                         | `upload: never` 且注释称「私有仓库」但 repo 已 public → 改 `upload: sarif` |

### TS/JS 质量

| #   | 发现                                              | 位置                                                                   | 要点                                                                                                                                          |
| --- | ------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| M10 | TS `VaultError` 联合类型过时且死代码              | `src/types/index.ts:63` vs `application/src/error.rs:14-34`（13 变体） | 调用方对错误做临时字符串处理                                                                                                                  |
| M11 | **剪贴板 30s 自动清除会静默失效**                 | `src/utils/clipboard.ts:34-45`                                         | WKWebView 失焦时 `readText()` 常被拒 → catch 静默吞掉，机密无限期留在剪贴板。改用 `@tauri-apps/plugin-clipboard-manager` 读写或至少让降级可见 |
| M12 | contextMenus 监听器未处理 rejection + null 解引用 | `extensions/chrome/src/background.js:525-543`                          | vault 锁定/tab.url undefined 时静默失败无反馈                                                                                                 |
| M13 | 测试文件被 tsc 排除                               | `tsconfig.json` exclude                                                | ~40 个测试文件从未类型检查                                                                                                                    |

---

## Low / Info（摘选）

**后端**: recovery key 走 `String` 非 `Zeroizing`（commands.rs:252、wrap.rs:97-111）；`cached_wrap_key()` 返回非 zeroizing 拷贝（session.rs:156-165）；legacy keychain 回退无 OS ACL（仅限未签名构建，已知取舍）；native host 对 `auth_token` 无 charset 校验（server 端已拒 CRLF/重复头兜底）；sync 无反回滚（AEAD 只认证内容不认证新鲜度，LWW+墓碑使实际危害有限）；pair 端点全局限流可被本地进程耗尽（仅骚扰级别）。
**扩展**: 自动填充提示条/角标暴露用户名、条目计数与扩展存在（content.js:500-504，建议 closed shadow root）；注册表单文本启发式可绕过（建议采纳 `autocomplete="new-password"` 硬信号）；Firefox 自定义 ID 配置与 host 校验不一致；NM 1MiB 响应上限贴近 Chrome 上限（大导出可能被丢）。
**前端**: TotpCode 在 setState 更新函数内发副作用（StrictMode 双调，失败会卡 0 并每秒重试）；EntryScreen 747 行 / SecuritySettingsSection 689 行超组件规范；GeneratorScreen 从未加载完的设置快照初始化；GroupManager 挂载时未处理 rejection；AccessibleDialog 对 `initialFocusSelector` 的依赖属潜在隐患；TOTP secret 用明文 `type="text"` 输入框；群组编辑框缺 aria-label、tab 缺 aria-current。
**TS/JS**: popup 内联 fuse 配置与桌面端重复（权重目前一致但会漂移）；`Option<T>` 建模为 `?:` 而线上是 null；`CreateEntryRequest` TS 可选字段在 Rust 端必填；配对失败 `catch { return false }` 吞掉连接类错误；popup toast 计时器竞态；错误分类靠子串匹配脆弱；**两端密码强度算法不一致**（同一密码两套标签/分数）。
**CI/仓库**: `tauri.conf.json` 存在未提交的纯缩进格式化改动（建议提交或还原，避免与下次 bump 混淆）；`.gitignore` 未覆盖 `releases/SHA256SUMS*`；README/AGENTS.md 版本停在 v1.1.6；`crates/domain/Cargo.lock` 多余（workspace 共享根锁）；`generate-latest-json.mjs` 平台映射硬编码 arm64；docs 内早期已作废 minisign 公钥残留未标注。

---

## 正面确认（审计中验证为正确的设计）

- **加密核心**: 全部安全随机走 OsRng（无 thread_rng）；bearer token / verification / pairing 恒时比较；用途绑定 AAD 全覆盖（bio/recovery/sync-cek/container 各异 + 记录级 `table||id||version`）；KDF 参数上下界先校验后分配。
- **HTTP 桥**: 16KB 头/10MB 体上限、POST-only、强制 JSON content-type（抗 no-cors CSRF/DNS rebinding）、拒重复头与 CRLF、有界 worker 池背压、`public_message()` 错误脱敏、SO_REUSEADDR 而非 REUSEPORT。
- **扩展纵深**: 列表返回无密码字段的 Summary（延迟取密）；sender 白名单仅 2 条只读命令；token 存 `storage.session` 并主动清理 legacy local；配对码 OsRng 6 位 + 5 次/30s + 恒时比较 + 单次消费；NM host 命令白名单 + 10MB 帧上限 + 缓冲区 zeroize；`escapeHtml`/`textContent` 全插值点。
- **工程质量**: LWW merge 含 100 组种子性质测试（交换律/幂等/无损并/墓碑复活/指纹决胜）；TOTP 过 RFC 6238 Appendix B 向量；bincode 双读版本兼容有文档有测试；全 Rust 文件 ≤800 行（最大 790）。
- **CI/供应链**: 全部 action SHA 固定；无 `pull_request_target`；签名密钥仅 step env 传递；仓库无泄密（仅公钥材料）；rustls 0.23.45 钉住有效；10 处版本源 + tag 全部一致（`bump-version.sh --check` 通过）；X5 capabilities 范围与真实 DB 路径匹配。

## 验证运行结果

| 检查                                                                    | 结果                                                                                    |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `cargo test --workspace`（src-tauri）                                   | **256 通过 / 0 失败**                                                                   |
| `cargo fmt --all -- --check` / `cargo clippy --workspace --all-targets` | 干净                                                                                    |
| `pnpm tsc --noEmit` / `pnpm test`                                       | 通过 / **213 测试 50 文件全过**                                                         |
| `cargo audit`（后端 + native-host）                                     | **0 漏洞**，10 条 unmaintained 警告（bincode 1.x RUSTSEC-2025-0141 建议列入路线图迁移） |
| `pnpm audit --prod`                                                     | 无已知漏洞                                                                              |
| 泄密扫描 / 版本一致性 / gitleaks                                        | 干净 / 1.1.7 一致 / 配置在位                                                            |

## 修复优先级建议

- **P0**: H1（窗口互斥 + digest 预校验 + 补窗口交错测试）
- **P1**: M7（popup 填充域校验）、H2、H3、M1（Windows 凭据加密）、M2（https-only）
- **P2**: H4、M8、M9、M11（剪贴板降级可见化）、M10/M12/M13
- **P3**: 其余 Low/Info 与重构项

---

# 修复执行记录（2026-09-18，同日完成）

全部按「详细方案 → plan-reviewer 评审（REVISE 即修订复审至 PASS）→ ds-worker 实施 → 验收门」流水线执行，共 5 个批次。

## 执行结果

| 批次 | 范围 | 结果 | 关键产出 |
|------|------|------|----------|
| A（P0-H1+M4/M5） | D8 窗口互斥 + digest 预校验 + 交错测试 | ✅ 265 Rust 全绿（+9） | `exclusive_window` Mutex、`lock_epoch`、`unlock_if` 单临界区、`write_rekey`、窗口-vs-窗口交错测试 ×5 |
| B（P1-M7/H2/H3） | popup 填充域校验 + 限流提示 + 同步刷新 | ✅ 前端 246 全绿（+33） | AUTOFILL 协议补 entryUrl、content 权威门控 fail-closed、AuthContext 不变量、同步后刷新 |
| C（P1-M1/M2） | Windows 凭据 DPAPI + https-only | ✅ 271 Rust 全绿（+6） | dpapi1: 格式向后兼容、io_lock 互斥、open_backend 封堵绕过、CHANGELOG 声明 |
| D（P2-H4/M8-M13） | eslint hooks + CI 权限/CodeQL + 剪贴板插件 + 类型/测试 typecheck + Windows job | ✅ 前端 252、lint 0/0、cargo deny ok | react-hooks 7.1.1、全 workflow permissions:{} 矩阵、upload: always、tauri-plugin-clipboard-manager、quality-rust-windows |
| E（P3 快赢 ×24） | 文档卫生 + 扩展/前端/Rust 小修 | ✅ 24/24 全绿（0 跳过） | 密码强度两端统一、TotpCode 重构、recovery key Zeroizing 化、死代码清理 |

## 最终状态（独立复核）

- `cargo test --workspace`：**271 通过 / 0 失败**（基线 256 → 净增 15 个测试，含 9 个并发交错用例）
- `cargo fmt` / `clippy --workspace --all-targets` / `cargo deny`：全部干净
- `extensions/native-host cargo test`：19 全绿
- `pnpm test`：**237 / 46 files 全绿**（规范覆盖净增 206→237；基线曾含 dist 拷贝重复用例 46 个，已在 vitest exclude 修正）
- `pnpm tsc --noEmit` + 链式测试 typecheck：通过；`pnpm lint`：0 error / 0 warning
- `build.sh`：Chrome/Firefox v1.1.7 dist 再生成 + 全部 packaging verify 通过
- 改动规模：75 个跟踪文件 +4054/−477 行 + 新增文件，全部未提交（`git rm crates/domain/Cargo.lock` 已暂存）

## 实施期新发现（记录，未擅自处理）

1. **passwordStrength 两端评分上限 75 < 第五档阈值 80**：'Very Strong' 档两端皆不可达（本次仅做两端统一，算法改动待定夺）。
2. 前端基线曾把 `extensions/*/dist` 旧拷贝的重复测试计入（vitest exclude 已修正）。

## 遗留（延期清单，见 plan-E「明确延期」节）

dispatcher 244 行拆分、巨型组件/函数分段、background.js 错误分类结构化、NM 响应分页、sync 反回滚、pair 每 caller 限流、锁屏事件化、fuse 索引性能改造等——均为需专项会话的重构项。
