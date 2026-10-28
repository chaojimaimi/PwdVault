# fix_impl_plan_v1.6.3 — 技术债班车：扩展 JS 拆分 + .btn 宽度根治 + 路线图刷新

> 状态: R3 **PASS**（R2 复审仅剩 1×P1 已按评审员给定文本修复——命名空间全名形式 + 非空断言，评审员授权该条快审放行；2×P2 并入）
> 来源: v1.6.0 评审遗留记录 + 用户 2026-10-27 指令（技术债班车，完成后直接发版）
> 范围: extensions/chrome/src/**（+两个 manifest content_scripts）、src/styles/**、约 26 个 tsx 的 className、quality.yml、AGENTS.md §3
> 明确不做: popup.js 拆分（见 §5）、本地 ZCode commit-gate hook 扩展到 .js（用户级基础设施，另批）、内容脚本动态 import（既有否决不变）

---

## 0. 事实基础（2026-10-27 现场核对 + R1 评审实测）

**超帽源文件**（800 帽；dist/ 为构建副本不算）：

| 文件           | 行数 | 加载方式                                                                                                        | 本批处置                                   |
| -------------- | ---- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| content.js     | 2159 | manifest `content_scripts.js` 数组（经典脚本，同 isolated world 共享全局作用域）                                | **拆分**（五分 + 入口，§2 WP1）            |
| background.js  | 1073 | 两端 manifest 均 `type: "module"`；已 import 五个既有模块                                                       | **拆分**（ES module 抽取）                 |
| popup/popup.js | 1692 | popup.html `<script type="module">`；实为单个 1660 行 `class PopupApp`（`this.*` 高内聚，无行为测试仅源码契约） | **本批豁免**（§5），WP3 守卫带显式豁免标记 |

**readFileSync 源码契约测试（共 6 个，全部要过）**：

1. `sender-auth.test.js:667-668` — sender-auth.js ↔ content.js 的 BEGIN/END DOMAIN-MATCH 标记区比对（`replaceAll("export function ", "function ")` 后字节一致；块内注释在标记区内，两侧锁步改不破坏守卫）。
2. `content-is-trusted.test.js:13,76` — isTrusted GUARD 计数 ==8（**跨文件并集语义**）。
3. `content-shadow.test.js:16,24-25,35` — attachShadow==1 / mountShadowHost==6 / style createElement==1（并集）。
4. `content-save-prompt.test.js:13-14` — functionBody 提取（handlePossibleSubmit 等）、`'case "VAULT_LOCKED":'` 500 字符窗口、`let pendingSaveBar` 全文、`password: creds.password` 精确计数==1。
5. `search-parity.test.js:16-21` — regex 提取 popup.js 的 FUSE_SEARCH_OPTIONS（popup 不拆，不受影响）。
6. `background-fill-gate.test.js:17-18,38-40,82,96-97` — background import 行断言（:38-40 绑定 background.js 文本，随簇迁移允许更新 import 文本）、popup/content 读取。

**迁移铁律（R1 评审 P1）**：跨文件并集/精确计数的断言（2/3/4 的计数类）一律改为**按 manifest 数组顺序 join('\n') 后断言**；**禁止**拆分数值、放宽计数或逐文件断言——否则新增 secret 触点不再全局可见，守卫静默瓦解。读取路径指向搬入文件。

**.btn 现状**（R1 评审实测校正）：全仓 **101 处** className 含 btn（26 文件）；`.btn { width:100% }`（components.css:36-49）；`.btn-full { width:100%; margin-top }`（settings.css:70，tsx 10 处、其中 ImportExportScreen 5 处）；`.btn-inline`（components.css:145-147）；scoped 覆盖现状：`.dashboard-rerun`（settings.css:278-282）**只剩 margin-left:auto + 过时注释**；`.trash-header .btn-danger`、`.security-status-row .btn` 规则**已不存在**（按钮已带 .btn-inline，仅剩过时注释 vault.css:367-374、settings.css:164-169）；`.confirm-modal-actions .btn` = components.css:514-516 的 **`flex: 1`（Cancel/Save 50/50 分栏，非宽度压制，保留不动）**；`.group-manage-first` 的 width:auto（vault.css:189）是唯一现存宽度压制。

**构建/打包**：build.sh:24 `cp -R src → dist/src` 整目录（新文件自动进包）；verify_manifest.py:25-26 对 js 数组通用遍历（无单文件硬编码）；web-ext@10.5.0 与 quality.yml:235 一致。

## 1. 目标

1. 全部非测试扩展 .js ≤800 行（popup.js 凭显式豁免标记暂缓），CI 永久守住。
2. `.btn` 宽度反转：默认内容宽、整宽显式 `.btn-block`；清除现存唯一宽度压制与全部过时注释。
3. AGENTS.md §3 路线图反映现实。

## 2. 工作包

### WP1 — content.js + background.js 拆分

**content.js（2159 → 拆 5 + 入口 ~200）**，manifest 数组顺序 = 加载顺序，示例（以实测依赖为准调整顺序，数组完整性同步两个 manifest）：

| 新文件                   | 内容（实测行段）                                                                                                      | 约行数 |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------- | ------ |
| `domain-match.js`        | 逐字块 4-292 **原样搬走**（含标记注释，零字节改动；块内头注释点名 content.js 的表述与 sender-auth.js 侧**锁步**改写） | 292    |
| `content-forms.js`       | 表单检测 + autofill + 剪贴板（297-710）                                                                               | ~414   |
| `content-ui-shadow.js`   | mountShadowHost + SHADOW_CSS（712-1088）                                                                              | ~377   |
| `content-ui-bar.js`      | bar/overlay/toast + 悬浮按钮 + 提示逻辑（1090-1623 与 1638-1669 两段）                                                | ~566   |
| `content-save-prompt.js` | 保存/更新提示捕获（1671-2030）                                                                                        | ~360   |
| `content.js`（入口）     | 命名空间使用方 + 键盘（1624-1636）+ 消息处理（2032-2099）+ init（2101-2157）+ MutationObserver/装配                   | ~200   |

**命名空间四硬约束（R1 评审 P1#6 + R2 评审 P1 钉死形式）**：

1. 拆分文件间的函数与可变状态**只走 `globalThis.PwdVaultContent.<prop>` 全名**引用与挂载定义（本地别名仅限头部幂等初始化行 `globalThis.PwdVaultContent ??= {}`——禁止 `NS.foo = ...` / `NS.foo()` 形式，防契约测试空集通过）；domain-match.js 例外——字节冻结，其顶层声明经共享全局作用域以裸标识符直接引用，与今日单文件 IIFE 的引用方式完全相同，引用零改写。
2. 拆分文件**禁止 `/* global */` 注释**（防 no-undef 静默失效）。domain-match 冻结名**必然**触发 no-undef（后续文件裸引用）——eslint 配置以 `languageOptions.globals` 显式声明冻结名单（7 名：MULTI_LABEL_SUFFIXES / registeredDomain / normalizedDomain / entryMatchMode / exactHost / entryMatchesSenderUrl / entryMatchesPageUrl），不允许注释级豁免。
3. `pnpm lint`（no-undef）列为 WP1 引用完整性验收门。
4. **新增契约测试 `content-namespace.test.js`**（readFileSync 风格与全仓一致）：跨六个 content 文件静态交叉核对——每个 `PwdVaultContent.<prop>` 全名引用必有对应全名定义（refs ⊆ defs），**且必须断言非空**：全名引用计数 ≥8（实测跨段调用下限：autofillLogin×3 / showOverlay×2 / entryMatchesPageUrl / dismissSavePrompt / mountShadowHost 调用方）、domain-match 裸标识符集合非空且与 eslint 冻结名单一致——空集即失败，杜绝 vacuous pass。

**background.js（1073 → 入口 ~300-500）**：ES module 抽取，manifest 不变：

- `background-native.js`：NM 传输层 + **模块级传输状态**（connectionStatus/requestId/apiToken/pendingPairNonce/lastConnectionError，background.js:71-75）。
- `background-commands.js`：逐命令处理器整簇（含 save-prompt 降级标志 verifyUnsupported）。
- background.js 留顶层同步监听注册 + 路由装配（MV3 要求顶层注册，:1072-1073 现状即如此；background-save-prompt.test.js:91 的 `await import("./background.js")` 驱动入口不受影响）。
- **禁止入口重新导出可变绑定**（ESM live-binding 跨文件易错）；background-fill-gate:38-40 的 import 行断言随簇迁移到新文件并允许更新 import 文本（守卫语义不变：strict gate 委托 + 无第三处手写主机名比较）。

**测试路径同步**：6 个契约测试的读取路径/对象更新到位；2、3、4 的计数断言按 join 规则改写；断言语义零放宽。全部 6 测试 + 其余扩展套件绿。

**验收**：非 dist 扩展 .js（除豁免的 popup.js）wc -l ≤800；build.sh 双包成功；`pnpm dlx web-ext@10.5.0 lint --source-dir extensions/firefox/dist --warnings-as-errors` 零 error；`pnpm lint` 零新增 error；扩展全套件绿。

### WP2 — .btn 宽度反转（按 R1 现状核对清单）

1. `components.css`：`.btn` 删 `width: 100%`（注释写明反转决策）；新增 **`.btn-block { width: 100% }`**（纯宽度零副作用；`.btn-full` 原样保留服务既有 10 处）。
2. 101 处站点分类机械扫（以实际 grep 为准）：堆叠表单/主操作按钮追加 `.btn-block`；flex 行内不动。分类表进报告。
3. **现状核对后的清除清单**（R1 评审校正版）：
   - `.group-manage-first` 的 `width: auto` 行（vault.css:189）——行级删除（唯一现存宽度压制）。
   - `.confirm-modal-actions .btn`（components.css:514-516 `flex: 1`）——**保留**（50/50 分栏，非宽度压制）。
   - `.dashboard-rerun`（settings.css:278-282）、vault.css:367-374、settings.css:164-169——清除**过时注释**（规则体已无宽度声明）。
   - `.btn-inline` 精简为 `flex-shrink: 0`（width:auto 已是默认）+ 注释更新；过时注释清单加 components.css:191-192（custom-fields 行）、groups.css:69/115、vault.css:382、settings.css:172/280。
4. 扩展端零改动。

### WP3 — CI 行数守卫

quality.yml quality-extension job 增加一步：`find extensions/chrome/src -name '*.js'`（仅 src——天然排除 dist 与 node_modules；Firefox 经 symlink 共享源不重复计数；测试文件一并受限）逐文件行数 ≤800；**文件头 10 行内含 `LINE-CAP EXEMPTION` 标记的文件跳过，且守卫必须断言带标记文件数恰为 1 且路径为 popup/popup.js**（防未来任意文件自行加标记静默绕过——R2 评审 P2），失败时列出文件名。popup.js 文件头加标记注释：`// LINE-CAP EXEMPTION (v1.6.3): single PopupApp class, split tracked as its own batch — remove when under 800.`

### 路线图刷新（主代理随发版文档做）

AGENTS.md §3：Future 勾掉 **Touch ID / TOTP / 云同步**（Secure notes 保留未做——R1 勘误）；Biometric 拆注（Touch ID 已上线，Windows Hello 待做）；HIBP 标注待隐私决策；补记录项（popup.js 拆分批次、重复条目自动检测、native host 签名、zip allowlist 2027-06-30、本地 commit-gate 扩展）。

## 3. 风险

- **内容脚本共享作用域**：平台稳定行为；风险在引用完整性——三层防护：NS 命名空间约束 + no-undef 门 + 新增 namespace 交叉核对契约测试；T54 真机冒烟兜底。
- **逐字守卫**：join 断言迁移 + 锁步注释是 WP1 最敏感操作；ds-worker 先读全部 6 个守卫实现、每改一步跑一次。
- **.btn 反转爆炸半径**：101 处、jsdom 全盲、直接发版（用户指令）——T54 后置必做；`.btn-block` 纯宽度语义压缩风险面；回归按 v1.6.4 热修复姿态。
- **web-ext lint**：新文件进包即受检，构建后必跑。

## 4. 验收与发版

1. 扩展全测试套件绿（6 守卫 + 全部）；wc -l 合规；双包构建 + web-ext lint + pnpm lint 绿。
2. `pnpm test` CI-true 591+N / 77 文件（N = 新增 content-namespace.test.js 用例数，以实现为准）、`pnpm typecheck` 绿、cargo 套件不变绿（本批零 Rust）。
3. clean worktree 全套门禁（含 build.sh + web-ext lint）。
4. 扩展域 + 前端域评审，P0-P2 清零。
5. 发版机械步骤（主代理）：CHANGELOG 1.6.3 → qa_manual 追加 T54 → AGENTS.md（头部/基线/会话日志/路线图）→ bump-version.sh 1.6.3 + 双锁 --locked 验证 → docs/release/style 提交 → tag v1.6.3 → push → 轮询盯 CI（Release/QG/CodeQL/feed bot）→ 下载 DMG+Chrome zip 到 releases/ 验签。
6. T54 真机清单（发版后）：全屏 .btn sweep（两主题：登录/设置/条目/各弹窗/仪表盘/回收站/分组管理宽度与节奏）、扩展 unpacked 冒烟（填充、保存提示、popup 三功能、锁后行为）、确认弹窗 Cancel/Save 仍 50/50。

## 5. 明确不在本批

- **popup.js 拆分**：单一 1660 行 `class PopupApp`、`this.*` 高内聚、零行为测试——类分解是真重构非机械搬移，独立批次（豁免标记已把债务钉在文件头 + WP3 守卫可见）。
- 本地 commit-gate hook 扩展到 .js：用户级基础设施另批。
- 内容脚本动态 import / 打包器：既有否决不变（指纹面、无构建链）。
- `.btn-full` 与 `.btn-block` 未来合并：可选后续，本批不动既有站点。
