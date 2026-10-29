# fix_impl_plan_v1.7.0 — 解锁页重设计 + 恢复密钥提示 + 弱口令检测增强

状态：R3（R2 复审 REVISE：1×P1 + 1×P2 + 3×P3，全部折叠；评审授权 R3 fast-pass）
日期：2026-10-29
班车内容（用户已确认）：

1. 解锁页重设计 —— 沉浸渐变玻璃底 + 品牌极简表单（高保真稿合并版已获用户定稿），
   覆盖 Setup / Unlock / Recovery 三个认证屏；
2. 恢复密钥状态提示 —— 锁屏底部状态微文案（未启用警示 / 已启用确认）；
3. 弱口令检测增强 —— zxcvbn（Rust/仪表盘）+ 中文语境弱口令语料层（三端共享算法）。

版本：v1.7.0（minor —— 含新特性与检测语义变更）。

---

## 0. 已验证的现状事实（本方案的地基）

- 强度打分现有**三份实现**，靠约定 + 测试钉同步：
  - 桌面 `src/utils/passwordStrength.ts`（getPasswordStrength + getGeneratorStrength；
    StrengthMeter.tsx 消费，Entry/Generator 两屏）；
  - 扩展 `extensions/chrome/src/password-strength.js`（popup.js:5 import、:360/:722/:1553 调用，
    头注释声明与 TS 逐字同步，password-strength.test.js 钉两端一致）；
  - Rust `crates/domain/src/strength.rs`（仪表盘 `score_password`，18 条共享向量 +
    `src/utils/__tests__/passwordStrength.rust-port.test.ts` 钉跨语言一致）。
- 共享启发式为纯字符统计（长度≤30/类别≤30/去重熵≤15；31 条整串精确匹配归零；
  顺序窗 -10×n；3+ 重复 -10×n；单类别 -15）。**用户实测**：Test@12#$、Test@1qaz、
  Admin@123 三例实得 66-68 分（Strong），弱密码线 ≤40 全部漏报；向量表中
  P@ssw0rd123=71 同样漏报。根因：无词典/模式/键盘走位检测。
- 仪表盘 `security_report.rs`：weak=score≤40 / reused=SHA-256 摘要桶≥2 / stale=>365d；
  前端 DashboardScreen.tsx:166 渲染 `${finding.score}/100`。
- zxcvbn crate（docs.rs 已验证，latest 3.1.1）：**无自定义词典 API**，
  唯一入口 `zxcvbn(password, user_inputs)`，user_inputs 按调用构建排名词典 ——
  语料（≤10k 词）逐调用注入不可行。⇒ 架构见 §2。
- 认证三屏共用 `.card`（components.css:8，max-width 420，surface 底）；
  UnlockScreen 已探测 `recoveryEnabled`（recoveryStatus()，静默降级），
  "Forgot password?" 链接仅在启用时渲染。
- 恢复机制（已向用户解释）：v1.1.6 opt-in，256 位一次性密钥，锁屏重置主密码、
  数据保留；未启用时锁屏对"无后路"这一事实只字不提 ⇒ 本次补提示。
- 测试基线：前端 603（78 文件，CI-true，含 symlink 双计）/ Rust 437(+1) / native-host 23。

## 2. 架构决策：分层打分（本班车最重要的决定）

约束：三个运行时各持一份实现（扩展 popup 无法同步调 Rust；zxcvbn-ts 进 popup
体积不可接受 ~700KB 词典；三实现分数级一致在任何 zxcvbn 方案下都不可保证）。

**决定：两能力分家，各落其位。**

| 能力                         | 落点                    | 说明                                                                |
| ---------------------------- | ----------------------- | ------------------------------------------------------------------- |
| **模式熵（zxcvbn）**         | 仅 Rust（domain crate） | l33t/键盘走位/序列/日期/重复的正则级识别 + 熵分；仪表盘权威判定     |
| **语料层（corpus）**         | 三端同算法移植          | 精确/反归一化整串匹配 + 核心词公式命中 → 一票弱；纯查表，三端可钉平 |
| **参数熵（passphrase/PIN）** | TS 端不变               | getGeneratorStrength 参数路径（v1.4.0 设计），zxcvbn 不适用         |

- Rust 弱判定 = `corpus_hit(password) OR zxcvbn_score ≤ 2`；
  语料层与 zxcvbn 各自独立触发弱标记（双保险，也规避自定义词典缺失）。
- 桌面/扩展展示层 = 现启发式 + 语料层（键盘走位罚分并入启发式，见 WP2/3）；
  **展示层不调 IPC**（打字即时反馈，避免异步化 StrengthMeter）。
- **一致性契约降级为诚实版**：TS↔JS 保持分数级逐字同步（现状守卫延续）；
  Rust↔JS 只钉**弱分类平价**（固定分类向量表，见附录 B）——两侧算法不同源，
  分数不承诺相等，弱判定必须一致。rust-port.test.ts 的 18 向量逐分钉死就此退役，
  替换为分类向量表。
- **已知并接受的代价（用户可见）**：个别密码在展示层 meter 与仪表盘可能判定相反
  （两套算法不同源，契约只钉弱分类的核心交集）——本决策的既有结果，非缺陷，
  CHANGELOG 说明。
- 拒绝的替代方案：a) zxcvbn-ts 全端（bundle 爆炸 + 三端仍不对齐）；b) Rust 单引擎
  走 IPC（popup 断网场景/异步化复杂度）；c) 语料塞 user_inputs（逐调用建词典，
  批量扫描不可行）。理由已与用户对齐。

## 3. WP1 — Rust：zxcvbn + 语料层 + 仪表盘语义

文件：

- `Cargo.toml`（workspace + domain）：新增 `zxcvbn = "=3.1.1"`（精确钉版；
  deny.toml/audit 如有新告警按既有流程处理）。
- `crates/domain/src/weak_passwords.txt`：语料主文件（include_str!，契约见附录 A）。
- `crates/domain/src/corpus.rs`（新）：语料层三件套（R1 P1 修正后的算法，
  三端逐算法对齐，实施前先在计划附录层面钉死）——
  `corpus_exact_hit(p)`：原始小写 ∈ 全量语料；
  `corpus_normalized_hit(p)`：归一化后整串 ∈ 全量语料（映射表见附录 B）；
  `core_word_formula_hit(p)`：在**原始小写串**与**归一化串**两个形态中查找核心词
  （附录 B，~70 词）：命中条件 = 匹配位置**左邻为非字母或串首**，且**匹配终点到
  串尾不再出现任何字母**（右界规则：防 "latest" 内嵌 "test" 类误伤），且原始
  密码含 ≥1 数字或符号 → 弱。子串搜索用 indexOf 逐词扫描，三端可逐字对齐。
  **为什么不用"字母段提取"**（R1 原设计）：归一化会把替换字母焊进相邻段
  （password1! → "passwordii"），段提取四条必弱向量命中不了；边界搜索 +
  元音位映射（1/! 不映射，见附录 B）联合可放行全部钉死向量（含
  P@ssw0rd123 → 归一化 "password123" 右界纯数字 ✓）。单元测试覆盖三函数边界
  （空串/纯数字/中文输入/双形态命中样本/误伤哨兵）。
- `crates/domain/src/strength.rs`：
  - `score_password`、SHARED_VECTORS 及对应测试**删除**（生产消费方已核实仅
    security_report 一处；`passwordStrength.rust-port.test.ts` 一并退役；
    Rust 基线数在 AGENTS.md 重钉）；
  - 新增 `classify_password(p) -> PasswordVerdict { Weak, Fair, Strong }`：
    `p 为空 → Weak`（存量行为：空密码行进弱列表，security_report.rs:302-310
    现有测试钉死，保持不变——注意 zxcvbn crate 对空串返回 Err，必须显式短路）；
    `语料三查任一命中 → Weak`；否则 zxcvbn(p, &[]) score ≤2 → Weak；
    =3 → Fair；=4 → Strong。
- `security_report.rs`：`WEAK_SCORE_THRESHOLD` 删除，改为 `WeakPasswordFinding.score`
  携带 zxcvbn 0-4（wire 字段名不变，**语义变更**——发布说明必须写）；
  `aggregate_report` 改用 classify；弱判定单测改写。
- `DashboardScreen.tsx`（归 WP2 改渲染，wire 语义对齐 WP1）：弱条目渲染
  `${score}/100` → zxcvbn 档位标签（0→"Very Weak"，1/2→"Weak"，3→"Fair"，
  4→"Strong"，与附录 B 档位映射一致——R2 P3 统一，不发明 "Weak+" 词条；
  统一映射表放 types/index.ts 注释 + utils 函数，避免散落）。
- 测试：新增 classify 向量表（附录 B 分类集，逐条断言）；**冻结前置实测
  （第 0 步，R2 P2 修正）**：动表前先对全部 17 向量跑 zxcvbn 3.1.1 取实分——
  哨兵实测 ≤2 → **换哨兵**（三词组合或更长随机变体，同步加入附录 A 语料排除集
  并在完成报告中汇报终表），禁止放松谓词或静默改表；zxcvbn ≤2 边界向量
  （abcdefgh、1234567890、ABCDEFGH! 等）；语料命中强制弱（zxcvbn 给 4 分的
  长语料串也必须 Weak）；既有 437 Rust 基线不回退。

风险：zxcvbn 首编 +30-60s（可接受）；二进制 +1-2MB（桌面可接受）；
**native-host 已验证不受影响**（评审核实：native-host/Cargo.toml 仅依赖
serde/serde_json，且不在 workspace 成员内）。

## 4. WP2 — 桌面前端：语料层 + 启发式升级

文件：

- `src/utils/weakCorpus.ts`（新）：`export const WEAK_PASSWORDS: Set<string>`
  （全量语料）+ `CORE_WORDS: Set<string>`（核心词集），内容为附录 A 语料文件的
  同步拷贝（guard 钉同步，见 WP3）。
- `passwordStrength.ts`：
  - COMMON_PASSWORDS(31) 删除，改语料层三查（exact/normalized/core-formula，
    算法与 Rust corpus.rs 逐算法对齐）；命中 → `score = min(score, 10)`（Very Weak 档）；
  - 键盘走位表（附录 B，30 条 4 字符窗口——计划原误计 28，WP2 按枚举 30 条
    落地：16 行 + 8 列 + 6 数字列）：每个不同命中 **-15**（R2 P1 修正：
    -10 时 Test@1qaz 68-20=48 压不进弱档；-15 后 68-30=38 ✓，评审已全局推演
    无副作用）。顺序窗罚分逻辑保留；
  - `getGeneratorStrength` 参数路径**不动**。
- `src/utils/__tests__/passwordStrength.rust-port.test.ts`：退役，替换为
  `passwordClassification.test.ts`（附录 B 分类集，TS 侧逐条断言 Weak/非 Weak）。
- `types/index.ts`：SecurityReportWeakEntry.score 与 SecurityReport.weak 两处注释
  更新（0-4 语义；:330 注释写死 "scoring ≤ 40" 一并改）+ 档位映射函数。
- `DashboardScreen.tsx`：weak 行渲染档位标签（映射函数，替换 `${score}/100`）；
  :162 提示文案 "Score 40 or below on the strength meter." 同步改写（语义变更后
  原句为假话）。
- 测试：Test@12#$ / Test@1qaz / Admin@123 / P@ssw0rd123 / 1qaz2wsx / woaini520 /
  qq123456 / a123456 全部落 ≤40（红线→绿线）；随机强串不误伤
  （kX9$mP2!vL5#nQ8@wR4&jF7^、correcthorsebatterystaple、D7g!kLm9@pQ2 等）。
  既有用例期望随语料化调整：passwordStrength.test.ts 的 `password→0` 改为
  钳位 10、modes 用例的 `qwerty123` 同理（评审指出的期望值冲突）。

## 5. WP3 — 扩展：JS 语料层 + 同步守卫

文件：

- `extensions/chrome/src/weak-corpus.js`（新）：与 WP2 相同内容的 JS 模块。
- `password-strength.js`：与 WP2 完全同算法移植（头注释同步声明改为
  "与 passwordStrength.ts 逐字同步"）。
- `password-strength.test.js`：两端一致断言集扩充（分类向量集 + 随机强串）。
- **承载方式（R1 P0 修复）**：全量语料以**空格分隔的密集字符串块**承载
  （TS/JS 各一个长字符串常量，运行时 split 成 Set；Rust 侧保持一行一词的 txt
  include_str!）——一词一行 ≈10k 行必击穿 quality.yml 的 JS 800 行守卫
  （find extensions/chrome/src + awk NR，唯一豁免被钉死在 popup.js）与 TS
  800 行惯例；语料条目禁止含空白字符（附录 A 过滤规则保证 split 安全）。
- **同步守卫（新增）**：`corpus-sync.test.js` readFileSync 读三份语料
  （domain txt 剥 `#` 注释行 / weakCorpus.ts / weak-corpus.js）+ 核心词集三份，
  断言**解析后集合相等**（各自解析为 Set 后比对，非逐行比对——密集串承载的
  直接后果；守卫正则引号无关 —— v1.4.1 教训）。
- 扩展 zip 体积预算：+~90-130KB（10k 词密集串 + 核心词 + 走位表；R1 估算 25KB
  偏低，评审修正），可接受，CHANGELOG 记录。

## 6. WP4 — 认证屏重设计 + 恢复密钥提示

已定稿视觉（用户选定的合并版高保真稿）：整窗径向渐变光晕（navy→teal）+
玻璃拟态卡片（backdrop-blur）+ 品牌极简表单（渐变盾徽 60px、标题、
"Local-first. Your passwords stay yours."、大写小标签、锁图标 + 显隐眼、
渐变 Unlock、or 分隔、soft Touch ID、Forgot 链接）+ 底部状态微文案。

文件：

- `src/styles/auth.css`（新，App.tsx 在 components.css 之后引入）：
  `.auth-*` 作用域类（**不触碰全局 .btn 语义** —— v1.6.3 反转教训）；
  渐变底/玻璃卡/徽章/字段/按钮/分隔/提示区；两主题走既有 token +
  新增 `--auth-glass`/`--auth-glass-border`/`--auth-field`（alpha 值按主题覆盖）；
  入场动画尊重 prefers-reduced-motion；focus-visible 沿用全局。
- `src/components/PasswordField.tsx`（新）：label + 锁图标 + input + 显隐眼
  （aria-label 切换 Show/Hide password）；Setup/Unlock/Recovery 复用。
- `UnlockScreen.tsx`：换壳（badge/标题/标语/PasswordField/渐变 Unlock/or 分隔/
  Touch ID soft 按钮）；底部提示区用已有 `recoveryEnabled` 探测——
  未启用 → `shield-alert` 警示色 + "No recovery key set up — enable one in
  Settings → Security before you need it."；已启用 → 卡内 Forgot 链接 +
  `shield-check` "Recovery key enabled"（提示为纯信息不可点击——锁屏无设置路由）；
  错误通道 / 限流文案 / loading 态全部保留。
- `SetupScreen.tsx` / `RecoveryScreen.tsx`：同壳换装（表单内容不变；
  Setup 保留强度条；Recovery 的密钥输入框为 type=text 不加眼）。
- 测试：UnlockScreen（提示两态、眼切换、错误路径、Touch ID 分支）、
  SetupScreen/RecoveryScreen 冒烟、PasswordField 单测；既有相关用例随迁。

QA（jsdom 盲区，真机项 T55）：两主题玻璃通透感/渐变/光晕、入场动画、
锁屏提示两态、Dashboard 用 Test@1qaz 等实测弱报、扩展 popup 生成器、
全屏按钮宽度回归（v1.6.3 T54 未清项一并复测）。

## 7. 实施顺序与审查

- Wave 1（并行）：WP1（Rust）+ WP4（认证屏）——文件零交集。
- Wave 2：WP2（TS，依赖 WP1 定稿的档位映射与分类向量终表）→ WP3（JS，
  与 WP2 逐字同步 + 守卫）。
- 双域审查：rust-reviewer（WP1）+ react-reviewer（WP2/3/4）；
  扩展文件归 react-reviewer 附带（与 v1.6.3 分工一致）。
- 文档（主代理）：DESIGN.md（认证屏沉浸方向条款 + 新 token）、
  AGENTS.md（session log、基线数、roadmap 勾选）、CHANGELOG、qa_manual T55。
- 发布 checklist（主代理，gates 全绿后）：bump-version.sh（10 文件，含
  native-host/Cargo.toml）→ cargo metadata 刷新 + `--locked` 验锁 →
  cargo deny/audit 预检（新依赖 zxcvbn 及其传递依赖）→ clean-worktree 全量门禁
  （native-host sidecar 预备步骤）→ tag v1.7.0 + push → 轮询盯 CI
  （gh watch 网络抖动改轮询，记忆 gotcha #10）。

## 8. 风险清单

| 风险                             | 缓解                                                                                                                 |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| zxcvbn 语料不可注入（已证实）    | 双层判定设计（§2），不依赖自定义词典                                                                                 |
| 三端语料漂移                     | corpus-sync.test.js 守卫 + 分类向量集三端钉                                                                          |
| 仪表盘 score 语义变更破坏消费方  | wire 字段名不变；消费点已全查（DashboardScreen :162/:166、types :330；扩展非 wire 消费方——评审核实）；CHANGELOG 高亮 |
| backdrop-filter 在 wry 的性能    | T55 真机验收；卡顿则降级实底卡（auth.css 预留注释开关）                                                              |
| 核心词公式误伤                   | 匹配为左界 + 右界的边界搜索（非子串包含，§3）；核心词集人工 curated ~70 词（附录 B 落清单）；分类向量集含误伤哨兵    |
| 基线数变动                       | 完成后在 AGENTS.md 重钉（前端/Rust 双侧）                                                                            |
| 弱判定收紧导致用户存量密码被标弱 | 预期行为（本班车目的），CHANGELOG 说明 + 仪表盘文案已引导"open an entry to fix it"                                   |

## 附录 A — 语料契约

- 主源（R1 P1 修正）：SecLists `Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt`
  （MIT；原 10-million-password-list-\* 系列已被上游删除——commit 4ff3ff8，内容
  与 xato 重复；取数日期 2026-10-29，PR 记录取数 commit）。过滤：仅 ASCII、
  长度 ≥4、小写去重、**剔除含空白字符的条目**（密集串 split 承载的前提）、
  **剔除以 `#` 开头的条目**（R2 P3：防同步守卫剥注释时连条目剥掉）；
  另加**中文语境补充集**（人工 curated ~100 条：woaini、woaini520、1qaz2wsx、
  qq123456、a123456、5201314、woaini1314、qq520woaini、woaixuemei 等——公共
  泄露库时代的经典）。总量 ≤10,100 条。
- 构建后校验（R1 P2 折叠）：附录 B 全部误伤哨兵 **∉ 最终语料**（含其小写与
  归一化形态），违者语料构建失败——防上游词表恰好收录哨兵整串推翻断言。
- 格式：Rust txt 一行一词 + `#` 注释头（来源与许可声明）；TS/JS 密集字符串块
  （§5 承载方式）。同步守卫解析后比对。
- 三份拷贝 + 同步守卫（WP3）；PR 中报告最终条数与文件大小。

## 附录 B — 钉死的分类向量集与常量（实施时 red→green）

### 判定谓词（R1 P1 修正：三端各钉各的，不再含混）

- **必弱谓词**：TS/JS 端 `getPasswordStrength(p).score ≤ 40`；Rust 端
  `classify_password(p) == Weak`。
- **非弱谓词**：TS/JS 端断言**语料三查与走位表均不命中**（新增惩罚不生效；
  既有启发式自身的 label 不在断言范围——correcthorsebatterystaple 在现启发式下
  label=Weak 属现状，本次不动，§2 已声明 meter↔仪表盘可能相反）；Rust 端断言
  `classify_password(p) != Weak`。

### 必弱向量（括号内为预期命中机制，实施时逐条验证）

`password1!`（核心词 password + 符号）｜`admin123`（corpus + 核心词 admin）｜
`Admin@123`（原始形态边界命中 admin）｜`Test@12#$`（原始形态边界命中 test）｜
`Test@1qaz`（走位 qaz、1qaz 双命中 × -15；右界规则放行不了边界命中 test——
qaz 在其后，R2 P1 修正标注）｜`P@ssw0rd123`（**corpus 精确命中**——著名 l33t
形态 `p@ssw0rd123` 已作为 exact 锚点入语料；原"归一化 password123"标注因
`3→e` 焊接不成立（实归一化为 password12e，右界拒绝），WP1 实测修正，
见语料文件 famous-forms 注释块）｜`1qaz2wsx`（走位 1qaz/2wsx）｜`woaini520`（corpus 中文集）｜
`qq123456`（corpus）｜`a123456`（corpus）｜`sunshine123`（核心词）｜
`qwerty!@#`（核心词）

### 非弱哨兵（误伤防线）

`kX9$mP2!vL5#nQ8@wR4&jF7^`｜`correcthorsebatterystaple`｜`D7g!kLm9@pQ2`｜
`latest#Rocket9`（latest ∉ 核心词集；内嵌 test 被左界规则放行）｜
`7hE-qu1ck-b0wnes`（quick/bownes 不命中）

### 核心词集（curated ~70 词，R1 P1 修正：落清单）

password, passwd, pass, admin, root, user, guest, test, login, qwerty, welcome,
hello, love, sunshine, princess, dragon, monkey, master, superman, batman,
football, baseball, basketball, soccer, hockey, shadow, michael, jordan,
charlie, andrew, daniel, jessica, pepper, hunter, ranger, harley, buster,
killer, george, freedom, whatever, ninja, money, happy, secret, access, flower,
summer, winter, angel, magic, phoenix, knight, warrior, samsung, apple, google,
computer, internet, service, starwars, letmein, trustno1, azerty, iloveyou,
family, online，中文语境：woaini, wodeaini, mima, wodemima, jiayou。
**必须排除**（哨兵防线）：latest, rocket, quick, brown, correct, horse, battery,
staple, troubador。最终清单随向量表同 commit 变更（red→green 钉死）。

### 冻结前置实测（实施第 0 步，R2 P2 修正）

动表前先对全部 17 向量跑 zxcvbn 3.1.1 取实分再冻结：哨兵实测 ≤2 → 换哨兵
（三词组合或更长随机变体，同步加入附录 A 排除集并汇报终表）；必弱向量若
zxcvbn 实测 >2，由语料层兜底弱判定（双保险设计本就允许），照常冻结。

### 归一化映射（三端一致；R1 折叠时二次修正）

`@→a 4→a 0→o 3→e $→s 5→s 7→t +→t`。
**1 与 ! 不映射**：数字→字母映射会把密码后缀数字焊成字母
（P@ssw0rd123 会变成 "passwordi23" 继续漏报——R2 P3 修正笔误）；元音位映射 +
边界搜索的右界规则（匹配后到串尾无字母）联合放行全部必弱向量。走位检测在
**原始串**上进行，不依赖归一化（"1qaz" 原样在表内）。
**实施期警示（WP1 实测发现的映射固有限制）**：`3→e` 同样会焊接尾数字
（password123 → password12e）——依赖归一化整串命中的形态不得含与映射冲突的
尾缀；此类著名形态改走语料 exact 锚点（见语料文件 famous-forms 块）。TS/JS
移植时逐字对齐映射表，不要"顺手"增删映射项。

### 键盘走位表（三端同一常量，原始串子串匹配，每命中 **-15**）

行：qwer, wert, erty, rtyu, tyui, yuio, uiop, asdf, sdfg, dfgh, fghj, ghjk,
hjkl, zxcv, xcvb, cvbn；列：qaz, wsx, edc, rfv, tgb, yhn, ujm, ikl；
数字列：1qaz, 2wsx, 3edc, 4rfv, 5tgb, 6yhn。（30 条：16 行 + 8 列 + 6 数字列；
计划原笔误计 28，WP2 实施按枚举落地）

### Rust 档位映射（wire score 0-4 → 展示）

0→Very Weak，1→Weak，2→Weak，3→Fair，4→Strong；弱判定 = 空串 ∪ 语料命中 ∪
zxcvbn≤2。
