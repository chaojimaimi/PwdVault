# v1.2.1 小版本修复实施方案

**日期**：2026-10-06 · **基线**：`main @ 78uba05`（v1.2.0 + feed）· **目标**：v1.2.1（patch）· **修订**：R2（评审 2 P1 + 1 P2 + 2 P3 全部采纳）
**范围**：三个已确认的小项（用户批准），单工人实施，流程按比例缩减（紧凑方案 → plan-reviewer 一轮 → 单工人 → 主代理复审 + code-reviewer → 门禁 → 发版）。

## 1. SEC-L3 残余收口：`error=` 分支补 state 校验

**现状**（baidu_oauth.rs `wait_for_callback` :338-373）：`denied = outcome 是 Err 且 reason 以 DENIED_BY_BAIDU_PREFIX 开头` 即终止——**不校验 state 回显**。伪造探针 `?error=x` 仍可终止 pending 授权（2026-10-04 审计 SEC-L3 的原始示例 URL）。v1.2.0 已修复无 error/伪 state 探针，本项补齐最后一块。

**设计**：

1. `callback_page_for` 现返回 `(CallbackOutcome, String)`，Err 分支丢失了已解析的 `state`——重构为同时返回解析出的 `state: Option<String>`（Ok 与 Err 分支都带），或改返回小结构体（实现时择一，倾向结构体 `ParsedCallback { outcome, state, page }`，文件内私有）。
2. 循环判定改为：`state_ok = parsed.state.as_deref() == Some(expected_state)`；**终止条件 = state_ok && (成功含 code || error= 拒绝)**；其余（无 state / 伪 state / 无 code 无 error）一律 respond 400 + continue。
3. 依据：RFC 6749 §4.1.2.1 规定授权服务器的 error 重定向必须回显 state——百度真实拒绝流程携带 state，校验不会误伤；理论风险（百度不回显 state → 真实拒绝等满 5 分钟超时报 timeout 而非 denied）可接受，写入代码注释。**同步改写两处旧注释**（评审 P3）：`wait_for_callback` doc 注释（:332-334 "terminates the wait immediately" 段）与 `INVALID_CALLBACK_PAGE` 注释（:39-42）——改后语义为 "error= 且 state 回显匹配才终止"。
4. **测试**（tests_baidu_oauth.rs——直接消费 `callback_page_for` 返回值的仅 :79/:84 两处（同一条测试），其余 6 条不经该函数**不要动**；评审 P3）：新增 (a) `error 探针无 state → 丢弃等待，真实回调仍完成`；(b) `error 带有效 state → 立即终止为拒绝`；(c) 既有"伪 state 成功回调被丢弃"不回归。

## 2. release.yml 预发布感知的 feed 门控

**现状**：`create-release` 的 "Commit updater feed to main" 步骤对每个 `v*` tag 无条件回填 feed → 任何测试 tag 都会推给全体用户（更新器只读 feed，不看 GitHub prerelease 标记）。

**设计**：

1. "Commit updater feed to main" 步骤加条件：`if: ${{ !contains(steps.version.outputs.version_clean, '-') }}`——tag 含 `-beta`/`-rc`/`-snapshot` 等预发布后缀时跳过 feed，GitHub Release 照常出产物（测试者手动下载，自动更新不可见）。
2. "Determine prerelease status" 步骤扩展：`version_clean` 含 `-` 也置 `prerelease=true`（GitHub 侧不计入 Latest，与签名缺失的既有逻辑 OR）。
3. 步骤注释写明策略与 bump-version.sh 的限制（脚本只支持三段式 X.Y.Z，预发布版本号需手动同步——见 CHANGELOG 说明文案由 release notes 承担，不动脚本）。

## 3. docs 旧 minisign 公钥标注 DEPRECATED

`docs/PHASE-AU-PLAN.md:35`：代码块内嵌的 base64 公钥与现行 `tauri.conf.json` 公钥（key ID `237BD03CF7C9D12D`，评审核实）不同——系早期已作废密钥（2026-09-18 审计遗留项）。**:36-38 已存在一段作废标注（评审 P2）——不要新增第二条，而是增强既有标注**：加 `⚠️ DEPRECATED` 前缀，并补入两个 key ID（**旧 key ID 由工人现场 `base64 -d` 解码该 blob 得出填入——⛔ 禁止拷贝本方案文本中的任何 ID 字样**，方案初稿曾抄错 ID，以现场解码为准；现行 ID 解码 tauri.conf.json:42 的 pubkey 核对）。代码块内容不动（留档）。

## 约束与验收

- 工人只动四个文件：`baidu_oauth.rs`、`tests_baidu_oauth.rs`、`.github/workflows/release.yml`、`docs/PHASE-AU-PLAN.md`。
- 验收：`cargo test --workspace` 全绿（v1.2.1 基线 305+1 ignored + 新增 ~2）；clippy/fmt 0；YAML `python3 -c "import yaml; yaml.safe_load(...)"` 通过；`grep -n "if:" release.yml` 确认门控落位。
- **版本同步（评审 P1，release-gate 拦不住缺失——必须显式执行）**：发版阶段先 `bash scripts/bump-version.sh 1.2.1 --changelog` 并填写 CHANGELOG 条目（Fixed: SEC-L3 state 校验；Internal: 预发布 tag feed 门控、docs 旧公钥标注增强），`bump-version.sh --check` 确认 10 处版本源 = 1.2.1 后才允许打 tag。
- 发版顺序（吸取 v1.2.0 教训）：commit → **先 push main 等 Quality 绿 → 再打 tag v1.2.1 推送** → 三线 CI 监控（Windows webdav 抖动则 rerun --failed）→ 确认产物与 feed（feed 版本须为 1.2.1）。
