# v1.2.3 实施方案（更新器信任锚 CI 断言）

**日期**：2026-10-07 · **基线**：`main @ 595aa4d`（v1.2.2 + feed）· **目标**：v1.2.3（patch，纯 CI/测试加固，**应用代码零变更**）
**修订**：R2——评审一轮 PASS（P2 CI 覆盖表述修正 + 两 P3 建议采纳：overlay 旁路守卫、endpoints 锚定）
**流程**：标准全流程（方案 → plan-reviewer 至 PASS → ds-worker → 主代理复审 + code-reviewer → 门禁 → 发版）
**背景**：密钥策略评估的 H3 加固项——仓库被攻破时攻击者可改 `tauri.conf.json` 的 updater pubkey + CI secret，给全体用户推"合法验签"的恶意更新（静默换锚）。本项把锚点钉进契约测试：换钥必须**显式**改测试内的钉住值，攻击从"静默"变成 review 里刺眼的一行 diff。

## 1. 设计（单测试函数）

在 `src-tauri/tests/golden_contract.rs`（既有"钉住不变量、变更成对更新"模式的自然扩展）新增：

```rust
/// UPDATER TRUST ANCHOR (v1.2.3, H3 hardening): the updater pubkey baked
/// into tauri.conf.json is the root of trust for every auto-update
/// (docs/UPDATER-KEYS.md). Pinning it here means a key swap cannot land
/// silently — changing the pubkey requires changing this constant in the
/// SAME commit, which is an unmissable review diff.
/// Current key: minisign public key 237BD03CF7C9D12D (decoded from the
/// base64 below; the full string is compared byte-for-byte).
const PINNED_UPDATER_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDIzN0JEMDNDRjdDOUQxMkQKUldRdDBjbjNQTkI3SS9TUzJhZnVMdjJPOFRHcDJ6U3F6NHlOVGRNMGZDamI3dWdOQkFiZWhZTmcK";

#[test]
fn updater_trust_anchor_matches_pinned_key() {
    let conf = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tauri.conf.json"))
        .expect("tauri.conf.json readable next to the crate manifest");
    let value: serde_json::Value = serde_json::from_str(&conf).expect("tauri.conf.json parses");
    let pubkey = value["plugins"]["updater"]["pubkey"]
        .as_str()
        .expect("plugins.updater.pubkey present");
    assert_eq!(
        pubkey, PINNED_UPDATER_PUBKEY,
        "UPDATER TRUST ANCHOR CHANGED. If this is an intentional rotation, update \
         PINNED_UPDATER_PUBKEY in this same commit and follow docs/UPDATER-KEYS.md \
         §3 (transition release, users must manually upgrade once). If not \
         intentional, treat it as a security incident (§4) — do NOT merge."
    );
}
```

要点：

1. **全串逐字节比较**（比只比 key ID 更强——任何字符变化即红）；key ID 写在注释与失败消息中供人类识别；**不新增依赖**（serde_json 已是 tauri-app 依赖，Cargo.toml:45；不做 base64 解码）。
2. `CARGO_MANIFEST_DIR` = src-tauri，conf 在其根——实际执行路径：**本地 / quality-rust（Linux）/ release-gate**（quality-rust-windows 因 WebView2Loader 问题排除 tauri-app crate，quality.yml:100-104 注释——本测试不在 Windows job 跑，强制力不受影响：每次 push/PR 到 main 与每次 tag 均执行）。文件随仓库必在。
3. golden_contract.rs 头部 doc 注释补一句：本文件除 IPC 同步契约外，还钉住更新器信任锚。
4. 失败消息双语不必——英文与文件既有风格一致，内容已完整（轮换流程指引 + 事故处置指引）。
5. **同函数两条顺带断言**（评审 P3 采纳，共 ~9 行零依赖）：a) **overlay 旁路守卫**——断言 manifest 目录不存在 `tauri.macos.conf.json` / `tauri.windows.conf.json` / `tauri.linux.conf.json`（Tauri v2 平台 overlay 可深合并覆盖 plugins.updater，是钉住 base conf 的理论旁路；新增 overlay 文件需先删本守卫，diff 显眼）；b) **endpoints 锚定**——断言 `plugins.updater.endpoints` 等于现值（单元素 `https://raw.githubusercontent.com/chaojimaimi/PwdVault/main/latest.json`，逐项相等，拒绝换/加非 https 端点）。
6. **不动** tauri.conf.json、不动生产代码、不动 docs（PHASE-AU-PLAN 的旧钥留档不改）。

## 2. 约束与验收

- 只动一个文件：`src-tauri/tests/golden_contract.rs`（+~40 行，含注释与两条顺带断言）；测试计数 golden 2→3（workspace 总数 307→308 +1 ignored 不变）。
- 验收：`cd src-tauri && cargo test --workspace` 全绿（+1）；clippy/fmt 0；**反向验证**（工人执行，三径各一次，改后必红、还原必绿）：① conf 的 pubkey 改一字符；② 新增空 `tauri.macos.conf.json`；③ endpoints 换 http URL（实证锚定与守卫有效，防"断言恒真"）。
- ⛔ 禁触：其它一切文件；不 commit、不改版本（bump 属发版阶段）。

## 3. 发版（v1.2.3）

CHANGELOG 条目（Security/Internal：**注明本版无应用代码变更**，产物与 1.2.2 功能等价，仅发布管线加固——按用户指示发版）；bump-version.sh 1.2.3 + `--check`；AGENTS 头部/Session Log/测试表（golden 2→3，workspace 308）；插件对核对；三段式 commit（锚点测试 / 版本+CHANGELOG / docs+plan）→ **先 push main 等 Quality 绿 → tag v1.2.3** → Release 六 job 监控 → feed 1.2.3 确认 → 记忆收尾。

## 4. 风险与回滚

| 风险                                 | 缓解                                                   | 回滚                        |
| ------------------------------------ | ------------------------------------------------------ | --------------------------- |
| 断言恒真（钉住值与 conf 同源复制错） | 反向验证步骤（改 conf 必红）写入验收                   | 单文件 revert               |
| 未来正常轮换被测试"挡住"             | 失败消息即轮换 SOP 指引（同 commit 更新钉住值）        | —                           |
| 纯测试变更发版引起用户无谓更新提示   | CHANGELOG 明示"无应用变更"；用户决定接受（已拍板发版） | 不发版即回滚（只留 commit） |
