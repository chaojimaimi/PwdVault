# v1.3.0 实施方案（bincode 1 → 2 换芯迁移，路线 A）

**日期**：2026-10-07 · **基线**：`main @ b9185a2`（v1.2.4 + feed）· **目标**：v1.3.0（minor：依赖与 codec 层变更，**磁盘格式字节级不变、用户零感知**）
**修订**：R2——评审 P0（advisory 为 crate 级、ignore 保留+动机重构）+ P1（调用面 20 文件重建、约束放宽）+ P2×2（fixture 生成前置、golden 矩阵补 sync/verification/header 四型）+ P3×2（allowlist 同步、Settings 镜像如实）全部采纳
**流程**：标准全流程（方案 → plan-reviewer 至 PASS → ds-worker → 主代理复审 + code-reviewer → 门禁 → 发版）
**上游**：SEC-L6 / deny.toml RUSTSEC-2025-0141 备案
**动机修正（评审 P0 核正）**：RUSTSEC-2025-0141 是 **crate 级**公告（"Bincode is unmaintained"，无版本豁免、无 patched 版本）——bincode 2.x 同样命中，**换芯不清除 advisory，deny ignore 保留**。本迁移的真实价值重述为：① 落到 bincode **2.0.1 终版 API**（1.x 双重死亡：unmaintained 且 API 停在 2019 年代；2.x 是该 crate 冻结前的最终形态）；② 建立 **golden 字节护栏 + bc_serialize/bc_deserialize 单一替换缝**——正是未来迁 postcard（真正清除 advisory 的终局路线）的前置基建，届时只改缝内一处；③ ignore 理由如实改写并设重估触发器。

## 0. P0 前置实验：已完成，结论为 GO

主代理在 /tmp/bincode-compat（独立 crate，bincode 1.3.3 与 **bincode 2.0.1** 并存）对 PwdVault 全部 bincode 类型形状做了**四向字节级验证**（b1 编码 = b2 编码；b1 字节可被 b2 解；b2 字节可被 b1 解；解回等值）：

- 类型样本：EncryptedData ×3（空/12B+4KB/0xFF×257）、PasswordEntry ×2（镜像真实字段：String/Option<String>/Vec<u8>/Option<Vec<u8>>/Vec<String>/i64/Option<i64>/Option<String>）、Group ×2（含 tombstone Option<i64>）、Settings ×2（u64/usize/bool×6 全域——usize 在 fixint 下与 u64 同线，镜像用 u8 属实验笔误、字节无风险，如实记录）、serde 默认表示枚举 ×3、基元 7 项（i64::MIN/u64::MAX/空串/UTF-8 多字节/Option None|Some/64KB Vec）。
- **结果 19/19 PASS**——`bincode2::serde::encode_to_vec(v, config::legacy())` 与 `bincode1::serialize(v)` 字节相同，双向解码互通。
- **已知边界（写入迁移注释）**：serde 内部标签枚举（`#[serde(tag=...)]`）bincode 1 本身即不支持（实验实证报错）——仓库 bincode 路径当前**无枚举**；给 bincode 路径类型新增 tagged enum 在两个版本下都不可行，此约束与迁移无关但一并记录防未来踩坑。
- 实验代码丢弃（/tmp），其结论以**常驻 golden 字节测试**的形式固化进仓库（§2.3）。

## 1. 调用面清单（R2 终版：13 生产 + 7 测试/bench = 20 文件，77 处调用 + 4 处注释提及）

**生产（14 文件）**：infrastructure 的 database/entry_codec.rs（9）、database/group_codec.rs（8）、database/mod.rs（8，含 Settings 双读与 verification 序列化）、database/vault_store.rs（1）、vault_header.rs（4）；application 的 service/entries.rs（8）、service/backup.rs（4）、service/totp.rs（1）、service/vault.rs（4，migrate 路径）、service/security/shared.rs（6，改密重封）、service/sync/state_io.rs（3）、service/sync/mod.rs（3）、service/sync/container.rs（2，LWW 指纹）。
**测试/bench（7 文件，`--all-targets` 编译必须同步换）**：fixtures.rs（5）、backup_tests.rs（5）、security/tests.rs（4）、vault_tests.rs（3）、sync/tests_window.rs（1）、native_messaging/tests.rs（1）、benches/vault_bench.rs（1）。
**依赖声明三处**：crates/application/Cargo.toml:20、crates/infrastructure/Cargo.toml:19（均 dependencies）、src-tauri/Cargo.toml:61（**dev-dependencies**）。工人以 `grep -rn 'bincode::' src-tauri/ --include='*.rs'` 终验清零——**4 处注释提及（database/mod.rs:23/:202、entries.rs:102、fixtures.rs:161）一并改写为 bc_* 术语后再验**（mod.rs:202 的注释承担 size 检查纪律说明，改写勿删）。

## 2. 实施设计

### 2.1 依赖替换

三处 Cargo.toml：`bincode = "1"` → `bincode = "2.0"` + `features = ["serde"]`（serde 桥必须；确认无 default 不需要的 feature）。`cargo update` 后 Cargo.lock 中 **bincode 1.3.3 条目应消失**（除非被传递依赖拉回——`cargo tree -i bincode@1.3.3` 验证为空）。

### 2.2 Codec 帮助层（集中替换点，防散弹枪）

在 **infrastructure 的 crypto/cipher.rs（或 database 模块合适位置）新增一对薄帮助函数**并全仓替换调用点：

```rust
/// bincode 2 serde bridge with the bincode-1-compatible "legacy" config —
/// byte-identical to what bincode 1.x produced (verified by golden tests,
/// v1.3.0 migration). All on-disk rows/blobs go through these two so the
/// swap site stays single.
pub fn bc_serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
}
pub fn bc_deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, bincode::error::DecodeError> {
    bincode::serde::decode_from_slice(bytes, bincode::config::legacy()).map(|(v, _)| v)
}
```

§1 全部调用点机械替换为 `bc_serialize` / `bc_deserialize`（错误映射：现有代码多为 `.map_err(|e| ... e.to_string())`——bincode2 错误类型同样实现 Display，映射层不变）。帮助函数放置 crate 由工人按依赖方向定（application 已依赖 infrastructure——放 infrastructure，application 直接用；src/ 适配层亦然）。

### 2.3 Golden 字节测试固化（防未来 legacy 语义漂移；R2：生成时序前置）

**实施顺序强制**：step 1 = 在**换依赖前**的当前 main 上，用 bincode 1.3.3 对样本矩阵生成 fixture 字节串并落盘到测试文件（此时 1.x 仍在树上，DoD#1 的 cargo-tree 清零之后不可能再生成）；step 2 = 才动三处 Cargo.toml。

新增 `infrastructure/src/database/bincode_golden.rs`（六型：PasswordEntry/Group/Settings/EncryptedData/VerificationData/VaultHeader）；**SyncEntry/SyncGroup 的 golden 测试放 application crate**（container.rs 指纹函数近旁测试模块——依赖方向 application→infrastructure，infrastructure 引不到这两型；放指纹旁也与 LWW 跨版本钉扎的理由最贴题）：**硬编码 bincode 1.3.3 实际产出的字节串**（工人用现仓库构建生成，勿手写）作为 fixture——覆盖 EncryptedData / PasswordEntry / Group / Settings / **SyncEntry / SyncGroup（container.rs LWW tiebreak 指纹依赖 bincode 字节——跨版本设备互连时指纹漂移会导致 tiebreak 不一致，必须钉扎）/ VerificationData（解锁关键路径）/ VaultHeader** 各 ≥2 样本（沿用实验矩阵 + 补四型）；断言 `bc_serialize` 逐字节复现 fixture 且 `bc_deserialize(fixture)` 解回等值。测试头注释写明：fixture 字节来自 bincode 1.3.3（升级 bincode 2 若致红即 legacy 语义漂移，必须在同 commit 显式评估磁盘兼容性）。

### 2.4 deny.toml 与 allowlist 收尾（R2 修订：ignore 保留）

- deny.toml 的 RUSTSEC-2025-0141 ignore **保留**，注释与理由改写："crate 全系冻结（RUSTSEC-2025-0141 覆盖 1.x 与 2.x，无 patched 版本）；v1.3.0 已落 bincode 2.0.1 终版 API 并建立 golden 字节护栏与单一序列化缝（bc_serialize/bc_deserialize），未来迁 postcard 只改缝内。重估触发器：bincode 出现实际 CVE，或下次格式级开发；例行复审 2027-10。"
- `docs/SECURITY-ADVISORY-ALLOWLIST.md` 同步该条目的理由/复审日期行。
- `cargo audit -n` 复核：lock 中 bincode **1.3.3 版本条目消失**（crate 级 INFO 仍会指向 2.0.1——属预期，由 deny ignore 覆盖，勿误判）；剩余 informational（fxhash/proc-macro-error/unic-* 等）**不动**，各自独立。
- CHANGELOG 归 **Changed**（非 Security——不构成 advisory 清除），注明"磁盘格式字节级不变，无需用户动作"。

## 3. 约束与验收（DoD）

- **只动**：三处 Cargo.toml + Cargo.lock、§1 全部 20 个调用点文件（**含测试与 bench**）、新增帮助函数与 golden 测试文件、deny.toml、docs/SECURITY-ADVISORY-ALLOWLIST.md。
- **禁触**：任何类型定义（零 serde derive 变化）、JSON 路径（backup/NM/sync 容器）、扩展、前端、manifest、workflows。
- **DoD**：
  1. `cargo tree -i bincode@1.3.3` 输出空（1.x 彻底离树）；
  2. `cargo test --workspace` 全绿（310+1 基线 + golden 新增 ~16（八型 ×2 样本，分置两 crate）；
  3. clippy/fmt 0；tsc×3/eslint/vitest 基线不变（前端零改动照跑防波及）；
  4. `cargo deny check advisories` 绿（ignore 条目保留、理由已更新——**不是**删除后绿）；
  5. **真实金库冒烟**（主代理复审阶段）：用本地测试金库（含 v1.0.5 时代 legacy 行 + v1.2.0 密封 sync 行的夹具金库，或 fixtures.rs 造一个）解锁→读→写→重读→改密→再读，全链路无错（工人以集成测试形式交付：`legacy fixtures 全链路 round-trip` 测试）；
  6. golden 字节测试在（临时降级 bincode2 小版本的模拟下）——可选项，若成本低则做"future drift 演练"：临时改 fixture 一个字节必红（防恒真）。

## 4. 风险与回滚

| 风险                                      | 缓解                                                                                                         | 回滚                                            |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------- |
| bincode2 legacy 与 1.x 存在未覆盖形状差异 | P0 实验 19/19 + golden 常驻 + 真实夹具全链路测试；仓库 bincode 路径类型全为 struct（无枚举/无 tagged serde） | 依赖与调用点集中 revert（帮助函数使替换点单一） |
| bincode 2.0.x 未来升级改 legacy 语义      | golden 字节测试即护栏（红=漂移警报）                                                                         | 钉 2.0.x                                        |
| 传递依赖把 bincode1 拉回                  | DoD #1 cargo tree 断言                                                                                       | 加 deny ban 或排除                              |
| 帮助函数位置造成依赖方向问题              | 放 infrastructure（application 已依赖它）                                                                    | —                                               |

## 5. 发版（v1.3.0）

CHANGELOG（Changed：序列化层换 bincode 2.0.1 终版（legacy 配置，字节级等价经 golden 测试钉扎），磁盘格式与产物行为零变化，无需用户动作；说明 advisory 为 crate 级、ignore 保留并附重估触发器）→ bump 1.3.0 → AGENTS（依赖备注/Session Log/测试表）→ 插件对核对 → commit（迁移 + 版本 + docs 三段式，marker 纪律）→ **main 绿后 tag v1.3.0** → Release 六 job 监控 → feed 确认 → 记忆（bincode 项状态更新：已落终版 API + 护栏，advisory 因 crate 级性质保留，postcard 终局路线与触发器已记录）。
