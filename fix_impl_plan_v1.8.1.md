# v1.8.1 修复计划 — Touch ID 取消误报错误横幅（紧凑 patch）

## 0. 背景与根因（真机 QA 反馈，已由主代理代码级钉死）

v1.8.0 锁屏自动弹指上线后，用户取消指纹对话框会在解锁页看到红色横幅
"Touch ID was cancelled"。设计意图是**取消静默**（AuthContext 注释与既有测试均如此
钉），但分类守卫自 v1.3.2 起失配，证据链：

1. v1.1.6（b8fa199）写下 `isBiometricCancelled`：
   `errorMessage(error, "") === "BiometricCancelled"` —— 当时 Tauri IPC 错误确实是
   序列化枚举名字符串。
2. v1.3.2 起 `VaultError` 的手写 Serialize 将**所有**变体经 `public_message()`
   序列化（error.rs 测试 `ipc_serialization_exposes_only_the_public_message` 钉死单一
   线上形态），`BiometricCancelled` 的线上字符串 = `"Touch ID was cancelled"`
   （error.rs public_message 臂）。
3. 严格相等永不命中 → 取消落进 `SET_ERROR` 分支 → 横幅。前端测试从未用真实线上
   形态做 rejection（mock 的是手写字符串），故从未拦住。v1.8.0 自动弹指把取消变成
   常规路径后必现。

## 1. 修复面（F1–F4，共 4 文件）

### F1 — `src/context/AuthContext.tsx`（唯一行为改动）

`isBiometricCancelled` 改为**精确字符串集合**匹配：

```ts
// The Tauri layer rejects with the serialized VaultError enum. Since v1.3.2
// every variant serializes to its public_message() text, so a dismissed Touch
// ID prompt arrives as "Touch ID was cancelled" (error.rs); the bare enum
// name is kept for the pre-v1.3.2 shape. EXACT strings only — never /cancel/i
// substring matching: IntegrityCheckFailed's public message contains "was
// cancelled" and must NOT be silenced. This set ↔ error.rs pairing is pinned
// by tests on BOTH sides (error.rs ipc test + frontend contract guard).
const BIOMETRIC_CANCELLED_STRINGS: ReadonlySet<string> = new Set([
  "BiometricCancelled",
  "Touch ID was cancelled",
]);

function isBiometricCancelled(error: unknown): boolean {
  return BIOMETRIC_CANCELLED_STRINGS.has(errorMessage(error, ""));
}
```

红线：**禁止子串/正则匹配** —— `IntegrityCheckFailed` 的 public_message 含
"The operation was cancelled and the vault is unchanged"，子串匹配会把数据库完整性
校验失败也静默吞掉。集合不入 errorMessage.ts（消费者仅 AuthContext，最小面）。

### F2 — `src-tauri/crates/application/src/error.rs`（仅测试 + 注释）

- 新增测试 `biometric_cancelled_wire_shape_is_pinned`：
  `serde_json::to_string(&VaultError::BiometricCancelled)` ==
  `"\"Touch ID was cancelled\""`，注释指向前端消费者
  `AuthContext.isBiometricCancelled`（跨端契约：改文案必须双侧同步）。
- public_message 的 `BiometricCancelled` 臂加一行注释指向该契约（零行为改动）。

### F3 — `src/context/AuthContext.biometric.test.tsx`（回归主案，red→green）

新增用例：`unlockBiometric.mockRejectedValue("Touch ID was cancelled")`（真实线上
形态）→ 自动弹指路径触发 catch → 断言 `auth-error` 保持空、`unlockBiometric` 恰一次。
**现行代码下此用例红**（横幅出现），F1 后绿 —— 真 red→green 回归。
既有用例全部保留（"Keychain unavailable" 仍须出横幅——那是真实失败）。
**settle 要求（评审 P3 折叠）**：缺席断言前必须先让 rejection 落定——
`waitFor(unlockBiometric 恰一次)` 后再 `await act(async () => {})` flush，禁止
裸同步断言（会在 rejection 落定前空过 → 假绿）。

### F4 — `src/context/biometricCancelledContract.test.ts`（新文件，源码对守卫）

`readFileSync` 双断言（先例：content-namespace / corpus-sync 源码守卫）：

- `../../src-tauri/crates/application/src/error.rs` 含
  `VaultError::BiometricCancelled => "Touch ID was cancelled"`
- `./AuthContext.tsx` 含 `Touch ID was cancelled`

任一侧单改文案 → 前端测试红，跨端失配再无静默断裂窗口。
**实施精度（评审 P3 折叠）**：① 路径用 `import.meta.url` + `join` 文件锚定
（corpus-sync.test.js 先例），禁 CWD 相对裸字符串（vitest CWD=仓库根，
`../../src-tauri` 会解析到仓库外）；② 双断言必须写在**单个 it()** 内
（基线算术 702/84 依赖 F4 恰 +1 例）。

## 2. 非目标

- 不改线上形态、不改 public_message 文案（HTTP API / 浏览器扩展侧零波及）。
- 不改 v1.8.0 一次性弹指语义（取消后仍不重弹；Use Touch ID 按钮仍可手动重试）。
- 真实失败（`BiometricLockedOut` / `KeychainError` / 限流）仍出横幅 —— 有意义的信息。
- Q2（无 Touch ID 系统四层降级）已核实无缺陷，不动。

## 3. 测试与基线

- 前端 700/83 → **702/84**（F3 +1 例；F4 新文件 +1 例）
- Rust 449 → **450**（F2 新测试）
- native-host 23 不变；`pnpm typecheck` 三 tsconfig；web-ext lint 不涉（无扩展改动）

## 4. QA（qa_manual T58 追加）

真机：① 弹指后取消 → 无横幅、不重弹；② 再点 Use Touch ID → 正常弹指可解锁；
③ 连续错指 / 系统锁定 → 仍出横幅（真实失败不静默）；④ 两主题下横幅样式不涉
（本次无 CSS 改动）。

## 5. 发布步骤

紧凑流水线：plan-reviewer PASS → 实施（ds_worker，dispatch 受阻则主代理直改——
v1.5.1/v1.7.1 小面积先例）→ react-reviewer + rust-reviewer 双域 → 门禁（干净
worktree + native-host sidecar 预置）→ bump 1.8.1 → CHANGELOG / AGENTS.md / T58 →
release commit + tag → push → CI 轮询 → 资产验证 → feed 同步（ff-only）。

## 6. 评审记录

- R1（plan-reviewer）：**PASS** — 0 P0-P2；3×P3 全部折叠进 §1（F4 文件锚定 +
  单 it() 双断言、F3 settle 要求）。7 项代码断言逐条实测核对（含红线论据
  error.rs:232 实证、F1 为唯一必要行为改动的验证、vitest include 收集确认）。
