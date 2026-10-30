# v1.8.2 修复计划 — 自动弹指焦点门控（idle 锁不再隔空弹窗；紧凑 patch）

## 0. 背景与根因（用户真机反馈，主代理代码级钉死）

v1.8.0 自动弹指把触发点定在"锁定片段开始"，但 idle 自动锁定恰恰发生在用户**不在**
的时候。四条锁定路径的实际窗口行为：

| 锁定路径        | 接线                                                                                                        | 窗口行为                                          | 弹指合理性  |
| --------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ----------- |
| 应用启动        | boot → 解锁屏挂载                                                                                           | 用户刚打开，必在前台                              | ✅          |
| 托盘手动锁      | lib.rs:352-358                                                                                              | `show + set_focus + reload`（主动拉前台）         | ✅          |
| 主界面锁按钮    | VaultScreen → authActions.lock()                                                                            | 人正看着窗口                                      | ✅          |
| **idle 自动锁** | lib.rs:64-70 → `reload_window()` = `window.eval("location.reload()")`（state.rs:199，**不 show 不 focus**） | 窗口在后台/托盘，系统级指纹对话框越过一切应用浮出 | ❌ 核心痛点 |

修复方向（用户已批方案 A）：触发点从"片段开始"改为"**用户注意力转向 App**"——
自动弹指增加第四道门 `windowFocused === true`；失焦期间锁定静默，focus 事件触发时
弹一次（v1.8.0 的每片段一次 flag 语义原样保留）。对启动/手动锁两条已验收路径
**行为零变化**（启动必在前台；托盘锁本就 set_focus）。

Tauri v2 API 已验证（@tauri-apps/api 2.12.4 window.d.ts）：
`getCurrentWindow().isFocused(): Promise<boolean>`、
`onFocusChanged(handler: EventCallback<boolean>): Promise<UnlistenFn>`
（内部订阅 tauri://focus / tauri://blur；**订阅不回放当前状态**，故需 isFocused 探测）。

## 1. 修复面（F1–F2，共 3 文件，纯前端零 Rust）

### F1 — `src/screens/UnlockScreen.tsx`

(a) 新增 import（src/ 全域首个 @tauri-apps/api/window 导入，评审 P3 折叠）：

```tsx
import { getCurrentWindow } from "@tauri-apps/api/window";
```

(b) 新增焦点状态 + 探测/订阅 effect：

```tsx
// v1.8.2: focus gate for the auto-prompt. Auto-lock fires while the user is
// AWAY (reload_window never raises the window), so the system fingerprint
// dialog must not float over unrelated work. null = unknown/failed → never
// auto-prompt (same silent-degrade philosophy as the other probes).
const [windowFocused, setWindowFocused] = useState<boolean | null>(null);

useEffect(() => {
  let cancelled = false;
  let eventSeen = false;
  let unlisten: (() => void) | undefined;
  void (async () => {
    try {
      const current = getCurrentWindow();
      const un = await current.onFocusChanged(({ payload: focused }) => {
        eventSeen = true;
        if (!cancelled) setWindowFocused(focused);
      });
      if (cancelled) {
        un();
        return;
      }
      unlisten = un;
      // Subscribe FIRST, then probe; apply the probe only if no event
      // arrived meanwhile (the event is always fresher than the probe —
      // a focus change racing between them must not be overwritten by
      // the stale initial answer).
      const focused = await current.isFocused();
      if (!cancelled && !eventSeen) setWindowFocused(focused);
    } catch {
      /* focus unknown → auto-prompt stays off; button still works */
    }
  })();
  return () => {
    cancelled = true;
    unlisten?.();
  };
}, []);
```

(b) 自动弹指 effect 增加第四道门 + deps 扩一位：

```tsx
if (
  !showTouchId ||
  state.isLoading ||
  state.biometricAutoPrompted ||
  windowFocused !== true // null（未知/探测失败）与 false 一样不弹
) {
  return;
}
```

deps：`[showTouchId, state.isLoading, state.biometricAutoPrompted, windowFocused, actions]`。
注释更新：v1.8.0 注释块追加 v1.8.2 段（自动锁 reload 不拉前台 → 弹窗只跟随注意力；
StrictMode 段保留原措辞，说明 windowFocused 初始 null 同样让首跑早退，双保险）。

红线：**探测/订阅失败绝不报错**（与 biometricStatus/recoveryStatus 探测同一静默
哲学）；flag 语义零改动（MARK 在 unlockBiometric 入口，RESET 在 lock——本计划不碰
AuthContext）。

### F2 — 测试（两个既有文件 +mock，无新文件）

两个文件都要 mock `@tauri-apps/api/window`：

```ts
const windowMock = {
  isFocused: vi.fn(),
  onFocusChanged: vi.fn(),
};
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => windowMock,
}));
```

beforeEach 默认：`isFocused → true`、`onFocusChanged → Promise.resolve(() => {})`
（保既有用例零改动——今天的行为即"前台上桌即弹"）。**两个文件各自都要设**
（评审 P2 折叠：AuthContext.biometric.test.tsx 若只加 vi.mock 不设默认，mock 返回
undefined → 四维门永关 → 既有用例 1 必红；且默认值必须在 `vi.clearAllMocks()`
**之后**设置）。

**F2a `src/screens/__tests__/UnlockScreen.security.test.tsx`（+3 用例）**：

1. 挂载时 `isFocused → false` → 不自动弹；手动触发订阅 handler(true) → 恰一次
2. handler(true→false→true) 连翻 → 仍恰一次（episode flag）
3. `isFocused` reject（探测失败降级）→ 不弹、无报错、按钮仍可用

**F2b `src/context/AuthContext.biometric.test.tsx`（+1 用例）**：
provider 级焦点生命周期：初始 false → 重挂（模拟 Loading 循环）不弹 → handler(true)
→ 恰一次 → 再翻 false/true 仍一次。

实施精度：handler 捕获形如
`onFocusChanged.mockImplementation(async (h) => { captured = h; return () => {}; })`；
用例内 `await act(async () => { await captured?.({ payload: true, ... }); })` 落定。
**重挂后触发 handler 前必须先等新挂载的订阅重建**（评审 P3 折叠：toggleScreen 是
同步 fireEvent，焦点 effect 是 async IIFE——立即触发的是已 cleanup 的旧 handler，
会被 cancelled 守卫静默丢弃 → 假红；先 `await act(async () => {})` 一拍或 waitFor
`onFocusChanged` 调用次数 +1 再触发）。
新用例数 **+4**；既有用例零改动。

## 2. 非目标

- 不改 AuthContext（flag/MARK/RESET 原样）；不改 Rust（reload_window/自动锁线程原样）。
- 不加设置开关（YAGNI，方案 C 已否）。
- 手动按钮、密码路径、一次性片段语义全部不变。

## 3. 测试与基线

- 前端 702/84 → **706/84**（F2a +3、F2b +1，两个既有文件）
- Rust 450(+1 ignored)、native-host 23 不变
- `pnpm typecheck` 三 tsconfig；web-ext lint 不涉

## 4. QA（qa_manual T59 追加）

真机（核心=第 1 条）：① App 后台或托盘时等 idle 自动锁 → **无指纹弹窗**浮出；
点托盘/窗口回来 → 弹一次；② 启动 → 通常即弹（启动时窗口通常在前台；评审 P3 折叠：
冷启动切走/登录项启动等未聚焦边缘下不弹、回焦补弹一次——新语义的预期行为而非
回归，T59 观察项）；③ 托盘手动锁 → 窗口前台 + 弹
（行为不变）；④ 前台发呆至自动锁 → 弹（人在机器前，可接受）；⑤ 取消后不重弹、
按钮可手动重试（v1.8.0/v1.8.1 语义回归）。

## 5. 发布

紧凑流水线：plan-reviewer PASS → ds_worker 实施 → react-reviewer → 门禁（干净
worktree + sidecar）→ bump 1.8.2（含 src-tauri/Cargo.lock 手动重生 + --locked 复验）
→ CHANGELOG/AGENTS/T59 → release + tag → push → CI 轮询 → feed 同步。

## 6. 评审记录

- R1（plan-reviewer）：**PASS** — 0 P0-P1；1×P2（F2b 两个文件各自 beforeEach 默认值
  且须在 clearAllMocks 之后）+ 4×P3（import 行、"启动必在前台"措辞收敛 + T59 边缘
  观察项、F2b 重挂后等订阅重建再触发 handler、实施首步先实跑钉死 702/84 基线）
  全部折叠进 §1/§4。§0 四条锁定路径接线逐行核实；eventSeen 守卫经 window.js 源码
  证实必要（onFocusChanged 订阅不回放当前状态）。
  **实施首步：先跑 `pnpm test` 钉死 702/84 基线再动手。**

- R2（react-reviewer）：**APPROVE** — 0 P0-P2，2×P3：① 记录准确性修正——R1 上文
  "被 F2b 用例真实行使"不实，四个新用例均未行使 eventSeen 竞态分支；守卫正确性
  来自源码推导 + 审查期一次性探针测试（探针证实守卫 sound 但未随批落地），竞态
  用例留待后续小批次补。② 变异测试证实四维门被真实行使（删门后 F2a×2 + F2b×1
  恰好变红）。实施期另收一笔：既有 late-failure 用例冷缓存抖动 2 次（authStateRef
  passive-effect 滞后 vs RTL waitFor 提前放行的既有竞态）→ waitFor 后补
  `await act` 冲刷，测试级一行修复。
