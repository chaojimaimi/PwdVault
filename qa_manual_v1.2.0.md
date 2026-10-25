# PwdVault v1.2.0 验证操作手册

**适用版本**：v1.2.0 – v1.2.3（统一在 **v1.2.3** 上执行；仅 §1 升级路径测试需从 v1.1.9 库升级）
**优先级**：§1 与 §2 为必测（行为变化 + 升级迁移），其余为回归确认
**测试环境建议**：macOS 本机全程可测；Windows 用 CI 产物抽查 §1/§2；同步测试推荐坚果云 WebDAV（比百度 OAuth 轻）； ideally 再备一台装 v1.1.9 的设备/库用于升级路径

---

## 0. 准备

| 场景                | 操作                                                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| 升级路径（§1 必需） | 在 v1.1.9 上：解锁金库 → 配置好同步（坚果云 WebDAV 最简）→ 确认 sync 一次成功 → 退出 → 安装 v1.2.0（覆盖安装，数据保留） |
| 全新安装            | 直接装 v1.2.0 新建/导入金库                                                                                              |
| 数据库位置          | macOS：`~/Library/Application Support/com.pwdvault.app/vault.db`；Windows：`%LOCALAPPDATA%\PwdVault\vault.db`            |

## 1. SEC-L2 同步配置加密与迁移（必测，升级路径）

- **T1 升级后同步可读**：v1.2.0 打开 → 设置 → 同步：应显示已连接，server URL / 用户名仍可见（读时自动迁移，对用户透明）。
- **T2 行已密文**（验证迁移真实发生）：
  ```bash
  # macOS（把 your-username 换成同步账号用户名片段）
  strings ~/Library/Application\ Support/com.pwdvault.app/vault.db | grep -c "your-username"
  # 预期：0（v1.1.9 上同命令为 ≥1）
  ```
- **T3 改密存活**：改主密码 → 同步设置**仍显示已连接**、sync_now 成功（re-seal 密钥轮换）。
- **T4 未访问即改密**（评审特别场景）：在 v1.1.9 配置过同步但**从未打开同步设置**的库 → 升级 → 直接改密 → 再打开同步设置：配置应完好（legacy 明文行在改密时被双读轮换）。
- **T5 断开回归**：断开连接 → 重新连接 → 正常。

## 2. SEC-L5 自动锁远程宽限（必测，行为变化）

先把设置中自动锁时长调为 **1 分钟**。心跳来源是**应用窗口内**的指针/键盘事件——"闲置"测试时把鼠标移出应用窗口或最小化。

- **T6 纯闲置即锁**：解锁金库 → 完全不碰应用（配对扩展挂着也不操作）→ 约 60 秒后自动锁。旧版此场景会被扩展心跳无限续期——这是本版核心变化。
- **T7 扩展操作只续 120 秒**：解锁 → 第 50 秒用扩展做一次填充 → 会话应活过 60 秒（本地窗口已过期但远程宽限生效）→ 最后一次扩展操作后约 120 秒锁定。
- **T8 桌面在席不误锁**：解锁 → 持续在应用内打字/移动鼠标（间隔 <30 秒）→ 1 分钟后**不应**锁（桌面输入维持全窗口）。
- **T9 解锁重置**：每次解锁后应获得完整的 1 分钟窗口。

## 3. SEC-L3 OAuth 回调（可选，需百度账号）

- **T10 垃圾探针不中断**：设置 → 连接百度网盘 → 浏览器跳转等待授权时，另开标签页访问 `http://127.0.0.1:17777/?probe=1` → 应返回错误页（400）**且**原授权流程继续 → 完成真实授权 → 连接成功。
- **v1.2.1 起行为更新**：`?error=xxx` 探针（无有效 state 回显）现在也会被**丢弃**、等待继续——请把 `?probe=1` 与 `?error=xxx` 两种探针都测，两者都不应中断授权；只有携带正确 state 的真实拒绝（用户点拒绝）才立即终止。

## 4. 浏览器扩展（SF-P1 回归 + 新反馈）

- **T11 锁定态三路径**：桌面锁定后——快捷键填充 / 右键菜单填充 → 页面应弹"Failed to fetch password (is the desktop app unlocked?)"类错误提示（不再出现绿色成功条或无反应）；popup 复制按钮 → "Failed to fetch password" toast；popup Auto-fill 按钮 → 同款 toast。
- **T12 解锁态回归**：三条路径正常填充/复制。
- **T13 剪贴板通知**：扩展复制密码 → 30 秒后站点无 clipboardRead 权限时，页面**至多一次**提示"Clipboard auto-clear failed"（每页去重，旧版为永久静默失败）。
- **T14 死代码删除回归**：popup 搜索、组过滤、GET_STATUS 连接状态正常。

## 5. SEC-L4 恢复密钥

- **T15 不落盘**：Enable recovery（不勾 Save to file）→ key 显示一次，行为同旧。
- **T16 落盘**：勾选 Save to file → Enable → 选路径 → toast "generated and saved" → 文件存在、`ls -l` 为 `rw-------`（0600）、内容含 key；取消保存对话框 → 应静默回表单且密码未被消耗。

## 6. CQ-P3d EntryScreen 拆分回归（纯迁移，预期零变化）

- **T17**：新建条目、编辑条目（脏检查与"未保存离开"确认）；TOTP 三态（添加 / 更换 / 清除，含粘贴 otpauth:// 链接的提示）；tags 编辑（含重复添加不清空输入框的原行为）；生成器弹窗取词。

## 7. CQ-P3b 配对限流回归

- **T18**：快速连续发起配对 11 次 → 第 11 次起报 rate limit（与旧版 10/分钟一致；并发下不再放宽——此项单测已覆盖，手动确认文案即可）。

## 8. 打包与清理

- **T19 扩展包无测试文件**：`unzip -l PwdVault-Chrome-Extension-v1.2.0.zip | grep test` → 应为空。
- **T20**：`scripts/windows-native-host-smoke.py` 仍在（CI 在用，禁删项）；应用正常启动（死代码删除无副作用）。

## 9. 仅代码级可验证的项（无需手动测，列测试锚点备查）

| 修复项                     | 覆盖测试                                                                                                                                           |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-L1 token 64-hex 白名单 | native-host `is_valid_token` 四分支单测                                                                                                            |
| SEC-L4 Zeroizing 返回      | recovery_file 单测（IPC 透明，外部不可观测）                                                                                                       |
| SEC-L5 语义四条            | session.rs `remote_touch_grants_only_grace` / `max_semantics` / `lock_clears_remote_activity` / touch_policy `service_op_touches_remote_not_local` |
| SEC-L2 加密/迁移/轮换      | tests_state_io 6 条 + tests_engine 存活 ×2（legacy 夹具）                                                                                          |
| keychain 真机冒烟          | CI quality-native-host job（本地 ignored）                                                                                                         |
| SF-P3a/c/d 日志类          | 代码级（tracing/console.warn），无 UI 面                                                                                                           |

## 10. 快速整体回归

导入导出 .pvault（含取消对话框）→ TOTP 码刷新 → 群组增删改 → 主题切换 → 托盘锁定/退出 → 锁定态打开应用需主密码/Touch ID。

## 问题报告格式

每条：步骤编号（T#）+ 平台 + 实际 vs 预期 + 截图/录屏 + （可选）`RUST_LOG`/控制台输出。已知残余（§3 T10 备注、剪贴板根治延期）请标注"known"以便过滤。

---

# v1.2.2 验证小节（2026-10-06）

## T21 Tags 输入框布局修复（components.css flex 行修复）

1. 打开 Entries → 编辑任一条目，滚动到 Tags 区。
2. 预期：输入框占满整行宽（不再塌缩为 ~50px 胶囊），占位符完整可见，输入字符实时可见。
3. 输入文字后点击 Add → chip 正常生成并显示，输入框清空且仍占满行宽。

## T22 设置页手动 "Check for updates"

1. Settings → Updates 区：确认版本行（Current version: v…）与 Check for updates 按钮可见；按钮不受 "Check on startup" 开关状态影响（开关关闭时仍可点击）。
2. 四态验证：
   - 点击 Check → 按钮变 "Checking…" 且禁用，状态行显示 "Checking for updates…"；
   - 有更新（本地 mock feed 或对照真实新版本）→ 页面顶部（Settings 标题栏下方）出现更新横幅，状态行 "Update available: vX.Y.Z — use the banner above to install"；横幅 Update now → 下载进度 → Relaunch 全流程可用，Dismiss 后横幅消失；
   - 无更新 → 状态行 "You're up to date (v…) — checked HH:MM"，若此前有横幅则被清除；
   - 断网（关 Wi-Fi / 防火墙拦截）→ 状态行 "Couldn't reach the update server — check your connection and try again"，恢复网络后可重试成功。
3. 下载中（进度条）与就绪（Relaunch）两种状态下 Check 按钮均禁用。
4. 回归：Vault 首页横幅行为不变（自动检查静默、dismiss 记忆仍生效——手动检查不受 dismiss 记忆影响属预期）。

## T23 分组行两种形态

1. Entries → 编辑条目 → Group 下拉形态：select 占满行宽，"New" 缩为内容宽度，同一行内比例正常。
2. 点击 "New" → 内联新建形态：输入框占满行宽，Add / Cancel 为内容宽度按钮，三元素同一行；新建成功后回到 select 形态且自动选中新组。
3. GroupManager 页内新建分组行不受本次修复影响（该页布局独立），正常增删改。

---

# v1.3.1 验证小节（2026-10-25）

## T24 `.screen` 短内容居中回归

1. 全新数据目录启动应用（无金库）→ Setup 屏在正常窗口尺寸下视觉居中。
2. 已有金库启动 → Unlock 屏居中；Settings → Recovery（或锁屏入口）进入恢复密钥展示前的短内容状态时居中。
3. App 启动 loading 态（进入解锁前的短暂加载画面）文字/图标居中（该态与三屏共用 `.screen` 容器，原本依赖 justify-content: center）。
4. Dark/Light 两主题各过一遍 1–3。

## T25 `.screen` 溢出可达性（500px 最小高度）

1. 把窗口高度拖到最小（500px），打开恢复密钥流程：展示密钥 + 确认输入两屏的**首屏字段完整可见**（不再被裁出视口顶部）。
2. 内容超出视口时可从顶部开始向下滚动（此前居中裁切导致顶部不可达）。
3. 回归：内容正常（不超高）时仍居中显示（`:only-child` auto-margin 生效）；`.screen-shell` 包裹的其余 6 屏（Vault/Entry/Generator/Settings 等）布局无变化。

## T26 Chrome 剪贴板自动清除端到端

1. popup 复制一个密码 → **立即关闭 popup** → 等 30s → 外部任意应用粘贴 → 应为空（清除由 background 执行，popup 已关也必须生效）。
2. 反向用例（digest 保护）：复制密码后 10s 内手动复制其他文本 → 30s 到点后粘贴 → **用户新复制的内容完好**，不被误清。
3. popup 复制后 toast 应显示 "...(auto-clears in 30s)"；若 background 未达（不可达场景）则降级为普通 "Password copied!" 且不承诺清除。
4. 实施备注：offscreen `reasons:['CLIPBOARD']` 有已知 Chromium bug 330570363；若本用例失败，先对照该 issue 的现象再定性。

## T27 Firefox 剪贴板自动清除端到端

1. about:debugging → This Firefox → Load Temporary Add-on 加载 firefox/ 目录 manifest。
2. 重复 T26 的两个用例（30s 清空生效；10s 内新复制内容不被误清）。Firefox 走 event page 隐藏 textarea + execCommand paste/copy 路径，无 offscreen。

## T28 Service Worker 被杀后 alarm 唤醒

1. popup 复制密码完成 arm → 打开 chrome://serviceworker-internals 手动 Stop 该扩展的 Service Worker（等价入口：chrome://extensions → 该扩展卡片上的 "Service Worker" 链接，二选一）。
2. 等 30s → 到点 alarm 应唤醒 Service Worker 并完成清除 → 外部粘贴为空。
3. 对照（可选）：arm 后立即 Stop SW，再于到点前保持浏览器活跃，确认 alarm 仍按期触发（alarm 由浏览器调度，不依赖 SW 常驻）。
4. 已知偏差（v1.3.1 评审备注）：Chrome 120+ 会把 <30s 的 alarm 延迟钳到 30s——失败后的 5s 重试实际会在 ~30s 后发生；arm 记录持久 + digest 校验保证晚到的清除依然安全，仅时间推迟。
