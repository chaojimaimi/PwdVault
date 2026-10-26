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

---

# v1.3.2 验证小节（content.js 全量重构 + UI P2 批）

> ⚠️ 携带项：**T26-T28（剪贴板端到端）必须在 v1.3.2 构建上重跑**——content.js 已全量迁移 Shadow DOM。

## T29 自动填充条 Shadow DOM 隔离与配色

1. 打开任一含登录表单的站点 → 浮动按钮与自动填充条应为 **navy/teal 新配色**（非旧靛蓝），与桌面端视觉一致。
2. 真实点击 Fill → 凭据正确填入；DevTools Elements 面板确认注入 UI 位于 closed shadow root 内。
3. 宿主页样式污染测试：DevTools 注入 `div { background: red !important; color: white !important; }` → 注入 UI 外观不受影响（`all:initial` 隔离生效）。

## T30 overlay 真实流

1. Ctrl+Shift+L 打开 overlay → 搜索过滤 → 点击条目展开 → Copy → Esc 或点击遮罩关闭；全程样式正常、modal 内点击不误关。

## T31 Light 主题对比度抽检

1. 桌面 Light 主题：输入框 placeholder、强度计标签（弱/中/强）肉眼清晰可辨（AA 达标）。

## T32 空态 CTA 与 Enter 保存

1. 空库下显示 "Add your first password" 主按钮，点击进入新增页；搜索无结果时不显示该按钮。
2. 条目编辑页：标题输入框内按 Enter → 触发保存；标签输入框按 Enter → 只加标签不触发保存；Delete 不触发保存。

---

# v1.4.0 验证小节（wry 0.54→0.57 跳跃 + 四个产品件）

## T33 updater 真机端到端（wry 跳跃的 QA 主体，最高优先）

1. **macOS**：安装 v1.3.2 → Settings → Check for updates → 应发现 1.4.0 → 下载（进度可见）→ Install and relaunch → 重启后 About/设置确认 1.4.0；托盘与窗口基础行为（开合/锁定/左键托盘图标）各来一遍。
2. **Windows**：同上全流程。
3. 顺带核对更新期间 vault 锁定状态与自动锁定不紊乱。

## T34 eTLD+1 匹配真站

1. 建 URL 为 `https://accounts.example.com/login` 的条目 → 打开 `https://example.com/`（或其登录页）→ 浮动按钮出现且能匹配填充（v1.3.2 会漏配）。
2. 建 `https://www.example.co.uk` 条目 → 打开 `https://evil.co.uk` 类不同注册人站点 → **不得**匹配。
3. 无 URL 的泛型条目 → 不出现在任何自动填充列表（右键/快捷键路径）。

## T35 passphrase / PIN 生成器

1. 生成器切 Passphrase → 词数/分隔符/首字母大写/追加数字各选项生效；复制；历史列表出现且点击可复制；重启应用后历史清空（会话级）。
2. PIN 模式 4-16 位仅数字；popup 同款三模式可用。

## T36 回收站

1. 删除两条 → 回收站列出（标题+删除时间）→ 恢复一条（回到主列表且出现在"Recent"）→ 永久删除另一条（危险确认）→ Empty trash（确认模态）。
2. 双设备（如有）：一台恢复后另一台同步侧条目复活。

## T37 全局快捷键

1. 默认 `CmdOrCtrl+Shift+Space` 在任意应用前景下唤起主窗口并聚焦搜索。
2. 改键保存即时生效；注册一个已被占用的组合 → 设置页红字并回退旧值。
3. macOS 观察项：连按是否双触发（tauri#10025，代码已有 Pressed 守卫——如仍复现，记录现象）。

## T38 回收站入口迁入分组 tab（v1.4.1 UI 修补）

1. 主界面 tabs 行右侧出现 `[竖线] 🗑 Trash [⚙]` 固定簇；图标 12px 不失真（jsdom
   测不出 `.icon` 24px 压制规则是否生效——Light/Dark 两主题各看一眼）。
2. 点击 Trash → 原位切换为回收站列表（tabs 行保留，Trash 高亮且分组 tab 不高亮，
   互斥）；再点 Trash 或点 All/分组返回主列表；搜索/排序在回收站视图隐藏。
3. 零分组金库：Create group CTA 与 Trash 同行共存，Trash 仍可达、可返回。
4. 分组多到横向滚动出现时，Trash 与 ⚙ 不被滚走（固定簇在滚动区之外）。

## T39 安全仪表盘（v1.5.0）

1. 真实金库：header 盾牌按钮进入仪表盘；弱/重复/陈旧三清单与人工抽查一致；
   行点击跳进条目编辑；健康金库显示 All-clear 文案。
2. 只读性：打开仪表盘前后"最近使用"排序不变（报告不得触发 last_used_at 刷新）。
3. 陈旧文案必须是"超过一年未修改"语义（Unchanged for over a year），不是"未使用"。

## T40 CSV 导入真机（v1.5.0）

1. 四家真实导出各导一次（Bitwarden/1Password/Chrome/KeePassXC）：识别为正确预设、
   预览表无密码列、导入计数与源行数对账（跳过行显示）。
2. 现实边界：带 BOM 的 1Password/Chrome 导出、含引号内换行的备注行均可解析。
3. 组列：folder/Group 列建组并分配（重复组名合并）；无组列的导入全部 Ungrouped。
4. 同一文件导两次：第二次预览的"疑似重复"计数出现，且仍全量新增（Bitwarden 语义，
   不去重）。导错文件后重新选择：旧预览被替换，commit 不会提交上一次的数据。

## T41 回收站自动清理（v1.5.0）

1. 默认 0=关：删除条目后多次解锁，条目留在回收站（默认不清理是刻意的）。
2. 设为 7 天并保存 → 重启后设置回读正确；解锁后若有到期 tombstone，出现
   「回收站自动清理了 N 条」toast；无到期项时无 toast。
3. 被清理的条目不会在下一次同步时从远端拉回回收站（purge ledger 生效；
   双设备场景验证）。
4. 已知局限（设置页 hint 有写）：常驻不锁的金库不触发扫描；改设置需下次解锁生效。

## T42 每条目 URL 匹配三模式（v1.5.0）

1. exact：`accounts.example.com` 条目在 `www.example.com` 页**不**填充；同 host
   正常填充；带端口的不同端口页不匹配。
2. domain：同注册人子域互相匹配（等同 v1.4.0 auto）；跨注册人（evil.co.uk 类）
   不匹配。
3. auto：v1.4.0 行为完全不变（回归基线）。
4. 四条填充路径行为一致：popup 直发、content overlay、右键菜单、快捷键。
5. 前后兼容：v1.4.x 旧扩展配 v1.5.0 桌面 → 填充正常（缺字段回退 auto）；
   v1.5.0 扩展配 v1.4.x 旧桌面 → 同样正常。双设备同步：一端设 exact 后另一端
   同步获得该设置（容器 v2），未升级的旧端会明确提示容器版本不支持（引导升级，
   而非静默丢失设置）。

## T43 配对弹码扩展 ID 摘要（v1.5.0）

1. 新扩展配对：桌面 toast 同时显示 6 位码与请求方摘要（`abcd…wxyz` 形态），
   后 4 位与 chrome://extensions 中实际 ID 一致。
2. Firefox 配对：显示 `pwdvault@pwdvault.app` 原样。
3. 文案含"核对提示，非身份认证"限定。
