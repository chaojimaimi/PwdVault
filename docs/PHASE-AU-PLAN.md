# Phase AU 实施方案：应用内自动更新（tauri-plugin-updater v1.1.7）

> 依据：仓库已转 Public、签名密钥对已生成（`~/.pwdvault/updater.key`，**带密码保护**），
> `TAURI_SIGNING_PRIVATE_KEY` 已存入 GitHub Secrets（`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
> 由用户本人设置，密码不过第三方）。目标版本 v1.1.7。
> 流程：本方案 → plan-reviewer → ds-worker（单批）→ code-review 门。

## 0. 现状与目标

- 现状：v1.1.6 的更新检查（`update.rs` GitHub API 流程 + `VITE_UPDATE_CHECK_ENABLED`
  构建门控）只能"提示有新版 + 打开发布页"，无下载/安装能力；且受 prerelease 策略
  影响曾指向旧版（已由 f4a8e31 修复为列表取最高 semver）。
- 目标：应用内**一键下载 + 验签 + 安装 + 重启**的完整自动更新，升级包经 minisign
  签名验证（内置公钥），feed 为仓库内稳定的 `latest.json`。

## D1 关键设计

### D1.1 feed 与 prerelease 策略解耦

feed = `https://raw.githubusercontent.com/chaojimaimi/PwdVault/main/latest.json`
（公开仓库 raw 可匿名访问；由 create-release 作业在发布后通过 **GitHub Contents
API** 提交回 main——不用 `releases/latest/download` 稳定重定向，因为我们的
"未签名构建标为预发布"策略会让该重定向永远停在旧正式版）。Prerelease 标记
策略**保持不变**（未签名构建依旧标为预发布，更新 feed 不受其影响）。

### D1.2 签名与产物

- `tauri.conf.json` 增加 `bundle.createUpdaterArtifacts: true`；构建步骤注入
  `TAURI_SIGNING_PRIVATE_KEY` / `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`（均来自
  Secrets）→ 产出带 `.sig` 的更新产物：macOS `PwdVault.app.tar.gz(.sig)`、
  Windows `PwdVault_<ver>_x64-setup.exe(.sig)`。
- `tauri.conf.json` 增加 `plugins.updater = { pubkey: "<内置公钥>",
endpoints: ["https://raw.githubusercontent.com/chaojimaimi/PwdVault/main/latest.json"] }`。
  公钥（base64，已从 `updater.key.pub` 取得）：
  `dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEM2NEI2MUFFRTRENjFDRkEKUldUNkhOYmtybUZMeHMyZFEvUTV5bnRjVXMxVGdidkozSzhkY0hHcm1Na1hWK3FxdHB5KzhWdVIK`
- Secrets 已就位：`TAURI_SIGNING_PRIVATE_KEY` ✓；`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
  **由用户本人执行 `gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD`（交互输入）**——
  批 1 开工的前置条件（密钥带密码保护，已实测验证；此前误设的空密码 Secret 已删除）。
- **CI 上传链修补（评审 P0，关键）**：现有 glob 不覆盖 updater 产物——必须：
  - build-macos 的 upload-artifact 增加 `bundle/macos/*.app.tar.gz` 与
    `bundle/macos/*.app.tar.gz.sig`（release.yml:168-173 现只收 dmg 与 *.app）；
  - build-windows 的 upload-artifact 增加 `bundle/nsis/*.exe.sig`
    （release.yml:242-245 现只收 *.exe）；
  - create-release 的 files glob（release.yml:408-413）同步增加
    `*.app.tar.gz`、`*.app.tar.gz.sig`、`*.exe.sig`；
  - provenance 作业的 SHA-256 find（release.yml:329）纳入新产物；
    attest-build-provenance 的 subject-path（release.yml:347-352）可选一并
    纳入 `*.app.tar.gz(.sig)`（一行成本，供应链覆盖更完整）。
    否则 create-release 侧拿不到资产与 .sig，latest.json 全为 404 直链。

### D1.3 latest.json（CI 生成，schema 定死）

```json
{
  "version": "1.1.7",
  "pub_date": "2026-09-18T12:00:00Z",
  "platforms": {
    "darwin-aarch64": {
      "signature": "<.sig 内容>",
      "url": "<release 资产直链>"
    },
    "windows-x86_64": {
      "signature": "<.sig 内容>",
      "url": "<release 资产直链>"
    }
  }
}
```

- url 指向 GitHub Release 资产直链（`releases/download/v<ver>/...`）。
- 由 create-release 作业内的小脚本（Node，读已发布资产清单 + 各 `.sig` 文件）
  生成，并经 GitHub Contents API（`PUT /repos/.../contents/latest.json`，sha 取
  现值）提交回 main——避免 git 推送竞争；提交信息带 `[skip ci]`。
- 兼容规则：脚本只为**存在对应 .sig 的平台**写条目；某平台签名缺失 → 该平台
  不进 feed（不会发布未验签条目）。

### D1.4 应用内集成与旧流程退役

- 引入 **两个** 插件：`tauri-plugin-updater` 2.x（Rust `init` + capability
  `updater:default`）+ `tauri-plugin-process`（Rust `init` + capability
  `process:allow-restart`）——**`relaunch()` 属于 process 插件而非 updater**
  （评审 P1-1），三件套：Rust 两插件 + npm
  `@tauri-apps/plugin-updater`/`@tauri-apps/plugin-process`。前端 JS API：
  `check()`（`{ timeout: 5000 }`）→ `update.downloadAndInstall(progressCb)`
  → `relaunch()`。
- 启动检查保留现有触发模型：解锁后 + `settings.check_updates` 开启时静默
  check（保留"每启动仅一次"语义——移植 SettingsContext 的
  `checkedThisStartup` 模式）；发现新版 → 顶部横幅（版本号 + Update now
  按钮 + 下载进度条）→ 安装完成提示 Relaunch。失败静默降级（保持现有
  last-check 语义）。
- **退役旧流程（完整波及清单，评审 P2）**：
  - Rust：删 `service/update.rs`、`check_for_updates` 命令（commands.rs:249、
    lib.rs:313）、service/mod.rs:32 再导出、state.rs 的 `update_check_cancel`
    字段（:48,:101,:121）、UpdateInfo DTO（domain 导出链）
  - NM 侧：**dispatcher.rs 现已无 check_for_updates 分支（无需改动）**；
    golden_contract.rs **三处**移除——NM 列表（:37）、tauri 列表（:79）、
    core 断言数组（:135）——golden contract 是手工镜像，漏改不会报错恰是
    它要防的漂移（评审 P1-2 事实修正）
  - 前端：`VITE_UPDATE_CHECK_ENABLED` 构建门控（api/vault.ts:6）与
    release.yml:23 的同名 env 注入（含误导性注释）删除；
    types/index.ts 的 `UpdateInfo` 类型随 DTO 退役清理；
    SettingsContext.tsx（:77 门控、:82 触发、:146-160 actions）+ 其测试
    （SettingsContext.test.tsx:12-45 mock）迁移到 updater 流；
    SettingsScreen.tsx:8,:199-207 的 `disabled={!UPDATE_CHECK_AVAILABLE}`
    与"private builds"提示文案删除（更新器无此限制）；
    UpdateNotification.tsx 改造为 updater 流（openUrl 旧逻辑随
    plugin-opener 退役）
- `settings.check_updates` 开关语义不变，控制 updater 检查（含 5s 超时：
  `check({ timeout: 5000 })`，评审 P2）。

### D1.5 兼容与边界

- 首个内置更新器版本 = **v1.1.7**；v1.1.6 机器手动升级一次（发布说明注明）。
  手动 QA 方式（评审 P2 修正）：**本地 debug 构建一个版本号标 1.1.6 的
  updater 调试版**（endpoints 编译期改指 localhost——生产构建强制 HTTPS，
  本地调试可临时覆盖）→ feed 广播 1.1.7 → 下载真实资产完成验签安装全链路。
- macOS 未签名（ad-hoc）应用：updater 直接解包替换本地 .app，无 quarantine
  不经 Gatekeeper——本地构建可用；正式签名后此路径更稳（文档注明）。
- Windows：updater 下载 setup.exe 安装——默认 **installMode passive**（带
  进度 UI 的半自动，非完全静默 `/S`；无法自提升 admin，NSIS 默认 per-user
  安装可缓解；`windows.installMode` 可配置，评审 P3 修正）。
- feed 检查走 raw.githubusercontent.com（公开匿名，**CDN 有约 5 分钟缓存**
  ——发版后 feed 生效存在分钟级延迟，排障时须知，评审 P3）；**prerelease
  版本同样会进 feed 推送给开启 check_updates 的用户**（与现状列表取最高
  semver 的行为一致，有意决策，显式声明，评审 P3）。
- 密钥治理（评审 P2 补）：密码保护私钥、密码经用户交互自设 Secret、不经
  第三方（含 AI）——已落实。**泄露应急预案**：私钥泄露 = 后续更新可伪造 →
  ① 立即撤销 feed（删 latest.json）止血 → ② `tauri signer generate` 轮换
  密钥对、更新 Secrets 与 tauri.conf.json 公钥 → ③ 发布一个**须手动安装**
  的过渡版本内置新公钥 → ④ 排查泄露面。文档写入 BAIDU-SETUP 同级的
  `docs/UPDATER-KEYS.md`（与 setup 指南同文件维护）。

## 批次与任务（单批 ds-worker）

0. **前置检查（开工前）**：`gh api repos/chaojimaimi/PwdVault/branches/main`
   确认分支保护规则**允许 Actions 经 Contents API 直推 main**（release.yml:3-4
   注释显示 main 有保护规则；若含"require PR"则直推被 403 拒绝——fallback：
   feed 改放不受保护的 `gh-pages` 分支或独立 feed 仓库，raw 路径同步调整，
   评审 P1-3）；`gh secret list` 断言
   `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` 已由用户设置。
1. **配置**：tauri.conf.json（createUpdaterArtifacts、plugins.updater pubkey +
   endpoints）；capabilities 加 `updater:default` 与 `process:allow-restart`；
   Cargo 加 tauri-plugin-updater + tauri-plugin-process；前端
   `@tauri-apps/plugin-updater` + `@tauri-apps/plugin-process`。
2. **退役**：删 update.rs + `check_for_updates`（仅 golden contract 三处 +
   commands.rs/lib.rs 的命令注册——NM dispatcher 无需改动）+ UpdateInfo +
   VITE 门控；波及清单按 D1.4 执行（SettingsContext 及其测试、
   SettingsScreen、UpdateNotification 改造为 updater 流）。
3. **前端 UI**：启动检查（解锁后 + 开关，check({timeout:5000}) + 每启动
   一次）→ 横幅（版本号/Update now/下载进度/Relaunch）→ 失败静默；复用
   现有主题令牌与 busy 模式。
4. **CI**：build 步骤注入签名 Secrets；**上传链修补（P0）**——三个 upload-
   artifact/files glob 与 provenance find 增补 updater 产物与 .sig（见
   D1.2）；create-release 增加 latest.json 生成（Node 脚本：读已发布资产 +
   .sig → 组 JSON → **GitHub Contents API 提交 main**，sha 现值取改，
   409/竞争重试 3 次，提交信息 `[skip ci]`）+ 上传 latest.json 为 Release
   资产；脚本独立文件 `scripts/generate-latest-json.mjs` +
   `node --check` 验证。
5. **测试**：generate-latest-json 的可测核心（平台映射/签名缺失跳过/URL
   拼装）抽为可导入函数并以 vitest 覆盖；前端 updater mock（check 有新版/
   无新版/下载进度/失败静默/每启动一次）；golden contract 三处更新；
   全量回归。

## 验证清单

```bash
cargo test --workspace && cargo clippy --all-targets -- -D warnings && cargo fmt --all --check
cargo deny --manifest-path src-tauri/Cargo.toml --config deny.toml check   # 镜像 CI 门，验新传递依赖
pnpm test && pnpm tsc --noEmit && pnpm lint
node --check scripts/generate-latest-json.mjs
git diff --cached --name-only | xargs wc -l   # 全部 ≤800
```

手动 QA（人工，评审 P2 修正后的方式）：**本地 debug 构建"版本号标 1.1.6 的
updater 调试版"**（endpoints 编译期改指 `http://127.0.0.1:<port>` 的本地
伪造 feed，注明 debug 构建可覆盖 HTTPS 限制的方式）→ feed 广播 1.1.7 →
下载真实资产 → 验签安装 → 重启全链路；损坏签名 → 拒绝安装；macOS 无写
权限场景错误呈现。

## 风险

- **分支保护直推被拒**：前置检查（批 0）；fallback = feed 改放 gh-pages 或
  独立 feed 仓库（评审 P1-3）
- macOS 未签名替换升级：本地 debug 全链路 QA 验证；正式签名后更稳（文档注明）
- latest.json 提交 main 与人工提交竞争：Contents API 单文件原子更新 + 重试
- 用户密码 Secret 未设置前 CI 签名失败：批 1 前置检查（gh secret list 断言）
- feed 单点：raw URL 稳定；GitHub 故障时应用静默跳过检查（现状语义）；
  raw CDN 约 5 分钟缓存（发版后分钟级延迟，排障须知）
- 密钥泄露应急四步已写入 D1.5（撤销 feed → 轮换 → 手动过渡版 → 排查）
