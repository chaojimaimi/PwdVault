# 更新器签名密钥治理指南（UPDATER-KEYS）

> 适用于 PwdVault v1.1.7+ 应用内自动更新（Phase AU / 方案 PHASE-AU-PLAN.md）。
> 更新器信任模型：安装包由 **minisign 私钥签名**，应用内置**公钥**验签。
> 私钥泄露 = 攻击者可向所有开启检查的用户推送伪造更新，必须按第 4 节应急预案处置。

## 0. 信任链一览

```
~/.pwdvault/updater.key          （minisign 私钥，密码保护，绝不进 git / 对话 / 第三方）
        │ tauri build 注入 TAURI_SIGNING_PRIVATE_KEY(+PASSWORD)
        ▼
*.app.tar.gz.sig / *.exe.sig     （各平台更新产物的签名）
        │ scripts/generate-latest-json.mjs
        ▼
latest.json                      （feed：平台 → {signature, url}，经 Contents API 提交 main）
        │ raw.githubusercontent.com（HTTPS，公开匿名）
        ▼
应用内置公钥（tauri.conf.json → plugins.updater.pubkey）验签后才安装
```

- **私钥**：`~/.pwdvault/updater.key`，由 `tauri signer generate` 生成，带密码保护。
  密码由用户本人交互式存入 `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` Secret（不经任何第三方，
  包括 AI 工具）。**私钥本体永不入库、永不进 CI 日志**——CI 只经 Secrets 注入环境变量。
- **公钥**：base64 一行，写死在 `src-tauri/tauri.conf.json` 的
  `plugins.updater.pubkey`。随应用分发，换钥 = 发新版（见第 3 节）。
- **feed**：`https://raw.githubusercontent.com/chaojimaimi/PwdVault/main/latest.json`。
  注意 raw CDN 有约 5 分钟缓存，发版后 feed 生效存在分钟级延迟。

## 1. 首次生成（已完成，存档备查）

```bash
# 交互式生成，务必设置强密码（空密码曾在早期误用，已作废重生成）
pnpm tauri signer generate -w ~/.pwdvault/updater.key

# 公钥输出（updater.key.pub 内容即 base64 公钥），写入 tauri.conf.json
cat ~/.pwdvault/updater.key.pub

# 私钥存入 GitHub Secrets（value 走交互 stdin，勿放命令行参数）
gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.pwdvault/updater.key
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD   # 交互输入密码

# 验证
gh secret list   # 应同时看到 KEY 与 PASSWORD 两项
```

## 2. 日常使用（无需手工操作）

- `release.yml` 的 build-macos / build-windows 构建步骤从 Secrets 注入两个环境
  变量；`bundle.createUpdaterArtifacts: true` 时缺钥**直接构建失败**（不会静默
  产出未签名更新包）。
- create-release 作业运行 `scripts/generate-latest-json.mjs`：只为存在非空
  `.sig` 的平台写 feed 条目，全部平台缺签则拒绝发布空 feed。

## 3. 计划内轮换（建议每年或疑似弱密码时）

公钥随应用二进制分发，**新旧公钥无法热切换**，轮换必须发一个“过渡版本”：

1. `pnpm tauri signer generate -w ~/.pwdvault/updater.key.new`（新密码）。
2. 更新 Secrets：覆盖 `TAURI_SIGNING_PRIVATE_KEY` / `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
   为新钥；`tauri.conf.json` 的 `pubkey` 换成新公钥。
3. 发过渡版本 vX.Y.Z（内置新公钥），**发布说明注明“须手动下载安装”**——
   旧版用户内置的是旧公钥，无法验签新 feed，最后一次必须手动升级。
4. 过渡版铺开后删除旧钥文件与 `.pub`，完成轮换。

## 4. 泄露应急（私钥文件或密码疑似/确认泄露，按序执行）

> 私钥泄露的后果：攻击者可用自己的 latest.json + 重签名包推送恶意“更新”。
> 止血优先级高于排查，**先做第 1 步**。

1. **立即撤销 feed（止血）**：删除 main 分支的 `latest.json`（经 Contents API
   删除或直接改仓库文件）。没有 feed，应用端检查静默失败（现状语义），攻击面
   立即收窄。raw CDN 缓存约 5 分钟后彻底失效。
2. **轮换密钥对**：按第 3 节生成新钥，覆盖两个 Secrets，并更新
   `tauri.conf.json` 内置公钥。
3. **发布手动过渡版**：发布一个**须手动下载安装**的过渡版本（内置新公钥），
   通过官网/Release 页公告引导用户手动升级，旧 feed 域名不再恢复。
4. **排查泄露面**：确认泄露途径（本机失窃 / Secret 误泄露 / 备份外流），
   检查 GitHub 审计日志中 Secret 的访问记录、`latest.json` 的提交历史有无
   非预期提交，必要时轮换 GitHub Token 并撤销未知设备会话。

## 5. 相关文件

| 位置 | 作用 |
|------|------|
| `src-tauri/tauri.conf.json` → `plugins.updater` | 内置公钥、feed endpoints、Windows installMode |
| `.github/workflows/release.yml` | 构建签名注入、产物 `.sig` 上传、feed 生成与提交 |
| `scripts/generate-latest-json.mjs` | feed 组装（只收有 `.sig` 的平台）+ Contents API 提交（重试 3 次，`[skip ci]`） |
| `docs/PHASE-AU-PLAN.md` | 方案全文（D1.5 密钥治理决策记录） |
