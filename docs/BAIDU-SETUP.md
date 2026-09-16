# 百度网盘同步配置指南（BAIDU-SETUP）

> 适用于 PwdVault v1.1.6+ 云同步（Phase 3 / 方案 PHASE2-3-PLAN.md P3.4）。
> 百度网盘作为**哑存储**使用：云端只保存一个自包含的**端到端加密容器**
> （AES-256-GCM），百度无法看到任何明文数据。

## 0. 为什么需要本文档

PwdVault 通过百度网盘开放平台（OAuth2）访问你的网盘。访问需要一对
**AppKey / SecretKey**。出于安全考虑，PwdVault **不在运行时读取任何百度
凭据配置文件**，而是把它们作为**编译期占位常量**内嵌：

```rust
// src-tauri/crates/domain/src/constants.rs
pub const BAIDU_APP_KEY: &str = "";
pub const BAIDU_SECRET_KEY: &str = "";
```

发布版默认两个常量为空字符串 —— 此时百度网盘后端处于 **NotConfigured**
状态，设置页会显示本引导文案，其他功能（含 WebDAV 同步）不受影响。

## 1. 开发者注册与应用创建

1. 访问百度网盘开放平台 <https://openapi.baidu.com>（或联盟入口
   <https://pan.baidu.com/union>），使用百度账号登录并完成开发者注册。
2. 进入控制台 → **创建应用**，应用类型选择 **“网络云盘”**（网盘接入）。
3. 创建完成后记录两项凭据：
   - **AppKey**（client_id）
   - **SecretKey**（client_secret）

## 2. 注册回调地址（必须精确匹配）

在应用详情页的 **redirect URI / 授权回调地址** 中注册以下值
（OAuth 流程要求**逐字符精确匹配**，含端口与末尾斜杠）：

```
http://127.0.0.1:17777/
```

说明：
- `17777` 是 PwdVault 桌面端授权时临时监听的本地回环端口，
  刻意避开扩展桥使用的 `17429`。
- 仅监听 `127.0.0.1`，不对外网开放；监听只在授权期间存在
  （等待回调最多 5 分钟）。

## 3. 填入 AppKey / SecretKey 并重新编译

编辑 `src-tauri/crates/domain/src/constants.rs`：

```rust
pub const BAIDU_APP_KEY: &str = "<你的 AppKey>";
pub const BAIDU_SECRET_KEY: &str = "<你的 SecretKey>";
```

然后重新构建应用：

```bash
pnpm tauri build
```

> 安全说明：SecretKey 会内嵌进二进制。方案评审已接受该权衡 —— 二进制对
> 本机用户不提供机密性，而同步数据本身是端到端加密的，拿到 SecretKey 也
> 无法解密云端容器。请勿将填入凭据的源码提交到公开仓库。

## 4. 授权流程（用户视角）

1. 设置 → 云同步 → 后端选择 **百度网盘** → 点击 **授权**。
2. 应用返回授权 URL 并在系统浏览器中打开百度授权页
   （scope：`basic,netdisk`；display：`page`）。
3. 登录并点击 **授权** 后，浏览器会跳转到
   `http://127.0.0.1:17777/?code=...` —— 该请求由 PwdVault 捕获并
   显示“授权完成，请返回 PwdVault”页面。
4. 返回应用后完成连接（code 换 token 一次），token 写入**非交互凭据库**
   （macOS：无 ACL 的 Keychain 条目 `sync-baidu-token`；其他平台：
   数据目录下 0600 的 `sync-secrets.json`），**绝不会**触发 Touch ID 弹窗。
5. 之后按方案 D2 引导输入**容器密码**完成连接；此后同步免密
   （access token 过期时用 refresh token 自动刷新一次并重试；
   刷新失败则提示重新授权）。

## 5. 云端文件布局

同步只读写应用目录下的固定文件（D4）：

```
/apps/<appdir>/
  pwdvault-sync.pwsync            # 当前加密容器
  pwdvault-sync.manifest.json     # {rev, device_id, sha256, ts}
  history/pwdvault-sync-r<rev>-<device>-<ts>.pwsync   # 滚动历史（保留 10 份）
```

设置页的远程目录请填 `apps/<appdir>`（开放平台只允许第三方应用访问
`/apps` 下的文件）。

## 6. 常见问题

- **提示 “backend is not configured / 未配置”**：constants.rs 中的
  AppKey/SecretKey 仍为空，或使用了未重新编译的旧构建。
- **提示端口 17777 被占用**：上一次授权的监听仍在等待（5 分钟超时），
  稍后重试，或重启应用。
- **同步报 SYNC_AUTH_FAILED**：refresh token 已失效（长期未同步/授权被
  撤销）——在设置页重新走一次授权即可；本地数据与云端容器均不受影响。
- **删除同步连接**：仅删除本机的配置与 token；云端文件保留（多设备场景
  下其他设备不受影响），需要时可手动在网盘中删除 `/apps/<appdir>`。
