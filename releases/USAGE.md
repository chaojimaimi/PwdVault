# PwdVault 使用说明

## 安装

### macOS

1. 下载 `PwdVault-macOS-v0.1.0.zip` 并解压
2. 将 `PwdVault.app` 拖到 `Applications` 文件夹
3. 首次打开时右键 → 打开 → 仍要打开（未签名应用提示）
4. 或终端执行：`xattr -cr /Applications/PwdVault.app`

### Windows

Windows 安装包需要通过 GitHub Actions 或 Windows 机器构建。当前版本暂不包含 Windows 安装包。

如需 Windows 版本，在 Windows 电脑上执行：
```bash
git clone https://github.com/chaojimaimi/PwdVault.git
cd PwdVault
pnpm install
pnpm tauri build
```
生成的 `.exe` 安装程序在 `src-tauri/target/release/bundle/nsis/` 目录。

### Chrome 浏览器扩展

1. 下载 `PwdVault-Extension-v0.1.0.zip` 并解压
2. 打开 Chrome → 地址栏输入 `chrome://extensions/`
3. 开启右上角 **"开发者模式"**
4. 点击 **"加载已解压的扩展程序"**
5. 选择解压后的文件夹（包含 `manifest.json` 的目录）
6. 扩展图标出现在浏览器工具栏

---

## 首次使用

### 1. 创建保险库

启动 PwdVault → 设置主密码：

- 至少 8 个字符，建议混合大小写、数字、特殊符号
- **请牢记主密码**，丢失后无法恢复数据
- 密码强度指示器会实时显示安全等级

### 2. 解锁保险库

每次启动需输入主密码。应用通过 Argon2id 算法（64MB 内存, 3 次迭代）验证密码。

### 3. 添加密码条目

- 点击右下角 **+** 按钮
- 填写标题、URL、用户名、密码
- 点击 **生成器** 按钮可自动生成强密码
- 点击 **保存**

### 4. 使用密码

- 列表页鼠标悬停 → 出现 **复制用户名** / **复制密码** 按钮
- 点击条目 → 进入详情页，可查看和编辑
- 复制的密码 **30 秒后自动从剪贴板清除**

---

## 浏览器自动填充

> **前提**：桌面应用必须在后台运行（关闭窗口不会退出，最小化到系统托盘）。

| 方式 | 操作 |
|------|------|
| 自动提示 | 访问登录页，有匹配条目时顶部弹出"填充凭据"提示 |
| 浮动按钮 | 密码输入框旁出现紫色按钮，点击选择条目 |
| 右键菜单 | 输入框右键 → "Fill with PwdVault" |
| 快捷键 | `Ctrl+Shift+L`（Mac: `Cmd+Shift+L`） |
| 扩展弹窗 | 点击工具栏 PwdVault 图标，搜索并复制密码 |

---

## 系统托盘

PwdVault 关闭窗口后继续在后台运行（托盘图标在 macOS 菜单栏）：

- **左键点击** 托盘图标 → 显示/隐藏主窗口
- **右键点击** 托盘图标 → 菜单：
  - Show PwdVault — 显示主窗口
  - Lock Vault — 锁定保险库（清除内存密钥）
  - Quit — 退出应用

---

## 安全机制

| 特性 | 说明 |
|------|------|
| 加密算法 | AES-256-GCM（每次加密使用唯一随机 nonce） |
| 密钥派生 | Argon2id（64MB 内存，3 次迭代） |
| 主密码存储 | **永不存储在磁盘**，仅通过验证头验证 |
| 剪贴板安全 | 复制密码 30 秒后自动清除 |
| 锁定保护 | 锁定后内存密钥立即清零 |
| 数据库 | redb（纯 Rust，ACID 事务） |

---

## 快捷键

| 快捷键 | 功能 |
|--------|------|
| `Cmd/Ctrl + Shift + L` | 打开自动填充面板 |
| `Cmd/Ctrl + Shift + P` | 打开扩展弹窗 |

---

## 数据文件位置

| 平台 | 路径 |
|------|------|
| macOS | `~/Library/Application Support/com.pwdvault.app/vault.db` |
| Windows | `%LOCALAPPDATA%/PwdVault/vault.db` |
| Linux | `~/.local/share/pwdvault/vault.db` |

---

## 测试凭据

- 主密码：`TestMaster123`
- 测试条目：Test Website（https://example.com / testuser）
