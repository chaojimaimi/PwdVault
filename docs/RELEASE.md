# GitHub Actions 自动构建指南

## 📦 发布流程

PwdVault 使用 GitHub Actions 自动构建 macOS、Windows 安装包和 Chrome 浏览器插件。

### 方式一：使用发布脚本（推荐）

```bash
# 自动完成所有步骤
./scripts/release.sh v0.2.0
```

脚本会自动：
1. 检查 git 状态（确保无未提交更改）
2. 检查 tag 是否已存在
3. 创建并推送 tag
4. 触发 GitHub Actions workflow
5. 监控构建进度

### 方式二：手动触发

#### 1. 通过 Git Tag 触发

```bash
# 提交所有更改
git add .
git commit -m "chore: prepare for v0.2.0 release"

# 创建并推送 tag
git tag v0.2.0
git push origin v0.2.0
```

#### 2. 通过 GitHub CLI 手动触发

```bash
# 不创建 tag，直接触发构建
gh workflow run release.yml -f version=v0.2.0
```

#### 3. 通过网页手动触发

1. 访问：https://github.com/chaojimaimi/PwdVault/actions/workflows/release.yml
2. 点击 "Run workflow"
3. 输入版本号（如 `v0.2.0`）
4. 点击 "Run workflow"

---

## 📥 构建产物

构建完成后，会生成以下文件：

| 平台 | 文件名 | 格式 | 大小 |
|------|--------|------|------|
| macOS | `PwdVault_0.2.0_aarch64.dmg` | DMG 镜像 | ~3.6MB |
| macOS | `PwdVault-macOS-app.zip` | .app 压缩包 | ~3.5MB |
| Windows | `PwdVault_0.2.0_x64-setup.exe` | NSIS 安装程序 | ~2.5MB |
| Extension | `PwdVault-Extension.zip` | Chrome 插件 | ~20KB |

### 下载位置

1. **GitHub Releases（推荐）**: https://github.com/chaojimaimi/PwdVault/releases
2. **Actions Artifacts**: https://github.com/chaojimaimi/PwdVault/actions

---

## 🔧 Workflow 配置

Workflow 文件位置：`.github/workflows/release.yml`

### 构建任务

- **build-macos**: macOS DMG + .app bundle
- **build-windows**: Windows NSIS 安装程序
- **build-extension**: Chrome 扩展打包
- **create-release**: 自动创建 GitHub Release

### 触发条件

- 推送 tag: `git push origin v*`
- 手动触发: `gh workflow run release.yml`
- 网页操作: Actions 页面点击 "Run workflow"

---

## 📝 版本号规范

- **VERSION 文件**: `0.2.0.0` (4 位数，内部版本)
- **Git Tag**: `v0.2.0` (带 v 前缀，3 位数)
- **CHANGELOG**: `[0.2.0.0]` (4 位数，带方括号)

### 版本同步

使用 `scripts/bump-version.sh` 同步所有版本号：

```bash
./scripts/bump-version.sh 0.2.1.0
```

---

## ⚠️ 常见问题

### 1. 构建失败：找不到图标文件

确保 `src-tauri/icons/` 目录下有所有必需的图标：
- 32x32.png
- 128x128.png
- 128x128@2x.png
- icon.icns (macOS)
- icon.ico (Windows)

### 2. Release Notes 为空

确保 `CHANGELOG.md` 中有对应版本的更新日志：

```markdown
## [0.2.0.0] - 2026-04-15

### Added
- 新功能...

### Changed
- 改动...

### Fixed
- 修复...
```

### 3. 无法创建 Release

检查 GitHub Token 权限：
1. Settings → Actions → General
2. Workflow permissions: "Read and write permissions"

---

## 🚀 快速开始

```bash
# 首次发布
./scripts/release.sh v0.2.0

# 等待构建完成（约 10-15 分钟）

# 下载安装包
gh release download v0.2.0 -D ~/Downloads/

# 测试安装
open ~/Downloads/PwdVault_0.2.0_aarch64.dmg
```
