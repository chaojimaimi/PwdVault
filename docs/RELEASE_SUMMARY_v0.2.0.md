# PwdVault v0.2.0 发布总结

## 发布信息

- **版本**: v0.2.0
- **发布时间**: 2026-04-15 15:24:08 UTC
- **构建耗时**: ~6 分钟
- **Release URL**: https://github.com/chaojimaimi/PwdVault/releases/tag/v0.2.0

## 构建状态

✅ 所有任务成功完成

| 任务 | 平台 | 状态 | 耗时 |
|------|------|------|------|
| build-macos | macOS (aarch64) | ✅ | 1m29s |
| build-windows | Windows (x64) | ✅ | 4m38s |
| build-extension | Chrome Extension | ✅ | 6s |
| create-release | GitHub Release | ✅ | 15s |

## 构建产物

### macOS 安装包
- **PwdVault_0.2.0_aarch64.dmg** (3.6MB)
  - DMG 镜像文件
  - 支持 Apple Silicon (M1/M2/M3)
  - 下载: https://github.com/chaojimaimi/PwdVault/releases/download/v0.2.0/PwdVault_0.2.0_aarch64.dmg

- **PwdVault-macOS-app.zip** (3.5MB)
  - .app 应用程序包压缩文件
  - 可直接解压使用
  - 下载: https://github.com/chaojimaimi/PwdVault/releases/download/v0.2.0/PwdVault-macOS-app.zip

### Windows 安装包
- **PwdVault_0.2.0_x64-setup.exe** (~2.5MB)
  - NSIS 安装程序
  - 支持 Windows 64位
  - 下载: https://github.com/chaojimaimi/PwdVault/releases/download/v0.2.0/PwdVault_0.2.0_x64-setup.exe

### 浏览器插件
- **PwdVault-Extension.zip** (25.2KB)
  - Chrome 浏览器扩展
  - 包含所有必需文件和资源
  - 下载: https://github.com/chaojimaimi/PwdVault/releases/download/v0.2.0/PwdVault-Extension.zip

## 主要更新

### 设计系统
- ✨ 三主题设计系统（Classic、Cyber、Hybrid）
- 📐 统一的排版和间距 token
- 🎨 主题特定的视觉效果（Cyber: 空心图标, Hybrid: 柔光效果）

### UI 改进
- 🔄 水平分组标签页（替代下拉菜单）
- 🔍 带图标的搜索输入框
- ⚙️ 分组管理齿轮按钮
- 📝 重新设计的确认和删除模态框
- 🎴 卡片式分组管理界面

### 技术改进
- 🏗️ GitHub Actions 自动构建流程
- 📦 自动创建 GitHub Release
- 🔧 便捷的发布脚本 (`scripts/release.sh`)
- 📚 完整的发布文档 (`docs/RELEASE.md`)

## 发布流程

本次发布通过以下步骤完成：

1. ✅ 更新 GitHub Actions workflow
2. ✅ 修复 macOS 打包路径问题
3. ✅ 推送代码到远程仓库
4. ✅ 创建并推送 tag `v0.2.0`
5. ✅ GitHub Actions 自动触发构建
6. ✅ 所有平台构建成功
7. ✅ 自动创建 GitHub Release

## 下次发布

使用以下命令快速发布新版本：

```bash
./scripts/release.sh v0.2.1
```

或手动触发：

```bash
git tag v0.2.1
git push origin v0.2.1
```

## 已知问题

⚠️ **Node.js 20 Deprecation Warning**: GitHub Actions 提示 Node.js 20 将在 2026 年 9 月被移除。
建议在下次更新时升级相关 actions 到支持 Node.js 24 的版本。

## 验证清单

发布后建议验证以下项目：

- [ ] macOS DMG 可正常安装
- [ ] macOS .app 可正常启动
- [ ] Windows EXE 可正常安装
- [ ] 浏览器插件可正常加载
- [ ] 所有核心功能正常工作
- [ ] 数据库迁移兼容性

---

**发布人**: Andy
**发布方式**: GitHub Actions 自动构建
**仓库**: https://github.com/chaojimaimi/PwdVault
