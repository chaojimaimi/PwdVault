# PwdVault 实施路线图（2026-09 规划）

> 依据：2026-09 全面审计 + 三轮核查 + 业界对标调研 + 需求讨论（账号体系决策：不做自建账户；
> 多设备同步决策：走云盘 + 客户端三方合并路线）。
> 所有阶段遵循既有流程：详细方案 → plan-reviewer 评审 → ds-worker 落地 → code-review 门。

## 0. 决策基线（已定，不再重议）

| 决策           | 结论                                                                          |
| -------------- | ----------------------------------------------------------------------------- |
| 自建账户服务器 | **不做**（SaaS 重量级工程，颠覆本地-first，合规负担）                         |
| 多设备同步     | **做**，走"云盘哑存储 + 加密快照 + 客户端三方合并"路线（KeePass/Enpass 模式） |
| 加密格式       | 维持自有格式（Argon2id + AES-256-GCM + AAD），不做 Bitwarden 兼容重写         |
| redb           | 维持选型                                                                      |

## 1. 需求总账与依赖关系

```
Phase 0 安全收尾（独立，随时可做）
        │
Phase 1 密钥基建 ──→ 被三处依赖：生物识别/恢复密钥(自身)、云同步的 token 存储、
        │             丢机器场景的安全闭环
        ▼
Phase 2 数据格式 v3 一次迁移 ──→ tombstone(同步必需) + TOTP + 安全笔记字段搭同一班车，
        │                         避免多次格式迁移
        ▼
Phase 3 多设备云同步
   3A 合并引擎(本地可测) → 3B WebDAV + 同步引擎 → 3C 百度网盘适配器 → 3D 收尾
        │
        └── 附带产物：云加密备份 = 版本化快照（同步引擎的免费副产品）
```

关键联动：**格式迁移只做一次**。同步需要的 tombstone 与功能缺口（TOTP、安全笔记）
都要动条目结构，合并进同一次 v3 迁移，不分期改表。

## 2. 各阶段明细

### Phase 0 — 安全与质量收尾（~1.5 天，随时可做）

审计与使用中发现、但未进入已修复范围的遗留项：

| 项                                                      | 来源                     | 量级 |
| ------------------------------------------------------- | ------------------------ | ---- |
| 扩展握手错误文案区分"连不上"与"版本不匹配"              | 端口占用事件中的误导体验 | 小   |
| 17429 端口 bind 失败自动重试（退避）或 SO_REUSEADDR     | TIME_WAIT 场景实测踩中   | 小   |
| AccessibleDialog 非栈序关闭的 aria-hidden 快照污染      | code-review P3-1         | 小   |
| popup 选择器 `.option-row label` 改 id 定位             | code-review P3-3         | 小   |
| Tauri capabilities 增加 `fs:scope` 限定                 | 审计 P3-13               | 中   |
| 导入 KDF 下限收紧至 OWASP 底线（≥19MiB/t≥2）            | 审计建议，上云前必修     | 小   |
| AGENTS.md 更新（AppContext→三 Context、workspace 结构） | 文档债                   | 中   |

### Phase 1 — 密钥基建：改主密码 + Touch ID + 恢复密钥（~3-4 天）

三者共享同一套 wrap-key 基建，一次成型。

1. **change_password**（~1 天）：复用 `migrate_database` 的单事务全量重密封；
   新盐 + Argon2id 派生新密钥 + 新 verification 行 + digest 刷新 + 旧密钥 zeroize。
2. **Keychain 模块** `infrastructure/src/bio.rs`（~1 天）：`security-framework` +
   `SecAccessControl(BiometryCurrentSet | WhenUnlockedThisDeviceOnly)` 的
   generic-password 创建/读取/删除。
3. **生物识别解锁**（~1.5 天）：启用时生成 32B wrap_key 入 Keychain，主密钥
   AES-GCM 包装（AAD 绑定 `pwdvault-bio-v1`）后入 settings；解锁 = Touch ID →
   解包 → verification 校验 → 注入 session。边界：指纹集变化失效重启用、
   无 Touch ID 机型隐藏开关、改密码后自动 re-wrap。
4. **恢复密钥 / Emergency Kit**（~1 天）：同一 wrap 机制的第二把钥匙
   （32B 随机、打印保存、独立 AAD 域），忘主密码时解包重设。

验收：改密码后 Touch ID/恢复密钥仍有效；忘密码可用恢复密钥重置；锁定后
Keychain 之外的内存密钥照旧 zeroize。

### Phase 2 — 数据格式 v3：一次迁移带三件事（~1.5 天，含测试）

- tombstone：条目/分组增加 `deleted_at` 软删除，90 天 GC（同步必需）；
- **TOTP 字段**：`totp_secret`（加密属性，业界需求最高的功能缺口）；
- **安全笔记字段**：`notes` 已存在则确认纳入合并模型，缺失则补；
- 沿用版本化迁移注册表 + golden fixtures 回归矩阵。

> TOTP 生成器 UI（30s 动态码）可在本阶段或 Phase 3 后实现，数据层先行是为
> 了让 v3 迁移一次到位。

### Phase 3 — 多设备云同步（总计 ~10 天，分四个可交付里程碑）

架构：本地 redb 工作副本 + 主密码加密的可合并快照 + 云盘哑存储 + 客户端三方合并。

**3A 合并引擎（~4 天，本地可独立验证）**

- 快照格式 v3（.pvault 演进：+ tombstones + 设备 ID + base revision）；
- 三方合并语义：UUID 匹配、`updated_at` LWW（tiebreak 设备 ID）、
  删除 vs 修改按时间裁决；随机操作序列属性测试。

**3B 同步引擎 + WebDAV（~4 天）**

- `CloudBackend` trait：stat / conditional-upload / download / list-versions；
- WebDAV 适配器（ETag/If-Match 乐观并发）——坚果云、Nextcloud 全覆盖；
- 同步状态机：解锁态拉取 → 合并 → 条件上传；防抖/定时/手动 Sync now；
- 版本轮换：`sync-<设备>-<时间戳>.pvault` 保留最近 N 份（**云备份由此免费达成**，
  另提供"仅备份不同步"单向上传模式）。

**3C 百度网盘适配器（~2 天）**

- 开放平台 OAuth2（公共客户端/PKCE 设计，Secret 不当机密）；
- refresh token 存 Keychain（Phase 1 基建）；manifest revision 比对交换；
- 滚动版本兜底竞态。

**3D 收尾（~1 天）**

- 改主密码联动：重加密远端容器 + 旧版本失效指引（丢机器场景闭环）；
- 设置页同步状态/冲突提示；文档与发布说明。

## 3. 明确不做 / 存疑清单

| 项                          | 状态                                                |
| --------------------------- | --------------------------------------------------- |
| 自建账户服务器              | 不做（0 节决策）                                    |
| Bitwarden 兼容客户端        | 存疑（= 换产品定位，除非明确要接其生态）            |
| 密码提示（明文自设）        | 可选低优先（安全收益争议）                          |
| 本地多档案（多人共机）      | 按需（未被明确提出，留待用户诉求）                  |
| Windows Hello               | 二期后续（DPAPI + UserConsentVerifier，独立工作量） |
| 双因素锁定类后门/云托管密钥 | 永不做                                              |

## 4. 里程碑与节奏建议

| 里程碑   | 内容                                           | 累计聚焦工时 |
| -------- | ---------------------------------------------- | ------------ |
| M0       | Phase 0 收尾                                   | ~1.5 天      |
| M1       | 改主密码 + Touch ID + 恢复密钥（安全闭环成型） | ~5.5 天      |
| M2       | 格式 v3（为同步与 TOTP/笔记铺路）              | ~7 天        |
| M3B      | WebDAV 多设备同步可用（含云备份）              | ~11 天       |
| M3C      | 百度网盘接入                                   | ~13 天       |
| 并行可选 | TOTP/笔记 UI、Windows Hello                    | —            |

每阶段完成即发布（tag + CHANGELOG），M1/M3B 是两个值得单独发版的用户可感知节点。

## 5. 风险对冲备忘

- LWW 合并的用户预期：UI 明示 + 版本保留可手工找回（业界标准语义）；
- 百度 API 政策风险：CloudBackend 抽象 + WebDAV 主推对冲；
- 云端密文暴露：导出/同步 KDF 强制达标（Phase 0 的 KDF 收紧是前置）；
- 忘主密码：恢复密钥（M1）+ 云端版本化快照（M3B）双重兜底；
- 每阶段落地前走完整流程：详细方案 → plan-reviewer → ds-worker → code-review。
