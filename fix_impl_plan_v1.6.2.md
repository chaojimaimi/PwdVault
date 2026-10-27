# fix_impl_plan_v1.6.2 — 备份恢复去重（保留原始 id）+ 恢复对话框可用性

> 状态: R3 **PASS**（R2 复审通过；评审员 P2/P3 文档级修订已并入）
> 来源: 真机 QA 两个发现（2026-10-27）+ 代码级根因定位（本会话侦察，行号已核对）
> 范围: backup.rs（恢复路径）、ImportExportScreen.tsx、components.css + 两侧测试
> 明确不做: CSV 导入的 re-id 保留（真合并语义，见 §5）；merge.rs 逻辑零改动；扩展零改动

---

## 0. 两个 QA 发现的根因（已核对到行）

### 发现 1 — 输错确认词点 Restore 无任何反应

`ImportExportScreen.tsx:493` 的门控是**正确的**：
`disabled={importing || restoreConfirmation !== "RESTORE"}`。输入 "RESTOR" 时按钮
确实被禁用——但 `.btn-danger` **没有任何 `:disabled` 样式**。components.css 里只有：

- `.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }`（:62-65）
- `.btn-secondary:hover:not(:disabled)` 存在但同样没有 `:disabled` 规则
- `.btn-danger` 只有 hover 规则（:82-84）

禁用的危险按钮和可用状态长得一模一样，界面上也没有任何文字告诉用户"要输入什么才能继续"。
纯可用性缺陷，逻辑无 bug。同页面 CSV 选择按钮（:373 `btn-secondary` disabled）也有同样的
隐形禁用问题。

### 发现 2 — 删除后再同步，条目和分组 ×2 复制

三层机制叠加（潜伏自 v1.1.6 软删除 + v1.4.0 同步 + 恢复功能组合使用才暴露）：

1. **恢复路径给所有行铸造新 id**。`backup.rs:400-412 remap_import_groups` 用
   `Group::new`（新 UUID + created_at/updated_at 全部重置为 now）；`backup.rs:416-479
   encrypt_import_entries` 用 `PasswordEntry::new`（新 UUID），只回填 created_at/updated_at。
   注释自称 "new IDs avoid conflicts with the live vault"（:398-399）。
2. **import_vault 是替换语义，id 冲突根本不可能发生**。backup.rs:551-578：先收集
   existing ids 全部 remove（**包括本地墓碑**），再插入新行，单事务。re-id 的防御理由
   在替换语义下是空防御——纯粹的害处。
3. **同步按 id 并集 LWW 合并**。`sync/merge.rs:93-135`：id 相同才配对仲裁，id 不同
   就是两行并存。恢复清掉了本地墓碑（替换语义）→ 删除从未上云 → 下一次同步
   local{新 id live} ∪ remote{旧 id live} → 两份都 live 并回发布 → 每台设备 ×2。

用户实际复现路径还原：删除条目/分组（本地墓碑）→ **恢复旧备份**（替换清掉墓碑 +
新 id 副本）→ 同步（云上旧 id live 从未被删，与本地新 id live 无 id 交集）→ 双份。
分组同理（截图中 "Yonyou Personal Personal Yonyou"）。

**保留原始 id 后的正确收敛**（merge.rs 既有规则自动成立，无需改 merge）：

| 云上状态 vs 恢复行（同 id） | pair_is_conflict 判定 | 结果 |
| --- | --- | --- |
| 云更新（edited_at > 备份时刻） | 双 live、时间戳不等 → 非冲突 | LWW 云内容胜，单份 |
| 云墓碑（deleted_at > 备份时刻） | live.updated_at(备份时刻) ≤ deleted_at → 非冲突（`<=` 陈旧副本规则 :183-186） | 删除维持，不复活 |
| 云墓碑（deleted_at < 备份时刻，即备份出自删除后仍编辑过该条目的设备） | live.updated_at > deleted_at → **冲突**（R1 评审 P2 补） | 计冲突 +1，备份内容 live（merge.rs:214 live-wins，winner 为恢复行） |
| 内容一致（时间戳也相同） | 指纹相等 → 非冲突 | 静默去重，单份 |
| 备份比云新 | 双 live → 非冲突 | LWW 本地胜并回推，符合恢复语义 |

## 1. 目标

恢复备份后无论是否启用同步，都不产生重复；恢复对话框的禁用/确认状态对用户可见。

## 2. 工作包

### WP1 (Rust) — F1: 恢复保留 payload 原始 id + 回归测试

**文件: `src-tauri/crates/application/src/service/backup.rs`**

1. `remap_import_groups`（:400-412）→ 改名 `import_groups(payload: &BackupPayload) ->
   Vec<Group>`：直接返回 `payload.groups.clone()`。payload.groups 本来就是完整 domain
   `Group`（导出于 :184-197），id/name/created_at/updated_at 全量在备份里——顺带修复
   现在恢复会丢分组时间戳的隐性缺陷。删除 group_id_map。
2. `encrypt_import_entries`（:416-479）：去掉 group_id_map 参数；`PasswordEntry::new`
   之后加 `entry.id = export_entry.id.clone();`；`entry.group_id = export_entry.group_id.clone()`
   （替换原 :443-447 的 map 间接）；其余逐字保留。
3. `prepare_import_rows`（:485-492）签名随之简化。
4. **墓碑分组拒绝校验（R1 评审 P1）**：现状 re-id 经 `Group::new` 意外充当净化层
   （deleted_at 洗成 None）；改 clone 后该层消失——手改的 .pvault 可携带墓碑分组
   直接入库并经同步传播为对其他设备的删除。补法：`domain/validation.rs` 的
   `backup_payload`（:335-405，现查数量/重名/id/悬挂引用）增加拒绝
   `group.deleted_at.is_some()`（TOMBSTONED_GROUP_IN_BACKUP），与导出侧过滤
   （backup.rs:184-187）构成对称不变量"备份 payload 只含 live 行"。严格向后兼容：
   一切合法导出均无墓碑；v1.1.6 前备份 serde default → None。
5. 文档注释重写（:398-399、:414-415、:481-484）：新不变量 = 替换语义使 id 冲突不可能；
   保留 id 是同步收敛的前提（引用 §0 的五种收敛结果表）；跨金库恢复同一备份 → 相同 id
   相同内容 → 静默去重，仍正确。
6. 导出侧注释（:85-87 "restoring an older backup can still re-add a deleted entry
   under its old ID"）保持准确且成为期望行为，补一句指向新收敛语义。

**测试（`backup_tests.rs` / `tests_merge.rs`，红→绿）**

- `import_preserves_entry_and_group_ids`：构造已知 id/timestamps 的 payload → import →
  list 断言 id、created_at/updated_at（分组）、group_id 关联逐一相等。**修复前必红**。
- `import_rejects_tombstoned_group`（R1 评审 P1）：payload 带一个
  `deleted_at: Some(t)` 的分组 → import 拒绝（断言 VaultError 校验错误）。
  **校验落地前必红**（现状被 re-id 洗白不报错）。
- `restore_converges_with_cloud_without_duplication`（merge 层）：本地 = 恢复快照
  （备份 id、T0），远端 = **四个 id 各一行，与本地恢复快照逐 id 配对**：一条云更新
  （T1>T0）、一条云墓碑（deleted_at>T0）、一条云墓碑（deleted_at<T0，R1 评审 P2）、
  一条完全一致 →
  `merge_snapshots` 断言：无重复 id、云新内容胜、墓碑(新)维持删除、墓碑(旧)复活且
  conflict_count==1、指纹一致行静默去重。此测试钉住修复所依赖的收敛契约
  （双向绿色，文档化机制）。

### WP2 (前端) — F2 同步警告 + F3 禁用可见性 + 测试

**F2 — `ImportExportScreen.tsx`**

- 打开确认对话框（showImportConfirm=true）时 `syncStatus()`（api/vault.ts:246，已存在）
  取一次（effect + 防重入；卸载后 setState 防护）。
- `enabled === true` 时在对话框 body（确认词输入框之前）渲染一行同步警告。文案注意
  `enabled` 的真实语义是"已配置并开启"而非"最近同步成功"（engine.rs:602-604），
  第二句需限定删除传播前提（R1 评审 P3）："Cloud sync is active — after restoring,
  the next sync merges both sides by timestamp (newer wins). Entries deleted after
  this backup was taken stay deleted once their deletion has synced."
  样式复用既有 warning/hint 类，不新造主题 token。
- 请求失败 → 警告缺席、对话框正常（advisory-only，静默降级是明确设计）。

**F3 — `components.css` + `ImportExportScreen.tsx`**

- 新增 `.btn-danger:disabled` 与 `.btn-secondary:disabled`，逐字镜像
  `.btn-primary:disabled`（opacity: 0.5; cursor: not-allowed;）。**不做全局 `.btn:disabled`**
  （v1.5.1 教训：全局 .btn 改动爆炸半径大；此处按变体补齐即可）。
- 确认词输入框下方加实时提示（v1.6.1 确认框 error 通道同款模式）：**输入非空且 ≠
  "RESTORE" 时**显示 "Type exactly RESTORE to continue (case-sensitive)"
  （aria-live="polite"；空输入不显示，避免与紧邻 label :472 重复且打开瞬间播报
  aria-live——R1 评审 P3）；值精确匹配后隐藏。禁用按钮变暗 + 提示文字双通道，
  用户不再面对无声按钮。

**测试（新增 `__tests__/ImportExportScreen.restore.test.tsx`，参照 csv.test.tsx 的 mock 模式）**

- 对话框初始（输入为空）→ 提示不可见；输入 "RESTOR" → 提示可见 + Restore 按钮
  disabled；补全为 "RESTORE" → 提示消失 + 按钮可用。
- syncStatus mock enabled=true → 警告行渲染；enabled=false → 不渲染；
  mock reject → 对话框照常渲染（无警告、无崩溃）。

## 3. 风险与核对项

- **golden 合同不受影响**：golden 钉的是序列化字节，不涉及 import id 行为；已核对
  backup 两侧测试文件无任何 re-id 依赖断言（grep 零命中）。WP1 跑全量 workspace 测试确认。
- **跨金库恢复**：备份 id 进入不同金库——替换语义先清空，无碰撞可能；两金库后续同步
  同一备份内容 → 同 id 同内容静默去重（正确）。文档注释里写明。
- **行数预算**：backup.rs 净减（删 map 间接）；ImportExportScreen.tsx 503 行 +约 35 行
  ≈ 538，余量充足。
- **jsdom 看不见 CSS**（.btn 陷阱记忆）：F3 的禁用变暗只能真机验收，QA 项里立 T 项
  （两主题各看一次）。

## 4. 验收

1. `cd src-tauri && cargo test --workspace` 全绿（含新 3 测试）。
2. `pnpm test` CI-true 干净 worktree（含新 restore 测试文件）。
3. `pnpm typecheck` 通过。
4. rust-reviewer + react-reviewer 评审，P0-P2 清零。

## 5. 明确不在本批

- **CSV 导入保持 re-id**：CSV 是往活金库里追加（真合并语义），新 id 是正确行为，
  ImportExportScreen.tsx:362-363 注释已写明，勿动。
- merge.rs、publish.rs、engine.rs 零改动（收敛完全靠既有 id-union LWW）。
- 扩展、同步容器格式、codec 链零改动。
- 已重复金库的自动清理不做（用户已拿到手动清理配方；自动检测重复是独立功能项）。
