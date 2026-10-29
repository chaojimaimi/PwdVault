# PwdVault

A secure, local-first password manager built with Tauri + React.

**Last Updated**: 2026-10-29
**Repository**: https://github.com/chaojimaimi/PwdVault (Public)
**Release**: https://github.com/chaojimaimi/PwdVault/releases/tag/v1.7.0
**Current Version**: `v1.7.0` — 2026-10-29 M-tier batch (auth screens redesigned: Setup/Unlock/Recovery share the sanctioned immersive navy→teal glow + frosted-glass card with brand shield/tagline/show-hide toggles under scoped `.auth-*` styles — the one DESIGN.md decorative exception; lock-screen recovery-key status hint with a three-state probe that asserts nothing on transport failure; real weak-password detection: zxcvbn 3.1.1 engine on the Rust dashboard (wire score now 0–4 pattern tiers) + a 9,952-entry weak-password corpus with Chinese-context classics shared byte-identically across desktop TS / extension JS / Rust under a three-way sync guard + keyboard-walk penalty — Test@1qaz / Admin@123 / P@ssw0rd123-class passwords that satisfied every character rule were scored "Strong" by the old heuristic and are now flagged weak everywhere) on top of v1.6.3 tech-debt train (extension JS split under the 800-line cap — content.js 2159 → frozen domain-match block + four cohesive modules + 157-line entry riding a globalThis.PwdVaultContent namespace, background.js 1073 → native/commands modules, popup.js explicitly exempted with a tracked marker; permanent CI line-count guard; .btn global width:100% inverted to content-width default + explicit .btn-block — ends the four-crash flex-starvation trap) on top of v1.6.2 restore-duplication fix (backup restore keeps the payload's original entry/group ids and group timestamps — ends the delete+sync ×2 duplication whose root cause was re-id meeting REPLACE semantics; backup validation now rejects tombstoned groups; typed-RESTORE gate made visible with per-variant disabled dimming + live hint; restore-dialog cloud-sync advisory) on top of v1.6.1 acceptance patch (confirm-dialog error channel — save rejections were invisible behind the modal overlay; errorMessage strips the raw `CODE:` transport prefix; custom-field values lazy-load on section focus / row-reveal through the shared secret channel; spellcheck off + form-group rhythm) on top of v1.6.0 M-tier kernel batch (per-entry custom fields on a four-generation entry codec, sync container v3 + LWW conflict counter + opt-in auto-sync behind the sync_cycle leaf lock, browser-extension save/update prompt backed by a digest-only verify command, backup fidelity fix — .pvault now carries the TOTP/match-mode/custom-fields it had been silently dropping since v1.1.6/v1.5.0) + v1.5.1 UI patch + v1.5.0 M-tier product batch (security dashboard with in-process aggregation, 4-vendor CSV importers, trash auto-purge, per-entry URL match override on a three-generation codec + sync container v2, pair toast caller digest) + v1.4.1 trash-tab UI patch + v1.4.0 S-tier product batch (eTLD+1 autofill matching with fail-closed suffix table, passphrase/PIN generator + session history, recently-used sorting + recycle bin, global shortcut) + updater stack modernization (updater 2.14.0 / tauri 2.12.5 / wry 0.57.1; zip allowlist extended to 2027-06-30 — no zip ≥9 exists upstream yet) + v1.3.2 Shadow DOM/IPC sanitization + v1.3.1 clipboard redesign + v1.3.0 bincode swap + v1.1.9/v1.2.0 hardening + Phase 0-3 features
**Current Branch**: `main`

---

## 1. Project Architecture & Key Files

### Tech Stack

- **Frontend**: React 19 + TypeScript + Vite
- **Backend**: Tauri v2 + Rust
- **Database**: redb (pure Rust, ACID-compliant, embedded)
- **Encryption**: AES-256-GCM + Argon2id key derivation
- **Browser Extension**: Chrome/Firefox MV3 via Native Messaging bridge
- **CI/CD**: GitHub Actions (macOS + Windows builds)

### Directory Structure

```
PwdVault/
├── src/                          # React frontend
│   ├── App.tsx                   # Main app component with screen routing
│   ├── main.tsx                  # React entry point
│   ├── api/
│   │   └── vault.ts              # Unified Tauri/HTTP API client
│   ├── components/               # Shared UI: TotpSecretField, TagsEditor, modals…
│   │   ├── CustomFieldsEditor.tsx  # Custom fields editor (v1.6.0)
│   │   └── EntryGeneratorModal.tsx # Entry-screen generator modal
│   ├── context/
│   │   ├── AppContext.tsx        # Provider composition bucket (useApp facade removed);
│   │   │                         # state lives in the three Contexts below
│   │   ├── AuthContext.tsx       # Unlock/session state
│   │   ├── SettingsContext.tsx   # Auto-lock timeout, generator defaults
│   │   └── VaultContext.tsx      # Entries/groups/selection
│   ├── screens/
│   │   ├── SetupScreen.tsx       # Initial vault creation
│   │   ├── UnlockScreen.tsx      # Master password input
│   │   ├── VaultScreen.tsx       # Password list view with group tabs + fuzzy search
│   │   ├── EntryScreen.tsx       # Add/Edit password entry with strength meter
│   │   ├── GeneratorScreen.tsx   # Password generator with strength display
│   │   ├── GroupManager.tsx      # Create/rename/delete groups
│   │   ├── SettingsScreen.tsx    # Auto-lock timeout, default generator options
│   │   ├── ImportExportScreen.tsx # Encrypted backup/restore (.pvault)
│   │   └── useCustomFields.ts    # Custom-fields state + save assembly hook (v1.6.0)
│   ├── styles/
│   │   ├── themes.css            # Design tokens (shared + Light/Dark color overrides)
│   │   ├── base.css              # Global reset, scrollbar, accessibility
│   │   ├── components.css        # Buttons, inputs, modals, toasts, icons
│   │   ├── screens.css           # Entry/generator screen layouts
│   │   ├── vault.css             # Vault list, search, group tabs
│   │   ├── groups.css            # Group manager styles
│   │   └── settings.css          # Settings, theme selector, import/export
│   ├── types/
│   │   └── index.ts              # TypeScript type definitions
│   └── utils/
│       ├── passwordStrength.ts    # Password strength calculator
│       ├── clipboard.ts          # Clipboard with 30s auto-clear
│       ├── urlMatchMode.ts       # URL match-mode options + normalizer (v1.6.0)
│       └── toast.ts              # Toast notification system
│
├── src-tauri/                    # Rust backend (Cargo workspace)
│   ├── src/                      # Tauri adapter layer (tauri-app crate)
│   │   ├── main.rs               # Binary entry point
│   │   ├── lib.rs                # Tauri setup + state + system tray
│   │   ├── commands.rs           # #[tauri::command] IPC wrappers (incl. touch_activity heartbeat)
│   │   └── native_messaging.rs   # HTTP server (port 17429) for browser extension
│   ├── crates/                   # Business-logic workspace members (§5.6.3)
│   │   ├── domain/               # constants, DTOs, entities, validation
│   │   ├── infrastructure/       # crypto (cipher/kdf/keystore/verification), redb database,
│   │   │                         #   auth, pairing, paths, native_host_setup
│   │   └── application/          # AppState, session, VaultError, services (incl. backup), fixtures
│   ├── tests/                    # capability_contract.rs, golden_contract.rs
│   ├── Cargo.toml                # Workspace root + tauri-app dependencies
│   └── tauri.conf.json           # Tauri configuration
│
├── extensions/                   # Browser extension
│   ├── chrome/                   # Chrome extension
│   │   ├── manifest.json          # MV3 manifest
│   │   ├── src/
│   │   │   ├── background.js      # HTTP API communication
│   │   │   ├── content.js         # Auto-fill + form detection + floating button
│   │   │   ├── content.css
│   │   │   └── popup/            # Popup UI (search, copy, show/hide password)
│   │   └── icons/
│   ├── firefox/                   # Firefox extension (MV3, symlinks to chrome/)
│   │   ├── manifest.json          # Firefox MV3 manifest with gecko settings
│   │   ├── src → ../chrome/src/   # Symlink to shared source
│   │   └── icons → ../chrome/icons/ # Symlink to shared icons
│
├── .github/workflows/
│   └── release.yml               # CI: macOS + Windows + extension builds
├── releases/                     # Local release artifacts
├── scripts/
│   └── bump-version.sh           # Version sync across 10 files
├── DESIGN.md                     # Design system specification (Light/Dark themes)
├── VERSION                       # SemVer product version
├── CHANGELOG.md
├── password_generator_analysis.md # Password generator security analysis & fixes
└── AGENTS.md                     # This file
```

### Key Architectural Decisions

1. **Unified API Client** (`src/api/vault.ts`):
   - Tauri IPC only; throws if not in Tauri environment
   - Browser extension uses its own background.js with Native Messaging + HTTP API

2. **Shared AppState**:
   - Tauri desktop app and HTTP server share the same `Arc<AppState>`

3. **System Tray** (`src-tauri/src/lib.rs`):
   - Close window hides to tray, keeps HTTP server running
   - Tray menu: Show, Lock Vault, Quit
   - Left-click tray icon restores window

4. **Browser Extension Communication** (Native Messaging bridge):
   - Extension uses `sendNativeMessage('com.pwdvault.app', ...)`
   - Bundled host validates the browser caller and bridges to the bounded
     loopback desktop API

5. **Security Model**:
   - Master password never stored on disk
   - Argon2id key derivation (64MB memory, 3 iterations)
   - AES-256-GCM with unique nonce per encryption
   - Clipboard auto-clear after 30 seconds
   - Key zeroized on lock/quit

---

## 2. Current Status

### v1.0.0 (2026-05-01) — Released

**Completed: Phase G — v1.0 Release Preparation**

- **G1** Firefox extension — MV3 adaptation with gecko-specific manifest, symlink to shared source
- **G2** Test credential cleanup — verified no leaked credentials
- **G3** Documentation update — CHANGELOG, AGENTS.md, README.md all current
- **G4** Security checklist — CSP hardened, keystore .expect(), cargo audit in CI, .env in .gitignore
- **G5** CSP policy — replaced `null` with restrictive policy (script-src 'self', connect-src localhost only)
- **F2** Update notification — checks GitHub Releases for newer versions
- **F4** Rate limiting — 5 failed unlocks → 60s lockout

### v0.3.1 (2026-04-30)

**Completed: Frontend Redesign + Security Features**

- Light/Dark dual-theme system replacing Classic/Cyber/Hybrid
- Modular CSS: `App.css` (1300+ lines) split into 6 files
- New components: `BackHeader.tsx`, `Icons.tsx`, `StrengthMeter.tsx`, `UpdateNotification.tsx`
- Browser extension synced with Light/Dark theme system

### v0.3.0 (2026-04-17) — Released

**Completed: Phase E — User Features**

- **E1** Encrypted import/export — `.pvault` backup files with independent export password, AES-256-GCM + Argon2id
- **E2** Fuzzy search — fuse.js weighted search across title/username/URL/tags
- **E4** Settings screen — auto-lock timeout (1–60 min), default generator options, persisted to redb
- Added `ImportExportScreen`, `SettingsScreen`, `GroupManager` screens
- Added `themes.css` two-theme design system (Light/Dark)
- Browser extension updated with export/import API + group support + theme switching
- Security hardening: zeroization of plaintext passwords/notes, correct adaptive KDF params

### v0.2.0 (2026-04-15)

**Completed: Phase D — Project Identity**

- **D1** Rewrote README.md
- **D2** Brand icon verified across extension + Tauri
- **D3** CI DMG packaging for macOS
- **D4** Version sync script (`scripts/bump-version.sh`)
- Design system: three themes (Classic/Cyber/Hybrid) with CSS custom properties
- VaultScreen UX: group tabs, search input, redesigned modals
- Release: DMG (3.6MB) + app bundle (3.5MB) + extension (20.8KB)

### v0.1.3 (2026-04-01)

- Auto-lock race condition fix
- 48 Rust tests + 17 frontend tests
- Password generator security fix (shuffle-guarantee algorithm + OsRng)

### v0.1.1 (2026-03-31)

- Auto-lock (10 min timeout), tray menu state sync, browser extension create entry

### v0.1.0 Release (2026-03-27)

- Initial release: Tauri v2 + React 5 screens, AES-256-GCM + Argon2id, redb, HTTP API, Chrome extension, CI/CD

**Test Suite Summary** (counts from actual test output, 2026-10-29):

| Module                    | Tests                                                                                                                                                                            | Command                                   |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| Rust tauri-app lib        | 42                                                                                                                                                                               | `cd src-tauri && cargo test`              |
| Rust capability contract  | 1                                                                                                                                                                                | (same run)                                |
| Rust golden contract      | 3                                                                                                                                                                                | (same run)                                |
| Rust application crate    | 244                                                                                                                                                                              | `cd src-tauri && cargo test --workspace`  |
| Rust infrastructure crate | 133 (+1 ignored keychain SecItem smoke, CI 跑)                                                                                                                                   | (same run)                                |
| Rust domain crate         | 26                                                                                                                                                                               | (same run)                                |
| Rust native-host          | 23                                                                                                                                                                               | `cd extensions/native-host && cargo test` |
| Frontend + extension      | 694 (82 files; vitest collects chrome/ AND firefox/ via symlink — extension tests double-count by design; local `pnpm test` may report more if `dist/`/`releases/` copies exist) | `pnpm test`                               |

> **Note**: Rust tests no longer require `--test-threads=1` — the keystore is
> now per-`AppState` (A3), so parallel test execution is safe.

---

## 3. Roadmap

### Phase G — v1.0 Release ✅ Completed

- [x] **G1** Firefox extension (MV3, gecko manifest, shared source via symlink)
- [x] **G2** Clean up test credentials from docs (verified clean)
- [x] **G3** Update CHANGELOG + AGENTS.md
- [x] **G4** Security checklist (CSP hardened, cargo audit in CI, .env in .gitignore, keystore .expect())
- [x] **G5** Tighten CSP in tauri.conf.json (null → restrictive policy)

### Phase D — Project Identity (v0.2.0) ✅ Completed

- [x] **D1** Rewrite README.md with actual project info
- [x] **D2** Design PwdVault brand icon (SVG lock+shield, generate all sizes)
- [x] **D3** CI DMG packaging for macOS
- [x] **D4** Version sync script (`scripts/bump-version.sh`)

### Phase E — User Features (v0.3.0) ✅ Completed

- [x] **E1** Encrypted import/export (JSON backup/restore)
- [x] **E2** Fuzzy search (`fuse.js`, threshold=0.3)
- [x] **E3** Categories/folders (replaced by groups — implemented as `group_id` field)
- [x] **E4** Settings screen (auto-lock timeout, default generator options, redb `settings` table)

### Phase F — Distribution & Security (partial)

- [ ] **F1** macOS signing + notarization (requires Apple Developer account) — _skipped_
- [x] **F2** Update notification (checks GitHub Releases on startup)
- [ ] **F3** Linux build (.deb + .AppImage) — _skipped_
- [x] **F4** HTTP API rate limiting (5 failed unlocks → 60s lockout)

### Future (post-v1.0)

- [x] Biometric unlock — Touch ID (macOS Keychain wrap key, v1.1.6); **Windows Hello remains**
- [x] TOTP/2FA generator (v1.1.6 Phase 2)
- [x] Multi-device sync — encrypted container on the user's own cloud drive, LWW merge, conflict counter, auto-sync (v1.1.6 Phase 3 + v1.6.0)
- [ ] Secure notes (dedicated note-type entries beyond the existing notes field)
- [ ] Breach monitoring (HIBP) — **needs a privacy decision first**: k-anonymity hash prefixes leave the device
- [ ] Mobile apps (Tauri Mobile)
- [ ] Windows Hello biometric unlock (mirror of the Touch ID stack)
- [ ] Duplicate-entry auto-detection in the dashboard (same title+username) — post-v1.6.2 nice-to-have; real-vault cleanup recipe lives in qa_manual T53.5
- [ ] Extension popup.js split (1693 lines, single PopupApp class — the only LINE-CAP EXEMPTION; CI guard asserts exactly one)
- [ ] Extension native-host signing for distribution (bundle with F1)
- [ ] zip ≥9 / tauri-plugin-updater upgrade — allowlist expires **2027-06-30**, drags wry across minors
- [ ] Extend the local ZCode commit-gate hook to .js/.css (user-level infra; the in-repo CI guard covers CI, the local gate still checks .rs only)

---

## 4. Important Decisions

| Decision       | Choice                                                | Rationale                                                                   |
| -------------- | ----------------------------------------------------- | --------------------------------------------------------------------------- |
| Database       | redb                                                  | Pure Rust, no external deps, ACID-compliant                                 |
| Key storage    | Memory only                                           | Max security, key gone on power off                                         |
| Extension comm | Native Messaging → stdio host → HTTP API (port 17429) | Official browser API; host binary bridges stdio to the existing HTTP server |
| Cloud sync     | None (local-first)                                    | Simpler, no server costs, max privacy                                       |
| System tray    | Close-to-tray                                         | Keeps HTTP server alive for extension                                       |

---

## 5. Development Commands

```bash
# Development
source ~/.cargo/env && pnpm tauri dev

# Build macOS
pnpm tauri build --bundles app

# Build all platforms
pnpm tauri build

# Type check
pnpm tsc --noEmit

# Rust tests (parallel-safe; keystore is per-AppState)
cd src-tauri && cargo test

# Frontend tests
pnpm test

# Frontend tests (watch mode)
pnpm test:watch

# Trigger CI build
git tag vX.Y.Z && git push origin main --tags
```

---

## 6. Security Notes

- Master password is zeroized after key derivation
- All sensitive data encrypted with AES-256-GCM before database storage
- Verification header validates master password without revealing key
- Nonces randomly generated per encryption operation
- Database file locked exclusively while open
- Clipboard auto-clears after 30 seconds
- Key zeroized on vault lock or app quit
- Password/Touch ID unlock serializes against the exclusive D8 windows and
  re-validates the verification header before publishing keys (v1.1.9)
- The webview holds no filesystem capability — backup/recovery-key file IO
  is done by desktop Rust commands via native dialogs (v1.1.9)
- Cloud-sync plaintext-domain structures zeroize on drop (v1.1.9)
- Desktop input maintains the full auto-lock window; explicit vault
  operations (including paired-extension calls) extend only a 120s grace —
  unattended desktops lock even with a paired extension idle (v1.2.0)
- Sync config/state rows are encrypted at rest with read-time legacy
  migration and re-seal key rotation (v1.2.0)
- Custom field values are inner-encrypted like notes and leave the vault
  only through `get_entry_secret` (v1.6.0)
- `verify_entry_password` answers a constant-time SHA-256 digest
  comparison and never returns plaintext (v1.6.0)
- Extension save prompt: captured credentials live only in the
  page-side closure until the user confirms (≤60s); the background
  worker never holds them (v1.6.0)
- Backup payloads containing tombstoned groups are rejected on import
  (`TOMBSTONED_GROUP_IN_BACKUP`) — the export side's live-only filter
  is now a symmetric import-side invariant; preserved payload ids make
  restore converge with sync instead of duplicating (v1.6.2)

---

## 7. Session Log

### 2026-10-29 (v1.7.0 — auth redesign + recovery-key hint + real weak-password detection)

Pipeline: 高保真稿三选一（用户定稿「沉浸渐变 + 品牌极简表单」合并版）→ recon
（发现强度打分三份实现：桌面 TS / 扩展 JS / Rust）→ plan R1 → plan-reviewer
REVISE（1×P0：10k 行语料文件必击穿 CI 800 行守卫；4×P1：核心词算法被推演证伪
——归一化焊段、语料主源是上游已删除的 SecLists 路径、"非弱"谓词未定义、核心词
清单缺失）→ R2 REVISE（1×P1：Test@1qaz 走位罚分 -10×2=48 压不进弱档 → -15；
1×P2：哨兵需 zxcvbn 冻结前实测）→ R3 **fast-pass**（评审授权）→ 主代理预钉
语料数据（xato top-10000 @ commit c205c36 过滤 + 中文补充集 = 9952 条）→ 双
worker 并行（WP1 Rust / WP4 认证屏）→ 顺序 WP2（TS）→ WP3（JS 同步+守卫）→
主代理修复 WP1 测试滞后（famous-forms 锚点入语料后 corpus.rs 断言同步）→ 双域
审查（rust **APPROVE** 0 P0-P2, 3×P3；react **APPROVE** 0 P0-P2, 3×P3）→
P3 折叠两条（strength.rs 过时覆盖注释 10/12→11/12；锁屏提示改三态探测——探测
失败不再断言"未设置恢复密钥"这个未经验证的事实，新增拒绝路径测试）→ 其余 P3
记录在案（zxcvbn 双跑、corpus 双小写化、focusOnMount ref 重挂既有缺陷、
securityScoreLabel 落点）。

Shipped: 认证三屏 `.auth-*` 换壳（径向光晕 + backdrop-blur 玻璃卡 + 盾徽/标语/
显隐眼 + 恢复密钥底部两态提示；components.css 的 .btn/.card 零改动——v1.6.3
教训写进计划红线）。弱口令检测两层架构（§2 是本班车最重要的决定）：**zxcvbn
3.1.1 仅落 Rust**（crate 无自定义词典 API，已 docs.rs 验证；classify_password
= 空串→Weak ∪ 语料三查 ∪ zxcvbn≤2，fail-safe 通配臂），**语料层三端同算法**
（exact / 元音位归一化（1/! 不映射——数字→字母会焊段）/ 核心词 72 词边界搜索
（左邻非字母 + 右尾无字母，防 latest 内嵌 test 误伤）/ 键盘走位 30 条 ×-15），
TS↔JS 保持逐字同步（守卫钉死），**Rust↔JS 降级为弱分类平价**（算法不同源，
分数不承诺相等——契约诚实化，替代方案 zxcvbn-ts 全端/Rust 单引擎 IPC 均被真实
理由拒绝）。仪表盘 wire 语义变更：weak score 0-100 → zxcvbn 0-4（实现取
min(zxcvbn,2) 保证弱列表渲染永不出现 Strong 标签），消费点三处全改（渲染/文案/
注释）。17 向量冻结表由 zxcvbn 实测钉死（5 哨兵全 4 分免换）。语料三份拷贝 +
corpus-sync 守卫（解析后集合相等 + 9952 计数 + 锚点存在性 + 核心词 72 词 +
排除集），zip 实测 +32.5KB（预算 90-130KB 内）。DESIGN.md 增认证屏 sanctioned
exception 条款。

实施期修正（均入档）：P@ssw0rd123 归一化标注不可满足（3→e 把尾数字焊成
password12e）→ famous-forms exact 锚点入语料，三端同步；语料主源换
xato-net-10-million-passwords-10000.txt（SecLists 原 10-million 系列已被上游
删除，commit 4ff3ff8）；走位表实为 30 条（计划误计 28）。QA T55 appended——
两主题认证屏 sweep、提示两态（含启用者不闪警示）、仪表盘真弱口令实测是门禁项。

Tests: 694 frontend+extension CI-true (82 files; 基线 603/78 → rust-port 退役
-18、classification/sync/parity 新增 +109) / Rust 449 (+1 ignored；基线 437，
domain 15→26、application 243→244) / native-host 23 不变。web-ext lint 0/0/0。
Plan: fix_impl_plan_v1.7.0.md (R3 fast-pass)。

### 2026-10-28 (v1.6.3 — tech-debt train: extension JS split + .btn width inversion + CI line-count guard)

Pipeline: targeted recon (line counts, manifest loading modes, guard-test
reading paths, .btn site inventory) → plan R1 → plan-reviewer REVISE
(6×P1: content four-way split failed the cap arithmetic → five-way;
guard list was 4/6 — content-save-prompt + search-parity missed and
cross-file count assertions must be joined in manifest order, never
split; the scoped-override list was v1.5.1-era stale and
`.confirm-modal-actions .btn` is flex:1 50/50 split, NOT a width
suppression; popup.js is a single 1660-line PopupApp class with no
seam → deferred with a tracked exemption; Secure notes is NOT shipped
— plan claimed it; namespace init contradicted the byte-frozen
domain-match file) → R2 → re-review REVISE (1×P1: NS-alias form would
make the namespace contract vacuously pass — pinned to full-name
refs/defs + non-empty assertions; reviewer authorized fast-pass) → R3
**PASS** → two ds-workers in parallel (A: WP1 split; B: WP2+WP3) →
worker B correctly REFUSED a plan item (.group-manage-first width:auto
suppresses .group-manage-btn's 40px box, not .btn — plan defect) →
dual review (extension **APPROVE** 0 P0-P2, 4×P3; react **APPROVE**
0 P0-P2, 3×P3 — its render-semantics audit proved .btn-block
additions are pixel-identical to the old width:100% and enumerated
every protected site) → 5 cheap P3s folded (awk NR count, NUL-safe
find, exemption-removal hint, indentation, is-trusted start anchor
restored after grep proved uniqueness) → clean-worktree gates →
release.

Shipped: content.js 2159 → domain-match.js (byte-frozen, sloppy-mode
kernel — strict-safe, noted) + content-forms/ui-shadow/ui-bar/
save-prompt + 157-line entry, cross-file refs only via
`globalThis.PwdVaultContent.<prop>` full names (74 refs/20 props,
refs∖defs=∅ pinned by content-namespace.test.js with non-empty
assertions); background.js → background-native (transport + module
state) + background-commands + entry; 6 readFileSync guard tests
migrated with union-count semantics (join in manifest order — counts
never split); both manifests list six content files in dependency
order; popup.js 1693 deferred behind the only LINE-CAP EXEMPTION
marker (guard asserts exactly one, path-pinned); quality.yml gains
the permanent 800-line guard (src-only find, awk NR, NUL-safe).
Desktop: `.btn` width:100% removed → `.btn-block` explicit opt-in
(26 stacked-form sites classified), `.btn-full` untouched,
`.btn-inline` now flex-shrink-only, stale width-suppression comments
swept. Roadmap §3 refreshed (Touch ID/TOTP/sync checked off; Secure
notes honestly back on the list; popup split, HIBP-privacy, zip
2027-06-30, duplicate auto-detection recorded).

Tests: 603 frontend+extension CI-true (78 files — vitest collects
chrome/ AND firefox/ via symlink, extension tests double-count by
design; +12/+2 = namespace test counted on both paths) / Rust 437
(+1 ignored) / native-host 23, all unchanged. web-ext lint 0/0/0.
Plan: fix_impl_plan_v1.6.3.md (R3). QA T54 appended — full-screen
.btn sweep (two themes) + the four deliberate-content-width spots +
extension smoke are the post-release items (jsdom cannot see the
inversion).

### 2026-10-27 (v1.6.2 — restore keeps payload ids: ends delete+sync ×2 duplication; typed-RESTORE gate made visible)

Compact pipeline (two real-device findings → code-level root causes by
the main agent → plan R1 → plan-reviewer REVISE (1×P1: the
clone-verbatim design would have lost the tombstone sanitization that
re-id provided by accident — hand-crafted payloads could land
tombstoned groups that then sync as deletions to every device;
1×P2: fourth convergence pairing — cloud tombstone older than the
restored row = conflict + revive; 2×P3 copy/gating nits) → R2 →
re-review **PASS** (stale test count + 2×P3 reference wording folded)
→ single ds-worker (two red→green Rust tests with evidence;
documented deviations: .error-message reuse for the advisory +
probe-per-dialog-open semantics — both accepted) → dual review
(rust **APPROVE** 0 P0-P2, 2×P3: test-helper dedup + comment
precision; react **APPROVE** 0 P0-P2, 4×P3: warning severity class,
syncActive symmetry, role=status, csv mock hygiene) → main-agent
folded all six P3s → clean-worktree gates (fresh worktree + sidecar
pre-step; clean frontend count 591/76 exactly matching the fold
math).

Shipped: `import_groups` verbatim (payload.groups.clone() — group ids
AND timestamps survive; the remap had been silently resetting them to
now); encrypt_import_entries keeps entry.id/group_id from the payload;
`TOMBSTONED_GROUP_IN_BACKUP` in backup_payload (the export-side
live-only filter is now a symmetric import invariant; strictly
backward compatible — legit exports carry none, pre-v1.1.6 backups
serde-default to None); restore dialog sync advisory (role=status,
warning-tinted `.restore-sync-warning`, no invented token) + visible
typed-RESTORE gate (`.btn-secondary:disabled`/`.btn-danger:disabled`
mirror `.btn-primary` — a global `.btn:disabled` deliberately avoided
per the .btn lessons; hint gated on non-empty mismatch, aria-live
silent on open); convergence pinned by
`restore_converges_with_cloud_without_duplication` (four same-id
pairings, conflict_count==1, changed==true). CSV import re-id
untouched (true merge semantics); merge/publish/engine untouched.
Real-vault duplicate cleanup stays manual (recipe given; automatic
duplicate detection recorded as an independent future item).

Tests: 591 frontend CI-true (76 files; +6) / Rust 437 (+1 ignored; +3)
/ native-host 23. Plan: fix_impl_plan_v1.6.2.md (R3). QA T53 appended —
item 1 (restore→sync no-duplication E2E) is the gating item.

### 2026-10-27 (v1.6.1 — acceptance patch: confirm-dialog error channel, lazy custom-field values, input hygiene)

Compact pipeline (T45 real-device feedback → root causes located at code
level by the main agent → mini-plan R1 → plan-reviewer REVISE (2×P1: the
F2 transport premise was wrong — VaultError has serialized to the
public_message STRING since v1.3.2, so the planned object-shape mock was
a fictional contract and the visible text carries the raw "CODE: "
prefix; EntryScreen at 799 lines had no budget plan) → R2 REVISE (1×P1
was a merge residue: the superseded R1 F2 section survived alongside the
rewritten one) → R3 **PASS** → single ds-worker → react-reviewer REQUEST
CHANGES on a real P1 the suite structurally couldn't see — the shared
in-flight lazy-load promise returned the ROW SNAPSHOT taken at fetch
start, so rows typed during the fetch window were silently dropped from
both the diff and the patch (reviewer proved it with a probe test: zero
changes → leaveEntry, updateEntry never called) → fix: resolution-time
assembly from a latest-ref mirror + regression test (red→green verified;
all 12 earlier tests had scheduled edits before the fetch, exactly
skirting the window) → focused re-review **APPROVE** → clean-worktree
gates.

Shipped: ConfirmationModal error channel (role=alert inside the dialog;
form banner + 3 aria-describedby gated on `error && !showConfirmation`);
errorMessage strips an all-caps `CODE: ` prefix when the remainder is
non-empty (global display improvement closing CQ-P2a; TOTP/Baidu setup
classifiers read the raw rejection upstream, unaffected — reviewer
verified); Custom Fields section lazily loads stored values on
focus-capture / row-reveal via `loadValues(trigger)` sharing one
in-flight promise with the save guard (failure backs off focus retries
only, explicit/save unaffected; keyboard-through posture documented);
spellCheck off on field inputs; Custom Fields in its own form-group;
detectChanges verbatim to entryChanges.ts (EntryScreen 799→718).

Tests: 585 frontend CI-true (75 files; +13) / Rust & native-host
unchanged (434+1 / 23). Plan: fix_impl_plan_v1.6.1.md (R3). QA T52
appended.

### 2026-10-26 (v1.6.0 — M-tier kernel batch: custom fields, sync v3 + conflict counter + auto-sync, extension save prompt, backup fidelity)

Pipeline: 3-way Explore recon → plan R1 → plan-reviewer REVISE (1×P0: the
backup-fidelity design assumed ExportEntry carries ciphertext — it is a
plaintext payload (Zeroizing<String> password/notes, decrypt-on-export /
encrypt-on-import); verbatim-ciphertext backups would be unrestorable
across vaults and master-password changes) → R2 REVISE (1×P1 was the
reviewer self-correcting: its own R1 suggestion "count state divergence
XOR" would flag every routine deletion propagation as a conflict —
remove_entry overwrites updated_at=deleted_at, so a peer's stale live
copy always trips the XOR and trash auto-purge batches would report
hundreds of fake conflicts; tightened to edit-after-delete, live
updated_at > tombstone deleted_at) → R3 **PASS** → three ds-worker waves
(WP1+WP2 / WP3+WP4 / WP5, each verifying the inherited tree first) →
3-way review (rust APPROVE 0 P0-P2; extension APPROVE 0 P0-P2; react
REQUEST CHANGES on a real P1 — the editor's WeakMap row identity
remounted the row on every keystroke and lost focus each character,
invisible to the suite because no test simulates focus) → main-agent
fixes (P1: row identity moved into the data with strip-at-IPC-boundary +
focus-survival regression test; P2: per-row secret lock toggle — desktops
could not create secret fields at all; 7 cheap P3s across the three
domains, one correctly judged redundant and skipped) → react focused
re-review **APPROVE** → clean-worktree gates → release.

Shipped: `CustomField{label,value:Vec<u8>,secret}` as PasswordEntry's
15th field behind a four-generation decode chain (15 → LegacyEntryV4(14)
→ V3(13) → V2(11)); the 14-field layout froze as a permanent
NEVER-RECAPTURE fixture (cross-verified byte-identical to the pre-change
FULL golden) alongside the 13-field and v1/v2-container fixtures;
entry×2/sync_entry×2/settings×2 goldens recaptured same-commit.
CustomFieldsEditor rows keyed by data-carried ids (WeakMap removed),
whole-replace save guarded by a fetch that prevents wiping unloaded
values, secret flag editable per row. Sync container v2→v3
(SUPPORTED_READ_VERSIONS=[1,2,3], AAD unchanged); `pair_is_conflict` =
edit-after-delete OR equal-timestamp fingerprint divergence, with
stale-copy propagation/both-deleted/sequential-edit negatives pinned;
SyncStatusResponse.conflict_count + SyncState.last_conflict_count
(serde(default) — sealed rows are JSON inside). Auto-sync off by default
(Settings.auto_sync_interval_min), setup thread + sync_cycle leaf lock
(tick try-locks, manual sync/connect block) acquired before
exclusive_window — no reverse acquisition point. Extension: three
isTrusted-gated capture paths, crypto.subtle feature-detect (http pages
skip), digest-only CHECK + confirm-carries-plaintext SAVE_LOGIN_CONFIRMED
— background holds nothing, fifth closed shadow root, GUARDED_SITES 4→8,
UI_ROOTS 4→5, "Unknown command" session-sticky degradation. verify rides
`id_param` (NativeRequest.id is the u32 correlation field) — WP3/WP4
contract aligned and cross-checked by the main agent. Backups: ExportEntry
+url_match_mode/totp_secret/custom_fields (plaintext payload, empty-value
symmetric round-trip) — fixes the silent TOTP-loss-since-v1.1.6 and
match-mode-loss-since-v1.5.0 holes. Rider: `.btn-inline` utility replaced
the five accumulated scoped width suppressions; EntryScreen back under
the 800 cap (useCustomFields.ts / EntryGeneratorModal.tsx /
utils/urlMatchMode.ts extracted; sync_cycle split state_io 800→604 +
sealed_rows.rs).

Noted for a future batch: extension JS (content.js 2159, background.js 1057) exceeds the 800-line cap but commit-gate only checks .rs files —
either extend the gate or split via manifest multi-file content scripts
(reviewer suggestion; both need their own session).

Tests: 572 frontend CI-true (75 files; +107/+7) / Rust 434 (+1 ignored) /
native-host 23. Plan: fix_impl_plan_v1.6.0.md (R3). Manual QA T45-T51
appended — T48 (save prompt on real Chrome+Firefox) is the gating item.

### 2026-10-26 (v1.5.1 — flex-base-width UI fixes ×3 + trash Back button restored)

Compact pipeline (real-device QA feedback → mini-plan R1 → plan-reviewer
REVISE ×2 → R3 **PASS** → main-agent implementation (small surface) →
react-reviewer APPROVE (3×P3: indentation drift + one redundant assertion
fixed pre-commit; BackHeader-reuse memo) → clean-worktree gates → release).
Root cause of all three layout breaks: the global `.btn { width: 100% }`
acting as flex base size (the v1.2.2 trap, jsdom-invisible): dashboard
summary text collapsed to one word per line with Re-run check overflowing
the window edge; trash Empty trash stretched across the header; the shared
`.security-status-row` class stretched all nine Security/Cloud-Sync action
buttons full-width (plan-reviewer sweep caught this third instance and its
9-site blast radius; "50/50 split is intentional" had no evidence in the
codebase — reviewer-corrected to a deliberate content-width unification).
Fixes are three narrow scoped `width: auto` rules (`.dashboard-rerun`,
`.trash-header .btn-danger` — deliberately not `.btn` so the restored
`.btn-icon` keeps its 40px, `.security-status-row .btn`). Trash view
regains an explicit Back button after two QA rounds flagged the
toggle-only return; the Trash tab toggle keeps working. Note: scoped
overrides rely on settings/vault.css importing after components.css
(react-reviewer appendix: a future App.tsx import-order change would
silently break them — fold into the eventual `.btn` global-rootening
refactor, recorded as an independent item). Tests: 465 frontend CI-true
(68 files; +1 Back case) / Rust & native-host unchanged. Plan:
fix_impl_plan_v1.5.1.md (R3). Manual QA T44 appended.

### 2026-10-26 (v1.5.0 — M-tier batch: dashboard, CSV importers, trash auto-purge, URL match override, pair caller digest)

Pipeline: 3-way Explore recon → plan R1 (plan-reviewer REVISE, 1×P0: adding
a 14th PasswordEntry field on the two-generation codec would have made
every vault written since v1.1.5 unreadable — and recapturing the golden
fixtures would have laundered the regression) → R2 (REVISE again: the sync
container snapshot is serde_json, not bincode — plan and R1 reviewer both
had the mechanism wrong; the real hazards are silent field-stripping on
old devices plus cross-version fingerprint divergence) → R3 **PASS** →
three ds-worker waves (WP1+WP2 / WP3+WP5+WP6 / WP4, each verifying the
inherited tree first) → 3-way review (rust APPROVE with 2×P2 doc/
test-strength fixes; extension APPROVE with zero findings; react REQUEST
CHANGES on a real P2 — a failed CSV commit left a dead preview that can
never be committed, retrying would mislead) → main-agent fixes (P2s +
cheap P3s: sweep comment honesty, single-txn fuse comment,
normalizeMatchMode allowlist, preview 100-row render cap, dashboard
silent-catch toast, fallback busy-guard restructure) → both reviewers
ACCEPT → clean-worktree gates → release. commit-gate caught two staged
files over the 800 cap at commit time (entries.rs 1018,
native_messaging/tests.rs 911); both split test-module-only
(entries/tests.rs verbatim move; native_messaging generator cluster →
tests_generator.rs with pub(super) helpers), zero behavior change.

Shipped: `security_report` (in-process aggregation — Zeroizing plaintext,
SHA-256 buckets, ids/scores only; deliberately bypasses get_entry_secret's
last_used_at bump; strength ported to domain::strength, 18 shared vectors
pinned both sides); CSV importers (Bitwarden/1Password/Chrome/KeePassXC
header-signature detection, BOM/CRLF/RFC4180 tolerant; staged in AppState
with Zeroize + lock-discard; preview without passwords; single-txn commit
with the O(n²) per-row trap documented as a fuse on the only store.write);
`trash_auto_purge_days` (default OFF, ≤500 per unlock after keys publish,
Tauri+NM adapters emit trash-auto-purged); `UrlMatchMode` (three-gen codec
chain + LegacyEntryV3, permanent NEVER-RECAPTURE fixtures for the 13-field
blob and the v1 container; container format v2 with v1 read via serde
default — AAD unchanged; all four AUTOFILL constructors carry match_mode,
content falls back to auto, verbatim blocks byte-identical); pair toast
caller digest (advisory only — loopback-forgeable header documented);
golden_contract NM list de-drifted (it had been self-comparing for three
releases). Incidental: the formatter hook again reformatted touched test
files post-commit; quote-sensitive assertions survived via
minimal-escaping (v1.4.1 lesson held).

Tests: 464 frontend CI-true (68 files; +73/+7) / Rust 391 (+1 ignored) /
native-host 23. Plan: fix_impl_plan_v1.5.0.md (R3). Manual QA T39-T43
appended.

### 2026-10-26 (v1.4.1 — trash entry relocated to group-tabs Trash tab + main-red guard fix)

Compact pipeline (QA feedback → mini-plan R1 → plan-reviewer REVISE with
4×P1: the default `.icon` class's 24px rule beats the svg width/height
attribute so the tab icon needs a CSS suppression rule; D1/D6 contradicted
each other on `.group-manage-first`'s fate; trash-open state had no
navigation exclusivity — group-tab active/aria-current need a `!trashOpen`
condition; idle/loading states unspecified for the now-always-rendered row
→ R2 → re-review **PASS** with a condition: the exclusivity test must
assert DURING trash-open, not only after exit → ds-worker → react-reviewer
APPROVE (P2: injected groups state leaked across test cases via the
partial beforeEach reset; P3: Virtuoso mock key warning — both fixed
before landing) → gates → release. Shipped: Trash tab (icon + text,
toggle, aria-current, no aria-label — visible text is the name) pinned
right in the group-tabs row behind a divider beside the gear; trash
renders in place; trash and group tabs are mutually exclusive; the tabs
row is always rendered (idle/loading = empty scroll area, zero groups =
Create-group CTA shares the row, error retry inlined with a scoped
padding override); the old search-bar icon button is gone with a negative
test pinning its absence; `.group-tab-trash svg` 12px suppression (jsdom
cannot see it — T38 covers on-device, both themes). **Incidental**: main's
Quality Gates had been red since 63932d2 (the v1.4.0-closing formatter
pass flipped sender-auth.js to double quotes while the
background-fill-gate guard regex pinned single quotes) — that push landed
without watching CI; discovered while triaging a worker-reported failure,
fixed quote-agnostically (8f501f6, backreference form) with the lesson
memorialized: watch CI after every main push, and source-text guard
regexes use quote-agnostic forms. The formatter hook's post-commit
reformat of the two touched test files was collected as db9cf24
(minimal-escaping preserved the import assertion's inner quotes; 416/416
re-verified). Tests: 391 frontend CI-true (61 files; +4 in
VaultScreen.trash) / Rust & native-host unchanged. Plan:
fix_impl_plan_v1.4.1.md (R2). Manual QA T38 appended.

### 2026-10-25 (v1.4.0 — S-tier product batch + updater/wry modernization)

Pipeline: recon (crates.io verification exposed the WP1 premise break —
no tauri-plugin-updater release ships zip ≥9, incl. 3.0.0-alpha.3, so the
promised "upgrade clears the advisories" was impossible; user informed,
pivot approved into the plan) → plan R1 → plan-reviewer REVISE (P0: a
suffix-table miss degrades matching LOOSER — fail-closed ccTLD fallback
mandated; 4×P1: fifth matching gate entryMatchesSenderUrl,
getEntriesForUrl empty-entryUrl invariant, purge tombstone reflow,
last_used_at write amplification) → R2 → re-review REVISE (R2's purge
ledger would swallow legitimate live revivals) → R3 → **PASS** →
ds-worker (10 documented deviations, all sound — EntrySummary also gained
deleted_at, sortMode rides settings instead of a new context field,
BEGIN/END verbatim markers instead of fragile regex extraction, Settings
golden fixtures recaptured for the 3 new fields) → 3-way review (rust
REQUEST CHANGES on a genuinely flaky test — append_number yields a
1-digit suffix ~10% of the time and the shape test pinned exactly 2;
react APPROVE; extension APPROVE with a suffix-count comment fix
121→126) → main-agent fixes (flaky test relaxed+strengthened with a
digit-stripped word-count assertion, empty-trash routed behind the
danger modal, suffix comment synced both files) → clean-worktree full
gates (sidecar pre-step) → release. Shipped: eTLD+1 matching (126-entry
curated suffix table, fail-closed ccTLD degradation, two gates unified,
five sites → one source + verbatim copy, generic-entry invariant
preserved); passphrase/PIN generator (EFF short list via include_str!,
rejection sampling u16/64800, session history never persisted, NM
serde(default) back-compat); recently-used sort (60s-throttled
last_used_at, device-local: never bumps updated_at nor syncs — SyncEntry
verified field-free); recycle bin (restore/purge/empty + local
purged-id ledger filtered to tombstones only — live revivals pass
through and clear the ledger); global shortcut (CmdOrCtrl+Shift+Space
default, Rust-command re-registration, Pressed guard for tauri#10025);
updater 2.14.0 / tauri 2.12.5 / wry 0.57.1; zip allowlist extended to
2027-06-30 with upstream evidence (verified 2026-10-25). Tests: 387
frontend (61 files CI-true) / 352 Rust (+1 ignored) / 23 native-host.
Plan: fix_impl_plan_v1.4.0.md (R3). Manual QA T33-T37 appended — **T33
(updater E2E v1.3.2→v1.4.0 on macOS+Windows) is the release-gating item**
for the wry jump.

### 2026-10-25 (v1.3.2 — audit P2 batch: Shadow DOM isolation + re-theme, IPC error sanitization, UI polish)

Pipeline: recon → plan R1 → plan-reviewer REVISE (3×P1: TotpCode's enum-shape
polling check would break under serialize_str; TagsEditor Enter would
double-fire under the new form; eslint ignores would noop the new config
section) → R2 → re-review **PASS** → ds-worker (7 documented deviations, all
sound — notably Save uses type=submit+form= because a jsdom probe showed
implicit submission requires a submit button; GroupSelector got the same
preventDefault as TagsEditor) → 3-way split review (rust/react/extension —
the code-reviewer agent type was concurrency-limited, so domains went to
rust-reviewer + react-reviewer + general-purpose) all **APPROVE, 0 P0-P2** →
clean-worktree full gates → release. Clean-worktree caveat recorded: cargo
suites need the native-host sidecar pre-built into src-tauri/binaries/
(tauri.conf resources glob `binaries/pwdvault-native*`) — same pre-step as
release.yml's gate job. Shipped: content.js 4 UI roots → closed shadow roots
via a single mountShadowHost (:host navy/teal token block, all:initial +
re-pin, styles/keyframes scoped, toast dedupe via closure ref, escapeHtml
removed, empty content.css dropped from both manifests); VaultError
Serialize → public_message() (TotpCode startsWith contract, mock shapes
migrated); VaultScreen 4 async toasts; VaultContext actions stabilized
(DELETE_GROUP clears selection in reducer, latestRef workarounds removed);
UPDATE_FAILED phase (banner + settings, retry preserved); EntryScreen real
form semantics; extensions under ESLint (ignores narrowed to the firefox
symlink) + GET_STATUS parallelized + handshake app_version removed (zero
consumers, verified); UI AA tokens (muted #5B6B80, warning/accent/success
text variants), ellipsis, :focus-within, toast transform fix, modal shadows,
disabled hover guards, reduced-motion, empty-state CTA, DESIGN.md/popup.html
token sync. Tests: +content-shadow 4, +EntryScreen.form 3, +1 each
(UpdateNotification/SettingsScreen.updates/SettingsContext ipc shape),
Rust +1 (ipc_serialization_exposes_only_the_public_message) → **308 frontend
(54 files CI-true, verified in clean worktree) / 329 Rust (+1 ignored) / 23
native-host**. Plan: fix_impl_plan_v1.3.2.md (R2.1). Manual QA T29-T32
appended; **T26-T28 clipboard E2E must be re-run on this build**
(content.js fully rewritten).

### 2026-10-25 (v1.3.1 — audit P1 batch: clipboard clear redesign, event gating, screen overflow, rustls bump)

Full pipeline over the 6-track audit's P1 findings (plan R1 → plan-reviewer
REVISE → R2 → re-review **PASS** → ds-worker → independent code-reviewer
REQUEST CHANGES → main-agent fixes → focused re-review **APPROVE** → gates →
release). Notable: the cancelled first ds-worker run left a half-finished
tree; the successor verified every inherited change against the plan before
continuing (v1.3.0 precedent). The reviewer caught a real **P0**
(popup.js `import.meta.env` without optional chaining = popup white screen
in production — the extension ships as plain ESM via build.sh copy, there is
no vite build) and a **P1** (offscreen dedupe regex didn't match Chrome's
actual "Only a single offscreen document may be created per extension" error
— would have permanently broken clearing on Chrome 109-115 with a failure
toast on every copy). Shipped: clipboard auto-clear moved from the
popup-local timer to background (alarms + storage.session arm, offscreen
document on Chrome / hidden-textarea execCommand on Firefox, SHA-256
digest-verified overwrite, retry-once + notify-once; +alarms/offscreen/
clipboardRead permissions and minimum_chrome_version 109 — clipboardRead is
a deliberate expansion, the digest check prevents clobbering newer user
content); isTrusted gates on 4 content.js credential triggers; .screen
flex-start + :only-child margin:auto clipping fix (Setup/Unlock/Recovery/
loading at 500px min height); rustls 0.23.46 / rustls-webpki 0.103.16 /
webpki-roots·certs 1.0.11 / clipboard-win 5.4.3; zip RUSTSEC-2026-0367/0368/
0369 allowlisted (deny.toml + NEW root .cargo/audit.toml + quality.yml audit
steps aligned to root-cwd `--file` form incl. the `-n` offline retry;
expiry 2026-12-31 forces the tauri-plugin-updater/zip≥9 upgrade into the
next minor — the plugin bump drags wry 0.54→0.57, patch-ineligible).
Tests: clipboard-clear 18 + content-is-trusted 5 + sender-auth +2
(verified 295/51-file CI-true in a clean checkout after the release gate
caught a tab-vs-space drift in the content.js verbatim copy — local runs
can over-count via untracked dist/ copies; clean-worktree verification is
now part of the release checklist). Test baseline after: 328 Rust (+1
ignored) + 23 native-host + 295 frontend (51 files). Plan:
fix_impl_plan_v1.3.1.md (R2.1). Manual QA T24-T28 appended (real-browser
clipboard behavior is unmockable — T26 is the gating item, see Chromium bug
330570363 if it fails).

### 2026-10-07 (v1.3.0 — bincode 1→2 serialization swap, byte-identical)

Standard pipeline with a twist worth recording. **P0 pre-experiment**
(main agent, /tmp dual-version crate): bincode 1.3.3 ↔ 2.0.1
serde+legacy() byte-identical across all PwdVault shapes — 19/19
four-way checks. **Plan review caught the headline misconception**
(R1 P0): RUSTSEC-2025-0141 is crate-wide (2.x equally unmaintained, no
patched version) — the migration does NOT clear the advisory; reframed
honestly as terminal-API landing + golden guardrail + single
serialization seam (bc_serialize/bc_deserialize in crypto/codec.rs) as
groundwork for a future postcard migration; deny ignore retained with
a trigger (real CVE / next format work; review 2027-10). ds-worker hit
a quota cap mid-run and left a half-finished tree; the re-dispatched
general-purpose worker verified the inherited work independently and
caught two fabricated sync fixtures from the predecessor (odd-length
hex / wrong length), regenerating them with real 1.3.3 bytes — the
code-reviewer then re-verified all 16 fixtures three ways (hand byte
accounting, independent bincode-1.3.3 crate reproduction, non-tautological
assertion check). Shipped: 20 files swapped (77 call sites), 16 golden
tests across 8 types (incl. sync LWW fingerprint pinning for
cross-version tiebreak stability), full-chain legacy round-trip test,
deny/allowlist rationale sync. Disk format byte-identical; no user
action. Test baseline after: 328 Rust (+1 ignored) + 23 native-host +
270 frontend. Plan: fix_impl_plan_v1.3.0.md (R2).

### 2026-10-07 (v1.2.4 — audit-polish integration batch)

### 2026-10-07 (v1.2.4 — audit-polish integration batch)

Standard pipeline over the consolidated backlog from the audit ledger
(plan → plan-reviewer PASS after one revise round that caught a
debug-assert placement that would have broken baseline tests, four
non-narrowable pub symbols, and a wrong section anchor → ds-worker,
five groups → code-reviewer APPROVE with comments, 0 P0-P2 → gates →
release). Shipped: pair_confirm shares the pair 10/min rate-limit
budget (tests via execute_command); sender URL matching gains
scheme-less parity with the popup (empty entryUrl divergence pinned by
comment); the A-class secrets-invariant debug-assert landed at the
read_local_rows call site; 12 pub items narrowed / 4 skipped as
cross-crate API; dead types & exports swept; tags dirty-check is now
order-insensitive (sorted-join, multiplicity preserved); Updates
section extracted (SettingsScreen 408 lines); cargo audit gains an
offline fallback in quality (release gate stays fail-closed);
SHA256SUMS is minisign-signed in provenance and ships as an asset;
CLAUDE.md removed / audit snapshot moved to docs/ / .conductor gone.
Test baseline after: 310 Rust (+1 ignored CI smoke) + 23 native-host +
270 frontend (78 extension). Plan: fix_impl_plan_v1.2.4.md (R2).

### 2026-10-07 (v1.2.3 — updater trust anchor pinned in CI)

Compact pipeline (mini-plan → plan-reviewer PASS in one round, P2/P3
folded in → ds-worker → code-reviewer APPROVE with comments, 0 P0-P2 →
gates → release). Shipped the H3 hardening from the key-strategy
review: golden_contract now pins the updater pubkey (byte-for-byte,
key 237BD03CF7C9D12D), asserts the single https feed endpoint, and
rejects any `tauri.<platform>.conf.json` overlay (incl. android/ios
for future mobile) — a trust-anchor swap or feed hijack can no longer
land silently; the test's failure message IS the rotation runbook
(docs/UPDATER-KEYS.md §3/§4). Worker reverse-verified all three
assertions red→green. No application code changes; release is
functionally identical to 1.2.2. Test baseline: 308 Rust (+1 ignored
CI smoke) + 23 native-host + 266 frontend. Plan: fix_impl_plan_v1.2.3.md
(R2).

### 2026-10-07 (v1.2.2 — manual update check + tags/group layout fix)

Standard pipeline (plan → plan-reviewer PASS after three rounds that
caught a mid-download handle-close hazard, an auto/manual interleave
ref leak, and a dead-click button spec gap → ds-worker → main-agent
review + independent code-reviewer APPROVE, 0 P0-P2 → gates →
release). Shipped: **manual "Check for updates"** in Settings →
Updates — current version line, check button (disabled while
checking/downloading/ready), aria-live status line with visible
errors; manual check bypasses a dismissed version without rewriting
the key; auto path gained the symmetric close-before-overwrite so
auto/manual interleaves can't leak the plugin Update handle (13 new
tests, incl. downloading/ready guards and an interleave case).
**Layout fix**: the Tags input on the entry page (and the group
inline rows) collapsed to a ~50px pill because `.btn`'s global
`width:100%` acted as the flex base size and starved the `flex:1`
input — pre-existing since the v0.3.1 theme redesign (jsdom can't see
layout, found in manual QA); fixed with a scoped `width:auto +
flex-shrink:0` in the two rows (same pattern as the earlier
GroupManager fix). Test baseline after: 307 Rust (+1 ignored) + 23
native-host + 266 frontend. Plan: `fix_impl_plan_v1.2.2.md` (R3); QA
items T21-T23 appended to `qa_manual_v1.2.0.md`.

### 2026-10-06 (v1.2.1 — closure fixes: OAuth state-echo enforcement, prerelease feed gating)

Compact pipeline (mini-plan → plan-reviewer PASS after one revise round
that caught a transcribed key ID and a missing version-bump step → one
worker → code-reviewer APPROVE, zero findings → gates → release).
Shipped: **SEC-L3 closure** — the OAuth callback `error=` branch now
requires the state echo to match before terminating (forged `?error=`
probes are discarded; real denials echo state per RFC 6749), with the
accepted tradeoff that an anomalous state-less denial degrades to a
timeout; **prerelease-aware publishing** — semver pre-release tags
(`vX.Y.Z-beta.N`) build artifacts, are marked GitHub prerelease, and
skip the updater-feed commit, so test builds are invisible to
auto-update (bump-version.sh stays three-part; pre-release versions
sync manually); **docs** — the retired minisign public key in
PHASE-AU-PLAN.md is marked DEPRECATED with both key IDs (decoded
on-site, not copied from the plan). Test baseline after: 307 Rust
(+1 ignored CI smoke) + 23 native-host + 253 frontend. Plan:
`fix_impl_plan_v1.2.1.md` (R2).

### 2026-10-05 (v1.2.0 — audit remediation complete: Low hardening + cleanup)

Same pipeline as v1.1.9 (plan → 3-round plan-reviewer PASS → 5 workers in
2 waves → main-agent review + independent code-reviewer APPROVE with
comments, 0 P0/P1/P2 → gates → release). ds-worker provider hit a quota
limit mid-run; Wave 2 was re-dispatched to general-purpose workers with
identical specs. Shipped: **SEC-L5** auto-lock remote-activity grace —
desktop input keeps the full window, explicit vault ops (incl. paired
extension) extend only 120s; `last_remote_activity` lives in
`SessionInner::Unlocked`; 20 service touch sites → remote, 4 in-person
`state.touch_activity` sites kept local with comments.
**SEC-L2** sync_config/sync_state rows encrypted at rest (PVSYNC1 + AAD
row binding), read-time legacy migration, and re-seal key rotation via
the dual-read helper (reusing `parse_sync_row`, never bare unwrap —
unmigrated plaintext rows survive password change; survival tests ×2
with legacy fixtures). **SEC-L1** native-host 64-hex token whitelist;
**SEC-L3** Baidu OAuth callback loop-discards invalid probes (error=
denial still returns immediately); **SEC-L4** recovery key returned as
`Zeroizing<String>`. SF-P3a-f silent-failure batch; CQ-P3a revoke
service-layer delegation; CQ-P3b pair rate-limit single-mutex; CQ-P3d
EntryScreen split (TotpSecretField + TagsEditor + pure detectChanges,
752→686); fuse-options parity test (desktop↔popup); dead-code cleanup
(schemas, 8 extension dead cases, unused deps serde_json/base64/uuid —
Cargo.lock −3 lines); ST-1 (typecheck covers tsconfig.node.json;
TS5069 not triggered on TS 5.8, composite kept); keychain SecItem CI
smoke (ignored locally, real keychain on the macOS quality job — filter
must use the full test path, substring + --exact silently matches 0).
Test baseline after: 305 Rust (+1 ignored CI smoke) + 23 native-host +
253 frontend (76 extension). Plan: `fix_impl_plan_v1.2.0.md` (R3).

### 2026-10-05 (v1.1.9 — full-codebase audit + security fixes)

Five-way subagent audit (security / silent failures / quality / static /
dead code) with an independent second review, then a reviewed, staged
implementation (`fix_impl_plan_v1.1.9.md`, plan-reviewer PASS after one
revise round; four ds-worker work packages; independent code-reviewer
APPROVE). Fixes shipped: **SEC-M1** unlock paths take the
`exclusive_window` + re-validate the verification fingerprint
(`complete_unlock`, covers biometric; interleave tests T1-T3);
**SEC-M2** webview fs capability recalled — `export_vault_file` /
`read_backup_file` / `enable_recovery(save_path)` desktop commands with
native dialogs, atomic 0600 writes, 14 MiB cap, vault-dir exclusion
(capability_contract reversed to assert removal); **SEC-M3** sync
plaintext domain `derive(Zeroize, ZeroizeOnDrop)` + `decrypt_inner`
clone-escape fix (E0509 handled via `mem::take`); **SF-P1** extension
secret-fetch failures surface real errors on all fill/copy paths (no more
empty-password "success"); SF-P2a-d silent-failure fixes (clipboard-clear
notify-once, ErrorBoundary with Restart App, lock-failure toast, 0600
credential creation); **CQ-P2a** shared `errorMessage` everywhere (raw
JSON / enum-name errors gone); **CQ-P2b** import_vault staged split;
SEC-L5 auto-lock semantics documented (implementation deferred to v1.2).
Test baseline after: 294 Rust workspace + 19 native-host + 243 frontend
(72 extension). Audit trail: `code_audit_2026-10-04.md` (§7-8 are the
second-review conclusions), `code_audit_fix_plan_2026-10-04.md`.

### 2026-09-17 (v1.1.6 — Phase 1/2/3 landed)

**Phase 1 — key infrastructure** (`b05fb09` backend, `b8fa199` frontend):
change master password (full reseal in one transaction, D8 exclusive-drain
serialization), Touch ID unlock (macOS Keychain wrap key with biometric ACL,
dual-mode: data-protection preferred with legacy login-keychain fallback for
unsigned builds — `95c3544`, LAContext-gated `95c3544`/`6b491b3`), recovery
key (256-bit, shown once, lock-screen reset). New `keychain.rs`,
`crypto/wrap.rs`, `service/security/` (split to ≤800-line modules).

**Phase 2 — format v3 groundwork** (`e45f01f`): soft delete (tombstones with
`updated_at` bump), TOTP field + RFC 6238 generator (`totp.rs`, base32 +
otpauth parsing), dual-read legacy blob compat in entry/group codecs
(LegacyEntryV2/LegacyGroupV2, modeled on LegacySettingsV1 — bincode 1.x has
no trailing-field defaults). Security notes were found already implemented.

**Phase 3 — cloud sync** (`23cbc4a`, `37717ea`, `85549d2`, `364f4e0`):
encrypted self-contained container on the user's own cloud drive (WebDAV +
Baidu Netdisk adapters behind `CloudBackend`), device-side 2-way LWW merge
with fingerprint tiebreak, D8 exclusive-window reuse (republish copies the
original keys), rolling 10-snapshot history (= free encrypted backup),
OAuth device pairing for Baidu (fixed loopback port 17777, no PKCE).
Frontend: Sync settings section, TOTP field/codes.

**Manual-QA fixes** (`493a155`, `67a280f`, `6b491b3`, `95c3544`, `417f5a0`):
first-connect credential ordering, WebDAV 409-on-missing-ancestor treated
as absent (Nutstore), Touch ID dual-mode keychain fallback (unsigned builds:
data-protection keychain needs signed entitlements → legacy login keychain +
LAContext gate).

**CI gate fixes** (`a036eae`, `722d0d5`): workspace rustfmt drift, rustls
0.23.45 (RUSTSEC-2026-0285), native-host Cargo.lock regeneration, clippy on
latest stable (drop_non_drop + unused imports), over-cap modules split
(native_messaging/ 1611→5 files, tests_baidu, tests_engine, vault_tests).
All Rust files now ≤800 lines. Test baseline: 256 Rust + 19 native-host +
169 frontend.

### 2026-09 (Security Audit + Phase 0 Hardening)

**Three-way audit → verification → fixes** (backend / extension / desktop):

- **Commits**: `a519ee1` (backend: integrity fail-open, init/port/blob paths),
  `43ae1d3` (desktop: auto-lock activity reporting, clipboard/lock/dialog
  hardening), `ad5cb61` (extension: deferred secret fetch, register-form
  gating, autofill/pairing UX), `c557492` (follow-up: activity throttle from
  auto-lock timeout, SPA register gating), `1da542b` (extension: keep live
  pairing code across popup reopen)
- Findings were re-verified against the code before each fix; regressions
  covered by new unit tests on both Rust and frontend sides.

**Phase 0 hardening (this release candidate):**

- **X1** Extension handshake errors now distinguish "cannot reach the app"
  (connection copy) from "protocol version mismatch" (upgrade copy), and
  surface the desktop-provided error message when the host responds.
- **X2** Native messaging listener binds with `SO_REUSEADDR` (socket2) plus a
  bounded 1s/2s/4s retry for `AddrInUse` only — quick app restarts no longer
  leave the extension bridge silently down.
- **X3** `AccessibleDialog` keeps ONE owner-owned snapshot of the pre-dialog
  background state; out-of-order dialog closes no longer leave `aria-hidden`
  on `#root` (screen-reader regression).
- **X4** Popup generator length label addressed by `id="gen-length-label"`
  instead of fragile DOM-order selectors.
- **X5** Tauri capabilities: `fs:allow-read-file/write-file/stat` scoped to
  user locations (`$HOME/**`, `/Volumes/**`, `$TEMP/**`) with explicit deny
  for the vault database directories (macOS `com.pwdvault.app`, Windows
  `%LOCALAPPDATA%/PwdVault`).
- **X6** Import-side KDF floor (19 MiB / t=2, OWASP baseline) enforced before
  backup key derivation; unlock path deliberately unchanged so historical
  vaults keep opening; `AdaptiveParams::adaptive` start clamped to the floor.
  Behavior change: backups created by older versions on slow machines with
  t=1 params are now rejected on import (re-export from the unlocked vault
  to migrate).
- **X7** AGENTS.md factual refresh (this document).

### 2026-05-01 (Phase G — v1.0.0 Release)

**Tag**: `v1.0.0`

**G5: CSP Hardening:**

- Replaced `null` CSP in `tauri.conf.json` with restrictive policy
- `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:17429`

**G4: Security Checklist:**

- `keystore.rs`: 4× `.unwrap()` → `.expect("keystore lock poisoned")`
- `native_messaging.rs`: Added CORS wildcard security justification comment
- `.gitignore`: Added `.env` and `.env.*`
- `.github/workflows/release.yml`: Added `security-audit` job with `cargo audit`

**G1: Firefox Extension:**

- Created `extensions/firefox/manifest.json` with `browser_specific_settings.gecko`
- Symlinks: `src → ../chrome/src/`, `icons → ../chrome/icons/`
- Updated `build.sh` to package both Chrome and Firefox extensions
- Updated `bump-version.sh` for 7th file (Firefox manifest)
- CI now builds both Chrome and Firefox extension artifacts

**G3: Documentation:**

- CHANGELOG.md: Added v0.3.1 entry (Light/Dark redesign, F2, F4, modular CSS)
- AGENTS.md: Updated version, roadmap, directory structure, session log
- README.md: Updated status to v1.0.0, added Firefox install section, updated roadmap

### 2026-04-30 (v0.3.1)

- Frontend redesign: Light/Dark dual-theme system replacing Classic/Cyber/Hybrid
- Modular CSS: App.css split into 6 files (themes, base, components, screens, vault, groups, settings)
- F2: Update notification (ureq + semver version comparison)
- F4: Rate limiting (5 failed unlocks → 60s lockout)
- New components: BackHeader, Icons, StrengthMeter, UpdateNotification
- Browser extension synced with Light/Dark theme system

### 2026-04-17 (Phase E — v0.3.0 Release)

**Commit**: `a86edc6` · **Tag**: `v0.3.0` · **GitHub Release**: published

**E1: Encrypted Import/Export:**

- `export_vault` / `import_vault` Tauri commands + HTTP API endpoints
- `.pvault` file format: AES-256-GCM encrypted JSON with Argon2id key derivation
- Export password independent of master password (portable backups)
- Import restores entries + groups + settings with confirmation prompt
- Security: zeroization of plaintext passwords/notes, adaptive KDF params stored in backup
- `ImportExportScreen.tsx` — Tauri dialog for file save/open, browser fallback
- Browser extension: `exportVault` / `importVault` API wrappers

**E2: Fuzzy Search:**

- fuse.js weighted search: title (0.4), username (0.3), url (0.2), tags (0.1)
- Consistent config between desktop app and browser extension

**E4: Settings Screen:**

- `SettingsScreen.tsx` — auto-lock timeout (1–60 min), default generator options
- Settings persisted to redb `settings` table
- Dynamic auto-lock reads timeout from settings
- Backward compatible: pre-v0.3 vaults fallback to defaults

**CI/CD:**

- GitHub Actions v0.3.0 build: macOS DMG + app bundle, Windows exe, extension zip
- All 4 jobs passed; GitHub Release published with artifacts

### 2026-04-16 (Browser Extension Fixes)

**Commits**: `0c381e3`, `25e787c`

- Fixed browser extension group display inconsistency with desktop app
- Fixed password generator button not showing generated password UI
- Added theme switching support to browser extension
- Fixed tray menu Lock/Unlock state sync after vault lock

### 2026-04-01 (Phase A/B/C — Quality & Tests)

**Commits**: `d748292`

**Phase A (v0.1.2) — Bug Fixes:**

- Fixed auto-lock race condition: `clear_key()` + activity reset now atomic under same mutex
- Removed all `eprintln!("[DEBUG]...")` from production code

**Phase B (v0.1.3) — Rust Test Coverage:**

- Extracted `paths.rs` shared module (eliminated ~40 lines duplicate code)
- Added 48 Rust tests covering crypto, database, lib.rs commands, and all 13 HTTP API endpoints
- Replaced all `.unwrap()` with `.expect("descriptive message")` in lib.rs and native_messaging.rs
- Unified `lock_vault` HTTP command to use `state.lock_vault()` atomic method

**Phase C (v0.1.3) — Frontend Tests:**

- Configured Vitest + Testing Library + jsdom
- 17 frontend tests: passwordStrength calculator and vault API client

**Phase D (v0.1.3) — Password Generator Security Fix:**

- Fixed character type guarantee issue: implemented shuffle-guarantee algorithm ensuring all selected character types are included
- Upgraded random number generation from thread_rng to OsRng for stronger entropy
- Added 11 comprehensive password generator tests covering all scenarios
- Updated both lib.rs and native_messaging.rs with consistent implementation
- Created detailed technical analysis document (`password_generator_analysis.md`)

**Phase E (v0.1.3) — Release Packaging:**

- Fixed TypeScript test compilation error (added missing `tags` property)
- Rebuilt macOS application bundle (3.5MB)
- Rebuilt Chrome extension package (21KB)
- Updated release artifacts in `/releases/` directory
- Updated AGENTS.md with v0.1.3 release information

**Technical Notes:**

- Rust tests are parallel-safe (keystore is per-AppState, no global statics)
- Tauri v2 `MenuItem<R: Runtime>` generic prevents direct storage; solved with closure type erasure (`Box<dyn Fn(&str) + Send + Sync>`)
- Password generator now guarantees 100% coverage of selected character types using shuffle-guarantee algorithm

### 2026-03-26 (Phase 1 — Crypto & Core)

**Duration**: Full day
**Commits**: `c0b00c2`, `3010745`, `cabb999`

- Complete encryption system (AES-256-GCM + Argon2id)
- Working desktop application with 5 screens
- HTTP API for browser extension
- All CRUD operations functional
- Pushed to GitHub private repo

### 2026-03-27 (Phase 2 — UI/UX & Release)

**Duration**: Full day
**Commits**: `555a6ae`, `7d06b04`, `1831119`, `ec2c9bc`
**Branch**: `feature/phase1-crypto` → merged to `main`

**Parallel Development (3 worktrees):**

- Password strength indicator (`src/utils/passwordStrength.ts`)
- Chrome Popup UI enhancement (search, show/hide, copy, URL)
- Content script + clipboard integration (auto-fill prompt, MutationObserver, keyboard shortcuts)

**Infrastructure:**

- System tray with close-to-tray behavior
- Fixed browser extension communication (native messaging → HTTP API)
- Added missing HTTP API commands (`update_entry`, `remove_entry`, `get_entry_count`)
- GitHub Actions CI/CD (macOS + Windows builds)
- GitHub Release v0.1.0 with macOS/Windows installers + Chrome extension

**Bugs Fixed:**

1. Extension `background.js` used native messaging but desktop provides HTTP API — rewrote to use `fetch()`
2. HTTP API missing 3 commands — added `update_entry`, `remove_entry`, `get_entry_count`
3. macOS bundle identifier ended with `.app` — changed to `com.pwdvault.desktop`
4. GitHub Actions CI failed — missing `pnpm/action-setup@v4` before `actions/setup-node@v4`

**Build Outputs:**

- macOS `.app`: 9.8 MB
- Windows `.exe`: 2.3 MB
- Chrome extension `.zip`: 20 KB

### 2026-04-13 (Tests & GroupManager)

- Added unit tests for `GroupManager` (create, rename, delete)
- Frontend test suite stabilized; Rust backend tests remain green

### 2026-04-14 (Phase D — Project Identity + Design System)

**Phase D — Project Identity (v0.2.0):**

- Created `scripts/bump-version.sh` — version sync across 6 files
- Updated `.github/workflows/release.yml` — DMG packaging for macOS
- Rewrote `README.md` (~120 lines) and created `LICENSE` (MIT)
- Verified brand icon consistency across extension + Tauri
- Bumped all versions to v0.2.0

**Bug Fixes (Groups + Delete):**

- Fixed GroupSelector/GroupManager: replaced `prompt()`/`confirm()` with inline UI (Tauri WebView doesn't support browser native dialogs)
- Fixed "Vault is already unlocked" error: added `groupManager` route in App.tsx + made `set_key()` idempotent
- Fixed entries not showing after adding to groups: added `LegacyPasswordEntry` fallback deserialization for bincode v1 backward compatibility
- Fixed delete button not working: created `DeleteConfirmModal` component replacing `confirm()`

**Design System (/design-consultation):**

- Competitive research: 1Password, Bitwarden, KeePassXC design analysis
- Created three-theme design system documented in `DESIGN.md`:
  - **Classic** (default): Industrial Refined — cyan #0EA5E9, Plus Jakarta Sans
  - **Cyber**: CyberForge — neon cyan #00F0FF + magenta #FF0080, Space Grotesk
  - **Hybrid**: Warm-tech fusion — cyan #06B6D4 + rose #F472B6, subtle glow
- All themes switchable via `data-theme` CSS attribute
- Preview pages generated at `/tmp/design-consultation-preview-pwdvault*.html`

### 2026-04-15 (Design System Implementation + UX Polish)

**Design System Applied (themes.css + App.css):**

- Added type scale CSS variables: `--text-h1` (1.5rem) through `--text-micro` (0.6875rem) per DESIGN.md
- Added spacing tokens: `--space-xs` (4px) through `--space-2xl` (32px) per DESIGN.md
- Added `--icon-style` token per theme: solid (Classic), hollow (Cyber), glow (Hybrid)
- Replaced all hardcoded `px`/`rem` in App.css with CSS custom properties
- Cyber theme: hollow entry icons (transparent bg + border + glow color)
- Hybrid theme: password fields in primary color, subtle hover glow on buttons
- Hybrid theme: radial gradient background (cyan top-left + rose bottom-right)

**VaultScreen UX Redesign:**

- Replaced `<select>` dropdown group filter with horizontal scrollable group tabs
- Active tab: primary-dim background + primary color text + primary border
- Search input with magnifying glass SVG icon
- Group management via gear icon (⚙) in tabs bar
- "Create group" prompt shown when no groups exist
- Removed all inline styles from VaultScreen component

**ConfirmationModal & DeleteConfirmModal Redesign:**

- Replaced all inline styles with CSS classes
- Edit confirmation: icon header (pen icon in primary-dim circle), diff-style change list (~~old~~ → **new**), checkbox + Save/Cancel buttons
- Delete confirmation: danger icon header (trash in danger-dim circle), message body, Cancel/Delete buttons
- Consistent modal layout: header → content → footer

**GroupManager Redesign:**

- Card-based layout: each group as a card with folder icon, name, and entry count
- Action buttons always visible with `background: var(--color-input)` + `border: 1px solid var(--color-border)`
- Rename: 32px icon button, hover → primary color highlight
- Delete: 32px icon button, hover → danger color highlight
- New group: inline input bar with primary border accent, Enter/Escape key support
- Header + button in top-right for creating groups (consistent with vault page pattern)

**Release Artifacts:**

- `PwdVault_0.2.0_aarch64.dmg` (3.6MB) — macOS DMG installer
- `PwdVault-macOS-v0.2.0.zip` (3.5MB) — macOS .app bundle
- `PwdVault-Extension-v0.2.0.zip` (20.8KB) — Chrome extension

---

## Plugin Tools (Mandatory)

代码开发任务必须主动根据情况择优调用以下插件工具，不需要用户提醒：

| 阶段 | 推荐工具                                 |
| ---- | ---------------------------------------- |
| 规划 | gstack `/plan-eng-review`、planner agent |
| 编码 | superpowers 代码生成、ECC TDD 技能       |
| 审查 | `code-reviewer` agent、gstack `/review`  |
| 安全 | `security-reviewer` agent、ECC 安全技能  |
| 测试 | gstack `/qa`、`tdd-guide` agent          |
| 构建 | `build-error-resolver` agent             |

简单/单文件修改可酌情跳过，复杂多文件功能必须调用。

---

## Design System

Always read DESIGN.md before making any visual or UI decisions.
All font choices, colors, spacing, and aesthetic direction are defined there.
Two themes available: Light (default), Dark. Automatically follows OS preference.
Do not deviate without explicit user approval.
In QA mode, flag any code that doesn't match DESIGN.md.

---

## Native Messaging Architecture (v1.0.3+)

### Current Architecture

The browser extension communicates with the desktop app via the official
**Native Messaging API**, not direct HTTP fetch:

```
extension (background.js)
  │ chrome.runtime.sendNativeMessage('com.pwdvault.app', {...})
  │   (Bearer token carried in body field 'auth_token' — NM has no headers)
  ▼
pwdvault-native (host binary, stdio, serde-only deps)
  │ 4-byte length-prefixed JSON  →  HTTP POST 127.0.0.1:17429
  │   (injects Origin header + lifts auth_token → Authorization: Bearer)
  ▼
desktop app (tiny_http server on 17429, unchanged business logic)
  ▼
encrypted vault (redb)
```

### Key Files

| File                                                       | Role                                                      |
| ---------------------------------------------------------- | --------------------------------------------------------- |
| `extensions/native-host/src/main.rs`                       | Host binary: stdio↔HTTP bridge                            |
| `extensions/chrome/src/background.js`                      | Extension: sendNativeMessage transport                    |
| `src-tauri/crates/infrastructure/src/native_host_setup.rs` | Manifest generation + browser registration                |
| `src-tauri/src/lib.rs` `register_native_host()`            | Auto-register on startup (chmod +x, read IDs from config) |
| `extensions/chrome/scripts/install-native-host.sh`         | Write extension IDs to config file                        |

### Setup for Development

The extension ID is unstable when loading unpacked. To connect:

```bash
# 1. Load extension in Chrome, copy the ID from chrome://extensions/
# 2. Write the ID to the config file:
bash extensions/chrome/scripts/install-native-host.sh <chrome-extension-id> [firefox-id]
# 3. Restart the desktop app — it reads the config and writes browser manifests
```

Config file: `~/Library/Application Support/com.pwdvault.app/native-host.json`
Format: `{"chrome": "<id>", "firefox": "<id>"}`

### Known Issues / Deferred

- **Stage 3 (socket transport) skipped**: The HTTP TCP port 17429 is still
  open (loopback only). Converting to Unix domain socket / Windows named pipe
  is deferred as a non-blocking optimization. NM's `allowed_origins` already
  provides the source-locking security benefit.
- **Extension ID stability**: `allowed_origins` uses the dev extension ID from
  config. After store publication with fixed IDs, update `native_host_setup.rs`.
- **Pre-existing test failures**: Resolved — the keystore is now per-`AppState`
  (A3), so tests run in parallel without `--test-threads=1`.
- **macOS code signing**: The host binary is unsigned in local builds. CI
  release builds may need codesign/notarize steps for distribution.
- **Tauri resources executable bit**: `bundle.resources` does not preserve +x;
  `register_native_host()` auto-fixes this on every launch.
