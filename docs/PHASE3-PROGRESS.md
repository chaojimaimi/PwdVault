# Phase 3 Implementation Progress

> **Document**: 前端数据可信度与隐私
> **Plan**: PwdVault-Comprehensive-Optimization-Plan-v1.0.5.md §5.3.1–5.3.7
> **Date**: 2026-07-16
> **Status**: ⚠️ Core acceptance complete; native clipboard ownership tracking pending

---

## Summary

Phase 3 removes ambiguous frontend data states, gates update-network access on
trusted settings, keeps group state coherent across screens, and makes entry
secret access demand-driven. Loading failures are no longer rendered as empty
data, settings failures cannot overwrite backend values, and metadata-only
entry edits neither fetch nor resubmit the existing password or notes.

The eight explicit §5.3.7 acceptance criteria are implemented and covered by
automated or code-path verification. One defense-in-depth implementation detail
remains: clipboard timeout ownership currently compares a SHA-256 digest of the
current clipboard content instead of using a native pasteboard sequence/change
counter.

## Implemented Scope

### Resource State and Boot Recovery

- Entries, groups, and settings now carry independent
  `idle | loading | success | error` status and error details.
- Vault renders loading, retryable failure, actual empty vault, and empty search
  results as different states.
- Settings values are copied into the form only after a successful backend load;
  controls and Save stay disabled after a loading error.
- Initial setup detection failures render a fatal boot error with Retry instead
  of falling through to the first-run setup screen.

### Update Privacy

- Update checks require all of: unlocked vault, successful settings load,
  `check_updates=true`, enabled trusted update feed, and no prior check in the
  current startup.
- Private-repository builds default `VITE_UPDATE_CHECK_ENABLED` to false and
  therefore perform no update network request.
- The Settings UI explains why the toggle is unavailable in private builds.
- No GitHub token or other repository credential is embedded in the client.

### Group State Consistency

- `GroupSelector` now consumes `VaultContext` groups/actions rather than
  maintaining a private API-backed copy.
- Creating a group refreshes global groups and selects the returned group.
- Deleting a group refreshes both groups and entries, applying the backend
  ungroup cascade immediately.
- Deleting the selected filter clears `selectedGroupId` and returns Vault to All.

### Secret-Minimizing Entry Updates

- Added backend `UpdateEntryRequest`: password is optional and notes use an
  explicit `update_notes` flag.
- Metadata-only patches preserve encrypted password and notes without decrypting
  or re-encrypting them.
- Edit screens load metadata only. Password is fetched on explicit reveal/copy;
  notes are fetched only when the user chooses to edit them.
- Hiding an unchanged revealed password removes it from component state.
- Backend regression testing verifies metadata patches preserve both secrets.

### Clipboard Lifetime

- Desktop and extension timeout callbacks retain only a SHA-256 digest, not the
  plaintext password, for the 30-second comparison window.
- Clipboard content is cleared only if its digest still matches the value
  written by PwdVault; a value replaced by the user or another application is
  preserved.
- Username copying no longer uses the sensitive auto-clear path.

### Form Integrity

- Desktop generator and Settings reject all-character-sets-disabled state and
  disable Generate/Save until valid.
- Extension generator prevents deselecting the final character set.
- Entry, Settings, and extension Create flows track dirty state and warn before
  in-app back navigation discards changes.
- Save/create/generate actions use pending state to prevent duplicate submits.

## §5.3.7 Acceptance Criteria Verification

| # | Criterion | Status | Evidence |
|---|---|---|
| 1 | 加载错误绝不显示为空库 | ✅ | Vault resource error branch and `Phase3ResourceState` regression test |
| 2 | settings 加载失败时 Save disabled | ✅ | Settings fieldset and Save require `settingsStatus === success`; Retry is explicit |
| 3 | `check_updates=false` 时 0 次；true 时每次启动最多一次 | ✅ | Provider privacy test covers disabled and opted-in feed; private builds make 0 requests by default |
| 4 | 非敏感 entry 编辑不调用 `get_entry_secret` | ✅ | Frontend secret-boundary test plus backend metadata-patch preservation test |
| 5 | Entry 内创建组后全局组立即可见 | ✅ | GroupSelector delegates to context `createGroup`, which refreshes global groups and returns created ID |
| 6 | 删除当前筛选组后自动返回 All | ✅ | `deleteGroup` clears matching selected ID and refreshes cascaded entries |
| 7 | 所有 charset false 时无法生成或保存 | ✅ | Generator and Settings validity guards; extension prevents final deselection |
| 8 | 脏表单返回提示，未修改不提示 | ✅ | Shared desktop unsaved-changes modal, Entry regression test, extension Create guard |

## Verification Results

| Gate | Result |
|---|---|
| Rust main app tests | 134 passed, 1 ignored benchmark |
| Main app `cargo fmt --check` / Clippy `-D warnings` | Passed |
| Frontend tests | 36 passed across 11 files |
| TypeScript | Passed |
| Frontend production build | Passed; existing Vite mixed-import warning only |
| Extension popup JavaScript syntax | Passed (`node --check`) |
| Extension source package verification | Passed; existing Firefox source-symlink distribution warning remains |

## Remaining Boundaries

1. **Native clipboard ownership tracking** — replace digest comparison with a
   native clipboard command using macOS pasteboard change count, Windows
   clipboard sequence number, and a suitable Linux ownership/change mechanism.
   The current implementation removes the JavaScript plaintext closure and
   safely avoids clearing replaced content, but does not satisfy the stronger
   native sequence-counter design.
2. **Public update metadata** — before enabling
   `VITE_UPDATE_CHECK_ENABLED=true`, publish a public trusted metadata source
   (preferably the signed updater manifest planned for release engineering).
3. **Extension automated UI coverage** — Create dirty/pending and generator
   guards are source-verified and package-verified; browser E2E remains part of
   the Phase 5 extension test matrix.
4. **Stable release remains frozen** — Windows ACL acceptance, native clipboard
   ownership, Phase 5 Native Messaging release hardening, Phase 6 release gates,
   and independent security review remain open.
