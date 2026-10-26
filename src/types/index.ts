// API Types - matches Rust backend

/**
 * Per-entry URL matching override for the browser-extension autofill gates
 * (v1.5.0). Mirrors Rust `UrlMatchMode` (domain/entities.rs, serde lowercase:
 * the wire values are exactly these strings). Absent/unknown on the wire
 * degrades to "auto" on every consumer.
 */
export type UrlMatchMode = 'auto' | 'exact' | 'domain';

/**
 * v1.6.0 custom field, plaintext submission shape (mirrors Rust
 * `CustomFieldInput`): sent in the clear over IPC, encrypted server-side
 * with the rest of the entry. `secret` only controls UI masking — the
 * backend encrypts every value regardless.
 */
export interface CustomFieldInput {
  label: string;
  value: string;
  secret: boolean;
}

/**
 * v1.6.0 custom field metadata as it appears on EntrySummary rows: label
 * and masking flag only — values never leave the secret channel
 * (get_entry_secret), mirroring Rust `CustomFieldMeta`.
 */
export interface CustomFieldMeta {
  label: string;
  secret: boolean;
}

/**
 * v1.6.0 custom field with its decrypted value, from the secret channel
 * (mirrors Rust `CustomFieldValue`; Zeroizing discipline lives Rust-side).
 */
export interface CustomFieldValue {
  label: string;
  value: string;
  secret: boolean;
}

export interface CreateEntryRequest {
  title: string;
  url?: string;
  username: string;
  password: string;
  notes?: string;
  tags: string[];
  group_id?: string | null;
  /** Omit = auto (the Rust side carries `#[serde(default)]`). */
  url_match_mode?: UrlMatchMode;
  /**
   * v1.6.0: always carried by this frontend (an empty array clears nothing
   * on create — there is nothing to clear); rows with an empty label AND
   * an empty value are filtered out before the request.
   */
  custom_fields?: CustomFieldInput[];
}

export interface UpdateEntryRequest {
  title: string;
  url?: string;
  username: string;
  /** Omit to preserve the encrypted password already stored by the backend. */
  password?: string;
  /** Omit with update_notes=false to preserve existing encrypted notes. */
  notes?: string;
  update_notes: boolean;
  tags: string[];
  group_id?: string | null;
  /**
   * TOTP secret tri-state (same update semantics as the notes patch):
   * omit = leave unchanged, "" = clear, value = set. The value may be a
   * plain base32 secret or a full otpauth:// URI (the backend parses both).
   */
  totp_secret?: string;
  /** Replaced wholesale on update; omit = auto (serde default). */
  url_match_mode?: UrlMatchMode;
  /**
   * v1.6.0 custom fields, same metadata-replacement semantics as tags:
   * omit = leave the stored set untouched, provide = replace WHOLESALE.
   * The frontend only sends this when the loaded original differs, so an
   * omitted key never wipes stored values.
   */
  custom_fields?: CustomFieldInput[];
}

export type ResourceStatus = 'idle' | 'loading' | 'success' | 'error';

export interface EntrySecretResponse {
  password: string;
  notes?: string;
  last_used_at?: number;
  /**
   * v1.6.0: decrypted custom-field values. Optional because responses from
   * a pre-v1.6.0 desktop lack the field; treat as "no custom fields".
   */
  custom_fields?: CustomFieldValue[];
}

export interface EntrySummary {
  id: string;
  title: string;
  url?: string;
  username: string;
  tags: string[];
  group_id?: string | null;
  created_at: number;
  updated_at: number;
  /** v1.4.0: device-local usage stamp (drives the "Recent" sort). */
  last_used_at?: number | null;
  /** v1.4.0: set only on trash (list_deleted_entries) rows. */
  deleted_at?: number | null;
  /**
   * v1.5.0: per-entry autofill match override. Optional because responses
   * from a pre-v1.5.0 desktop lack the field; treat as "auto".
   */
  url_match_mode?: UrlMatchMode;
  /**
   * v1.6.0: custom-field metadata (label + secret flag, never values).
   * Optional because responses from a pre-v1.6.0 desktop lack the field;
   * treat as "no custom fields" (same precedent as url_match_mode).
   */
  custom_fields?: CustomFieldMeta[];
}

export interface Group {
  id: string;
  name: string;
  created_at: number;
  updated_at: number;
}

// M10: mirrors pwdvault_application::VaultError
// (src-tauri/crates/application/src/error.rs) with serde's external tagging:
// unit variants arrive as plain strings; payload-carrying variants arrive as
// single-key objects. 22 variants = 14 unit + 6 newtype(String) +
// InvalidInput/RateLimited struct variants. REGENERATE this union whenever
// the Rust enum changes — it is the wire contract for IPC rejections.
export type VaultError =
  // --- unit variants (14) ---
  | 'VaultLocked'
  | 'VaultAlreadyExists'
  | 'LegacyVaultRequiresMigration'
  | 'InvalidPassword'
  | 'EntryNotFound'
  | 'WeakKdfParams'
  | 'BiometricUnavailable'
  | 'BiometricCancelled'
  | 'BiometricLockedOut'
  | 'WrapBlobCorrupt'
  | 'RecoveryKeyInvalid'
  | 'RecoveryNotEnabled'
  | 'CurrentPasswordInvalid'
  | 'IntegrityCheckFailed'
  // --- newtype(String) variants (6) ---
  | { EncryptionFailed: string }
  | { DecryptionFailed: string }
  | { DatabaseError: string }
  | { InternalError: string }
  | { InvalidBackup: string }
  | { KeychainError: string }
  // --- struct variants (2) ---
  | { InvalidInput: { code: string; message: string } }
  | { RateLimited: { retry_after_secs: number } };

// App State Types

export type AppScreen = 'setup' | 'unlock' | 'vault' | 'entry' | 'generator' | 'groupManager' | 'settings' | 'importExport' | 'recovery' | 'dashboard';

// Phase 1 security: mirrors pwdvault_domain::BiometricStatus. `available` —
// the platform can prompt for biometry (device support + enrollment);
// `enabled` — the vault has a biometric wrap blob (Touch ID unlock set up).
export interface BiometricStatus {
  available: boolean;
  enabled: boolean;
}

// SEC-M2 (v1.1.9): mirrors pwdvault_application::EnableRecoveryResult
// (serde camelCase — `fileSaved`), returned by `enable_recovery`.
export interface RecoveryEnableResult {
  key: string;
  /** True when the backend also wrote the recovery-key file. */
  fileSaved: boolean;
}

// Phase 2 TOTP: mirrors pwdvault_domain::TotpCodeResponse (serde field
// names — the backend serializes snake_case, no camelCase rewrite).
export interface TotpCodeResponse {
  code: string;
  /** Seconds until the displayed code rotates. */
  seconds_remaining: number;
}

// Phase 3 cloud sync: mirrors pwdvault_application::SyncConfig /
// SyncStatusResponse / BaiduAuthStart (snake_case serde names). `backend`
// matches SyncBackendKind's lowercase serde representation.
export type SyncBackendKind = 'webdav' | 'baidu';

export interface SyncConfig {
  enabled: boolean;
  backend: SyncBackendKind;
  /** WebDAV server root, e.g. https://dav.jianguoyun.com/dav */
  server_url: string;
  /** Directory on the remote holding the container files. */
  remote_dir: string;
  /** WebDAV user name (non-sensitive). */
  username: string;
}

export interface SyncStatusResponse {
  enabled: boolean;
  backend?: string | null;
  last_sync_at?: number | null;
  /** "ok" after a successful cycle; otherwise a short error code. */
  last_result?: string | null;
  remote_rev?: number | null;
  /**
   * v1.6.0: LWW conflicts auto-resolved during the last merge (D5). Optional
   * because a pre-v1.6.0 desktop response omits the key — readers must `?? 0`.
   */
  conflict_count?: number;
}

export interface BaiduAuthStart {
  /** Authorization URL for the system browser. */
  auth_url: string;
}

export type GeneratorMode = "password" | "passphrase" | "pin";

export interface PasswordGeneratorOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
  /** v1.4.0: selects the generator backend; omitted on legacy callers = password. */
  mode?: GeneratorMode;
  /** Passphrase word count (3-10, EFF short list). */
  words?: number;
  /** Passphrase separator; empty string allowed (no separator). */
  separator?: string;
  capitalize?: boolean;
  appendNumber?: boolean;
}

/** Sort modes for the vault list (persisted in Settings, v1.4.0). */
export type SortMode = "recent" | "updated" | "alpha";

export interface Settings {
  auto_lock_secs: number;
  default_length: number;
  default_include_uppercase: boolean;
  default_include_lowercase: boolean;
  default_include_numbers: boolean;
  default_include_symbols: boolean;
  check_updates: boolean;
  /** Vault list ordering (v1.4.0). Unknown values fall back to "recent". */
  sort_mode: SortMode;
  /** Global show-vault shortcut (v1.4.0). Registration lives in Rust. */
  global_shortcut_enabled: boolean;
  global_shortcut: string;
  /**
   * Trash auto-purge (v1.5.0): tombstones older than this many days are
   * physically deleted by the post-unlock sweep (one ≤500-row batch per
   * unlock). 0 = off; the UI offers 0/7/30/90.
   */
  trash_auto_purge_days: number;
  /**
   * Timed auto-sync (v1.6.0): minutes between automatic sync cycles while
   * the vault is unlocked. 0 = off (strict opt-in, same semantics as
   * trash_auto_purge_days); the UI offers 0/5/15/30/60. Device-local
   * preference — lives in Settings, not SyncConfig.
   */
  auto_sync_interval_min: number;
}

export const DEFAULT_SETTINGS: Settings = {
  auto_lock_secs: 600,
  default_length: 16,
  default_include_uppercase: true,
  default_include_lowercase: true,
  default_include_numbers: true,
  default_include_symbols: true,
  check_updates: true,
  sort_mode: "recent",
  global_shortcut_enabled: true,
  global_shortcut: "CmdOrCtrl+Shift+Space",
  trash_auto_purge_days: 0,
  auto_sync_interval_min: 0,
};

// Backup/Restore Types

export interface VaultBackup {
  version: number;
  created_at: number;
  magic?: string;
  kdf_name?: string;
  cipher_name?: string;
  salt: string;
  kdf_memory: number;
  kdf_iterations: number;
  kdf_parallelism: number;
  nonce: string;
  data: string;
}

export interface ImportResult {
  entries_imported: number;
  groups_imported: number;
}

// Security Dashboard (v1.5.0 WP1) — mirrors
// pwdvault_application::SecurityReport. The report is the security contract:
// ids, counts, and scores only — the backend never sends plaintext secrets.

export interface SecurityReportWeakEntry {
  id: string;
  /** 0-100 on the shared getPasswordStrength heuristic. */
  score: number;
}

export interface SecurityReport {
  generated_at: number;
  /** Live entries scanned. */
  total: number;
  /** Entries scoring ≤ 40 ("Very Weak"/"Weak" on the strength meter). */
  weak: SecurityReportWeakEntry[];
  /** Groups of ≥ 2 entries sharing the identical password. */
  reused: string[][];
  /** Entries not modified for more than a year (updated_at-based). */
  stale: string[];
}

// Third-party CSV import (v1.5.0 WP2) — mirrors
// pwdvault_application::CsvImportPreview / CsvImportResult. Preview rows
// carry password PRESENCE flags, never values (the plaintext stays in the
// backend staging between open and commit).

export interface CsvImportPreviewRow {
  title: string;
  username: string;
  url?: string | null;
  group?: string | null;
  has_password: boolean;
  has_notes: boolean;
  has_totp: boolean;
}

export interface CsvImportPreview {
  /** "Bitwarden" | "1Password" | "Chrome" | "KeePassXC". */
  preset: string;
  /** Data rows in the file (header excluded, blank lines included). */
  total_rows: number;
  /** Rows that will NOT import (blank lines + validation failures). */
  skipped_rows: number;
  /** Staged rows whose (username, url) pair already exists in the vault. */
  duplicate_candidates: number;
  rows: CsvImportPreviewRow[];
}

export interface CsvImportResult {
  created_entries: number;
  created_groups: number;
  skipped_rows: number;
}
