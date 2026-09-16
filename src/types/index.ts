// API Types - matches Rust backend

export interface EncryptedData {
  nonce: number[];
  ciphertext: number[];
}

export interface CreateEntryRequest {
  title: string;
  url?: string;
  username: string;
  password: string;
  notes?: string;
  tags: string[];
  group_id?: string | null;
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
}

export type ResourceStatus = 'idle' | 'loading' | 'success' | 'error';

export interface EntrySecretResponse {
  password: string;
  notes?: string;
  last_used_at?: number;
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
}

export interface Group {
  id: string;
  name: string;
  created_at: number;
  updated_at: number;
}

export type VaultError =
  | 'VaultLocked'
  | 'VaultAlreadyExists'
  | 'InvalidPassword'
  | 'EntryNotFound'
  | { EncryptionFailed: string }
  | { DecryptionFailed: string }
  | { DatabaseError: string }
  | { InternalError: string };

// App State Types

export type AppScreen = 'setup' | 'unlock' | 'vault' | 'entry' | 'generator' | 'groupManager' | 'settings' | 'importExport' | 'recovery';

// Phase 1 security: mirrors pwdvault_domain::BiometricStatus. `available` —
// the platform can prompt for biometry (device support + enrollment);
// `enabled` — the vault has a biometric wrap blob (Touch ID unlock set up).
export interface BiometricStatus {
  available: boolean;
  enabled: boolean;
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
}

export interface BaiduAuthStart {
  /** Authorization URL for the system browser. */
  auth_url: string;
}

export interface VaultState {
  isInitialized: boolean;
  isUnlocked: boolean;
  entries: EntrySummary[];
  selectedEntry: EntrySummary | null;
  searchQuery: string;
  groups: Group[];
  selectedGroupId?: string | null;
}

export interface PasswordGeneratorOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
}

export interface Settings {
  auto_lock_secs: number;
  default_length: number;
  default_include_uppercase: boolean;
  default_include_lowercase: boolean;
  default_include_numbers: boolean;
  default_include_symbols: boolean;
  check_updates: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  auto_lock_secs: 600,
  default_length: 16,
  default_include_uppercase: true,
  default_include_lowercase: true,
  default_include_numbers: true,
  default_include_symbols: true,
  check_updates: true,
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

export interface UpdateInfo {
  has_update: boolean;
  latest_version: string;
  release_notes: string;
  download_url: string;
}
