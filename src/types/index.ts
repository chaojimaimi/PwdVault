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

export type AppScreen = 'setup' | 'unlock' | 'vault' | 'entry' | 'generator' | 'groupManager' | 'settings' | 'importExport';

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