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
}

export interface EntryResponse {
  id: string;
  title: string;
  url?: string;
  username: string;
  password: string;
  notes?: string;
  tags: string[];
  created_at: number;
  updated_at: number;
  last_used_at?: number;
}

export interface EntrySummary {
  id: string;
  title: string;
  url?: string;
  username: string;
  tags: string[];
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

export type AppScreen = 'setup' | 'unlock' | 'vault' | 'entry' | 'generator';

export interface VaultState {
  isInitialized: boolean;
  isUnlocked: boolean;
  entries: EntrySummary[];
  selectedEntry: EntryResponse | null;
  searchQuery: string;
}

export interface PasswordGeneratorOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
}