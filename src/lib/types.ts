export type EntryType = 'login' | 'note' | 'card' | 'api';
export type Flag = 0 | 1;

export interface CustomField {
  label: string;
  value: string;
  masked: Flag;
}

export interface HistoryItem {
  password: string;
  changedAt: number;
}

/** A decrypted vault entry. Optional fields may be missing in vaults created by older versions. */
export interface Entry {
  id: string;
  type?: EntryType;
  service: string;
  username: string;
  email: string;
  password: string;
  totpSecret?: string;
  recEmail: string;
  qa: string;
  notes: string;
  fields?: CustomField[];
  tags?: string[];
  fav?: Flag;
  created: number;
  pwChanged?: number;
  history?: HistoryItem[];
}

/** An entry without an id, e.g. freshly parsed from a CSV import. */
export type NewEntry = Omit<Entry, 'id'>;

/** Encrypted profile record as persisted in IndexedDB and in backup files. */
export interface ProfileRecord {
  salt: string;
  iv: string;
  ct: string;
  created?: number;
}

export type ProfileMap = Record<string, ProfileRecord>;
