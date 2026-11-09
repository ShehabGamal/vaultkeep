import type { Flag } from './types';

/* Device settings (non-secret, stored unencrypted in localStorage). */
export const SETTINGS_KEY = 'vaultkeep.settings';

export const LOCK_OPTS: readonly [number, string][] = [
  [1, '1 minute'],
  [3, '3 minutes'],
  [5, '5 minutes'],
  [15, '15 minutes'],
  [0, 'Never'],
];

export interface DeviceSettings {
  lockMin: number;
  escLock: Flag;
}

const DEFAULTS: DeviceSettings = { lockMin: 3, escLock: 1 };

export function cfg(): DeviceSettings {
  try {
    return { ...DEFAULTS, ...(JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? 'null') as Partial<DeviceSettings>) };
  } catch {
    return { ...DEFAULTS };
  }
}

export function setCfg(patch: Partial<DeviceSettings>): void {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ ...cfg(), ...patch }));
  } catch {
    /* ignore quota / disabled storage */
  }
}

export function lockLabel(): string {
  const m = cfg().lockMin;
  return m ? `auto-locks after ${m} idle minute${m > 1 ? 's' : ''}` : 'auto-lock off';
}
