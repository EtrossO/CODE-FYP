export const SafetyStatusValues = {
  SAFE: 'SAFE',
  SUSPICIOUS: 'SUSPICIOUS',
  UNSAFE: 'UNSAFE',
  LOADING: 'LOADING'
} as const;

export type SafetyStatus = typeof SafetyStatusValues[keyof typeof SafetyStatusValues];

export interface ScanResult {
    id: string;
    url: string;
    status: SafetyStatus;
    timestamp: number;
    reason?: string;
    title?: string;
    description?: string;
    imageUrl?: string;
}

export type TabType = 'scanner' | 'history';