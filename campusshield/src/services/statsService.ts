import { db } from '../db/database';
import { SafetyStatusValues } from '../types';

export interface DomainStats {
  domain: string;
  total: number;
  safe: number;
  suspicious: number;
  unsafe: number;
}

export function extractDomain(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

export async function getDomainStats(): Promise<DomainStats[]> {
  const all = await db.scanHistory.toArray();
  const map = new Map<string, DomainStats>();

  for (const item of all) {
    const domain = extractDomain(item.url);
    let entry = map.get(domain);
    if (!entry) {
      entry = { domain, total: 0, safe: 0, suspicious: 0, unsafe: 0 };
      map.set(domain, entry);
    }
    entry.total++;
    if (item.status === SafetyStatusValues.SAFE) entry.safe++;
    else if (item.status === SafetyStatusValues.SUSPICIOUS) entry.suspicious++;
    else if (item.status === SafetyStatusValues.UNSAFE) entry.unsafe++;
  }

  return Array.from(map.values()).sort((a, b) => b.total - a.total);
}
