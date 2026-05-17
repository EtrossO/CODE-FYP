import Dexie, { type Table } from 'dexie';
import type { ScanResult } from '../types';

export class CampusShieldDB extends Dexie {
  scanHistory!: Table<ScanResult, string>;

  constructor() {
    super('CampusShieldDB');
    this.version(1).stores({
      scanHistory: 'id, status, timestamp',
    });
  }
}

export const db = new CampusShieldDB();
