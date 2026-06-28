import { create } from 'zustand';
import { PolicyDecision } from './trust-store';

export interface AuditRecord {
  id: string;
  timestamp: Date;
  user: string;
  trustScore: number;
  anomalies: string[];
  decision: PolicyDecision;
  riskScore?: number;
  // Backend fields (populated when record comes from API)
  auditId?: string;
  explanation?: string;
  source: 'live' | 'mock';
}

export type DataSource = 'LIVE' | 'CACHED' | 'MOCK' | 'OFFLINE';

export interface AuditStore {
  records: AuditRecord[];
  dataSource: DataSource;

  // Actions
  addRecord: (record: Omit<AuditRecord, 'id' | 'timestamp' | 'source'> & { source?: 'live' | 'mock'; auditId?: string }) => void;
  setRecordsFromBackend: (records: AuditRecord[]) => void;
  setDataSource: (source: DataSource) => void;
  clearRecords: () => void;
}

export const useAuditStore = create<AuditStore>((set) => ({
  records: [],
  dataSource: 'MOCK',

  addRecord: (record) => set((state) => {
    // Deduplicate by auditId if present
    if (record.auditId) {
      const exists = state.records.some(r => r.auditId === record.auditId);
      if (exists) return state;
    }
    const newRecord: AuditRecord = {
      ...record,
      id: `aud-${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date(),
      source: record.source ?? 'mock',
    };
    return { records: [newRecord, ...state.records].slice(0, 200) };
  }),

  setRecordsFromBackend: (records) => set({ records, dataSource: 'LIVE' }),

  setDataSource: (dataSource) => set({ dataSource }),

  clearRecords: () => set({ records: [], dataSource: 'MOCK' }),
}));
