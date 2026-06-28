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
}

export interface AuditStore {
  records: AuditRecord[];
  
  // Actions
  addRecord: (record: Omit<AuditRecord, 'id' | 'timestamp'>) => void;
  clearRecords: () => void;
}

export const useAuditStore = create<AuditStore>((set) => ({
  records: [],

  addRecord: (record) => set((state) => {
    const newRecord: AuditRecord = {
      ...record,
      id: `aud-${Math.random().toString(36).substring(7)}`,
      timestamp: new Date()
    };
    return { records: [newRecord, ...state.records] };
  }),

  clearRecords: () => set({ records: [] })
}));
