import { create } from 'zustand';

export interface ApiLogEntry {
  id: string;
  method: string;
  endpoint: string;
  payloadBytes: number;
  responseBytes: number;
  latencyMs: number;
  statusCode: number;
  requestId: string;
  retryCount: number;
  error?: string;
  timestamp: Date;
  curlCommand: string;
}

export interface ApiLogStore {
  entries: ApiLogEntry[];
  totalRequests: number;
  totalErrors: number;
  avgLatencyMs: number;

  addEntry: (entry: Omit<ApiLogEntry, 'id' | 'timestamp'>) => void;
  clear: () => void;
}

export const useApiLogStore = create<ApiLogStore>((set, get) => ({
  entries: [],
  totalRequests: 0,
  totalErrors: 0,
  avgLatencyMs: 0,

  addEntry: (entry) => set((state) => {
    const newEntry: ApiLogEntry = {
      ...entry,
      id: Math.random().toString(36).substring(2, 10),
      timestamp: new Date(),
    };

    const newEntries = [newEntry, ...state.entries].slice(0, 50);
    const totalRequests = state.totalRequests + 1;
    const totalErrors = entry.statusCode >= 400 ? state.totalErrors + 1 : state.totalErrors;
    const totalLatency = newEntries.reduce((sum, e) => sum + e.latencyMs, 0);
    const avgLatencyMs = Math.round(totalLatency / newEntries.length);

    return { entries: newEntries, totalRequests, totalErrors, avgLatencyMs };
  }),

  clear: () => set({ entries: [], totalRequests: 0, totalErrors: 0, avgLatencyMs: 0 }),
}));
