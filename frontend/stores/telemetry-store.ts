import { create } from 'zustand';

export interface LogEntry {
  id: string;
  timestamp: Date;
  event: string;
  type: 'info' | 'warning' | 'error' | 'success';
  source: string;
}

export interface TelemetryStore {
  logs: LogEntry[];
  isPaused: boolean;
  filterLevel: 'all' | 'warning' | 'error';
  
  // Actions
  addLog: (log: Omit<LogEntry, 'id' | 'timestamp'>) => void;
  clearLogs: () => void;
  togglePause: () => void;
  setFilter: (level: 'all' | 'warning' | 'error') => void;
}

export const useTelemetryStore = create<TelemetryStore>((set) => ({
  logs: [],
  isPaused: false,
  filterLevel: 'all',

  addLog: (log) => set((state) => {
    if (state.isPaused) return state;
    
    const newLog: LogEntry = {
      ...log,
      id: Math.random().toString(36).substring(7),
      timestamp: new Date()
    };
    
    // Keep last 100 logs
    return { logs: [newLog, ...state.logs].slice(0, 100) };
  }),

  clearLogs: () => set({ logs: [] }),
  togglePause: () => set((state) => ({ isPaused: !state.isPaused })),
  setFilter: (filterLevel) => set({ filterLevel })
}));
