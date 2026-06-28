import { create } from 'zustand';

export interface WsEvent {
  event: string;
  [key: string]: any;
}

interface SentinelState {
  isConnected: boolean;
  setConnected: (status: boolean) => void;
  
  // A circular buffer of the last N events to show in timelines
  recentEvents: WsEvent[];
  addEvent: (event: WsEvent) => void;

  // Active sessions counter
  activeSessions: number;
  setActiveSessions: (count: number) => void;
}

const MAX_EVENTS = 50;

export const useSentinelStore = create<SentinelState>((set) => ({
  isConnected: false,
  setConnected: (status) => set({ isConnected: status }),

  recentEvents: [],
  addEvent: (event) =>
    set((state) => {
      const newEvents = [event, ...state.recentEvents];
      if (newEvents.length > MAX_EVENTS) {
        newEvents.pop(); // Keep only the most recent
      }
      return { recentEvents: newEvents };
    }),

  activeSessions: 0,
  setActiveSessions: (count) => set({ activeSessions: count }),
}));
