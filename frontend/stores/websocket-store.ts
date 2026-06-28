import { create } from 'zustand';
import { useTelemetryStore } from './telemetry-store';

export type WebSocketStatus = 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR';

export interface WebSocketStore {
  status: WebSocketStatus;
  lastPing: Date | null;
  reconnectAttempts: number;
  
  setStatus: (status: WebSocketStatus) => void;
  recordPing: () => void;
  incrementReconnect: () => void;
  resetReconnect: () => void;
}

export const useWebSocketStore = create<WebSocketStore>((set) => ({
  status: 'DISCONNECTED',
  lastPing: null,
  reconnectAttempts: 0,
  
  setStatus: (status) => set({ status }),
  recordPing: () => set({ lastPing: new Date() }),
  incrementReconnect: () => set((state) => ({ reconnectAttempts: state.reconnectAttempts + 1 })),
  resetReconnect: () => set({ reconnectAttempts: 0 })
}));

// Initialize WS connection manager (singleton pattern for the frontend)
let wsInstance: WebSocket | null = null;
let heartbeatInterval: NodeJS.Timeout | null = null;

export const initializeWebSocket = (url: string = 'ws://localhost:8000/ws') => {
  if (typeof window === 'undefined') return; // Next.js SSR guard
  
  if (wsInstance && (wsInstance.readyState === WebSocket.OPEN || wsInstance.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const { setStatus, recordPing, incrementReconnect, resetReconnect } = useWebSocketStore.getState();
  const { addLog } = useTelemetryStore.getState();

  setStatus('CONNECTING');

  try {
    wsInstance = new WebSocket(url);

    wsInstance.onopen = () => {
      setStatus('CONNECTED');
      resetReconnect();
      addLog({
        event: 'WebSocket connection established with TrustOS backend.',
        type: 'success',
        source: 'System'
      });
      
      // Setup heartbeat ping simulation (or actual if backend supports it)
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      heartbeatInterval = setInterval(() => {
        if (wsInstance?.readyState === WebSocket.OPEN) {
          // Sent simple ping
          wsInstance.send(JSON.stringify({ type: 'PING', timestamp: new Date().toISOString() }));
          recordPing();
        }
      }, 5000);
    };

    wsInstance.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'PONG') {
          recordPing();
          return;
        }
        
        // Handle incoming live telemetry events
        if (data.event) {
            addLog({
                event: data.event,
                type: data.type || 'info',
                source: data.source || 'Stream'
            });
        }
      } catch (e) {
        // Ignore unparseable frames
      }
    };

    wsInstance.onclose = () => {
      setStatus('DISCONNECTED');
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      
      addLog({
        event: 'WebSocket connection lost. Attempting to reconnect...',
        type: 'warning',
        source: 'System'
      });

      const attempts = useWebSocketStore.getState().reconnectAttempts;
      if (attempts < 5) {
        incrementReconnect();
        setTimeout(() => initializeWebSocket(url), Math.min(1000 * Math.pow(2, attempts), 10000));
      } else {
        setStatus('ERROR');
        addLog({
          event: 'Maximum reconnect attempts reached. Stream halted.',
          type: 'error',
          source: 'System'
        });
      }
    };

    wsInstance.onerror = () => {
      setStatus('ERROR');
    };
    
  } catch (e) {
    setStatus('ERROR');
  }
};
