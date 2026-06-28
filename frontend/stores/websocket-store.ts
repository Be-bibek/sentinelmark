import { create } from 'zustand';
import { useTelemetryStore } from './telemetry-store';

export type WebSocketStatus = 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR';

export interface WebSocketStore {
  status: WebSocketStatus;
  lastPing: Date | null;
  lastEventAt: Date | null;
  connectedAt: Date | null;
  reconnectAttempts: number;
  messagesReceived: number;
  messagesSent: number;

  setStatus: (status: WebSocketStatus) => void;
  recordPing: () => void;
  recordMessageReceived: () => void;
  recordMessageSent: () => void;
  incrementReconnect: () => void;
  resetReconnect: () => void;
}

export const useWebSocketStore = create<WebSocketStore>((set) => ({
  status: 'DISCONNECTED',
  lastPing: null,
  lastEventAt: null,
  connectedAt: null,
  reconnectAttempts: 0,
  messagesReceived: 0,
  messagesSent: 0,

  setStatus: (status) => set((state) => ({
    status,
    connectedAt: status === 'CONNECTED' && state.status !== 'CONNECTED'
      ? new Date()
      : state.connectedAt,
  })),
  recordPing: () => set({ lastPing: new Date(), lastEventAt: new Date() }),
  recordMessageReceived: () => set((state) => ({
    messagesReceived: state.messagesReceived + 1,
    lastEventAt: new Date(),
  })),
  recordMessageSent: () => set((state) => ({ messagesSent: state.messagesSent + 1 })),
  incrementReconnect: () => set((state) => ({ reconnectAttempts: state.reconnectAttempts + 1 })),
  resetReconnect: () => set({ reconnectAttempts: 0 }),
}));

// ─── Singleton WebSocket manager ─────────────────────────────────────────────

let wsInstance: WebSocket | null = null;
let heartbeatInterval: NodeJS.Timeout | null = null;

export const initializeWebSocket = (url: string = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8080/api/v1/ws') => {
  if (typeof window === 'undefined') return; // SSR guard

  if (wsInstance && (wsInstance.readyState === WebSocket.OPEN || wsInstance.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const store = useWebSocketStore.getState();
  const { addLog } = useTelemetryStore.getState();

  store.setStatus('CONNECTING');

  try {
    wsInstance = new WebSocket(url);

    wsInstance.onopen = () => {
      useWebSocketStore.getState().setStatus('CONNECTED');
      useWebSocketStore.getState().resetReconnect();
      addLog({ event: 'WebSocket connected to TrustOS backend.', type: 'success', source: 'System' });

      // Heartbeat: send ping every 30s (matches backend ping/pong)
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      heartbeatInterval = setInterval(() => {
        if (wsInstance?.readyState === WebSocket.OPEN) {
          wsInstance.send(JSON.stringify({ type: 'PING', timestamp: new Date().toISOString() }));
          useWebSocketStore.getState().recordMessageSent();
          useWebSocketStore.getState().recordPing();
        }
      }, 30000);
    };

    wsInstance.onmessage = (event) => {
      useWebSocketStore.getState().recordMessageReceived();

      try {
        const data = JSON.parse(event.data as string);

        if (data.event === 'connected') {
          // Welcome frame from backend
          return;
        }

        // Map backend WsEvent types to telemetry log entries
        const eventType = data.event as string;
        let logMessage = '';
        let logType: 'info' | 'warning' | 'error' | 'success' = 'info';

        switch (eventType) {
          case 'trust_evaluated':
            logMessage = `Trust evaluated for ${data.user_id} → ${data.decision} (score: ${data.trust_score?.toFixed(1)}, ${data.evaluation_time_ms}ms)`;
            logType = data.decision === 'BLOCK' ? 'error' : data.decision === 'ALLOW' ? 'success' : 'warning';
            break;
          case 'risk_changed':
            logMessage = `Risk changed for ${data.user_id}: ${data.previous_score?.toFixed(2)} → ${data.new_score?.toFixed(2)}`;
            logType = 'warning';
            break;
          case 'policy_changed':
            logMessage = `Policy decision: ${data.decision} for ${data.user_id}`;
            logType = data.decision === 'BLOCK' ? 'error' : 'info';
            break;
          case 'audit_created':
            logMessage = `Audit record created: ${data.audit_id} for ${data.user_id}`;
            logType = 'success';
            break;
          case 'session_blocked':
            logMessage = `Session BLOCKED for ${data.user_id}: ${data.reason}`;
            logType = 'error';
            break;
          case 'multi_sig_required':
            logMessage = `Multi-sig required for ${data.user_id} (risk: ${data.risk_score?.toFixed(2)})`;
            logType = 'warning';
            break;
          case 'telemetry_received':
            logMessage = `Telemetry from ${data.user_id}: ${data.action_type} on ${data.device_id}`;
            logType = 'info';
            break;
          case 'profile_updated':
            logMessage = `Behavior profile updated for ${data.user_id}`;
            logType = 'info';
            break;
          default:
            logMessage = `WS event: ${eventType}`;
        }

        if (logMessage) {
          addLog({ event: logMessage, type: logType, source: 'WebSocket' });
        }
      } catch {
        // Ignore unparseable frames
      }
    };

    wsInstance.onclose = () => {
      useWebSocketStore.getState().setStatus('DISCONNECTED');
      if (heartbeatInterval) clearInterval(heartbeatInterval);

      addLog({ event: 'WebSocket disconnected. Reconnecting...', type: 'warning', source: 'System' });

      const attempts = useWebSocketStore.getState().reconnectAttempts;
      if (attempts < 5) {
        useWebSocketStore.getState().incrementReconnect();
        const delay = Math.min(1000 * Math.pow(2, attempts), 30000);
        setTimeout(() => initializeWebSocket(url), delay);
      } else {
        useWebSocketStore.getState().setStatus('ERROR');
        addLog({ event: 'Max reconnect attempts reached. Stream halted.', type: 'error', source: 'System' });
      }
    };

    wsInstance.onerror = () => {
      useWebSocketStore.getState().setStatus('ERROR');
    };
  } catch {
    useWebSocketStore.getState().setStatus('ERROR');
  }
};

export const disconnectWebSocket = () => {
  if (wsInstance) {
    if (heartbeatInterval) clearInterval(heartbeatInterval);
    wsInstance.close();
    wsInstance = null;
  }
};
