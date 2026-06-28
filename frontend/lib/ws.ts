import { useSentinelStore } from "./store";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8080/api/v1/ws";
let socket: WebSocket | null = null;
let reconnectTimeout: NodeJS.Timeout | null = null;
let isIntentionalClose = false;

export const connectWebSocket = () => {
  if (socket?.readyState === WebSocket.OPEN || socket?.readyState === WebSocket.CONNECTING) {
    return;
  }

  socket = new WebSocket(WS_URL);
  isIntentionalClose = false;

  socket.onopen = () => {
    console.log("[Sentinel WS] Connected");
    useSentinelStore.getState().setConnected(true);
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      // Dispatch the event to the global store
      useSentinelStore.getState().addEvent(data);
    } catch (err) {
      console.error("[Sentinel WS] Failed to parse message", err);
    }
  };

  socket.onclose = () => {
    console.log("[Sentinel WS] Disconnected");
    useSentinelStore.getState().setConnected(false);
    socket = null;

    if (!isIntentionalClose) {
      // Reconnect after 3 seconds
      reconnectTimeout = setTimeout(connectWebSocket, 3000);
    }
  };

  socket.onerror = (error) => {
    console.error("[Sentinel WS] Error", error);
  };
};

export const disconnectWebSocket = () => {
  isIntentionalClose = true;
  if (socket) {
    socket.close();
  }
  if (reconnectTimeout) {
    clearTimeout(reconnectTimeout);
  }
};
