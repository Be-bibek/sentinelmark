import { useSentinelStore } from "./store";
import { toast } from "sonner";
import { QueryClient } from "@tanstack/react-query";

// Need a global queryClient reference to invalidate caches, normally done via context, 
// but we can export the instance from Providers or just let React Query auto-refetch
// For WS events, updating the Zustand store or showing a Toast is primary.

let socket: WebSocket | null = null;
let reconnectAttempt = 0;
let reconnectTimeout: NodeJS.Timeout;
let pingInterval: NodeJS.Timeout;

const WS_BASE_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8080/api/v1/ws";
const MAX_RECONNECT_ATTEMPTS = 5;
const BASE_RECONNECT_DELAY = 1000;

export const connectWebSocket = (queryClient?: QueryClient) => {
  if (socket?.readyState === WebSocket.OPEN || socket?.readyState === WebSocket.CONNECTING) return;

  try {
    socket = new WebSocket(WS_BASE_URL);

    socket.onopen = () => {
      useSentinelStore.getState().setConnected(true);
      reconnectAttempt = 0;
      
      // Start Heartbeat
      pingInterval = setInterval(() => {
        if (socket?.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: "ping" }));
        }
      }, 30000);
      
      toast.success("WebSocket Connected", { description: "Real-time threat feed established." });
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        // Handle incoming WebSocket events
        if (data.event === "TrustEvaluated") {
          useSentinelStore.getState().addEvent(data);
          
          // If we passed a queryClient, invalidate metrics and audit logs
          if (queryClient) {
            queryClient.invalidateQueries({ queryKey: ["metrics"] });
            queryClient.invalidateQueries({ queryKey: ["audit"] });
          }
        } else if (data.event === "TelemetryReceived") {
          useSentinelStore.getState().addEvent(data);
        }
      } catch (err) {
        console.error("Failed to parse WS message", err);
      }
    };

    socket.onclose = () => {
      useSentinelStore.getState().setConnected(false);
      clearInterval(pingInterval);
      
      if (reconnectAttempt < MAX_RECONNECT_ATTEMPTS) {
        const delay = BASE_RECONNECT_DELAY * Math.pow(2, reconnectAttempt);
        reconnectAttempt++;
        reconnectTimeout = setTimeout(() => connectWebSocket(queryClient), delay);
        toast.warning("WebSocket Disconnected", { 
          description: `Reconnecting in ${delay/1000}s (Attempt ${reconnectAttempt}/${MAX_RECONNECT_ATTEMPTS})...` 
        });
      } else {
        toast.error("WebSocket Failed", { description: "Max reconnect attempts reached." });
      }
    };

    socket.onerror = (error) => {
      console.error("[Sentinel WS] Error", error);
      // Close will be called automatically which handles reconnect
    };
  } catch (error) {
    console.error("Failed to initialize WebSocket", error);
  }
};

export const disconnectWebSocket = () => {
  if (socket) {
    clearTimeout(reconnectTimeout);
    clearInterval(pingInterval);
    socket.close();
    socket = null;
  }
};
