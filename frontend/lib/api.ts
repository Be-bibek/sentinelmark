import axios, { AxiosError, AxiosResponse, InternalAxiosRequestConfig } from "axios";
import { v4 as uuidv4 } from "uuid";
import { toast } from "sonner";

// Get base URL from environment or fallback to localhost
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

// Create a robust Axios instance
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000, // 10 second timeout
  headers: {
    "Content-Type": "application/json",
  },
});

// Request Interceptor: Attach X-Request-ID
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const requestId = uuidv4();
  config.headers.set("X-Request-ID", requestId);
  return config;
});

// Response Interceptor: Error mapping and global toasts
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    // Unwrap the { success, data, meta } envelope automatically
    // The backend returns standard envelopes for SentinelMark
    if (response.data && typeof response.data === 'object' && 'data' in response.data) {
        return response.data.data;
    }
    return response.data;
  },
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // Handle Network Offline
    if (!error.response) {
      toast.error("Network Error", {
        description: "Cannot connect to the SentinelMark backend. Please check your connection.",
      });
      return Promise.reject(new Error("Network Error: Cannot connect to backend"));
    }

    const status = error.response.status;
    const errorData = error.response.data as any;
    const errorMessage = errorData?.error?.message || error.message || "An unexpected error occurred.";

    // Handle 500 / 503 Auto-retry logic
    if ((status >= 500 || status === 429) && !originalRequest._retry) {
      originalRequest._retry = true;
      toast.info("Retrying Request...", {
        description: "The backend is experiencing transient issues. Reconnecting...",
      });
      
      // Exponential backoff strategy could go here; simple delay for now
      await new Promise((resolve) => setTimeout(resolve, 1000));
      return apiClient(originalRequest);
    }

    // Global Error Toasts for specific status codes
    if (status === 401) {
      toast.error("Unauthorized", { description: "Session expired or invalid API key." });
    } else if (status === 403) {
      toast.error("Forbidden", { description: "You don't have access to this resource." });
    } else if (status === 404) {
      toast.error("Not Found", { description: "The requested resource does not exist." });
    } else if (status >= 500) {
      toast.error("Backend Error", { description: errorMessage });
    }

    return Promise.reject(new Error(errorMessage));
  }
);

// Define API contract structures based on Rust Axum backend responses

export interface EventPayload {
  device_id?: string;
  browser_fingerprint?: string;
  ip_address?: string;
  geo_region?: string;
  action_type?: string;
  transaction_amount?: number;
  session_duration_secs?: number;
}

export interface EvaluateRequest {
  user_id: string;
  event: EventPayload;
}

export interface EvaluateResponse {
  decision: "ALLOW" | "MFA" | "MULTI-SIG" | "BLOCK";
  trust_score: number;
  risk_score: number;
  risk_factors: string[];
}

export interface HealthResponse {
  status: string;
  version: string;
  database: string;
}

export interface SystemMetrics {
  active_sessions: number;
  evaluations_last_hour: number;
  average_latency_ms: number;
}

export interface BehaviorProfile {
  user_id: string;
  trust_score: number;
  risk_score: number;
  known_devices: string[];
  known_regions: string[];
  avg_login_hour: number;
  avg_session_duration: number;
  avg_transaction_amount: number;
  mfa_enrolled: boolean;
}

export interface AuditRecord {
  id: string;
  timestamp: string;
  user_id: string;
  event_type: string;
  trust_score: number;
  risk_score: number;
  decision: string;
  anomalies: string[];
}

export interface PaginatedAudit {
  records: AuditRecord[];
  total: number;
  page: number;
  limit: number;
}

// SentinelAPI class encapsulating React Query/Axios calls
export class SentinelAPI {
  static async getHealth(): Promise<HealthResponse> {
    return apiClient.get('/api/v1/health');
  }

  static async getMetrics(): Promise<SystemMetrics> {
    return apiClient.get('/api/v1/metrics');
  }

  static async evaluate(payload: EvaluateRequest): Promise<EvaluateResponse> {
    return apiClient.post('/api/v1/evaluate', payload);
  }

  static async getBehaviorProfile(userId: string): Promise<BehaviorProfile> {
    return apiClient.get(`/api/v1/behavior-profile/${userId}`);
  }

  static async getAuditLogs(userId?: string, page = 1, limit = 50): Promise<PaginatedAudit> {
    const params = new URLSearchParams();
    params.append("page", page.toString());
    params.append("limit", limit.toString());
    if (userId) {
      params.append("user_id", userId);
    }
    return apiClient.get(`/api/v1/audit?${params.toString()}`);
  }
}
