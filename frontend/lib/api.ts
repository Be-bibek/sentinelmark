import axios, { AxiosError, AxiosResponse, InternalAxiosRequestConfig } from "axios";
import { v4 as uuidv4 } from "uuid";
import { toast } from "sonner";

// ─── Base configuration ───────────────────────────────────────────────────────

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: { "Content-Type": "application/json" },
});

// ─── Request interceptor: attach X-Request-ID, record start time ──────────────

apiClient.interceptors.request.use((config: InternalAxiosRequestConfig & { _requestId?: string; _startMs?: number }) => {
  const requestId = uuidv4();
  config.headers.set("X-Request-ID", requestId);
  config._requestId = requestId;
  config._startMs = Date.now();
  return config;
});

// ─── Response interceptor: unwrap envelope, log to api-log-store ──────────────

apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    const config = response.config as InternalAxiosRequestConfig & { _requestId?: string; _startMs?: number };
    const latencyMs = config._startMs ? Date.now() - config._startMs : 0;

    // Write to api-log-store (dynamic import to avoid circular deps)
    try {
      const { useApiLogStore } = require("@/stores/api-log-store");
      const payload = config.data ? JSON.stringify(config.data) : "";
      const responseBody = JSON.stringify(response.data);
      const endpoint = (config.url ?? "").replace(API_BASE_URL, "");
      const baseUrl = API_BASE_URL;
      const headers = Object.entries(config.headers ?? {})
        .filter(([k]) => k.toLowerCase() !== "authorization")
        .map(([k, v]) => `-H "${k}: ${v}"`)
        .join(" \\\n  ");
      const curlCommand = `curl -X ${(config.method ?? "GET").toUpperCase()} "${baseUrl}${endpoint}" \\\n  ${headers}${payload ? ` \\\n  -d '${payload}'` : ""}`;

      useApiLogStore.getState().addEntry({
        method: (config.method ?? "GET").toUpperCase(),
        endpoint,
        payloadBytes: new Blob([payload]).size,
        responseBytes: new Blob([responseBody]).size,
        latencyMs,
        statusCode: response.status,
        requestId: config._requestId ?? "",
        retryCount: 0,
        curlCommand,
      });
    } catch { /* store may not be ready */ }

    // Unwrap the { success, data, meta } envelope
    if (response.data && typeof response.data === "object" && "data" in response.data) {
      // Also expose meta on the unwrapped response for tracing
      const unwrapped = response.data.data;
      if (unwrapped && typeof unwrapped === "object") {
        unwrapped.__meta = response.data.meta;
      }
      return unwrapped;
    }
    return response.data;
  },
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean;
      _requestId?: string;
      _startMs?: number;
      _retryCount?: number;
    };

    const latencyMs = originalRequest?._startMs ? Date.now() - originalRequest._startMs : 0;

    // Log failed request
    try {
      const { useApiLogStore } = require("@/stores/api-log-store");
      const endpoint = (originalRequest?.url ?? "").replace(API_BASE_URL, "");
      useApiLogStore.getState().addEntry({
        method: (originalRequest?.method ?? "GET").toUpperCase(),
        endpoint,
        payloadBytes: 0,
        responseBytes: 0,
        latencyMs,
        statusCode: error.response?.status ?? 0,
        requestId: originalRequest?._requestId ?? "",
        retryCount: originalRequest?._retryCount ?? 0,
        error: error.message,
        curlCommand: `curl -X ${(originalRequest?.method ?? "GET").toUpperCase()} "${API_BASE_URL}${endpoint}"`,
      });
    } catch { /* store may not be ready */ }

    // Network offline
    if (!error.response) {
      toast.error("Network Error", {
        description: "Cannot connect to the SentinelMark backend.",
      });
      return Promise.reject(new Error("Network Error: Cannot connect to backend"));
    }

    const status = error.response.status;
    const errorData = error.response.data as Record<string, unknown>;
    const errorMessage = (errorData?.error as string) || error.message || "An unexpected error occurred.";

    // Auto-retry once on 5xx / 429
    if ((status >= 500 || status === 429) && !originalRequest._retry) {
      originalRequest._retry = true;
      originalRequest._retryCount = (originalRequest._retryCount ?? 0) + 1;
      toast.info("Retrying request...");
      await new Promise((resolve) => setTimeout(resolve, 1000));
      return apiClient(originalRequest);
    }

    if (status === 401) toast.error("Unauthorized", { description: "Session expired or invalid API key." });
    else if (status === 403) toast.error("Forbidden", { description: "Access denied." });
    else if (status === 404) toast.error("Not Found", { description: "Resource does not exist." });
    else if (status >= 500) toast.error("Backend Error", { description: errorMessage });

    return Promise.reject(new Error(errorMessage));
  }
);

// ─── Type contracts matching actual Rust backend responses ───────────────────

export interface EventPayload {
  device_id: string;           // required by backend
  browser_fingerprint: string; // required by backend
  ip_address: string;          // required by backend
  geo_region: string;          // required by backend
  action_type: string;         // required by backend
  transaction_amount?: number;
  session_duration_secs?: number;
}

export interface EvaluateRequest {
  user_id: string;
  event: EventPayload;
}

export interface EvaluateResponse {
  user_id: string;
  decision: string;
  trust_score: number;
  risk_score: number;
  risk_factors: string[];
  explanation: string;
  requires_multi_sig: boolean;
  audit_id?: string;
  // Injected from meta envelope
  __meta?: {
    request_id: string;
    timestamp: string;
    evaluation_time_ms?: number;
  };
}

/** GET /api/v1/health/ready */
export interface HealthReadyResponse {
  status: string;      // "ready" | "degraded"
  database: string;    // "ok" | "degraded"
  websocket: string;   // "ok"
  timestamp: string;
}

/** GET /api/v1/health/live */
export interface HealthLiveResponse {
  status: string;
  timestamp: string;
}

/** GET /api/v1/version */
export interface VersionResponse {
  service: string;
  version: string;
  sdk_version: string;
  api: string;
}

/** GET /api/v1/behavior-profile/:user_id */
export interface BehaviorProfileResponse {
  user_id: string;
  known_devices: string[];
  known_regions: string[];
  avg_transaction_amount: number;
}

/** GET /api/v1/audit/:user_id */
export interface AuditRow {
  id: string;
  user_id: string;
  trust_score: number;
  risk_score: number;
  decision: string;
  reasons: string[];
  explanation: string;
  evaluation_ms: number;
  created_at: string;
}

export interface AuditListResponse {
  user_id: string;
  entries: AuditRow[];
  page: number;
  per_page: number;
  total_returned: number;
}

// ─── API class ────────────────────────────────────────────────────────────────

export class SentinelAPI {
  /** GET /api/v1/health/live */
  static async getHealthLive(): Promise<HealthLiveResponse> {
    return apiClient.get("/api/v1/health/live");
  }

  /** GET /api/v1/health/ready — includes DB and WS status */
  static async getHealthReady(): Promise<HealthReadyResponse> {
    return apiClient.get("/api/v1/health/ready");
  }

  /** GET /api/v1/version */
  static async getVersion(): Promise<VersionResponse> {
    return apiClient.get("/api/v1/version");
  }

  /**
   * GET /api/v1/metrics — Prometheus text format.
   * Returns raw text; parse `sentinelmark_ws_connected_clients` manually.
   */
  static async getMetricsRaw(): Promise<string> {
    const response = await apiClient.get<string>("/api/v1/metrics", {
      headers: { Accept: "text/plain" },
      transformResponse: [(data) => data], // don't JSON.parse
    });
    return response as unknown as string;
  }

  /** POST /api/v1/evaluate */
  static async evaluate(payload: EvaluateRequest): Promise<EvaluateResponse> {
    return apiClient.post("/api/v1/evaluate", payload);
  }

  /** GET /api/v1/behavior-profile/:user_id */
  static async getBehaviorProfile(userId: string): Promise<BehaviorProfileResponse> {
    return apiClient.get(`/api/v1/behavior-profile/${encodeURIComponent(userId)}`);
  }

  /**
   * GET /api/v1/audit/:user_id
   * Backend path is /:user_id, NOT ?user_id= query param.
   */
  static async getAuditLogs(userId: string, page = 1, perPage = 50): Promise<AuditListResponse> {
    return apiClient.get(`/api/v1/audit/${encodeURIComponent(userId)}`, {
      params: { page, per_page: perPage },
    });
  }
}
