import axios from "axios";

// Determine the base URL depending on environment variables
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

// Create a configured Axios instance
export const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    "Content-Type": "application/json",
  },
});

// Generic API response envelope matching the Rust backend
export interface ApiResponse<T> {
  success: boolean;
  data: T;
  meta: {
    request_id: string;
    timestamp: string;
    evaluation_time_ms?: number;
  };
}

// ---------------------------------------------------------------------------
// Type Definitions
// ---------------------------------------------------------------------------

export interface EvaluateRequest {
  user_id: string;
  event: {
    device_id: string;
    browser_fingerprint: string;
    ip_address: string;
    geo_region: string;
    action_type: string;
    transaction_amount?: number;
    session_duration_secs?: number;
  };
}

export interface EvaluateResponse {
  user_id: string;
  risk_score: number;
  trust_score: number;
  decision: "Allow" | "MfaRequired" | "RequireApproval" | "Block";
  requires_multi_sig: boolean;
  risk_factors: string[];
  explanation: string;
  audit_id?: string;
}

export interface TelemetryRequest {
  user_id: string;
  device_id: string;
  browser_fingerprint?: string;
  ip_address?: string;
  geo_region?: string;
  action_type: string;
  transaction_amount?: number;
  session_duration_secs?: number;
}

export interface TelemetryAck {
  telemetry_id: string;
  user_id: string;
  accepted: boolean;
}

export interface BehaviorProfile {
  user_id: string;
  known_devices: string[];
  known_regions: string[];
  avg_transaction_amount: number;
}

export interface AuditEntry {
  id: string;
  user_id: string;
  trust_score: number;
  risk_score: number;
  decision: string;
  anomalies: string[];
  policy_decision: string;
  explanation: string;
  evaluation_time_ms?: number;
  created_at: string;
}

export interface AuditListResponse {
  user_id: string;
  entries: AuditEntry[];
  page: number;
  per_page: number;
  total_returned: number;
}

// ---------------------------------------------------------------------------
// API Methods
// ---------------------------------------------------------------------------

export const SentinelAPI = {
  evaluate: async (payload: EvaluateRequest): Promise<ApiResponse<EvaluateResponse>> => {
    const res = await api.post<ApiResponse<EvaluateResponse>>("/evaluate", payload);
    return res.data;
  },

  telemetry: async (payload: TelemetryRequest): Promise<ApiResponse<TelemetryAck>> => {
    const res = await api.post<ApiResponse<TelemetryAck>>("/telemetry", payload);
    return res.data;
  },

  getBehaviorProfile: async (userId: string): Promise<ApiResponse<BehaviorProfile>> => {
    const res = await api.get<ApiResponse<BehaviorProfile>>(`/behavior-profile/${userId}`);
    return res.data;
  },

  getAuditLog: async (userId: string, page = 1, perPage = 20): Promise<ApiResponse<AuditListResponse>> => {
    const res = await api.get<ApiResponse<AuditListResponse>>(`/audit/${userId}?page=${page}&per_page=${perPage}`);
    return res.data;
  },
};
