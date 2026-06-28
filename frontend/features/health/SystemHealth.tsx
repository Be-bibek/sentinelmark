"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { SentinelAPI } from "@/lib/api";
import { useWebSocketStore } from "@/stores/websocket-store";
import { useApiLogStore } from "@/stores/api-log-store";
import { DataSourceBadge } from "@/components/ui/DataSourceBadge";
import { OfflineBanner } from "@/components/ui/OfflineBanner";
import {
  Server, Database, Wifi, Tag, Users, Clock,
  Activity, Copy, Check, AlertTriangle, CheckCircle2
} from "lucide-react";
import { formatDistanceToNow, format } from "date-fns";

// ─── Metric Tile ──────────────────────────────────────────────────────────────

function MetricTile({
  icon: Icon,
  label,
  value,
  subValue,
  status = "ok",
}: {
  icon: React.ElementType;
  label: string;
  value: React.ReactNode;
  subValue?: string;
  status?: "ok" | "degraded" | "offline" | "unknown";
}) {
  const statusColors = {
    ok:       "text-emerald-400 bg-emerald-500/10",
    degraded: "text-amber-400  bg-amber-500/10",
    offline:  "text-red-400    bg-red-500/10",
    unknown:  "text-zinc-400   bg-zinc-500/10",
  };
  return (
    <div className="dark:bg-[#0c0c0c] bg-white border dark:border-white/10 border-zinc-200 rounded-xl p-4 flex flex-col gap-3 shadow-sm">
      <div className="flex items-center justify-between">
        <div className={`p-2 rounded-lg ${statusColors[status]}`}>
          <Icon className="w-4 h-4" />
        </div>
        {status !== "unknown" && (
          <span className={`text-[10px] font-bold tracking-wider px-2 py-0.5 rounded-full border ${
            status === "ok"       ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" :
            status === "degraded" ? "text-amber-400  bg-amber-500/10  border-amber-500/20" :
                                    "text-red-400    bg-red-500/10    border-red-500/20"
          }`}>
            {status.toUpperCase()}
          </span>
        )}
      </div>
      <div>
        <div className="text-lg font-bold dark:text-white text-zinc-900 truncate">{value}</div>
        <div className="text-[10px] text-zinc-500 uppercase tracking-wider mt-0.5">{label}</div>
        {subValue && <div className="text-[10px] text-zinc-600 mt-0.5 font-mono">{subValue}</div>}
      </div>
    </div>
  );
}

// ─── API Log Table ────────────────────────────────────────────────────────────

function ApiDiagnosticsTable() {
  const { entries, totalRequests, totalErrors, avgLatencyMs } = useApiLogStore();
  const [copied, setCopied] = useState<string | null>(null);

  const copyAsCurl = (curlCommand: string, id: string) => {
    navigator.clipboard.writeText(curlCommand);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="dark:bg-[#0c0c0c] bg-white border dark:border-white/10 border-zinc-200 rounded-2xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h3 className="text-sm font-bold dark:text-white text-zinc-900 mb-1">API Request Log</h3>
          <p className="text-xs text-zinc-500">Last {entries.length} requests captured by the interceptor</p>
        </div>
        <div className="flex gap-4 text-right">
          <div>
            <div className="text-xs text-zinc-500">Avg Latency</div>
            <div className="text-sm font-bold text-blue-400 font-mono">{avgLatencyMs}ms</div>
          </div>
          <div>
            <div className="text-xs text-zinc-500">Errors</div>
            <div className={`text-sm font-bold font-mono ${totalErrors > 0 ? "text-red-400" : "text-emerald-400"}`}>{totalErrors}</div>
          </div>
          <div>
            <div className="text-xs text-zinc-500">Total</div>
            <div className="text-sm font-bold dark:text-zinc-300 text-zinc-700 font-mono">{totalRequests}</div>
          </div>
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="text-center text-zinc-600 text-xs py-8">No API requests recorded yet. Execute a vector to populate.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="border-b dark:border-white/5 border-zinc-200 text-[10px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="pb-2 pr-4">Method</th>
                <th className="pb-2 pr-4">Endpoint</th>
                <th className="pb-2 pr-4">Status</th>
                <th className="pb-2 pr-4">Latency</th>
                <th className="pb-2 pr-4">Req Size</th>
                <th className="pb-2 pr-4">Request ID</th>
                <th className="pb-2">cURL</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-white/5 divide-zinc-200">
              {entries.slice(0, 20).map((entry) => (
                <tr key={entry.id} className="group dark:hover:bg-white/[0.02] hover:bg-zinc-50">
                  <td className="py-2 pr-4">
                    <span className={`font-mono font-bold ${
                      entry.method === "POST" ? "text-blue-400" :
                      entry.method === "GET"  ? "text-emerald-400" : "text-zinc-400"
                    }`}>{entry.method}</span>
                  </td>
                  <td className="py-2 pr-4 font-mono dark:text-zinc-300 text-zinc-700 max-w-[200px] truncate">{entry.endpoint}</td>
                  <td className="py-2 pr-4">
                    <span className={`font-mono font-bold ${
                      entry.statusCode < 300 ? "text-emerald-400" :
                      entry.statusCode < 500 ? "text-amber-400" : "text-red-400"
                    }`}>{entry.statusCode || "ERR"}</span>
                  </td>
                  <td className="py-2 pr-4 font-mono text-blue-400">{entry.latencyMs}ms</td>
                  <td className="py-2 pr-4 font-mono text-zinc-500">{entry.payloadBytes}B</td>
                  <td className="py-2 pr-4 font-mono text-zinc-600 max-w-[100px] truncate">{entry.requestId || "—"}</td>
                  <td className="py-2">
                    <button
                      onClick={() => copyAsCurl(entry.curlCommand, entry.id)}
                      className="opacity-0 group-hover:opacity-100 p-1 dark:hover:bg-white/10 hover:bg-zinc-200 rounded transition-all"
                      title="Copy as cURL"
                    >
                      {copied === entry.id
                        ? <Check className="w-3.5 h-3.5 text-emerald-400" />
                        : <Copy className="w-3.5 h-3.5 text-zinc-400" />}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Main SystemHealth Component ──────────────────────────────────────────────

export default function SystemHealth() {
  const wsStore = useWebSocketStore();

  const { data: healthReady, isError: healthError, refetch: retryHealth, isLoading: healthLoading } = useQuery({
    queryKey: ["health", "ready"],
    queryFn:  SentinelAPI.getHealthReady,
    refetchInterval: 10000,
    retry: 1,
  });

  const { data: versionData } = useQuery({
    queryKey: ["version"],
    queryFn:  SentinelAPI.getVersion,
    staleTime: Infinity,
    retry: 1,
  });

  const { data: metricsRaw } = useQuery({
    queryKey: ["metrics"],
    queryFn:  SentinelAPI.getMetricsRaw,
    refetchInterval: 10000,
    retry: 1,
  });

  // Parse Prometheus text for connected clients
  let connectedClients = wsStore.status === "CONNECTED" ? "≥ 1" : "0";
  if (metricsRaw && typeof metricsRaw === "string") {
    const match = metricsRaw.match(/sentinelmark_ws_connected_clients\s+(\d+)/);
    if (match) connectedClients = match[1];
  }

  const isOffline = healthError;

  const apiStatus  = isOffline ? "offline" : healthLoading ? "unknown" : "ok";
  const dbStatus   = healthReady?.database === "ok" ? "ok" : healthReady?.database === "degraded" ? "degraded" : isOffline ? "offline" : "unknown";
  const wsStatus   = wsStore.status === "CONNECTED" ? "ok" : wsStore.status === "CONNECTING" ? "degraded" : "offline";

  const dataSource = isOffline ? "OFFLINE" : healthLoading ? "CACHED" : "LIVE";

  const connectedDuration = wsStore.connectedAt
    ? formatDistanceToNow(wsStore.connectedAt, { addSuffix: false })
    : "—";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <DataSourceBadge source={dataSource} />
        <span className="text-xs text-zinc-500 font-mono">
          {healthReady?.timestamp ? `Last check: ${format(new Date(healthReady.timestamp), "HH:mm:ss")}` : "Polling..."}
        </span>
      </div>

      {isOffline && <OfflineBanner onRetry={() => retryHealth()} />}

      {/* Service Status Grid */}
      <div>
        <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-3">Service Status</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <MetricTile icon={Server}   label="API Gateway"  value={apiStatus === "ok" ? "Online" : apiStatus === "offline" ? "Offline" : "Checking"} status={apiStatus} subValue={`v${versionData?.api ?? "?"}`} />
          <MetricTile icon={Database} label="PostgreSQL"   value={dbStatus === "ok" ? "Connected" : dbStatus === "degraded" ? "Degraded" : "Unknown"} status={dbStatus} />
          <MetricTile icon={Wifi}     label="WebSocket"    value={wsStore.status} status={wsStatus} subValue={`${wsStore.messagesReceived} msgs received`} />
        </div>
      </div>

      {/* Version & SDK */}
      <div>
        <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-3">Service Info</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MetricTile icon={Tag}      label="Service"        value={versionData?.service ?? "—"}      status="unknown" />
          <MetricTile icon={Tag}      label="Backend Version" value={versionData?.version ?? "—"}     status="unknown" />
          <MetricTile icon={Tag}      label="SDK Version"    value={versionData?.sdk_version ?? "—"}  status="unknown" />
          <MetricTile icon={Tag}      label="API"            value={`/api/${versionData?.api ?? "?"}`} status="unknown" />
        </div>
      </div>

      {/* WebSocket Diagnostics */}
      <div>
        <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-3">WebSocket Diagnostics</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MetricTile icon={Users}    label="Connected Clients"  value={connectedClients}         status="unknown" />
          <MetricTile icon={Activity} label="Messages Received"  value={wsStore.messagesReceived} status="unknown" />
          <MetricTile icon={Activity} label="Messages Sent"      value={wsStore.messagesSent}     status="unknown" />
          <MetricTile icon={Clock}    label="Reconnect Attempts" value={wsStore.reconnectAttempts} status={wsStore.reconnectAttempts > 0 ? "degraded" : "ok"} />
          <MetricTile icon={Clock}    label="Connection Duration" value={connectedDuration}        status="unknown" />
          <MetricTile icon={Clock}    label="Last Event"         value={wsStore.lastEventAt ? formatDistanceToNow(wsStore.lastEventAt, { addSuffix: true }) : "—"} status="unknown" />
          <MetricTile icon={Clock}    label="Last Heartbeat"     value={wsStore.lastPing ? formatDistanceToNow(wsStore.lastPing, { addSuffix: true }) : "—"} status="unknown" />
          <MetricTile icon={Wifi}     label="Stream Status"      value={wsStore.status} status={wsStatus} />
        </div>
      </div>

      {/* Backend Gaps Notice */}
      <div className="bg-amber-500/5 border border-amber-500/15 rounded-xl p-4">
        <h3 className="text-xs font-bold text-amber-400 mb-2 flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5" /> Missing Backend Endpoints (Production Readiness Report)
        </h3>
        <div className="space-y-1.5 text-xs text-amber-200/70">
          {[
            "GET /api/v1/sessions — No sessions endpoint exists. Active Sessions page uses static mock data.",
            "GET /api/v1/metrics (JSON) — Only Prometheus text format available. CPU/memory/throughput metrics not exposed.",
            "Per-engine timing breakdown — /evaluate returns total eval_ms only. Individual engine latencies not available.",
          ].map((gap, i) => (
            <div key={i} className="flex items-start gap-2">
              <AlertTriangle className="w-3 h-3 text-amber-500 mt-0.5 shrink-0" />
              <span className="font-mono">{gap}</span>
            </div>
          ))}
        </div>
      </div>

      {/* API Request Log */}
      <ApiDiagnosticsTable />
    </div>
  );
}
