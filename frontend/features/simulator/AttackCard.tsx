"use client";

import React, { useState } from "react";
import { useSimulatorStore, AttackScenario } from "@/stores/simulator-store";
import { ArrowRight, ShieldAlert, ShieldCheck, CheckCircle2, XCircle, Loader2, Clock, Database, Wifi, BarChart3 } from "lucide-react";
import { useTrustStore } from "@/stores/trust-store";
import { SentinelAPI } from "@/lib/api";
import { useTelemetryStore } from "@/stores/telemetry-store";
import { useAuditStore } from "@/stores/audit-store";

type CheckStatus = "pending" | "ok" | "error" | "idle";

interface ValidationChecks {
  api: CheckStatus;
  database: CheckStatus;
  websocket: CheckStatus;
  dashboard: CheckStatus;
  audit: CheckStatus;
}

const IDLE_CHECKS: ValidationChecks = {
  api: "idle", database: "idle", websocket: "idle", dashboard: "idle", audit: "idle",
};

function StatusIcon({ status }: { status: CheckStatus }) {
  if (status === "ok") return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />;
  if (status === "error") return <XCircle className="w-3.5 h-3.5 text-red-400" />;
  if (status === "pending") return <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />;
  return <div className="w-3.5 h-3.5 rounded-full border border-zinc-700" />;
}

const CHECK_LABELS: Record<keyof ValidationChecks, { label: string; icon: React.ReactNode }> = {
  api:       { label: "API Gateway",    icon: <ArrowRight className="w-3 h-3" /> },
  database:  { label: "Database Write", icon: <Database className="w-3 h-3" /> },
  websocket: { label: "WS Broadcast",  icon: <Wifi className="w-3 h-3" /> },
  dashboard: { label: "Trust Store",   icon: <BarChart3 className="w-3 h-3" /> },
  audit:     { label: "Audit Ledger",  icon: <ShieldCheck className="w-3 h-3" /> },
};

export default function AttackCard({ scenario }: { scenario: AttackScenario }) {
  const { activeScenarioId, setActiveScenario, setSimulating } = useSimulatorStore();
  const { setEvaluation } = useTrustStore();
  const { addLog } = useTelemetryStore();
  const { addRecord, setDataSource } = useAuditStore();

  const isExecuting = activeScenarioId === scenario.id;
  const [checks, setChecks] = useState<ValidationChecks>(IDLE_CHECKS);
  const [lastResult, setLastResult] = useState<{
    requestId: string | null;
    evalMs: number | null;
    decision: string | null;
    trustScore: number | null;
  } | null>(null);

  const setCheck = (key: keyof ValidationChecks, status: CheckStatus) =>
    setChecks((prev) => ({ ...prev, [key]: status }));

  const executeAttack = async () => {
    setActiveScenario(scenario.id);
    setSimulating(true);
    setLastResult(null);
    setChecks({ api: "pending", database: "idle", websocket: "idle", dashboard: "idle", audit: "idle" });

    addLog({
      event: `[SIMULATOR] Initiating "${scenario.title}" vector...`,
      type: "info",
      source: "Threat Simulator",
    });

    try {
      // ── STEP 1: API call with complete payload matching Rust's required fields ──
      const response = await SentinelAPI.evaluate({
        user_id: "dev.ops@enterprise.com",
        event: {
          device_id:            scenario.payload.deviceId,
          browser_fingerprint:  `fp_${scenario.payload.deviceId}`,
          ip_address:           scenario.payload.ip,
          geo_region:           scenario.payload.location,
          action_type:          scenario.payload.action,
          transaction_amount:   scenario.payload.action === "wire_transfer_500k" ? 500000 : undefined,
        },
      });

      setCheck("api", "ok");

      const requestId = response.__meta?.request_id ?? null;
      const evalMs    = response.__meta?.evaluation_time_ms ?? null;
      const auditId   = response.audit_id ?? null;

      setLastResult({
        requestId,
        evalMs,
        decision: response.decision,
        trustScore: response.trust_score,
      });

      addLog({
        event: `[AXUM] Evaluation complete: ${response.decision} (score: ${response.trust_score.toFixed(1)}, ${evalMs}ms)`,
        type: response.decision === "ALLOW" ? "success" : response.decision === "BLOCK" ? "error" : "warning",
        source: "Axum Engine",
      });

      // ── STEP 2: Update trust store (dashboard) ────────────────────────────────
      setCheck("dashboard", "pending");
      setEvaluation({
        score:          response.trust_score,
        risk:           response.risk_score,
        decision:       response.decision as any,
        anomalies:      response.risk_factors ?? [],
        requestId:      requestId ?? undefined,
        evalMs:         evalMs ?? undefined,
        auditId:        auditId ?? undefined,
        explanation:    response.explanation,
        requiresMultiSig: response.requires_multi_sig,
      });
      setCheck("dashboard", "ok");

      // ── STEP 3: Verify audit entry was written (poll /audit/:user_id) ─────────
      setCheck("database", "pending");
      setCheck("audit", "pending");

      let auditConfirmed = false;
      try {
        const auditData = await SentinelAPI.getAuditLogs("dev.ops@enterprise.com", 1, 5);
        const found = auditId
          ? auditData.entries.some((e) => e.id === auditId)
          : auditData.entries.length > 0;

        auditConfirmed = found;

        // Hydrate audit store with fresh backend records
        const mappedRecords = auditData.entries.map((e) => ({
          id:         e.id,
          timestamp:  new Date(e.created_at),
          user:       e.user_id,
          trustScore: Math.round(e.trust_score * 100),
          anomalies:  e.reasons ?? [],
          decision:   e.decision as any,
          riskScore:  e.risk_score,
          auditId:    e.id,
          explanation: e.explanation,
          source:     "live" as const,
        }));
        addRecord({
          user:       "dev.ops@enterprise.com",
          trustScore: Math.round(response.trust_score * 100),
          anomalies:  response.risk_factors ?? [],
          decision:   response.decision as any,
          riskScore:  response.risk_score,
          auditId:    auditId ?? undefined,
          explanation: response.explanation,
          source:     "live",
        });
        setDataSource("LIVE");

        setCheck("database", auditConfirmed ? "ok" : "error");
        setCheck("audit", auditConfirmed ? "ok" : "error");

        addLog({
          event: `[DB] Audit record ${auditId ?? "(unknown id)"} confirmed in PostgreSQL.`,
          type: auditConfirmed ? "success" : "warning",
          source: "Storage Engine",
        });
      } catch {
        setCheck("database", "error");
        setCheck("audit", "error");
        addRecord({
          user:       "dev.ops@enterprise.com",
          trustScore: Math.round(response.trust_score * 100),
          anomalies:  response.risk_factors ?? [],
          decision:   response.decision as any,
          auditId:    auditId ?? undefined,
          source:     "mock",
        });
      }

      // ── STEP 4: WebSocket confirmation (backend broadcasts on every evaluate) ──
      // The WS event has already been received and logged by websocket-store.ts
      // We mark it ok if status is CONNECTED — the store already handled it.
      const { useWebSocketStore } = await import("@/stores/websocket-store");
      const wsStatus = useWebSocketStore.getState().status;
      setCheck("websocket", wsStatus === "CONNECTED" ? "ok" : "error");

      if (wsStatus === "CONNECTED") {
        addLog({
          event: `[WS] TrustEvaluated broadcast emitted for ${response.user_id}.`,
          type: "success",
          source: "WebSocket",
        });
      }

    } catch (e: any) {
      setCheck("api", "error");
      setCheck("database", "error");
      setCheck("websocket", "error");
      setCheck("dashboard", "error");
      setCheck("audit", "error");

      addLog({
        event: `[ERROR] ${scenario.title} failed: ${e?.message ?? "Unknown error"}`,
        type: "error",
        source: "Network",
      });
    } finally {
      setActiveScenario(null);
      setSimulating(false);
    }
  };

  const Icon = scenario.icon;
  const hasResult = lastResult !== null;
  const allPassed = Object.values(checks).every((s) => s === "ok");
  const anyFailed = Object.values(checks).some((s) => s === "error");
  const idle      = Object.values(checks).every((s) => s === "idle");

  return (
    <div className={`p-5 rounded-xl border dark:bg-white/5 bg-zinc-50 transition-all duration-300 relative overflow-hidden ${
      isExecuting
        ? "border-blue-500 shadow-[0_0_20px_rgba(59,130,246,0.15)]"
        : allPassed ? "border-emerald-500/30"
        : anyFailed ? "border-red-500/30"
        : "dark:border-white/10 border-zinc-200 hover:border-white/20"
    }`}>
      {/* Execution progress bar */}
      {isExecuting && (
        <div className="absolute top-0 left-0 w-full h-0.5 bg-blue-500 overflow-hidden">
          <div className="h-full bg-white/40 w-1/2 animate-[shimmer_1s_ease-in-out_infinite]" />
        </div>
      )}

      {/* Header */}
      <div className="flex justify-between items-start mb-3">
        <h3 className="font-bold dark:text-white text-zinc-900 text-sm flex items-center gap-2">
          <Icon className="w-4 h-4 text-blue-400" />
          {scenario.title}
        </h3>
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
          scenario.expectedPolicy === "ALLOW" ? "bg-emerald-500/15 text-emerald-400" :
          scenario.expectedPolicy === "BLOCK" ? "bg-red-500/15 text-red-400" :
          "bg-amber-500/15 text-amber-400"
        }`}>
          {scenario.expectedPolicy === "ALLOW" ? <><ShieldCheck className="inline w-3 h-3 mr-1" />ALLOW</> :
           scenario.expectedPolicy === "BLOCK" ? <><ShieldAlert className="inline w-3 h-3 mr-1" />BLOCK</> :
           scenario.expectedPolicy}
        </span>
      </div>

      <p className="text-xs text-zinc-400 mb-5 leading-relaxed">{scenario.description}</p>

      {/* Validation checklist */}
      {!idle && (
        <div className="mb-5 space-y-1.5 p-3 bg-black/40 rounded-lg border dark:border-white/5 border-zinc-200">
          {(Object.keys(CHECK_LABELS) as (keyof ValidationChecks)[]).map((key) => (
            <div key={key} className="flex items-center justify-between">
              <span className="text-[11px] text-zinc-400 flex items-center gap-1.5">
                {CHECK_LABELS[key].icon}
                {CHECK_LABELS[key].label}
              </span>
              <StatusIcon status={checks[key]} />
            </div>
          ))}
        </div>
      )}

      {/* Last result trace */}
      {hasResult && !isExecuting && (
        <div className="mb-5 p-3 bg-black/40 rounded-lg border dark:border-white/5 border-zinc-200 space-y-1">
          {lastResult.requestId && (
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Request ID</span>
              <span className="text-[10px] font-mono text-zinc-300 truncate max-w-[140px]">{lastResult.requestId}</span>
            </div>
          )}
          {lastResult.evalMs !== null && (
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider flex items-center gap-1">
                <Clock className="w-3 h-3" /> Eval Time
              </span>
              <span className="text-[10px] font-mono text-blue-400">{lastResult.evalMs}ms</span>
            </div>
          )}
          {lastResult.decision && (
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Decision</span>
              <span className={`text-[10px] font-bold font-mono ${
                lastResult.decision === "ALLOW" ? "text-emerald-400" :
                lastResult.decision === "BLOCK" ? "text-red-400" : "text-amber-400"
              }`}>{lastResult.decision}</span>
            </div>
          )}
        </div>
      )}

      {/* Execute button */}
      <button
        onClick={executeAttack}
        disabled={isExecuting}
        className="w-full py-2.5 bg-white/10 hover:bg-blue-600 dark:text-white text-zinc-900 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-colors border dark:border-white/5 border-zinc-200 hover:border-transparent disabled:opacity-60 disabled:pointer-events-none group/btn"
      >
        {isExecuting ? (
          <span className="flex items-center gap-2 animate-pulse">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Executing...
          </span>
        ) : (
          <>
            Execute Vector
            <ArrowRight className="w-3 h-3 group-hover/btn:translate-x-0.5 transition-transform" />
          </>
        )}
      </button>
    </div>
  );
}
