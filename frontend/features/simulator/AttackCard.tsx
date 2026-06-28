"use client";

import React from "react";
import { useSimulatorStore, AttackScenario } from "@/stores/simulator-store";
import { Play, ShieldAlert, Crosshair, ArrowRight, ShieldCheck, FileKey } from "lucide-react";
import { useTrustStore } from "@/stores/trust-store";
import { SentinelAPI } from "@/lib/api";
import { useTelemetryStore } from "@/stores/telemetry-store";
import { useAuditStore } from "@/stores/audit-store";

export default function AttackCard({ scenario }: { scenario: AttackScenario }) {
  const { activeScenarioId, setActiveScenario, setSimulating } = useSimulatorStore();
  const { setEvaluation } = useTrustStore();
  const { addLog } = useTelemetryStore();
  const { addRecord } = useAuditStore();
  
  const isExecuting = activeScenarioId === scenario.id;

  const executeAttack = async () => {
    setActiveScenario(scenario.id);
    setSimulating(true);

    addLog({
      event: `Initiating ${scenario.title} sequence...`,
      type: "info",
      source: "Threat Simulator"
    });

    try {
      // Direct call to Rust backend
      const response = await SentinelAPI.evaluate({
        user_id: "dev.ops@enterprise.com",
        event: {
          action_type: scenario.payload.action,
          ip_address: scenario.payload.ip,
          device_id: scenario.payload.deviceId,
          user_agent: scenario.payload.userAgent,
          location: scenario.payload.location,
        }
      });
      
      const evalState = {
        score: response.trust_score,
        risk: 1 - (response.trust_score / 100),
        decision: response.decision as any,
        anomalies: response.risk_factors || [],
      };

      setEvaluation(evalState);

      addLog({
        event: `Evaluation complete. Backend responded with ${response.decision}.`,
        type: response.decision === "ALLOW" ? "success" : "error",
        source: "Axum Engine"
      });

      addRecord({
        user: "dev.ops@enterprise.com",
        trustScore: evalState.score,
        anomalies: evalState.anomalies,
        decision: evalState.decision
      });

    } catch (e) {
      console.error(e);
      addLog({
        event: "Failed to reach backend engine.",
        type: "error",
        source: "Network"
      });
    } finally {
      setActiveScenario(null);
      setSimulating(false);
    }
  };

  const Icon = scenario.icon;

  return (
    <div className={`p-5 rounded-xl border bg-white/5 transition-all duration-300 relative overflow-hidden group ${
      isExecuting ? "border-blue-500 shadow-[0_0_20px_rgba(59,130,246,0.2)]" : "border-white/10 hover:border-white/20"
    }`}>
      {isExecuting && (
        <div className="absolute top-0 left-0 w-full h-1 bg-blue-500 overflow-hidden">
          <div className="h-full bg-white/50 w-1/3 animate-[shimmer_1s_infinite]"></div>
        </div>
      )}

      <div className="flex justify-between items-start mb-3">
        <h3 className="font-bold text-white text-sm flex items-center gap-2">
          <Icon className={`w-4 h-4 text-blue-400`} />
          {scenario.title}
        </h3>
      </div>

      <p className="text-xs text-zinc-400 mb-4 h-8">{scenario.description}</p>

      <div className="grid grid-cols-2 gap-3 mb-5">
        <div className="bg-black/40 p-2.5 rounded-lg border border-white/5 col-span-2">
          <span className="block text-[9px] uppercase tracking-wider text-zinc-500 mb-1">Expected Policy</span>
          <span className={`text-xs font-bold font-mono flex items-center gap-1.5 ${
            scenario.expectedPolicy === 'ALLOW' ? 'text-emerald-400' :
            scenario.expectedPolicy === 'BLOCK' ? 'text-red-400' : 'text-amber-400'
          }`}>
            {scenario.expectedPolicy === 'ALLOW' ? <ShieldCheck className="w-3 h-3"/> : <ShieldAlert className="w-3 h-3"/>}
            {scenario.expectedPolicy}
          </span>
        </div>
      </div>

      <button
        onClick={executeAttack}
        disabled={isExecuting}
        className="w-full py-2.5 bg-white/10 hover:bg-blue-600 text-white rounded-lg text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-colors border border-white/5 hover:border-transparent group/btn"
      >
        {isExecuting ? (
          <span className="animate-pulse">Executing sequence...</span>
        ) : (
          <>
            Execute Vector <ArrowRight className="w-3 h-3 group-hover/btn:translate-x-1 transition-transform" />
          </>
        )}
      </button>
    </div>
  );
}
