"use client";

import React from "react";
import { motion } from "motion/react";
import { useTrustStore } from "@/stores/trust-store";
import { 
  Activity, 
  BrainCircuit, 
  Fingerprint, 
  Workflow, 
  ShieldAlert, 
  ShieldCheck, 
  ScrollText,
  ArrowRight
} from "lucide-react";

const PIPELINE_STAGES = [
  { id: "telemetry", label: "Telemetry", icon: Activity, color: "text-blue-400" },
  { id: "behavior", label: "Behavior Engine", icon: BrainCircuit, color: "text-purple-400" },
  { id: "identity", label: "Identity Engine", icon: Fingerprint, color: "text-indigo-400" },
  { id: "workflow", label: "Workflow Engine", icon: Workflow, color: "text-amber-400" },
  { id: "risk", label: "Risk Engine", icon: ShieldAlert, color: "text-red-400" },
  { id: "trust", label: "Trust Engine", icon: ShieldCheck, color: "text-emerald-400" },
  { id: "audit", label: "Audit Ledger", icon: ScrollText, color: "text-zinc-400" }
];

export default function TrustEnginePipeline() {
  const { decision } = useTrustStore();

  return (
    <div className="ui-card p-6 relative overflow-hidden group">
      <div className="absolute inset-0 bg-gradient-to-r from-blue-500/5 via-purple-500/5 to-emerald-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-1000"></div>
      
      <h3 className="text-sm font-semibold dark:text-white text-zinc-900 mb-6 flex items-center gap-2">
        <Workflow className="w-4 h-4 text-blue-400" />
        Deterministic Engine Pipeline
      </h3>

      <div className="flex items-center justify-between relative z-10 w-full overflow-x-auto pb-4 hide-scrollbar">
        {PIPELINE_STAGES.map((stage, i) => (
          <React.Fragment key={stage.id}>
            <div className="flex flex-col items-center gap-3 shrink-0">
              <div className="w-12 h-12 ui-subcard !p-0 !rounded-xl flex items-center justify-center shadow-lg relative dark:group-hover:dark:border-white/20 hover:border-zinc-300 transition-colors">
                <stage.icon className={`w-5 h-5 ${stage.color}`} />
                {/* Active pulse effect */}
                <motion.div 
                  className="absolute inset-0 rounded-xl border dark:border-white/20 border-zinc-300"
                  animate={{ scale: [1, 1.1, 1], opacity: [0, 0.5, 0] }}
                  transition={{ duration: 2, repeat: Infinity, delay: i * 0.2 }}
                />
              </div>
              <span className="text-[10px] font-mono font-medium text-zinc-400 uppercase tracking-wider">{stage.label}</span>
            </div>

            {i < PIPELINE_STAGES.length - 1 && (
              <div className="flex-1 min-w-[30px] flex items-center justify-center relative shrink-0 px-2">
                <div className="h-px w-full dark:bg-white/10 bg-zinc-200 absolute top-1/2 -translate-y-1/2"></div>
                {/* Data flow animation */}
                <motion.div 
                  className="absolute top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.8)]"
                  initial={{ left: "0%", opacity: 0 }}
                  animate={{ left: "100%", opacity: [0, 1, 0] }}
                  transition={{ duration: 1.5, repeat: Infinity, delay: i * 0.2, ease: "linear" }}
                />
                <ArrowRight className="w-3 h-3 text-zinc-600 relative z-10 dark:bg-black/40 bg-white" />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>

      <div className="mt-6 flex justify-between items-center text-xs border-t dark:border-white/5 border-zinc-200 pt-4">
        <span className="text-zinc-500">Pipeline Latency: <span className="text-emerald-400 font-mono">14ms</span></span>
        <span className="text-zinc-500">Last Output: <span className="dark:text-white text-zinc-900 font-bold">{decision}</span></span>
      </div>
    </div>
  );
}
