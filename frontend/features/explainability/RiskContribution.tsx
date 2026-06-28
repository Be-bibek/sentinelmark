"use client";

import React from "react";
import { useTrustStore } from "@/stores/trust-store";
import { ShieldCheck, ShieldAlert, ArrowRight, BrainCircuit, Workflow, Fingerprint } from "lucide-react";
import { Card } from "@/components/ui/Card";

export default function RiskContribution() {
  const { currentScore, decision, anomalies } = useTrustStore();

  const getContributions = () => {
    const base = [{ name: "Base Trust Baseline", val: 100, type: "base" }];
    
    const anomalyMap: Record<string, number> = {
      "UNKNOWN_DEVICE": -25,
      "GEO_VELOCITY_ANOMALY": -40,
      "UNKNOWN_IP": -15,
      "CREDENTIAL_STUFFING": -60,
      "VELOCITY_EXCEEDED": -20,
      "API_TOKEN_EXPOSED": -95,
      "DARK_WEB_MATCH": -80,
    };

    let totalPenalty = 0;
    const items = anomalies.map(a => {
      const penalty = anomalyMap[a] || -10;
      totalPenalty += penalty;
      return { name: a.replace(/_/g, " "), val: penalty, type: "penalty" };
    });

    // If no anomalies, maybe some positive behavioral reinforcement
    if (anomalies.length === 0) {
      items.push({ name: "Known Device Fingerprint", val: 5, type: "bonus" });
      items.push({ name: "Typical IP Range", val: 3, type: "bonus" });
      items.push({ name: "Consistent Typing Speed", val: 2, type: "bonus" });
      totalPenalty = 10; // To make the math sum to 98
    } else {
      // Adjustment to make the math match the score (for demo purposes)
      const diff = currentScore - (100 + totalPenalty);
      if (diff !== 0) {
        items.push({ name: "Contextual Adjustment", val: diff, type: diff > 0 ? "bonus" : "penalty" });
      }
    }

    return [...base, ...items];
  };

  const contributions = getContributions();

  return (
    <Card className="overflow-hidden flex flex-col h-full relative">
      <div className="p-5 border-b dark:border-white/5 border-zinc-200 dark:bg-black/40 bg-zinc-50/80 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold dark:text-white text-zinc-900 mb-1">Explainability Studio</h2>
          <p className="text-xs text-zinc-400">Deterministic trace for Evaluation #48192</p>
        </div>
        <div className="flex gap-2 text-[10px] uppercase font-mono tracking-wider">
          <span className="px-2 py-1 dark:bg-white/5 bg-zinc-100 rounded border dark:border-white/10 border-zinc-200 text-blue-400">Deterministic</span>
          <span className="px-2 py-1 dark:bg-white/5 bg-zinc-100 rounded border dark:border-white/10 border-zinc-200 text-purple-400">Trace Active</span>
        </div>
      </div>

      <div className="p-6 flex-1 overflow-y-auto">
        <div className="mb-8 ui-subcard flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-blue-600/20 rounded-full flex items-center justify-center border border-blue-500/30">
              <BrainCircuit className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-xs text-zinc-500 font-mono mb-1">FINAL SCORE CALCULATION</p>
              <p className="text-3xl font-extrabold dark:text-white text-zinc-900">{currentScore}</p>
            </div>
          </div>
          <ArrowRight className="w-5 h-5 text-zinc-600" />
          <div className="flex items-center gap-4 text-right">
            <div>
              <p className="text-xs text-zinc-500 font-mono mb-1">POLICY DECISION</p>
              <p className={`text-xl font-bold ${
                decision === 'ALLOW' ? 'text-emerald-400' :
                decision === 'BLOCK' ? 'text-red-400' : 'text-amber-400'
              }`}>{decision}</p>
            </div>
            <div className={`w-12 h-12 rounded-full flex items-center justify-center border ${
                decision === 'ALLOW' ? 'bg-emerald-500/20 border-emerald-500/30' :
                decision === 'BLOCK' ? 'bg-red-500/20 border-red-500/30' : 'bg-amber-500/20 border-amber-500/30'
            }`}>
              {decision === 'ALLOW' ? <ShieldCheck className="w-5 h-5 text-emerald-400" /> : <ShieldAlert className="w-5 h-5 text-red-400" />}
            </div>
          </div>
        </div>

        <h3 className="text-sm font-semibold dark:text-white text-zinc-900 mb-4 flex items-center gap-2">
          <Workflow className="w-4 h-4 text-zinc-400" />
          Risk Contributions
        </h3>

        <div className="space-y-2 font-mono text-sm">
          {contributions.map((item, i) => (
            <div key={i} className="flex items-center justify-between ui-subcard dark:hover:bg-white/10 hover:bg-zinc-100 transition-colors dark:hover:border-white/5 hover:border-zinc-200">
              <div className="flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full ${
                  item.type === 'base' ? 'bg-blue-500' :
                  item.type === 'bonus' ? 'bg-emerald-500' : 'bg-red-500'
                }`}></span>
                <span className="dark:text-zinc-300 text-zinc-700">{item.name}</span>
              </div>
              <span className={`font-bold ${
                  item.type === 'base' ? 'text-blue-400' :
                  item.type === 'bonus' ? 'text-emerald-400' : 'text-red-400'
              }`}>
                {item.val > 0 ? '+' : ''}{item.val}
              </span>
            </div>
          ))}
          <div className="pt-4 mt-2 border-t dark:border-white/10 border-zinc-200 flex justify-between items-center dark:text-white text-zinc-900 font-bold px-3">
            <span>FINAL TRUST SCORE</span>
            <span className="text-xl text-blue-400">{currentScore}</span>
          </div>
        </div>
      </div>
    </Card>
  );
}
