"use client";

import React from "react";
import DashboardKPIs from "@/features/dashboard/DashboardKPIs";
import TrustTimeline from "@/features/charts/TrustTimeline";
import LiveEventCenter from "@/features/dashboard/LiveEventCenter";
import TrustEnginePipeline from "@/features/dashboard/TrustEnginePipeline";
import AttackCard from "@/features/simulator/AttackCard";
import { Card } from "@/components/ui/Card";
import { ATTACK_SCENARIOS } from "@/stores/simulator-store";
import { useTrustStore } from "@/stores/trust-store";

export default function DashboardPage() {
  const { currentScore, decision, anomalies, sessionHistory } = useTrustStore();

  return (
    <div className="flex h-[calc(100vh-4rem)] -m-6">
      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        
        {/* Top KPIs */}
        <div className="mb-6">
          <DashboardKPIs />
        </div>


        {/* Animated Trust Engine Pipeline */}
        <TrustEnginePipeline />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Timeline Chart */}
          <Card className="lg:col-span-2 p-5 min-h-[350px] flex flex-col">
            <h3 className="text-sm font-semibold dark:text-white text-zinc-900 mb-4">Trust Degradation Timeline</h3>
            <div className="flex-1 min-h-[250px]">
              <TrustTimeline data={sessionHistory.length > 0 ? (sessionHistory as any) : Array.from({length: 20}).map((_,i) => ({timestamp: new Date(), score: 98}))} />
            </div>
          </Card>

          {/* Active Anomalies / Incident Queue */}
          <Card className="p-5 flex flex-col">
            <h3 className="text-sm font-semibold dark:text-white text-zinc-900 mb-4 flex items-center justify-between">
              Incident Queue
              <span className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded text-[10px] font-bold">{anomalies.length} Active</span>
            </h3>
            <div className="flex-1 overflow-y-auto space-y-2">
              {anomalies.map((anomaly, i) => (
                <div key={i} className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center justify-between">
                  <span className="text-xs text-red-200 font-mono">{anomaly}</span>
                  <span className="text-[10px] bg-red-500/20 text-red-400 px-2 py-0.5 rounded font-bold">HIGH</span>
                </div>
              ))}
              {anomalies.length === 0 && (
                <div className="text-center text-zinc-500 text-xs py-8">
                  No active incidents detected.
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Threat Simulator section */}
        <div>
          <h3 className="text-lg font-bold dark:text-white text-zinc-900 mb-4">Threat Simulation Vectors</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {ATTACK_SCENARIOS.map(scenario => (
              <AttackCard key={scenario.id} scenario={scenario} />
            ))}
          </div>
        </div>

      </div>

      {/* Right Sidebar - Live Event Center */}
      <LiveEventCenter />
    </div>
  );
}