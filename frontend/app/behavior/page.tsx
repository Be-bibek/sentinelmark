"use client";

import { useState } from "react";
import { TrustRadar } from "@/components/charts/TrustRadar";
import { SessionHeatmap } from "@/components/charts/SessionHeatmap";
import { Activity, MapPin, Smartphone, Clock, ShieldCheck } from "lucide-react";

export default function BehaviorExplorer() {
  const [userId, setUserId] = useState("user-123");

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <header className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            Behavior Explorer
          </h1>
          <p className="text-muted-foreground mt-1">Deep dive into a user's behavioral fingerprint and risk factors</p>
        </div>
        <div className="flex gap-2">
          <input 
            type="text" 
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            className="px-4 py-2 rounded-lg border bg-card text-sm focus:ring-1 focus:ring-primary outline-none"
            placeholder="User ID"
          />
          <button className="px-4 py-2 bg-primary text-primary-foreground font-medium rounded-lg text-sm hover:opacity-90">
            Analyze
          </button>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* User Identity Box */}
        <div className="p-6 rounded-xl border bg-card shadow-sm flex flex-col gap-6">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-full bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 font-mono text-xl font-bold">
              U
            </div>
            <div>
              <h2 className="font-bold text-lg">{userId}</h2>
              <div className="flex items-center gap-2 mt-1">
                <span className="px-2 py-0.5 rounded text-[10px] uppercase tracking-wider bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 font-bold">Trusted</span>
                <span className="text-xs text-muted-foreground">Score: 0.88</span>
              </div>
            </div>
          </div>

          <div className="space-y-4 pt-4 border-t border-border">
            <div className="flex items-center gap-3 text-sm">
              <MapPin className="w-4 h-4 text-muted-foreground" />
              <span>Primary Geo: <strong>US-West (California)</strong></span>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <Smartphone className="w-4 h-4 text-muted-foreground" />
              <span>Known Devices: <strong>3 registered</strong></span>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <Clock className="w-4 h-4 text-muted-foreground" />
              <span>Avg Velocity: <strong>2 tx / day</strong></span>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
              <span>MFA Enrolled: <strong>Yes</strong></span>
            </div>
          </div>
        </div>

        {/* Trust Radar */}
        <div className="lg:col-span-2 p-6 rounded-xl border bg-card shadow-sm">
          <h2 className="text-sm font-bold uppercase tracking-wider mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-500" />
            Trust Fingerprint Vector
          </h2>
          <div className="h-[300px]">
            <TrustRadar />
          </div>
        </div>
      </div>

      {/* Session Heatmap */}
      <div className="p-6 rounded-xl border bg-card shadow-sm">
        <h2 className="text-sm font-bold uppercase tracking-wider mb-6 flex items-center gap-2">
          <Clock className="w-4 h-4 text-blue-500" />
          24x7 Activity Heatmap
        </h2>
        <SessionHeatmap />
      </div>
    </div>
  );
}
