"use client";

import { useSentinelStore } from "@/lib/store";
import { LiveTrustTimeline } from "@/components/charts/LiveTrustTimeline";
import { TrustGauge } from "@/components/charts/TrustGauge";
import { TelemetryStream } from "@/components/charts/TelemetryStream";
import { Activity, ShieldAlert, Wifi, Users, ServerCrash } from "lucide-react";

export default function Dashboard() {
  const isConnected = useSentinelStore((state) => state.isConnected);
  const activeSessions = useSentinelStore((state) => state.activeSessions);
  const recentEvents = useSentinelStore((state) => state.recentEvents);

  const telemetryCount = recentEvents.filter(e => e.event === "TelemetryReceived").length;
  const evalCount = recentEvents.filter(e => e.event === "TrustEvaluated").length;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <header className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">SOC Dashboard</h1>
          <p className="text-muted-foreground mt-1">Live Trust Monitoring & Threat Intelligence</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border bg-card text-sm">
            <Wifi className={`w-4 h-4 ${isConnected ? 'text-emerald-500' : 'text-red-500'}`} />
            {isConnected ? 'WebSocket Connected' : 'Disconnected'}
          </div>
        </div>
      </header>

      {/* KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-6 rounded-xl border bg-card shadow-sm flex flex-col gap-2">
          <div className="flex items-center gap-2 text-muted-foreground">
            <Users className="w-4 h-4 text-blue-500" />
            <span className="text-sm font-medium uppercase tracking-wider">Active Sessions</span>
          </div>
          <div className="text-3xl font-mono font-bold">{activeSessions || 142}</div>
        </div>
        
        <div className="p-6 rounded-xl border bg-card shadow-sm flex flex-col gap-2">
          <div className="flex items-center gap-2 text-muted-foreground">
            <Activity className="w-4 h-4 text-emerald-500" />
            <span className="text-sm font-medium uppercase tracking-wider">Evaluations (Local)</span>
          </div>
          <div className="text-3xl font-mono font-bold">{evalCount}</div>
        </div>

        <div className="p-6 rounded-xl border bg-card shadow-sm flex flex-col gap-2">
          <div className="flex items-center gap-2 text-muted-foreground">
            <ShieldAlert className="w-4 h-4 text-orange-500" />
            <span className="text-sm font-medium uppercase tracking-wider">Threat Vectors</span>
          </div>
          <div className="text-3xl font-mono font-bold">12</div>
        </div>

        <div className="p-6 rounded-xl border bg-card shadow-sm flex flex-col gap-2">
          <div className="flex items-center gap-2 text-muted-foreground">
            <ServerCrash className="w-4 h-4 text-red-500" />
            <span className="text-sm font-medium uppercase tracking-wider">Blocked Events</span>
          </div>
          <div className="text-3xl font-mono font-bold">3</div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="col-span-1 lg:col-span-2 p-6 rounded-xl border bg-card shadow-sm">
          <h2 className="text-sm font-bold uppercase tracking-wider mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-500" />
            Live Trust & Risk Timeline
          </h2>
          <div className="h-[250px]">
            <LiveTrustTimeline />
          </div>
        </div>

        <div className="col-span-1 p-6 rounded-xl border bg-card shadow-sm flex flex-col">
          <h2 className="text-sm font-bold uppercase tracking-wider mb-4">Global Trust Index</h2>
          <div className="flex-1">
            <TrustGauge />
          </div>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 gap-6">
        <div className="p-6 rounded-xl border bg-card shadow-sm">
          <h2 className="text-sm font-bold uppercase tracking-wider mb-4 flex items-center gap-2">
            <Wifi className="w-4 h-4 text-blue-500" />
            Live Telemetry Stream
          </h2>
          <div className="h-[200px]">
            <TelemetryStream />
          </div>
        </div>
      </div>
    </div>
  );
}
