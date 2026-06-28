"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, useMotionValue, useSpring, useTransform, animate } from "motion/react";
import { Activity, ShieldAlert, Database, Terminal, Wifi, Users, ShieldCheck, Server } from "lucide-react";
import { useWebSocketStore } from "@/stores/websocket-store";
import { useTrustStore } from "@/stores/trust-store";
import { SentinelAPI } from "@/lib/api";
import { DataSourceBadge, type DataSource } from "@/components/ui/DataSourceBadge";
import { SkeletonCard } from "@/components/ui/SkeletonCard";

function AnimatedNumber({ value, suffix = "" }: { value: number; suffix?: string }) {
  const motionValue = useMotionValue(value);
  const springValue = useSpring(motionValue, { stiffness: 50, damping: 15 });
  const displayValue = useTransform(springValue, (latest) => Math.round(latest));

  React.useEffect(() => {
    motionValue.set(value);
  }, [value, motionValue]);

  return (
    <motion.span>
      <motion.span>{displayValue}</motion.span>
      {suffix}
    </motion.span>
  );
}

interface KpiDef {
  label: string;
  value: React.ReactNode;
  icon: React.ElementType;
  color: string;
  bg: string;
  source: DataSource;
}

export default function DashboardKPIs() {
  const { status, messagesReceived } = useWebSocketStore();
  const { currentScore, anomalies } = useTrustStore();

  // Poll /api/v1/health/ready every 10s
  const { data: health, isError: healthOffline } = useQuery({
    queryKey: ["health", "ready"],
    queryFn: SentinelAPI.getHealthReady,
    refetchInterval: 10000,
    retry: 1,
    staleTime: 8000,
  });

  // Poll /api/v1/metrics (Prometheus text) every 10s for connected clients
  const { data: metricsRaw } = useQuery({
    queryKey: ["metrics"],
    queryFn: SentinelAPI.getMetricsRaw,
    refetchInterval: 10000,
    retry: 1,
    staleTime: 8000,
  });

  // Parse connected_clients from Prometheus text
  let connectedClients = 0;
  if (metricsRaw && typeof metricsRaw === "string") {
    const match = metricsRaw.match(/sentinelmark_ws_connected_clients\s+(\d+)/);
    if (match) connectedClients = parseInt(match[1], 10);
  }

  const apiStatus  = healthOffline ? "OFFLINE" : health ? "LIVE" : "CACHED";
  const dbStatus   = healthOffline ? "OFFLINE" : health?.database === "ok" ? "LIVE" : "CACHED";
  const wsSource   = status === "CONNECTED" ? "LIVE" : status === "CONNECTING" ? "CACHED" : "OFFLINE";

  const kpis: KpiDef[] = [
    {
      label: "Average Trust",
      value: <AnimatedNumber value={currentScore} suffix="%" />,
      icon: ShieldCheck,
      color: currentScore > 80 ? "text-emerald-400" : "text-amber-400",
      bg: currentScore > 80 ? "bg-emerald-500/10" : "bg-amber-500/10",
      source: "LIVE",
    },
    {
      label: "High Risk Events",
      value: <AnimatedNumber value={anomalies.length} />,
      icon: ShieldAlert,
      color: anomalies.length > 0 ? "text-red-400" : "text-zinc-500",
      bg: anomalies.length > 0 ? "bg-red-500/10" : "bg-white/5",
      source: "LIVE",
    },
    {
      label: "Connected Clients",
      value: connectedClients > 0
        ? <AnimatedNumber value={connectedClients} />
        : (metricsRaw ? "0" : "—"),
      icon: Users,
      color: "text-indigo-400",
      bg: "bg-indigo-500/10",
      source: (metricsRaw ? "LIVE" : "OFFLINE") as DataSource,
    },
    {
      label: "WS Messages",
      value: <AnimatedNumber value={messagesReceived} />,
      icon: Activity,
      color: "text-purple-400",
      bg: "bg-purple-500/10",
      source: wsSource as DataSource,
    },
    {
      label: "WebSocket",
      value: status,
      icon: Wifi,
      color: status === "CONNECTED" ? "text-emerald-400" : status === "CONNECTING" ? "text-amber-400" : "text-red-400",
      bg: status === "CONNECTED" ? "bg-emerald-500/10" : "bg-amber-500/10",
      source: wsSource as DataSource,
    },
    {
      label: "API Gateway",
      value: healthOffline ? "OFFLINE" : health ? "ONLINE" : "CHECKING",
      icon: Server,
      color: healthOffline ? "text-red-400" : "text-emerald-400",
      bg: healthOffline ? "bg-red-500/10" : "bg-emerald-500/10",
      source: apiStatus as DataSource,
    },
    {
      label: "Database",
      value: healthOffline ? "OFFLINE" : health?.database === "ok" ? "OK" : "DEGRADED",
      icon: Database,
      color: healthOffline ? "text-red-400" : health?.database === "ok" ? "text-emerald-400" : "text-amber-400",
      bg: healthOffline ? "bg-red-500/10" : "bg-emerald-500/10",
      source: dbStatus as DataSource,
    },
    {
      label: "Terminal Events",
      value: <AnimatedNumber value={messagesReceived + anomalies.length} />,
      icon: Terminal,
      color: "text-blue-400",
      bg: "bg-blue-500/10",
      source: "LIVE",
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-4">
      {kpis.map((kpi, i) => (
        <div
          key={i}
          className="dark:bg-[#0c0c0c] bg-white border dark:border-white/5 border-zinc-200 rounded-xl p-4 flex flex-col justify-between group dark:hover:border-white/10 hover:border-zinc-300 transition-colors shadow-sm"
        >
          <div className="flex justify-between items-start mb-3">
            <div className={`p-2 rounded-lg ${kpi.bg}`}>
              <kpi.icon className={`w-4 h-4 ${kpi.color}`} />
            </div>
            <DataSourceBadge source={kpi.source} />
          </div>
          <div>
            <div className={`text-xl font-bold tracking-tight ${kpi.color}`}>
              {kpi.value}
            </div>
            <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mt-1">
              {kpi.label}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
