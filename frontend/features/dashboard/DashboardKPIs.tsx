"use client";

import React, { useEffect, useState } from "react";
import { motion, useMotionValue, useSpring, useTransform, animate } from "motion/react";
import { Activity, ShieldAlert, Database, Terminal, Wifi, Users, ShieldCheck, Server } from "lucide-react";
import { useWebSocketStore } from "@/stores/websocket-store";
import { useTrustStore } from "@/stores/trust-store";

// Animated Counter
function AnimatedCounter({ value, suffix = "" }: { value: number, suffix?: string }) {
  const motionValue = useMotionValue(value);
  const springValue = useSpring(motionValue, { stiffness: 50, damping: 15 });
  const displayValue = useTransform(springValue, (latest) => Math.round(latest));

  useEffect(() => {
    motionValue.set(value);
  }, [value, motionValue]);

  return (
    <motion.span>
      <motion.span>{displayValue}</motion.span>{suffix}
    </motion.span>
  );
}

export default function DashboardKPIs() {
  const { status } = useWebSocketStore();
  const { currentScore, anomalies } = useTrustStore();
  
  // Fake animated metrics for the specific enterprise feel
  const [evals, setEvals] = useState(148293);
  const [sessions, setSessions] = useState(4192);

  useEffect(() => {
    const interval = setInterval(() => {
      setEvals(prev => prev + Math.floor(Math.random() * 5));
      if (Math.random() > 0.7) {
        setSessions(prev => prev + (Math.random() > 0.5 ? 1 : -1));
      }
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const kpis = [
    { label: "Total Evaluations", value: evals, icon: Activity, color: "text-blue-400", bg: "bg-blue-500/10" },
    { label: "Active Sessions", value: sessions, icon: Users, color: "text-indigo-400", bg: "bg-indigo-500/10" },
    { label: "High Risk Events", value: anomalies.length, icon: ShieldAlert, color: anomalies.length > 0 ? "text-red-400" : "text-zinc-500", bg: anomalies.length > 0 ? "bg-red-500/10" : "bg-white/5" },
    { label: "Average Trust", value: currentScore, suffix: "%", icon: ShieldCheck, color: currentScore > 80 ? "text-emerald-400" : "text-amber-400", bg: currentScore > 80 ? "bg-emerald-500/10" : "bg-amber-500/10" },
    { label: "Connected Clients", value: sessions + 142, icon: Terminal, color: "text-purple-400", bg: "bg-purple-500/10" },
    { label: "WebSocket Status", value: status, icon: Wifi, color: status === 'CONNECTED' ? "text-emerald-400" : "text-amber-400", bg: status === 'CONNECTED' ? "bg-emerald-500/10" : "bg-amber-500/10" },
    { label: "API Gateway", value: "ONLINE", icon: Server, color: "text-emerald-400", bg: "bg-emerald-500/10" },
    { label: "Database", value: "SYNCED", icon: Database, color: "text-emerald-400", bg: "bg-emerald-500/10" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-4">
      {kpis.map((kpi, i) => (
        <div key={i} className="bg-[#0c0c0c] border border-white/5 rounded-xl p-4 flex flex-col justify-between group hover:border-white/10 transition-colors">
          <div className="flex justify-between items-start mb-4">
            <div className={`p-2 rounded-lg ${kpi.bg}`}>
              <kpi.icon className={`w-4 h-4 ${kpi.color}`} />
            </div>
          </div>
          <div>
            <div className={`text-xl font-bold tracking-tight ${kpi.color}`}>
              {typeof kpi.value === 'number' ? (
                <AnimatedCounter value={kpi.value} suffix={kpi.suffix} />
              ) : (
                kpi.value
              )}
            </div>
            <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mt-1">{kpi.label}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
