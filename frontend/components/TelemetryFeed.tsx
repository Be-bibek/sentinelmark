"use client";

import React from "react";
import { motion } from "motion/react";
import { Terminal, Cpu, Clock, HardDrive } from "lucide-react";
import StarBorder from "./StarBorder";

interface TelemetryFeedProps {
  logs: Array<{
    id: string;
    timestamp: Date;
    event: string;
    type: "info" | "warning" | "error" | "success";
    source: string;
  }>;
  theme?: "light" | "dark";
}

export default function TelemetryFeed({ logs, theme = "dark" }: TelemetryFeedProps) {
  const isDark = theme === "dark";

  const getLogTypeColor = (type: string) => {
    switch (type) {
      case "error":
        return isDark 
          ? "text-red-400 bg-red-500/10 border-red-500/20" 
          : "text-red-700 bg-red-50 border-red-200";
      case "warning":
        return isDark 
          ? "text-amber-400 bg-amber-500/10 border-amber-500/20" 
          : "text-amber-700 bg-amber-50 border-amber-200";
      case "success":
        return isDark 
          ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" 
          : "text-emerald-700 bg-emerald-50 border-emerald-200";
      default:
        return isDark 
          ? "text-blue-400 bg-blue-500/10 border-blue-500/20" 
          : "text-blue-700 bg-blue-50 border-blue-200";
    }
  };

  return (
    <StarBorder
      as={motion.div}
      color={isDark ? "rgba(16, 185, 129, 0.5)" : "rgba(16, 185, 129, 0.8)"}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.4 }}
      className={`rounded-[24px] p-6 flex flex-col h-[320px] border ${
        isDark
          ? "bg-zinc-950/40 border-white/5 text-zinc-100"
          : "bg-white border-zinc-200/80 text-zinc-800 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)]"
      }`}
    >
      <div className={`flex items-center justify-between border-b pb-4 mb-4 shrink-0 ${
        isDark ? "border-white/5" : "border-zinc-200"
      }`}>
        <h3 className={`text-xs font-bold uppercase tracking-wider flex items-center gap-2 ${
          isDark ? "text-zinc-400" : "text-zinc-500"
        }`}>
          <Terminal className="w-3.5 h-3.5 text-blue-500" />
          Ingress Stream Console
        </h3>
        <div className={`flex items-center gap-3 text-[10px] font-mono ${
          isDark ? "text-zinc-500" : "text-zinc-400"
        }`}>
          <span className="flex items-center gap-1">
            <Cpu className="w-3 h-3" />
            SOC-NODE-03
          </span>
          <span className="flex items-center gap-1">
            <HardDrive className="w-3 h-3" />
            AWS-EU-WEST
          </span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2.5 pr-2 font-mono text-[10px] no-scrollbar">
        {logs.map((log) => (
          <motion.div
            key={log.id}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            className={`flex items-start justify-between gap-4 p-2.5 rounded-xl border transition-colors ${
              isDark
                ? "bg-white/[0.01] border-white/5 hover:bg-white/[0.02]"
                : "bg-zinc-50 border-zinc-200/60 hover:bg-zinc-100 text-zinc-700"
            }`}
          >
            <div className="flex items-start gap-2.5">
              <span className={`flex items-center gap-1 shrink-0 mt-0.5 ${
                isDark ? "text-zinc-600" : "text-zinc-400"
              }`}>
                <Clock className="w-2.5 h-2.5" />
                {log.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </span>
              <span className={`leading-normal ${isDark ? "text-zinc-300" : "text-zinc-800"}`}>{log.event}</span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className={`text-[9px] uppercase ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>{log.source}</span>
              <span className={`px-1.5 py-0.5 rounded text-[8px] uppercase font-bold border ${getLogTypeColor(log.type)}`}>
                {log.type}
              </span>
            </div>
          </motion.div>
        ))}
        {logs.length === 0 && (
          <div className={`h-full flex items-center justify-center italic ${
            isDark ? "text-zinc-500" : "text-zinc-400"
          }`}>
            Awaiting ingress pipeline initial payload...
          </div>
        )}
      </div>
    </StarBorder>
  );
}
