"use client";

import React, { useRef, useEffect } from "react";
import { useTelemetryStore } from "@/stores/telemetry-store";
import { Activity, Play, Pause, AlertCircle, ShieldAlert, CheckCircle2 } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { format } from "date-fns";

export default function LiveEventCenter() {
  const { logs, isPaused, togglePause, filterLevel, setFilter } = useTelemetryStore();

  const filteredLogs = logs.filter(log => {
    if (filterLevel === 'all') return true;
    return log.type === filterLevel;
  });

  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isPaused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filteredLogs.length, isPaused]);

  return (
    <div className="flex flex-col h-full bg-black/40 border-l border-white/5 w-80">
      <div className="p-4 border-b border-white/5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-400" />
          <h2 className="text-sm font-semibold text-white">Live Event Center</h2>
        </div>
        <button 
          onClick={togglePause}
          className="p-1.5 hover:bg-white/10 rounded-md transition-colors"
          title={isPaused ? "Resume Stream" : "Pause Stream"}
        >
          {isPaused ? <Play className="w-4 h-4 text-emerald-400" /> : <Pause className="w-4 h-4 text-zinc-400" />}
        </button>
      </div>

      <div className="p-2 border-b border-white/5 flex gap-2">
        <select 
          value={filterLevel}
          onChange={(e) => setFilter(e.target.value as any)}
          className="bg-white/5 border border-white/10 rounded px-2 py-1 text-xs text-zinc-300 w-full outline-none"
        >
          <option value="all">All Events</option>
          <option value="warning">Warnings Only</option>
          <option value="error">Errors Only</option>
        </select>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-hide">
        <AnimatePresence initial={false}>
          {filteredLogs.map(log => (
            <motion.div
              key={log.id}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              layout
              className={`p-3 rounded-lg border text-xs relative overflow-hidden group ${
                log.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-200' :
                log.type === 'warning' ? 'bg-amber-500/10 border-amber-500/20 text-amber-200' :
                log.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-200' :
                'bg-white/5 border-white/10 text-zinc-300'
              }`}
            >
              <div className="flex justify-between items-start mb-1 opacity-70">
                <span className="font-mono text-[10px]">{format(log.timestamp, "HH:mm:ss.SSS")}</span>
                <span>{log.source}</span>
              </div>
              <div className="flex items-start gap-2">
                {log.type === 'error' && <ShieldAlert className="w-3.5 h-3.5 mt-0.5 shrink-0 text-red-400" />}
                {log.type === 'warning' && <AlertCircle className="w-3.5 h-3.5 mt-0.5 shrink-0 text-amber-400" />}
                {log.type === 'success' && <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 shrink-0 text-emerald-400" />}
                <p className="font-medium leading-relaxed">{log.event}</p>
              </div>
            </motion.div>
          ))}
          {filteredLogs.length === 0 && (
            <div className="text-center text-zinc-500 text-xs py-8">
              No events to display
            </div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
