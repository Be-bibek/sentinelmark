"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Play,
  Pause,
  ChevronRight,
  ChevronLeft,
  Shield,
  ShieldAlert,
  Terminal,
  Activity,
  AlertOctagon,
  RefreshCw,
} from "lucide-react";
import StarBorder from "./StarBorder";

interface TelemetryStep {
  step: number;
  time: string;
  action: string;
  source: string;
  score: number;
  policy: "ALLOW" | "MFA" | "MULTI-SIG" | "BLOCK";
  anomaly: string | null;
}

const replaySequence: TelemetryStep[] = [
  { step: 1, time: "14:10:02", action: "User Session Initialized", source: "Auth Service", score: 95, policy: "ALLOW", anomaly: null },
  { step: 2, time: "14:10:05", action: "API Read Request: Enterprise Vault", source: "API Gateway", score: 94, policy: "ALLOW", anomaly: null },
  { step: 3, time: "14:11:15", action: "Access attempt from unrecognized browser fingerprint", source: "WAF Edge", score: 65, policy: "MFA", anomaly: "NEW_DEVICE" },
  { step: 4, time: "14:11:20", action: "MFA verification challenge issued", source: "MFA Service", score: 65, policy: "MFA", anomaly: null },
  { step: 5, time: "14:11:45", action: "Impossible travel speed detected (Paris -> Hong Kong)", source: "Analytics Engine", score: 40, policy: "MULTI-SIG", anomaly: "IMPOSSIBLE_TRAVEL" },
  { step: 6, time: "14:12:00", action: "Automated session block enforced", source: "IAM Controller", score: 12, policy: "BLOCK", anomaly: "CREDENTIAL_STUFFING" },
];

interface AttackReplayProps {
  theme?: "light" | "dark";
}

export default function AttackReplay({ theme = "dark" }: AttackReplayProps) {
  const [currentStepIdx, setCurrentStepIdx] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const isDark = theme === "dark";

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isPlaying) {
      interval = setInterval(() => {
        setCurrentStepIdx((prev) => {
          if (prev >= replaySequence.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [isPlaying]);

  const currentStep = replaySequence[currentStepIdx];

  const handleNext = () => {
    if (currentStepIdx < replaySequence.length - 1) {
      setCurrentStepIdx(currentStepIdx + 1);
    }
  };

  const handlePrev = () => {
    if (currentStepIdx > 0) {
      setCurrentStepIdx(currentStepIdx - 1);
    }
  };

  const handleReset = () => {
    setCurrentStepIdx(0);
    setIsPlaying(false);
  };

  const getPolicyColor = (policy: string) => {
    switch (policy) {
      case "ALLOW":
        return isDark 
          ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/5" 
          : "text-emerald-700 border-emerald-200 bg-emerald-50/70";
      case "MFA":
        return isDark 
          ? "text-amber-400 border-amber-500/30 bg-amber-500/5" 
          : "text-amber-700 border-amber-200 bg-amber-50/70";
      case "MULTI-SIG":
        return isDark 
          ? "text-orange-400 border-orange-500/30 bg-orange-500/5" 
          : "text-orange-700 border-orange-200 bg-orange-50/70";
      case "BLOCK":
        return isDark 
          ? "text-red-400 border-red-500/30 bg-red-500/5" 
          : "text-red-700 border-red-200 bg-red-50/70";
      default:
        return isDark 
          ? "text-zinc-400 border-zinc-700 bg-zinc-950" 
          : "text-zinc-700 border-zinc-200 bg-zinc-100";
    }
  };

  return (
    <StarBorder
      as={motion.div}
      color={isDark ? "rgba(16, 185, 129, 0.5)" : "rgba(16, 185, 129, 0.8)"}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.3 }}
      className={`rounded-[24px] p-6 flex flex-col h-[540px] justify-between border ${
        isDark
          ? "bg-zinc-950/40 border-white/5 text-zinc-100"
          : "bg-white border-zinc-200/80 text-zinc-800 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)]"
      }`}
    >
      <div className={`flex items-center justify-between border-b pb-4 mb-4 ${
        isDark ? "border-white/5" : "border-zinc-200"
      }`}>
        <div>
          <h2 className={`text-xs font-bold uppercase tracking-wider flex items-center gap-2 ${
            isDark ? "text-zinc-400" : "text-zinc-500"
          }`}>
            <Activity className="w-3.5 h-3.5 text-amber-500" />
            Attack Playback Sequence
          </h2>
          <p className={`text-[10px] mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
            Interactive Telemetry & Policy Simulation Replay
          </p>
        </div>
        <span className={`text-[10px] font-mono ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
          SIMULATION MODE
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 my-2 min-h-0">
        {/* Left pane: State Display & Anomaly details */}
        <div className="lg:col-span-1 flex flex-col gap-4">
          <div className={`p-5 rounded-[20px] border transition-all duration-500 flex-1 flex flex-col justify-center ${getPolicyColor(currentStep.policy)}`}>
            <div className={`text-[10px] font-mono uppercase ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>Enforced Security State</div>
            <div className="text-2xl font-bold tracking-tight mt-1">{currentStep.policy}</div>
            <div className="text-xs mt-3 flex items-center gap-1.5 font-mono">
              <Shield className="w-3.5 h-3.5" />
              Evaluation score: {currentStep.score}%
            </div>
          </div>

          <div className={`border rounded-[20px] p-5 flex-1 flex flex-col justify-center ${
            isDark ? "bg-[#0c0c0e]/50 border-white/5" : "bg-zinc-50 border-zinc-200"
          }`}>
            <h3 className={`text-[10px] font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5 ${
              isDark ? "text-zinc-400" : "text-zinc-600"
            }`}>
              <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
              Detected Anomalies
            </h3>
            <div className="text-xs font-mono mt-1">
              {currentStep.anomaly ? (
                <div className={`flex items-center gap-2 font-semibold px-3 py-2 rounded-xl border ${
                  isDark 
                    ? "text-orange-400 bg-orange-500/10 border-orange-500/20" 
                    : "text-orange-700 bg-orange-50 border-orange-200"
                }`}>
                  <AlertOctagon className="w-4 h-4" />
                  {currentStep.anomaly}
                </div>
              ) : (
                <span className={`${isDark ? "text-zinc-500" : "text-zinc-400"} italic`}>No anomalies observed in this sequence step.</span>
              )}
            </div>
          </div>
        </div>

        {/* Right pane: Telemetry Log */}
        <div className={`border rounded-[20px] p-5 flex flex-col overflow-hidden ${
          isDark ? "bg-[#08080a]/50 border-white/5" : "bg-zinc-50 border-zinc-200"
        }`}>
          <h3 className={`text-[10px] font-bold uppercase tracking-wider mb-3 flex items-center gap-1.5 ${
            isDark ? "text-zinc-400" : "text-zinc-600"
          }`}>
            <Terminal className="w-3.5 h-3.5 text-blue-500" />
            Live Ingress Stream Sequence
          </h3>
          <div className="flex-1 overflow-y-auto space-y-2 pr-2 no-scrollbar font-mono text-[11px]">
            {replaySequence.map((step, idx) => {
              const isCurrent = idx === currentStepIdx;
              const isPast = idx < currentStepIdx;
              return (
                <div
                  key={step.step}
                  className={`p-3 rounded-xl border transition-all duration-300 flex items-center justify-between ${
                    isCurrent
                      ? isDark
                        ? "bg-zinc-900 border-zinc-700 shadow-lg dark:text-white text-zinc-900"
                        : "bg-white border-zinc-300 text-zinc-950 font-bold shadow-sm"
                      : isPast
                      ? isDark
                        ? "bg-white/[0.01] border-white/5 text-zinc-500"
                        : "bg-zinc-100/50 border-zinc-200/50 text-zinc-400"
                      : isDark
                      ? "bg-transparent border-transparent text-zinc-700"
                      : "bg-transparent border-transparent text-zinc-300"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className={`text-[9px] ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>[{step.time}]</span>
                    <span>{step.action}</span>
                  </div>
                  <div className={`text-[9px] uppercase ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>{step.source}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Playback Controls */}
      <div className={`border rounded-[20px] p-4 mt-4 flex flex-col md:flex-row items-center justify-between gap-4 ${
        isDark ? "bg-[#09090b]/50 border-white/5" : "bg-zinc-50 border-zinc-200"
      }`}>
        {/* Buttons */}
        <div className="flex items-center gap-3">
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={handlePrev}
            disabled={currentStepIdx === 0}
            className={`w-9 h-9 flex items-center justify-center rounded-xl border disabled:opacity-30 ${
              isDark 
                ? "dark:bg-white/5 bg-zinc-50 dark:border-white/10 border-zinc-200 hover:bg-white/10 dark:text-white text-zinc-900" 
                : "bg-white border-zinc-200 hover:bg-zinc-100 text-zinc-700"
            }`}
          >
            <ChevronLeft className="w-4 h-4" />
          </motion.button>

          <motion.button
            whileHover={{ scale: 1.05, boxShadow: isDark ? "0 0 15px rgba(16, 185, 129, 0.2)" : "none" }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setIsPlaying(!isPlaying)}
            className="px-5 h-9 flex items-center justify-center gap-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-bold text-xs"
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5 fill-current" />
                Pause
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                Play Simulation
              </>
            )}
          </motion.button>

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={handleNext}
            disabled={currentStepIdx === replaySequence.length - 1}
            className={`w-9 h-9 flex items-center justify-center rounded-xl border disabled:opacity-30 ${
              isDark 
                ? "dark:bg-white/5 bg-zinc-50 dark:border-white/10 border-zinc-200 hover:bg-white/10 dark:text-white text-zinc-900" 
                : "bg-white border-zinc-200 hover:bg-zinc-100 text-zinc-700"
            }`}
          >
            <ChevronRight className="w-4 h-4" />
          </motion.button>

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={handleReset}
            className={`w-9 h-9 flex items-center justify-center rounded-xl border ${
              isDark 
                ? "dark:bg-white/5 bg-zinc-50 dark:border-white/10 border-zinc-200 hover:bg-white/10 dark:text-white text-zinc-900" 
                : "bg-white border-zinc-200 hover:bg-zinc-100 text-zinc-700"
            }`}
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </motion.button>
        </div>

        {/* Dynamic timeline bar */}
        <div className="flex-1 w-full flex items-center gap-4">
          <div className={`relative flex-1 h-1.5 rounded-full overflow-hidden ${isDark ? "bg-zinc-800" : "bg-zinc-200"}`}>
            <motion.div
              className="absolute left-0 top-0 h-full bg-emerald-500"
              animate={{ width: `${(currentStepIdx / (replaySequence.length - 1)) * 100}%` }}
              transition={{ duration: 0.3 }}
            />
          </div>
          <span className={`text-[10px] font-mono ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
            Step {currentStepIdx + 1} of {replaySequence.length}
          </span>
        </div>
      </div>
    </StarBorder>
  );
}
