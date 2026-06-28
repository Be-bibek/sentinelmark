"use client";

import React, { useEffect, useState } from "react";
import StarBorder from "./StarBorder";
import { motion, animate, AnimatePresence } from "motion/react";
import { ShieldCheck, ShieldAlert, RefreshCw } from "lucide-react";

interface TrustScoreCenterpieceProps {
  theme?: "light" | "dark";
}

export default function TrustScoreCenterpiece({ theme = "dark" }: TrustScoreCenterpieceProps) {
  const [scoreState, setScoreState] = useState<"safe" | "compromised">("safe");
  const [displayScore, setDisplayScore] = useState(92);
  const isDark = theme === "dark";

  // Animate the text number counter smoothly
  useEffect(() => {
    const target = scoreState === "safe" ? 92 : 41;
    const controls = animate(displayScore, target, {
      duration: 1.8,
      ease: "easeInOut",
      onUpdate: (value) => setDisplayScore(Math.round(value)),
    });
    return () => controls.stop();
  }, [scoreState]);

  // Handle auto-looping simulation
  useEffect(() => {
    const interval = setInterval(() => {
      setScoreState((prev) => (prev === "safe" ? "compromised" : "safe"));
    }, 5500);
    return () => clearInterval(interval);
  }, []);

  // Circle path math
  const radius = 80;
  const strokeWidth = 8;
  const circumference = 2 * Math.PI * radius;
  // Representing the gauge out of 100
  const strokeDashoffset = circumference - (displayScore / 100) * circumference;

  return (
    <StarBorder
      color={isDark ? "rgba(255, 255, 255, 0.3)" : "rgba(100, 100, 100, 0.4)"}
      className={`relative flex flex-col items-center justify-center p-8 border rounded-[32px] shadow-2xl backdrop-blur-xl w-full max-w-sm mx-auto overflow-hidden ${
      isDark
        ? "bg-zinc-950/40 border-white/5 text-zinc-100"
        : "bg-white border-zinc-200/80 text-zinc-800 shadow-[0_10px_35px_-5px_rgba(0,0,0,0.06)]"
    }`}>
      {/* Decorative premium radial glow */}
      <div 
        className={`absolute inset-0 -z-10 transition-colors duration-1000 opacity-20 filter blur-3xl pointer-events-none ${
          scoreState === "safe" ? "bg-blue-500" : "bg-amber-500"
        }`} 
      />

      {/* Header telemetry subtitle */}
      <div className={`flex items-center justify-between w-full mb-6 px-1 font-mono text-[9px] ${
        isDark ? "text-zinc-500" : "text-zinc-400"
      }`}>
        <span className="flex items-center gap-1.5 uppercase tracking-widest font-bold">
          <span className={`w-1.5 h-1.5 rounded-full ${scoreState === "safe" ? "bg-emerald-500" : "bg-amber-500 animate-pulse"}`} />
          Telemetry Channel Live
        </span>
        <button 
          onClick={() => setScoreState((p) => (p === "safe" ? "compromised" : "safe"))}
          className={`flex items-center gap-1 transition-colors cursor-pointer font-bold uppercase tracking-wider ${
            isDark ? "text-zinc-500 hover:text-zinc-300" : "text-zinc-400 hover:text-zinc-600"
          }`}
        >
          <RefreshCw className="w-2.5 h-2.5" />
          Test Drift
        </button>
      </div>

      {/* Circle Gauge Graphic */}
      <div className="relative w-48 h-48 flex items-center justify-center mb-6 select-none">
        <svg className="absolute w-full h-full transform -rotate-90">
          {/* Background circle */}
          <circle
            cx="96"
            cy="96"
            r={radius}
            className={isDark ? "stroke-zinc-900" : "stroke-zinc-100"}
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Animated gradient or solid state circle */}
          <motion.circle
            cx="96"
            cy="96"
            r={radius}
            fill="transparent"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.8, ease: "easeInOut" }}
            strokeLinecap="round"
            className={`transition-colors duration-1000 ${
              scoreState === "safe" 
                ? isDark ? "stroke-blue-500" : "stroke-blue-600" 
                : isDark ? "stroke-amber-500" : "stroke-amber-600"
            }`}
          />
        </svg>

        {/* Dynamic Center Metrics */}
        <div className="text-center z-10 flex flex-col items-center">
          <motion.span 
            className={`text-5xl font-bold tracking-tighter font-sans ${
              isDark ? "text-zinc-100" : "text-zinc-900"
            }`}
            animate={{ scale: scoreState === "safe" ? 1 : 0.95 }}
            transition={{ duration: 0.5 }}
          >
            {displayScore}%
          </motion.span>
          <span className={`text-[10px] font-mono uppercase tracking-wider mt-1.5 ${
            isDark ? "text-zinc-500" : "text-zinc-400"
          }`}>
            Trust Index
          </span>
        </div>
      </div>

      {/* Status Badge below */}
      <AnimatePresence mode="wait">
        {scoreState === "safe" ? (
          <motion.div
            key="verified"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.4 }}
            className={`inline-flex items-center gap-2 px-4 py-1.5 border rounded-full text-xs font-semibold ${
              isDark
                ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                : "bg-emerald-50 border-emerald-200 text-emerald-700"
            }`}
          >
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            Verified Session
          </motion.div>
        ) : (
          <motion.div
            key="mfa"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.4 }}
            className={`inline-flex items-center gap-2 px-4 py-1.5 border rounded-full text-xs font-semibold ${
              isDark
                ? "bg-amber-500/10 border-amber-500/20 text-amber-400"
                : "bg-amber-50 border-amber-200 text-amber-700"
            }`}
          >
            <ShieldAlert className="w-4 h-4 text-amber-500" />
            MFA Required
          </motion.div>
        )}
      </AnimatePresence>

      {/* Visual background details resembling Stripe style */}
      <div className={`w-full mt-6 pt-4 border-t flex items-center justify-between text-[10px] font-mono ${
        isDark ? "border-white/5 text-zinc-400" : "border-zinc-100 text-zinc-600"
      }`}>
        <div>
          <span className={`block ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>Fingerprint</span>
          <span className={`font-semibold ${isDark ? "text-zinc-300" : "text-zinc-700"}`}>FR-889-X9</span>
        </div>
        <div className="text-right">
          <span className={`block ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>Status Code</span>
          <span className={`font-semibold transition-colors duration-1000 ${
            scoreState === "safe" 
              ? isDark ? "text-emerald-400" : "text-emerald-600" 
              : isDark ? "text-amber-400" : "text-amber-600"
          }`}>
            {scoreState === "safe" ? "0x00A_OK" : "0x04F_CHALLENGE"}
          </span>
        </div>
      </div>
    </StarBorder>
  );
}
