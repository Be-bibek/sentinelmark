"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import Link from "next/link";
import { Shield, Sparkles, ArrowRight, Activity, Globe, Lock, ChevronRight, Sun, Moon, User } from "lucide-react";
import ParticleBackground from "@/components/ParticleBackground";
import Strands from "@/components/Strands";
import DashboardKPIs from "@/features/dashboard/DashboardKPIs";
import { useMetrics } from "@/hooks/use-queries";

export default function LandingPage() {
  const [theme, setTheme] = useState<"light" | "dark">("dark");
  const isDark = theme === "dark";
  const { data: metrics } = useMetrics();

  return (
    <div className={`min-h-screen font-sans overflow-x-hidden flex flex-col relative transition-colors duration-500 ${
      isDark 
        ? "bg-[#030303] text-zinc-100 selection:bg-blue-500/20" 
        : "bg-[#FAFAFA] text-zinc-800 selection:bg-blue-500/10"
    }`}>
      {/* Dynamic Background */}
      <ParticleBackground policyState="ALLOW" theme={theme} />
      
      {/* Background Particles */}
      <div className="absolute inset-0 z-0 opacity-30 pointer-events-none">
        <Strands 
          colors={["#F97316", "#7C3AED", "#06B6D4"]}
          count={2}
          speed={0.5}
        />
      </div>

      <AnimatePresence mode="wait">
        <motion.div
          key="landing"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.5 }}
          className="flex-1 flex flex-col relative z-10 w-full"
        >
          {/* Sticky Header */}
          <header className={`sticky top-0 z-50 h-16 border-b backdrop-blur-xl px-6 md:px-12 flex items-center justify-between transition-all duration-300 ${
            isDark 
              ? "border-white/5 bg-black/45 text-white" 
              : "border-zinc-200/80 bg-white/75 text-zinc-800 shadow-[0_2px_12px_rgba(0,0,0,0.02)]"
          }`}>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-blue-600 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)]">
                <Shield className="w-4.5 h-4.5 text-zinc-100" />
              </div>
              <div>
                <h1 className={`text-sm font-extrabold tracking-tight flex items-center gap-1.5 font-mono ${
                  isDark ? "text-white" : "text-zinc-900"
                }`}>
                  SENTINELMARK
                </h1>
                <span className="text-[8px] font-bold text-blue-400 tracking-widest block -mt-0.5">TRUSTOS</span>
              </div>
            </div>

            {/* Header Right Buttons */}
            <div className="flex items-center gap-4">
              <button
                onClick={() => setTheme(isDark ? "light" : "dark")}
                className={`p-2 rounded-xl border transition-all duration-300 cursor-pointer ${
                  isDark
                    ? "bg-white/5 border-white/10 text-zinc-300 hover:bg-white/10"
                    : "bg-white border-zinc-200 text-zinc-700 hover:bg-zinc-100 shadow-[0_2px_8px_rgba(0,0,0,0.04)]"
                }`}
              >
                {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-blue-600" />}
              </button>

              <div className={`w-px h-6 transition-colors duration-300 ${isDark ? "bg-white/10" : "bg-zinc-300"}`}></div>
              <Link href="/dashboard" className="flex items-center gap-2 group cursor-pointer">
                <div className="text-right hidden sm:block">
                  <p className={`text-[10px] font-semibold uppercase tracking-wider ${isDark ? "text-zinc-300" : "text-zinc-600"}`}>DevOps Admin</p>
                  <p className={`text-[9px] ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>prod-us-west</p>
                </div>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center border transition-all duration-300 ${
                  isDark 
                    ? "bg-zinc-800 border-white/10 group-hover:border-blue-500/50" 
                    : "bg-zinc-100 border-zinc-300 group-hover:border-blue-500"
                }`}>
                  <User className={`w-4 h-4 ${isDark ? "text-zinc-400" : "text-zinc-600"}`} />
                </div>
              </Link>
            </div>
          </header>

          {/* Hero Section */}
          <main className="flex-1 flex flex-col items-center justify-center p-6 md:p-12 text-center max-w-6xl mx-auto w-full">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
              className="w-full flex flex-col items-center"
            >
              <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border text-[10px] font-medium tracking-wide mb-8 transition-colors ${
                isDark
                  ? "bg-blue-500/10 border-blue-500/20 text-blue-400"
                  : "bg-blue-50 border-blue-200 text-blue-700 shadow-[0_2px_8px_rgba(59,130,246,0.08)]"
              }`}>
                <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse"></div>
                TrustOS V2 Beta is active
              </div>

              <h1 className={`text-4xl md:text-6xl lg:text-7xl font-extrabold tracking-tight leading-[1.1] mb-6 max-w-4xl transition-colors ${
                isDark ? "text-white" : "text-zinc-900"
              }`}>
                Continuous Trust{" "}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-cyan-400">
                  Infrastructure
                </span>
              </h1>

              <p className={`text-base md:text-xl max-w-2xl mb-12 font-medium transition-colors ${
                isDark ? "text-zinc-400" : "text-zinc-600"
              }`}>
                SentinelMark deterministically evaluates risk and enforces policy across your entire stack. 
                Zero-trust made measurable, explainable, and instantaneous.
              </p>

              <div className="flex flex-col sm:flex-row gap-4 items-center justify-center">
                <Link
                  href="/dashboard"
                  className="group relative px-8 py-3.5 bg-zinc-100 dark:bg-white text-zinc-900 font-bold rounded-full overflow-hidden shadow-[0_0_20px_rgba(255,255,255,0.15)] hover:shadow-[0_0_30px_rgba(255,255,255,0.3)] transition-all duration-300 transform hover:-translate-y-0.5"
                >
                  <div className="absolute inset-0 w-full h-full bg-gradient-to-r from-transparent via-white/40 to-transparent -translate-x-full group-hover:animate-[shimmer_1.5s_infinite]"></div>
                  <span className="relative flex items-center gap-2">
                    Launch SOC Console
                    <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                  </span>
                </Link>
              </div>
            </motion.div>

            <div className="mt-32 w-full pt-12 border-t border-white/5 relative">
               <div className={`absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 px-4 text-xs font-mono uppercase tracking-widest ${
                 isDark ? "bg-[#030303] text-zinc-500" : "bg-[#FAFAFA] text-zinc-400"
               }`}>
                 System Telemetry
               </div>
               <DashboardKPIs />
            </div>
          </main>
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
