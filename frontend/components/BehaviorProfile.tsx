"use client";

import React from "react";
import {
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { motion } from "motion/react";
import { UserCheck, ShieldCheck, Activity } from "lucide-react";
import StarBorder from "./StarBorder";

const riskFactors = [
  { subject: "Location Anomaly", A: 20, B: 10, fullMark: 100 },
  { subject: "Device Profile", A: 15, B: 20, fullMark: 100 },
  { subject: "Speed Vector", A: 10, B: 15, fullMark: 100 },
  { subject: "Access Frequency", A: 30, B: 25, fullMark: 100 },
  { subject: "Payload Size", A: 25, B: 30, fullMark: 100 },
];

const hourlyData = [
  { hour: "08:00", baseline: 85, current: 85 },
  { hour: "10:00", baseline: 90, current: 92 },
  { hour: "12:00", baseline: 80, current: 78 },
  { hour: "14:00", baseline: 88, current: 85 },
  { hour: "16:00", baseline: 92, current: 90 },
  { hour: "18:00", baseline: 85, current: 86 },
];

interface BehaviorProfileProps {
  score: number;
  theme?: "light" | "dark";
}

export default function BehaviorProfile({ score, theme = "dark" }: BehaviorProfileProps) {
  const isDark = theme === "dark";

  return (
    <StarBorder
      as={motion.div}
      color={isDark ? "rgba(245, 158, 11, 0.5)" : "rgba(245, 158, 11, 0.8)"}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.1 }}
      className={`rounded-[24px] p-6 flex flex-col h-[580px] justify-between border ${
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
            <UserCheck className="w-3.5 h-3.5 text-blue-500" />
            Identity Behavior Baseline
          </h2>
          <p className={`text-[10px] mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
            90-Day Cognitive Behavioral Model
          </p>
        </div>
        <div className={`flex items-center gap-2 px-2.5 py-1 rounded-full border ${
          isDark 
            ? "bg-blue-500/10 border-blue-500/20 text-blue-400" 
            : "bg-blue-50/80 border-blue-200 text-blue-700"
        }`}>
          <ShieldCheck className="w-3.5 h-3.5" />
          <span className="text-[10px] font-bold">ACTIVE SESSION PROTECTED</span>
        </div>
      </div>

      {/* Grid of charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1 my-2">
        {/* Radar Chart */}
        <div className="flex flex-col">
          <h3 className={`text-[10px] font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5 ${
            isDark ? "text-zinc-500" : "text-zinc-400"
          }`}>
            <Activity className="w-3 h-3" />
            Risk Surface Breakdown
          </h3>
          <div className="flex-1 w-full min-h-[180px]">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="75%" data={riskFactors}>
                <PolarGrid stroke={isDark ? "#27272a" : "#e4e4e7"} />
                <PolarAngleAxis dataKey="subject" tick={{ fill: isDark ? "#a1a1aa" : "#4b5563", fontSize: 8 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                <Radar name="Active Session" dataKey="A" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.25} />
                <Radar name="Cognitive Baseline" dataKey="B" stroke={isDark ? "#10b981" : "#059669"} fill={isDark ? "#10b981" : "#059669"} fillOpacity={0.1} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Temporal Baseline Chart */}
        <div className="flex flex-col">
          <h3 className={`text-[10px] font-bold uppercase tracking-wider mb-2 ${
            isDark ? "text-zinc-500" : "text-zinc-400"
          }`}>
            Access Velocity Patterns
          </h3>
          <div className="flex-1 w-full min-h-[180px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={hourlyData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorBaseline" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={isDark ? "#10b981" : "#059669"} stopOpacity={0.15} />
                    <stop offset="95%" stopColor={isDark ? "#10b981" : "#059669"} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#222" : "#e4e4e7"} vertical={false} />
                <XAxis dataKey="hour" stroke={isDark ? "#52525b" : "#9ca3af"} fontSize={8} />
                <YAxis stroke={isDark ? "#52525b" : "#9ca3af"} fontSize={8} domain={[0, 100]} />
                <Tooltip
                  contentStyle={
                    isDark
                      ? { backgroundColor: "#09090b", borderColor: "#27272a", fontSize: "10px", color: "#f4f4f5" }
                      : { backgroundColor: "#ffffff", borderColor: "#e4e4e7", fontSize: "10px", color: "#1f2937" }
                  }
                />
                <Area type="monotone" dataKey="baseline" stroke={isDark ? "#10b981" : "#059669"} strokeDasharray="3 3" fillOpacity={1} fill="url(#colorBaseline)" name="90D Baseline" />
                <Area type="monotone" dataKey="current" stroke="#3b82f6" strokeWidth={1.5} fill="none" name="Active Session" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className={`border-t pt-4 mt-2 ${isDark ? "border-white/5" : "border-zinc-200"}`}>
        <h3 className={`text-[10px] font-bold uppercase tracking-wider mb-2 ${
          isDark ? "text-zinc-500" : "text-zinc-400"
        }`}>
          Current Session Anomalies
        </h3>
        <div className={`p-3 border rounded-xl text-xs italic ${
          isDark
            ? "bg-white/[0.01] border-white/5 text-zinc-400"
            : "bg-zinc-50 border-zinc-200 text-zinc-600"
        }`}>
          {score >= 80
            ? "No cognitive behavior deviations detected. Active telemetry fully conforms to the established baseline profile."
            : "Adaptive access security triggered: session behavioral scores show slight drift in Location and Access Frequency indices."}
        </div>
      </div>
    </StarBorder>
  );
}
