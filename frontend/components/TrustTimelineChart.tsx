"use client";

import React from "react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";
import StarBorder from "./StarBorder";
import { motion } from "motion/react";
import { TrendingUp } from "lucide-react";

interface TrustTimelineChartProps {
  data: Array<{
    timestamp: Date;
    score: number;
  }>;
  theme?: "light" | "dark";
}

export default function TrustTimelineChart({ data, theme = "dark" }: TrustTimelineChartProps) {
  const isDark = theme === "dark";

  // Format dates for display
  const chartData = data.map((d) => ({
    time: d.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    score: d.score,
  }));

  return (
    <StarBorder
      as={motion.div}
      color={isDark ? "rgba(139, 92, 246, 0.5)" : "rgba(139, 92, 246, 0.8)"}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className={`rounded-[24px] p-5 flex flex-col h-[280px] border ${
        isDark
          ? "bg-zinc-950/40 border-white/5 text-zinc-100"
          : "bg-white border-zinc-200/80 text-zinc-800 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)]"
      }`}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className={`text-xs font-bold uppercase tracking-wider flex items-center gap-2 ${
          isDark ? "text-zinc-400" : "text-zinc-500"
        }`}>
          <TrendingUp className="w-3.5 h-3.5 text-emerald-500" />
          Continuous Trust Velocity
        </h3>
        <span className={`text-[10px] font-mono ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
          REAL-TIME TELEMETRY
        </span>
      </div>

      <div className="flex-1 w-full h-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={isDark ? "#10b981" : "#059669"} stopOpacity={0.25} />
                <stop offset="95%" stopColor={isDark ? "#10b981" : "#059669"} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#222" : "#e4e4e7"} vertical={false} />
            <XAxis
              dataKey="time"
              stroke={isDark ? "#52525b" : "#a1a1aa"}
              fontSize={9}
              tickLine={false}
              axisLine={false}
              dy={10}
            />
            <YAxis
              domain={[0, 100]}
              stroke={isDark ? "#52525b" : "#a1a1aa"}
              fontSize={9}
              tickLine={false}
              axisLine={false}
              dx={-5}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className={`border p-3 rounded-xl shadow-2xl text-[10px] font-mono ${
                      isDark
                        ? "bg-zinc-950/95 border-zinc-800 text-zinc-300"
                        : "bg-white border-zinc-200 text-zinc-800 shadow-[0_4px_12px_rgba(0,0,0,0.08)]"
                    }`}>
                      <p className={isDark ? "text-zinc-500" : "text-zinc-400"}>{payload[0].payload.time}</p>
                      <p className={`${isDark ? "text-emerald-400" : "text-emerald-600"} font-semibold mt-1`}>
                        Trust Score: {payload[0].value}%
                      </p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Area
              type="monotone"
              dataKey="score"
              stroke={isDark ? "#10b981" : "#059669"}
              strokeWidth={1.5}
              fillOpacity={1}
              fill="url(#colorScore)"
              animationDuration={500}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </StarBorder>
  );
}
