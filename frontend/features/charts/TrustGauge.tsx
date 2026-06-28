"use client";

import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

export interface TrustGaugeProps {
  score: number;
}

export default function TrustGauge({ score }: TrustGaugeProps) {
  const data = [
    { name: "Score", value: score },
    { name: "Empty", value: 100 - score }
  ];

  const getColor = (s: number) => {
    if (s >= 80) return "#10b981"; // emerald
    if (s >= 50) return "#f59e0b"; // amber
    return "#ef4444"; // red
  };

  const color = getColor(score);

  return (
    <div className="w-full h-full min-h-[200px] relative">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="100%"
            startAngle={180}
            endAngle={0}
            innerRadius={60}
            outerRadius={80}
            paddingAngle={0}
            dataKey="value"
            stroke="none"
          >
            <Cell fill={color} />
            <Cell fill="rgba(255,255,255,0.05)" />
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-end pb-4 pointer-events-none">
        <span className="text-3xl font-bold text-white mb-1" style={{ color }}>{score}</span>
        <span className="text-[10px] font-mono text-zinc-500 uppercase">Trust Score</span>
      </div>
    </div>
  );
}
