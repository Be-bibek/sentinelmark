"use client";

import { useSentinelStore } from "@/lib/store";
import { useEffect, useState } from "react";
import { RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis } from "recharts";

export function TrustGauge() {
  const recentEvents = useSentinelStore((state) => state.recentEvents);
  const [currentTrust, setCurrentTrust] = useState<number>(0.85); // Default placeholder

  useEffect(() => {
    // Find the most recent TrustEvaluated event
    const lastEval = recentEvents.find(ev => ev.event === "TrustEvaluated");
    if (lastEval && lastEval.trust_score !== undefined) {
      setCurrentTrust(lastEval.trust_score);
    }
  }, [recentEvents]);

  const percentage = Math.round(currentTrust * 100);
  
  // Determine color based on score
  let color = "#10b981"; // Green
  if (currentTrust < 0.5) color = "#ef4444"; // Red
  else if (currentTrust < 0.8) color = "#f59e0b"; // Yellow

  const data = [
    {
      name: "Trust",
      value: percentage,
      fill: color,
    },
  ];

  return (
    <div className="w-full h-full min-h-[200px] flex flex-col items-center justify-center relative">
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none z-10">
        <span className="text-4xl font-bold font-mono tracking-tighter" style={{ color }}>
          {percentage}
        </span>
        <span className="text-xs uppercase tracking-widest text-zinc-500 mt-1">Trust Index</span>
      </div>
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart 
          cx="50%" 
          cy="50%" 
          innerRadius="70%" 
          outerRadius="90%" 
          barSize={16} 
          data={data} 
          startAngle={180} 
          endAngle={0}
        >
          <PolarAngleAxis
            type="number"
            domain={[0, 100]}
            angleAxisId={0}
            tick={false}
          />
          <RadialBar
            background={{ fill: "rgba(255, 255, 255, 0.05)" }}
            dataKey="value"
            cornerRadius={8}
            isAnimationActive={true}
          />
        </RadialBarChart>
      </ResponsiveContainer>
    </div>
  );
}
