"use client";

import { useSentinelStore } from "@/lib/store";
import { useEffect, useState } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function LiveTrustTimeline() {
  const recentEvents = useSentinelStore((state) => state.recentEvents);
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    // Filter only events that contain a trust_score and reverse to show chronological order left-to-right
    const evaluations = recentEvents
      .filter((ev) => ev.event === "TrustEvaluated" && ev.trust_score !== undefined)
      .reverse()
      .map((ev, index) => ({
        name: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        trust: ev.trust_score,
        risk: ev.risk_score,
      }));

    // If no real data yet, we can show a placeholder or just an empty chart
    // For now, let's just populate with empty data if length is 0 so the chart renders
    if (evaluations.length === 0) {
      setData(Array.from({ length: 10 }).map((_, i) => ({ name: '', trust: 0, risk: 0 })));
    } else {
      setData(evaluations);
    }
  }, [recentEvents]);

  return (
    <div className="w-full h-full min-h-[250px] relative">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" vertical={false} />
          <XAxis dataKey="name" stroke="rgba(255,255,255,0.4)" fontSize={12} tickLine={false} axisLine={false} />
          <YAxis stroke="rgba(255,255,255,0.4)" fontSize={12} tickLine={false} axisLine={false} domain={[0, 1]} />
          <Tooltip 
            contentStyle={{ backgroundColor: 'rgba(10,10,12,0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
            itemStyle={{ color: '#fff' }}
          />
          <Line 
            type="monotone" 
            dataKey="trust" 
            stroke="#10b981" 
            strokeWidth={2} 
            dot={false}
            activeDot={{ r: 6, fill: '#10b981', stroke: '#fff' }}
            isAnimationActive={false} // Disable standard animation for a snappier live feed
          />
          <Line 
            type="monotone" 
            dataKey="risk" 
            stroke="#ef4444" 
            strokeWidth={2} 
            dot={false} 
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
