"use client";

import { useSentinelStore } from "@/lib/store";
import { useEffect, useState } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function TelemetryStream() {
  const recentEvents = useSentinelStore((state) => state.recentEvents);
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    // Generate buckets of telemetry volume over the last N events
    // For a live dashboard, we will just count events that are TelemetryReceived
    const now = new Date();
    
    // Create a rolling window of seconds
    const windowSeconds = 20;
    const buckets = Array.from({ length: windowSeconds }).map((_, i) => {
      const d = new Date(now.getTime() - (windowSeconds - 1 - i) * 1000);
      return {
        time: d,
        label: d.toLocaleTimeString([], { second: '2-digit' }),
        events: 0
      };
    });

    // In a real high-throughput scenario, we'd bucket by timestamp.
    // For this UI, let's create a simulated rolling wave based on recent activity volume.
    // If we have recent events, spike the current buckets.
    const telemetryEvents = recentEvents.filter(ev => ev.event === "TelemetryReceived");
    
    // Simple simulation of volume for visual effect since we don't have historical timestamps stored cleanly yet
    const volumeData = buckets.map((b, i) => {
      // Create a wavy baseline
      let val = Math.sin(i * 0.5) * 10 + 20;
      // Spike if there's a fresh event
      if (i > 15 && telemetryEvents.length > 0) {
        val += telemetryEvents.length * 15;
      }
      return {
        name: b.label,
        volume: Math.max(0, Math.floor(val))
      };
    });

    setData(volumeData);
  }, [recentEvents]);

  return (
    <div className="w-full h-full min-h-[200px] relative">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 5, right: 0, left: -30, bottom: 0 }}>
          <defs>
            <linearGradient id="colorVolume" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis dataKey="name" stroke="rgba(255,255,255,0.2)" fontSize={10} tickLine={false} axisLine={false} />
          <YAxis stroke="rgba(255,255,255,0.2)" fontSize={10} tickLine={false} axisLine={false} />
          <Tooltip 
            contentStyle={{ backgroundColor: 'rgba(10,10,12,0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
            itemStyle={{ color: '#3b82f6' }}
            labelStyle={{ color: '#a1a1aa' }}
          />
          <Area 
            type="monotone" 
            dataKey="volume" 
            stroke="#3b82f6" 
            strokeWidth={2}
            fillOpacity={1} 
            fill="url(#colorVolume)" 
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
