"use client";

import React, { useState, useEffect } from "react";
import BehaviorHeatmap from "@/features/charts/BehaviorHeatmap";
import { Laptop, Globe, Clock, MousePointer2, Keyboard, ShieldAlert } from "lucide-react";

export default function BehaviorProfile() {
  // Generate fake behavior data for the Heatmap
  const [heatmapData, setHeatmapData] = useState<any[]>([]);

  useEffect(() => {
    const data = [];
    for (let day = 0; day < 7; day++) {
      for (let hour = 0; hour < 24; hour++) {
        // More activity during work hours (9-17) on weekdays (1-5)
        const isWorkHour = hour >= 9 && hour <= 17;
        const isWeekday = day >= 1 && day <= 5;
        let baseCount = 5;
        
        if (isWorkHour && isWeekday) baseCount += 80;
        if (isWeekday && (hour === 8 || hour === 18)) baseCount += 40;
        
        // Add some random noise
        const count = Math.max(0, baseCount + (Math.random() * 40 - 20));
        data.push({ day, hour, count: Math.round(count) });
      }
    }
    setHeatmapData(data);
  }, []);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column - Key Identity Baselines */}
        <div className="space-y-6">
          <div className="bg-[#0c0c0c] border border-white/10 rounded-2xl p-5 shadow-lg">
            <h3 className="text-sm font-semibold text-white mb-4">Device Baseline</h3>
            <div className="space-y-4">
              <div className="flex items-start gap-3 p-3 bg-white/5 rounded-lg border border-white/5">
                <Laptop className="w-5 h-5 text-emerald-400 mt-0.5" />
                <div>
                  <div className="text-sm text-zinc-200">MacBook Pro (M2)</div>
                  <div className="text-xs text-zinc-500 font-mono mt-1">Chrome 120.0.0.0 • macOS</div>
                  <div className="text-[10px] bg-emerald-500/20 text-emerald-400 inline-block px-1.5 py-0.5 rounded mt-2 font-bold">PRIMARY DEVICE</div>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 bg-white/5 rounded-lg border border-white/5 opacity-50">
                <Laptop className="w-5 h-5 text-zinc-400 mt-0.5" />
                <div>
                  <div className="text-sm text-zinc-200">iPhone 14 Pro</div>
                  <div className="text-xs text-zinc-500 font-mono mt-1">Safari 17.0 • iOS</div>
                  <div className="text-[10px] bg-zinc-500/20 text-zinc-400 inline-block px-1.5 py-0.5 rounded mt-2 font-bold">SECONDARY DEVICE</div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-[#0c0c0c] border border-white/10 rounded-2xl p-5 shadow-lg">
            <h3 className="text-sm font-semibold text-white mb-4">Behavioral Biometrics</h3>
            <div className="space-y-3">
              <div className="flex justify-between items-center pb-2 border-b border-white/5">
                <div className="flex items-center gap-2">
                  <Keyboard className="w-4 h-4 text-zinc-400" />
                  <span className="text-sm text-zinc-300">Keystroke Dynamics</span>
                </div>
                <span className="text-sm text-emerald-400 font-mono">98% Match</span>
              </div>
              <div className="flex justify-between items-center pb-2 border-b border-white/5">
                <div className="flex items-center gap-2">
                  <MousePointer2 className="w-4 h-4 text-zinc-400" />
                  <span className="text-sm text-zinc-300">Cursor Velocity</span>
                </div>
                <span className="text-sm text-emerald-400 font-mono">94% Match</span>
              </div>
              <div className="flex justify-between items-center pb-2 border-b border-white/5">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-zinc-400" />
                  <span className="text-sm text-zinc-300">Session Duration</span>
                </div>
                <span className="text-sm text-amber-400 font-mono">Anomaly (+40m)</span>
              </div>
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-zinc-400" />
                  <span className="text-sm text-zinc-300">Geo-Velocity</span>
                </div>
                <span className="text-sm text-emerald-400 font-mono">Normal</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column - Heatmap */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-[#0c0c0c] border border-white/10 rounded-2xl p-5 shadow-lg flex flex-col min-h-[400px]">
            <div className="flex justify-between items-start mb-6">
              <div>
                <h3 className="text-sm font-semibold text-white">7-Day Activity Heatmap</h3>
                <p className="text-xs text-zinc-500 mt-1">Displays frequency of authentication and session events.</p>
              </div>
              <div className="flex gap-2">
                <div className="flex items-center gap-1 text-[10px] text-zinc-500">
                  <div className="w-2 h-2 rounded-full bg-indigo-500/80"></div> Low
                </div>
                <div className="flex items-center gap-1 text-[10px] text-zinc-500">
                  <div className="w-2 h-2 rounded-full bg-blue-500/80"></div> Med
                </div>
                <div className="flex items-center gap-1 text-[10px] text-zinc-500">
                  <div className="w-2 h-2 rounded-full bg-emerald-500/80"></div> High
                </div>
              </div>
            </div>
            
            <div className="flex-1 w-full min-h-[300px]">
              {heatmapData.length > 0 && <BehaviorHeatmap data={heatmapData} />}
            </div>
          </div>
          
          <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-5 shadow-lg flex items-start gap-4">
            <div className="p-3 bg-red-500/20 rounded-full shrink-0">
              <ShieldAlert className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-red-400 mb-1">Behavioral Deviation Detected</h3>
              <p className="text-sm text-red-200/80 mb-3">
                The current session exhibits a 40-minute longer duration than the historical baseline for this user on Fridays. Additionally, mouse velocity dropped by 18% during the sensitive transaction phase.
              </p>
              <button className="text-xs bg-red-500/20 hover:bg-red-500/30 text-red-400 font-bold py-1.5 px-3 rounded transition-colors border border-red-500/20">
                Acknowledge Deviation
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
