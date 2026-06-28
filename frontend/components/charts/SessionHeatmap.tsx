"use client";

import { useMemo } from "react";

export function SessionHeatmap() {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  
  // Generate random heatmap data for demonstration (24 hours x 7 days)
  const data = useMemo(() => {
    return Array.from({ length: 7 }).map(() => 
      Array.from({ length: 24 }).map(() => Math.random())
    );
  }, []);

  const getColor = (value: number) => {
    if (value < 0.2) return 'bg-blue-500/10 border-white/5';
    if (value < 0.5) return 'bg-blue-500/30 border-blue-500/20';
    if (value < 0.8) return 'bg-blue-500/60 border-blue-500/50';
    return 'bg-blue-500 border-blue-400';
  };

  return (
    <div className="w-full flex flex-col gap-2">
      {data.map((dayData, dayIdx) => (
        <div key={dayIdx} className="flex items-center gap-2">
          <div className="w-8 text-xs text-muted-foreground font-mono">{days[dayIdx]}</div>
          <div className="flex-1 flex gap-1">
            {dayData.map((val, hourIdx) => (
              <div 
                key={hourIdx} 
                className={`flex-1 aspect-square rounded-sm border ${getColor(val)} transition-colors hover:border-white cursor-pointer`}
                title={`Hour: ${hourIdx}:00 - Intensity: ${Math.round(val * 100)}%`}
              />
            ))}
          </div>
        </div>
      ))}
      <div className="flex items-center gap-2 mt-2">
        <div className="w-8"></div>
        <div className="flex-1 flex justify-between text-[10px] text-muted-foreground font-mono">
          <span>00:00</span>
          <span>12:00</span>
          <span>23:00</span>
        </div>
      </div>
    </div>
  );
}
