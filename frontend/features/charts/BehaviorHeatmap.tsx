"use client";

import React from "react";
import { ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from "recharts";

export interface BehaviorHeatmapProps {
  data: Array<{ hour: number; day: number; count: number }>;
}

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

export default function BehaviorHeatmap({ data }: BehaviorHeatmapProps) {
  return (
    <div className="w-full h-full min-h-[300px]">
      <ResponsiveContainer width="100%" height="100%">
        <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
          <XAxis 
            type="number" 
            dataKey="hour" 
            name="Hour" 
            domain={[0, 23]} 
            tickCount={24} 
            stroke="rgba(255,255,255,0.3)" 
            fontSize={10}
            axisLine={false}
            tickLine={false}
          />
          <YAxis 
            type="number" 
            dataKey="day" 
            name="Day" 
            domain={[0, 6]} 
            tickCount={7}
            stroke="rgba(255,255,255,0.3)" 
            fontSize={10}
            tickFormatter={(val) => DAYS[val]}
            axisLine={false}
            tickLine={false}
          />
          <ZAxis type="number" dataKey="count" range={[20, 200]} name="Events" />
          <Tooltip 
            cursor={{ strokeDasharray: '3 3' }}
            contentStyle={{ 
              backgroundColor: 'rgba(0,0,0,0.8)', 
              borderColor: 'rgba(255,255,255,0.1)',
              borderRadius: '8px',
              fontSize: '12px'
            }}
            formatter={(value: number, name: string) => {
              if (name === 'Day') return DAYS[value];
              if (name === 'Hour') return `${value}:00`;
              return value;
            }}
          />
          <Scatter name="Activity" data={data}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.count > 50 ? "#10b981" : entry.count > 20 ? "#3b82f6" : "#6366f1"} fillOpacity={entry.count > 0 ? 0.7 : 0} />
            ))}
          </Scatter>
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}
