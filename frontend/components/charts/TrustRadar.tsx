"use client";

import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from "recharts";

const data = [
  { subject: 'Device Trust', A: 120, fullMark: 150 },
  { subject: 'Geo Trust', A: 98, fullMark: 150 },
  { subject: 'Session Velocity', A: 86, fullMark: 150 },
  { subject: 'Workflow Integ', A: 99, fullMark: 150 },
  { subject: 'Identity Match', A: 85, fullMark: 150 },
  { subject: 'Historical', A: 65, fullMark: 150 },
];

export function TrustRadar() {
  return (
    <div className="w-full h-full min-h-[300px]">
      <ResponsiveContainer width="100%" height="100%">
        <RadarChart cx="50%" cy="50%" outerRadius="80%" data={data}>
          <PolarGrid stroke="rgba(255,255,255,0.1)" />
          <PolarAngleAxis dataKey="subject" tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 12 }} />
          <PolarRadiusAxis angle={30} domain={[0, 150]} tick={false} axisLine={false} />
          <Tooltip 
            contentStyle={{ backgroundColor: 'rgba(10,10,12,0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
            itemStyle={{ color: '#10b981' }}
          />
          <Radar name="Trust Fingerprint" dataKey="A" stroke="#10b981" fill="#10b981" fillOpacity={0.3} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}
