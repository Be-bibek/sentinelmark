"use client";

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";

const data = [
  { name: 'Mon', Allow: 4000, MFA: 240, Block: 120 },
  { name: 'Tue', Allow: 3000, MFA: 139, Block: 221 },
  { name: 'Wed', Allow: 2000, MFA: 980, Block: 229 },
  { name: 'Thu', Allow: 2780, MFA: 390, Block: 200 },
  { name: 'Fri', Allow: 1890, MFA: 480, Block: 218 },
  { name: 'Sat', Allow: 2390, MFA: 380, Block: 250 },
  { name: 'Sun', Allow: 3490, MFA: 430, Block: 210 },
];

export function PolicyStackedBar() {
  return (
    <div className="w-full h-full min-h-[250px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis dataKey="name" stroke="rgba(255,255,255,0.3)" fontSize={11} tickLine={false} axisLine={false} />
          <YAxis stroke="rgba(255,255,255,0.3)" fontSize={11} tickLine={false} axisLine={false} />
          <Tooltip 
            contentStyle={{ backgroundColor: 'rgba(10,10,12,0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
            itemStyle={{ color: '#fff' }}
          />
          <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
          <Bar dataKey="Allow" stackId="a" fill="#10b981" radius={[0, 0, 4, 4]} />
          <Bar dataKey="MFA" stackId="a" fill="#f59e0b" />
          <Bar dataKey="Block" stackId="a" fill="#ef4444" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
