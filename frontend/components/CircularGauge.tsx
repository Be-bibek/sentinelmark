'use client';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

interface CircularGaugeProps {
  trustScore: number;
}

export default function CircularGauge({ trustScore }: CircularGaugeProps) {
  const getColor = (score: number) => {
    if (score >= 80) return '#10B981'; // Green (ALLOW)
    if (score >= 50) return '#F59E0B'; // Amber (MFA)
    if (score >= 30) return '#F97316'; // Orange (MULTI-SIG)
    return '#EF4444'; // Red (BLOCK)
  };

  const data = [
    { name: 'Score', value: trustScore, color: getColor(trustScore) },
    { name: 'Remaining', value: 100 - trustScore, color: '#1e293b' },
  ];

  return (
    <div className="relative w-full h-full flex items-center justify-center min-h-[160px]">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="100%"
            startAngle={180}
            endAngle={0}
            innerRadius="75%"
            outerRadius="100%"
            dataKey="value"
            stroke="none"
            isAnimationActive={true}
            animationDuration={600}
            animationEasing="ease-out"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute bottom-0 left-0 right-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-display font-bold tabular-nums tracking-tighter" style={{ color: getColor(trustScore) }}>
          {trustScore}
        </span>
        <span className="text-[10px] uppercase tracking-widest text-zinc-500 mt-1">Trust Integer</span>
      </div>
    </div>
  );
}
