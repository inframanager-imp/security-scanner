import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import type { ScanSummary } from '../../types';

interface SeverityDonutProps {
  summary: ScanSummary;
  showLegend?: boolean;
  size?: number;
}

const COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
};

const RADIAN = Math.PI / 180;

interface LabelProps {
  cx: number;
  cy: number;
  midAngle: number;
  innerRadius: number;
  outerRadius: number;
  percent: number;
}

function renderCustomLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent }: LabelProps) {
  if (percent < 0.05) return null;
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text
      x={x}
      y={y}
      fill="white"
      textAnchor="middle"
      dominantBaseline="central"
      fontSize={10}
      fontWeight="700"
    >
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
}

function CustomTooltip({ active, payload }: any) {
  if (active && payload && payload.length) {
    const item = payload[0];
    const name = (item.name || '') as string;
    const value = item.value as number;
    const color = (item.payload?.color || '#3b82f6') as string;
    return (
      <div className="bg-slate-900/95 backdrop-blur-md text-white text-xs px-3 py-2 rounded-xl shadow-xl border border-slate-800 flex items-center gap-2.5 z-50">
        <span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-200 capitalize">{name.toLowerCase()}</span>
          <span className="font-extrabold text-white tabular-nums">{value}</span>
        </div>
      </div>
    );
  }
  return null;
}

export function SeverityDonut({ summary, showLegend = true, size = 240 }: SeverityDonutProps) {
  const data = [
    { name: 'CRITICAL', value: summary.critical, color: COLORS.CRITICAL },
    { name: 'HIGH', value: summary.high, color: COLORS.HIGH },
    { name: 'MEDIUM', value: summary.medium, color: COLORS.MEDIUM },
    { name: 'LOW', value: summary.low, color: COLORS.LOW },
    { name: 'INFO', value: summary.info, color: COLORS.INFO },
  ].filter((d) => d.value > 0);

  if (data.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center text-gray-400" style={{ height: size }}>
        <p className="text-3xl font-bold text-gray-200">0</p>
        <p className="text-xs mt-1">No findings</p>
      </div>
    );
  }

  const innerR = Math.round(size * 0.28);
  const outerR = Math.round(size * 0.44);

  return (
    <div className="relative shrink-0 flex items-center justify-center" style={{ width: size, height: size }}>
      <ResponsiveContainer width={size} height={size}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={innerR}
            outerRadius={outerR}
            paddingAngle={2}
            dataKey="value"
            labelLine={false}
            label={renderCustomLabel}
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          {showLegend && (
            <Legend
              iconType="circle"
              iconSize={8}
              wrapperStyle={{ fontSize: 11 }}
            />
          )}
        </PieChart>
      </ResponsiveContainer>
      {/* Center label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className={`${size < 160 ? 'text-base' : 'text-xl'} font-extrabold text-gray-900 leading-tight tabular-nums`}>{summary.total}</span>
        <span className="text-[10px] text-gray-400 font-medium uppercase tracking-wider">Total</span>
      </div>
    </div>
  );
}
