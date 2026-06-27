import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

interface ServiceData {
  service: string;
  count: number;
}

interface ServiceBarProps {
  data: ServiceData[];
}

const BAR_COLORS = [
  '#dc2626',
  '#f97316',
  '#eab308',
  '#3b82f6',
  '#6b7280',
  '#8b5cf6',
  '#ec4899',
  '#14b8a6',
];

export function ServiceBar({ data }: ServiceBarProps) {
  const sorted = [...data].sort((a, b) => b.count - a.count).slice(0, 10);

  if (sorted.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-400 text-sm">
        No service data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart
        data={sorted}
        layout="vertical"
        margin={{ top: 4, right: 16, left: 40, bottom: 0 }}
      >
        <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f0f0f0" />
        <XAxis type="number" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis
          type="category"
          dataKey="service"
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          width={80}
        />
        <Tooltip contentStyle={{ fontSize: 12 }} />
        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
          {sorted.map((_, index) => (
            <Cell
              key={`cell-${index}`}
              fill={BAR_COLORS[index % BAR_COLORS.length]}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
