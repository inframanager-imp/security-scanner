import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Flame, Globe, ShieldAlert, Building2, Filter } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { findingsApi, type PrioritizedFinding } from '../api/findings';

function riskBadge(score: number | null): { classes: string; label: string } {
  if (score == null) return { classes: 'bg-gray-50 text-gray-500 ring-gray-200', label: '—' };
  if (score >= 90) return { classes: 'bg-red-100 text-red-800 ring-red-200', label: `${score}` };
  if (score >= 75) return { classes: 'bg-orange-100 text-orange-800 ring-orange-200', label: `${score}` };
  if (score >= 60) return { classes: 'bg-yellow-50 text-yellow-800 ring-yellow-200', label: `${score}` };
  return { classes: 'bg-blue-50 text-blue-800 ring-blue-200', label: `${score}` };
}

const SEVERITY_CLASSES: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 ring-red-200',
  HIGH:     'bg-orange-100 text-orange-800 ring-orange-200',
  MEDIUM:   'bg-yellow-100 text-yellow-800 ring-yellow-200',
  LOW:      'bg-blue-50 text-blue-700 ring-blue-200',
  INFO:     'bg-gray-50 text-gray-600 ring-gray-200',
};

const REACHABILITY_CLASSES: Record<string, string> = {
  PUBLIC:   'bg-red-50 text-red-700 ring-red-200',
  INTERNAL: 'bg-amber-50 text-amber-700 ring-amber-200',
  PRIVATE:  'bg-emerald-50 text-emerald-700 ring-emerald-200',
};

export function PrioritizedRisks() {
  const [minScore, setMinScore] = useState(70);
  const [limit, setLimit] = useState(50);

  const { data: rows = [], isLoading } = useQuery({
    queryKey: ['prioritized-findings', minScore, limit],
    queryFn: () => findingsApi.prioritized({ minRiskScore: minScore, limit }),
    staleTime: 30_000,
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Flame className="text-red-600" size={28} />
            Prioritized Risks
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Findings re-scored by reachability, business context, and exploitability.
          </p>
        </div>
      </div>

      <Card>
        <div className="flex flex-wrap gap-4 items-end">
          <div>
            <label className="text-xs text-gray-600 flex items-center gap-1 mb-1">
              <Filter size={12} /> Min risk score
            </label>
            <input
              type="number"
              min={0}
              max={100}
              value={minScore}
              onChange={(e) => setMinScore(Math.max(0, Math.min(100, parseInt(e.target.value, 10) || 0)))}
              className="border rounded px-2 py-1 text-sm w-24"
            />
          </div>
          <div>
            <label className="text-xs text-gray-600 mb-1 block">Limit</label>
            <input
              type="number"
              min={10}
              max={200}
              step={10}
              value={limit}
              onChange={(e) => setLimit(Math.max(10, Math.min(200, parseInt(e.target.value, 10) || 50)))}
              className="border rounded px-2 py-1 text-sm w-24"
            />
          </div>
        </div>
      </Card>

      <Card title={`Top ${rows.length} risks`}>
        {isLoading ? (
          <div className="py-10 text-center text-sm text-gray-500">Loading…</div>
        ) : rows.length === 0 ? (
          <div className="py-10 text-center text-sm text-gray-500">
            No findings with risk score ≥ {minScore}. Run a scan to populate risk scores.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-gray-500 border-b">
                <tr>
                  <th className="py-2">Risk</th>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Service</th>
                  <th>Account</th>
                  <th>Reachability</th>
                  <th>Context</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f: PrioritizedFinding) => {
                  const r = riskBadge(f.riskScore);
                  return (
                    <tr key={f.id} className="border-b last:border-0 hover:bg-gray-50">
                      <td className="py-2">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-bold ring-1 ${r.classes}`}>
                          {r.label}
                        </span>
                      </td>
                      <td>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ring-1 ${SEVERITY_CLASSES[f.severity] ?? ''}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="max-w-[420px]">
                        <div className="font-medium truncate" title={f.title}>{f.title}</div>
                        <div className="text-xs text-gray-500 truncate" title={f.description}>{f.description}</div>
                      </td>
                      <td className="text-xs">{f.service}</td>
                      <td className="text-xs">
                        <span className="inline-flex items-center gap-1">
                          <Building2 size={11} className="text-gray-400" />
                          {f.account?.name ?? '—'}
                          <span className="text-gray-400">({f.provider})</span>
                        </span>
                      </td>
                      <td>
                        {f.reachability ? (
                          <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs ring-1 ${REACHABILITY_CLASSES[f.reachability] ?? ''}`}>
                            {f.reachability === 'PUBLIC' && <Globe size={10} />}
                            {f.reachability}
                          </span>
                        ) : <span className="text-gray-400 text-xs">—</span>}
                      </td>
                      <td className="text-xs">
                        {f.businessContext && Object.keys(f.businessContext).length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {Object.entries(f.businessContext).slice(0, 3).map(([k, v]) => (
                              <span key={k} className="inline-flex items-center gap-1 px-1 py-0.5 bg-purple-50 text-purple-700 rounded text-[10px]">
                                <ShieldAlert size={9} /> {k}={String(v)}
                              </span>
                            ))}
                          </div>
                        ) : <span className="text-gray-400">—</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

export default PrioritizedRisks;
