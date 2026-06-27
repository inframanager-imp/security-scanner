import { useState } from 'react';
import { Reports as CloudReports } from './Reports';
import AspmReports from '../aspm/components/Reports';
import '../aspm/aspm-theme.css';

const tabs = [
  { id: 'cloud', label: 'Cloud Reports' },
  { id: 'appsec', label: 'Application Security' },
];

/** Unified Reports: cloud (CSPM) + application security (ASPM) under one page. */
export function ReportsHub() {
  const [tab, setTab] = useState<'cloud' | 'appsec'>('cloud');
  return (
    <div className="space-y-4">
      <div className="flex gap-1 border-b border-gray-200">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id as 'cloud' | 'appsec')}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.id
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === 'cloud' ? <CloudReports /> : <div className="aspm-root"><AspmReports /></div>}
    </div>
  );
}
