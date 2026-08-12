import type { ComplianceTag } from '../../types';

/**
 * Small badges showing which compliance framework(s) a finding maps to
 * (e.g. "CIS 1.16", "PCI DSS") — one badge per framework, deduplicated,
 * hover title lists every mapped control ID for that framework.
 */
export function ComplianceTagBadges({ tags }: { tags?: ComplianceTag[] }) {
  if (!tags || tags.length === 0) {
    return <span className="text-xs text-gray-300">—</span>;
  }

  // Group by framework so a finding mapped to multiple controls within the
  // same framework (rare, but possible) shows one badge, not several.
  const byFramework = new Map<string, string[]>();
  for (const t of tags) {
    const list = byFramework.get(t.frameworkShortName) ?? [];
    list.push(t.controlId);
    byFramework.set(t.frameworkShortName, list);
  }

  return (
    <div className="flex flex-wrap gap-1">
      {[...byFramework.entries()].map(([framework, controlIds]) => (
        <span
          key={framework}
          title={`Control${controlIds.length > 1 ? 's' : ''}: ${controlIds.join(', ')}`}
          className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium bg-indigo-50 text-indigo-700 ring-1 ring-indigo-200 whitespace-nowrap"
        >
          {framework}
        </span>
      ))}
    </div>
  );
}
