/**
 * ConfigDiffView
 *
 * Renders a before→after diff between two resource configuration snapshots.
 * Shows exactly what changed — field by field — similar to Baseline & Drift
 * but for any resource in Config Changes.
 */

import { useState } from 'react';
import { ChevronDown, ChevronRight, Plus, Minus, ArrowRight } from 'lucide-react';
import { computeConfigDiff, groupDiffBySection, formatDiffValue } from '../utils/configDiff';
import type { FieldChange } from '../utils/configDiff';

interface ConfigDiffViewProps {
  before: Record<string, unknown> | null | undefined;
  after:  Record<string, unknown> | null | undefined;
  /** CREATED = show after only | DELETED = show before only | MODIFIED = show diff */
  changeAction?: 'CREATED' | 'MODIFIED' | 'DELETED';
}

const TYPE_STYLES = {
  added:   { row: 'bg-emerald-50 border-l-2 border-emerald-400', badge: 'text-emerald-700 bg-emerald-100', Icon: Plus,   label: 'Added'   },
  removed: { row: 'bg-red-50 border-l-2 border-red-400',         badge: 'text-red-700 bg-red-100',         Icon: Minus,  label: 'Removed' },
  changed: { row: 'bg-amber-50 border-l-2 border-amber-400',     badge: 'text-amber-700 bg-amber-100',     Icon: ArrowRight, label: 'Changed' },
};

export function ConfigDiffView({ before, after, changeAction = 'MODIFIED' }: ConfigDiffViewProps) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  // For pure CREATED — show after config as a flat list
  if (changeAction === 'CREATED' && !before && after) {
    return <ConfigSnapshot label="New Resource Configuration" config={after} color="emerald" />;
  }

  // For pure DELETED — show before config as a flat list
  if (changeAction === 'DELETED' && before && !after) {
    return <ConfigSnapshot label="Resource Configuration (before deletion)" config={before} color="red" />;
  }

  // Both null — no config data available
  if (!before && !after) {
    return (
      <div className="text-xs text-gray-400 italic py-2">
        Configuration snapshot not available for this event.
      </div>
    );
  }

  // Only one side — show what we have
  if (!before && after) {
    return <ConfigSnapshot label="Resource Configuration (after)" config={after} color="emerald" />;
  }
  if (before && !after) {
    return <ConfigSnapshot label="Resource Configuration (before)" config={before} color="red" />;
  }

  const changes = computeConfigDiff(before, after);

  if (changes.length === 0) {
    return (
      <div className="text-xs text-gray-400 italic py-2">
        No configuration differences detected between snapshots.
      </div>
    );
  }

  const groups = groupDiffBySection(changes);

  function toggleSection(section: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      next.has(section) ? next.delete(section) : next.add(section);
      return next;
    });
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3 mb-2">
        <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
          {changes.length} field{changes.length !== 1 ? 's' : ''} changed
        </span>
        <span className="text-xs text-emerald-600 font-medium">
          {changes.filter((c) => c.type === 'added').length} added
        </span>
        <span className="text-xs text-red-600 font-medium">
          {changes.filter((c) => c.type === 'removed').length} removed
        </span>
        <span className="text-xs text-amber-600 font-medium">
          {changes.filter((c) => c.type === 'changed').length} changed
        </span>
      </div>

      {Array.from(groups.entries()).map(([section, sectionChanges]) => {
        const isOpen = !collapsed.has(section);
        return (
          <div key={section} className="border border-gray-200 rounded-lg overflow-hidden">
            {/* Section header */}
            <button
              onClick={() => toggleSection(section)}
              className="w-full flex items-center gap-2 px-3 py-2 bg-gray-50 hover:bg-gray-100 transition-colors text-left"
            >
              {isOpen ? <ChevronDown size={12} className="text-gray-400" /> : <ChevronRight size={12} className="text-gray-400" />}
              <span className="text-xs font-semibold text-gray-700 capitalize">{section}</span>
              <span className="ml-auto text-[10px] text-gray-400">{sectionChanges.length} change{sectionChanges.length !== 1 ? 's' : ''}</span>
            </button>

            {/* Changes */}
            {isOpen && (
              <div className="divide-y divide-gray-100">
                {sectionChanges.map((change, i) => (
                  <ChangeRow key={i} change={change} />
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ChangeRow({ change }: { change: FieldChange }) {
  const [expanded, setExpanded] = useState(false);
  const styles = TYPE_STYLES[change.type];
  const Icon = styles.Icon;

  // Determine if values are complex enough to warrant expand
  const isComplexBefore = change.before !== null && typeof change.before === 'object';
  const isComplexAfter  = change.after  !== null && typeof change.after  === 'object';
  const isComplex = isComplexBefore || isComplexAfter;

  // Short display path — strip leading section prefix for cleanliness
  const displayPath = change.path.includes('.') ? change.path.split('.').slice(1).join('.') : change.path;

  return (
    <div className={`px-3 py-2 text-xs ${styles.row}`}>
      <div className="flex items-start gap-2">
        <Icon size={11} className={change.type === 'added' ? 'text-emerald-600 mt-0.5 shrink-0' : change.type === 'removed' ? 'text-red-600 mt-0.5 shrink-0' : 'text-amber-600 mt-0.5 shrink-0'} />

        <div className="flex-1 min-w-0">
          {/* Field path */}
          <span className="font-mono font-semibold text-gray-800 break-all">{displayPath || change.path}</span>

          {change.type === 'changed' && (
            <div className="mt-1 flex items-start gap-2 flex-wrap">
              <span className="bg-red-100 text-red-800 font-mono px-1.5 py-0.5 rounded text-[10px] break-all max-w-xs">
                {formatDiffValue(change.before)}
              </span>
              <ArrowRight size={10} className="text-gray-400 mt-0.5 shrink-0" />
              <span className="bg-emerald-100 text-emerald-800 font-mono px-1.5 py-0.5 rounded text-[10px] break-all max-w-xs">
                {formatDiffValue(change.after)}
              </span>
            </div>
          )}

          {change.type === 'added' && (
            <div className="mt-1">
              <span className="bg-emerald-100 text-emerald-800 font-mono px-1.5 py-0.5 rounded text-[10px] break-all">
                {formatDiffValue(change.after)}
              </span>
            </div>
          )}

          {change.type === 'removed' && (
            <div className="mt-1">
              <span className="bg-red-100 text-red-800 font-mono px-1.5 py-0.5 rounded text-[10px] break-all line-through">
                {formatDiffValue(change.before)}
              </span>
            </div>
          )}

          {/* Expand button for complex values */}
          {isComplex && (
            <button
              onClick={() => setExpanded((e) => !e)}
              className="mt-1 text-[10px] text-gray-400 hover:text-gray-700 underline"
            >
              {expanded ? 'collapse' : 'view full value'}
            </button>
          )}

          {expanded && isComplex && (
            <div className="mt-2 grid grid-cols-2 gap-2">
              {change.before != null && (
                <div>
                  <p className="text-[10px] text-gray-400 mb-0.5 font-semibold">Before</p>
                  <pre className="text-[10px] text-red-700 bg-red-50 border border-red-200 rounded p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                    {JSON.stringify(change.before, null, 2)}
                  </pre>
                </div>
              )}
              {change.after != null && (
                <div>
                  <p className="text-[10px] text-gray-400 mb-0.5 font-semibold">After</p>
                  <pre className="text-[10px] text-emerald-700 bg-emerald-50 border border-emerald-200 rounded p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                    {JSON.stringify(change.after, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>

        <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded shrink-0 ${styles.badge}`}>
          {styles.label}
        </span>
      </div>
    </div>
  );
}

/** Simple snapshot view for CREATED/DELETED where there's only one side */
function ConfigSnapshot({ label, config, color }: {
  label:  string;
  config: Record<string, unknown>;
  color:  'emerald' | 'red';
}) {
  const [expanded, setExpanded] = useState(false);
  const colorClass = color === 'emerald'
    ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
    : 'border-red-200 bg-red-50 text-red-700';
  const preClass = color === 'emerald'
    ? 'text-emerald-800 bg-emerald-50'
    : 'text-red-800 bg-red-50';

  const flatEntries = flattenConfig(config);

  return (
    <div className={`border rounded-lg overflow-hidden ${colorClass}`}>
      <div className="px-3 py-2 flex items-center justify-between">
        <span className="text-xs font-semibold">{label}</span>
        <button
          onClick={() => setExpanded((e) => !e)}
          className="text-[10px] underline opacity-70 hover:opacity-100"
        >
          {expanded ? 'collapse' : `show ${flatEntries.length} fields`}
        </button>
      </div>
      {expanded && (
        <div className="border-t divide-y divide-opacity-30">
          {flatEntries.slice(0, 50).map(([path, value]) => (
            <div key={path} className={`px-3 py-1.5 text-xs ${preClass} flex items-start gap-3`}>
              <span className="font-mono font-semibold text-gray-600 shrink-0 w-48 truncate" title={path}>{path}</span>
              <span className="font-mono break-all">{formatDiffValue(value)}</span>
            </div>
          ))}
          {flatEntries.length > 50 && (
            <div className="px-3 py-1.5 text-xs text-gray-400">+{flatEntries.length - 50} more fields…</div>
          )}
        </div>
      )}
    </div>
  );
}

function flattenConfig(obj: Record<string, unknown>, prefix = '', depth = 0): [string, unknown][] {
  if (depth > 4) return [];
  const entries: [string, unknown][] = [];
  for (const [key, value] of Object.entries(obj)) {
    if (key.startsWith('_') || key.startsWith('@')) continue;
    const path = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === 'object' && !Array.isArray(value) && depth < 3) {
      entries.push(...flattenConfig(value as Record<string, unknown>, path, depth + 1));
    } else {
      entries.push([path, value]);
    }
  }
  return entries;
}
