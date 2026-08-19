/**
 * Config Diff Utility
 *
 * Computes a field-level diff between two resource configuration snapshots.
 * Used by ConfigDiffView to show exactly what changed (before → after).
 *
 * Produces a flat list of FieldChange objects with dot-notation paths,
 * e.g. "settings.ipConfiguration.requireSsl", "ingressRules[0].fromPort"
 */

export type DiffType = 'added' | 'removed' | 'changed';

export interface FieldChange {
  path:   string;
  type:   DiffType;
  before: unknown;
  after:  unknown;
}

// Fields that are noise — timestamps, internal IDs, etags, metadata we don't care about
const NOISE_KEYS = new Set([
  'eTag', 'etag', 'ETag', 'selfLink', 'id', 'fingerprint', 'kind',
  'creationTimestamp', 'createTime', 'updateTime', 'lastModified',
  'lastModifiedTime', 'ResponseMetadata', '$metadata',
  'RequestId', 'requestId', 'HostId', 'Metadata',
]);

// Keys where we show a summary instead of deep-diffing (large nested objects)
const SUMMARIZE_KEYS = new Set([
  'policy', 'trustPolicy', 'iamPolicy', 'redrivePolicy',
  'deliveryPolicy', 'lifecycle', 'lifecycleRules',
]);

function isNoise(key: string): boolean {
  return NOISE_KEYS.has(key) || key.startsWith('_') || key.startsWith('@');
}

function isLeaf(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean') return true;
  if (Array.isArray(value)) {
    // Treat arrays of primitives as leaf values
    return value.every((v) => typeof v !== 'object' || v === null);
  }
  return false;
}

function serialize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return String(value);
  try { return JSON.stringify(value, null, 0); } catch { return String(value); }
}

export function computeConfigDiff(
  before: Record<string, unknown> | null | undefined,
  after:  Record<string, unknown> | null | undefined,
  maxDepth = 6,
): FieldChange[] {
  const changes: FieldChange[] = [];

  function walk(
    bObj: unknown,
    aObj: unknown,
    path: string,
    depth: number,
  ): void {
    if (depth > maxDepth) return;

    // Both null/undefined — no change
    if (bObj == null && aObj == null) return;

    // One side is null/undefined
    if (bObj == null && aObj != null) {
      changes.push({ path, type: 'added', before: null, after: aObj });
      return;
    }
    if (bObj != null && aObj == null) {
      changes.push({ path, type: 'removed', before: bObj, after: null });
      return;
    }

    // Leaf values — compare directly
    if (isLeaf(bObj) || isLeaf(aObj)) {
      const bs = serialize(bObj);
      const as_ = serialize(aObj);
      if (bs !== as_) {
        changes.push({ path, type: 'changed', before: bObj, after: aObj });
      }
      return;
    }

    // Array of objects — compare element by element up to min length
    if (Array.isArray(bObj) && Array.isArray(aObj)) {
      const maxLen = Math.max(bObj.length, aObj.length);
      for (let i = 0; i < maxLen; i++) {
        const bItem = bObj[i];
        const aItem = aObj[i];
        // Use a key hint if the element has a descriptive identifier
        const keyHint = getArrayItemKey(bItem ?? aItem, i);
        walk(bItem, aItem, `${path}[${keyHint}]`, depth + 1);
      }
      return;
    }

    // Objects — recurse into each key
    if (typeof bObj === 'object' && typeof aObj === 'object' && !Array.isArray(bObj) && !Array.isArray(aObj)) {
      const bRecord = bObj as Record<string, unknown>;
      const aRecord = aObj as Record<string, unknown>;
      const allKeys = new Set([...Object.keys(bRecord), ...Object.keys(aRecord)]);

      for (const key of allKeys) {
        if (isNoise(key)) continue;

        const childPath = path ? `${path}.${key}` : key;
        const bVal = bRecord[key];
        const aVal = aRecord[key];

        // For known complex objects, summarize instead of deep-diffing
        if (SUMMARIZE_KEYS.has(key)) {
          const bs = serialize(bVal);
          const as_ = serialize(aVal);
          if (bs !== as_) {
            changes.push({ path: childPath, type: 'changed', before: bVal, after: aVal });
          }
          continue;
        }

        walk(bVal, aVal, childPath, depth + 1);
      }
      return;
    }

    // Mixed types (one is array, other is object, etc.) — treat as changed
    const bs = serialize(bObj);
    const as_ = serialize(aObj);
    if (bs !== as_) {
      changes.push({ path, type: 'changed', before: bObj, after: aObj });
    }
  }

  walk(before ?? {}, after ?? {}, '', 0);
  return changes;
}

function getArrayItemKey(item: unknown, index: number): string {
  if (item == null || typeof item !== 'object') return String(index);
  const obj = item as Record<string, unknown>;
  // Common identifier fields in AWS/Azure/GCP resource configs
  const keyFields = [
    'IpProtocol', 'protocol', 'FromPort', 'fromPort', 'toPort', 'ToPort',
    'name', 'Name', 'id', 'Id', 'ruleNumber', 'RuleNumber',
    'Effect', 'Action', 'Principal', 'Sid',
    'priority', 'Priority', 'port', 'Port',
    'cidrIp', 'CidrIp', 'cidrBlock', 'CidrBlock',
    'policyName', 'PolicyName', 'policyArn', 'PolicyArn',
    'email', 'role', 'member',
  ];
  for (const field of keyFields) {
    if (obj[field] != null) return String(obj[field]);
  }
  return String(index);
}

export function formatDiffValue(value: unknown, maxLen = 120): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return value.length > maxLen ? value.slice(0, maxLen) + '…' : value;
  try {
    const s = JSON.stringify(value, null, 2);
    return s.length > maxLen ? s.slice(0, maxLen) + '…' : s;
  } catch {
    return String(value);
  }
}

/**
 * Groups diff changes by top-level section for display.
 */
export function groupDiffBySection(changes: FieldChange[]): Map<string, FieldChange[]> {
  const groups = new Map<string, FieldChange[]>();
  for (const change of changes) {
    const section = change.path.split('.')[0]?.replace(/\[.*$/, '') || 'general';
    if (!groups.has(section)) groups.set(section, []);
    groups.get(section)!.push(change);
  }
  return groups;
}
