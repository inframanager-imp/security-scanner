/**
 * inventorySync
 *
 * Called after every ConfigChange upsert.
 *
 * Handles two cases:
 *   DELETION  — marks matching ResourceInventory as DELETED + creates snapshot
 *   MODIFIED  — updates configState on the matching record + creates snapshot
 *
 * Sub-resource events (e.g. Azure securityRules, AWS SecurityGroupIngress) are
 * matched against the parent resource by stripping the trailing sub-resource path
 * segment and merging the change into the parent's configState under a keyed section.
 */

import { prisma } from '../config/database';
import { Prisma } from '@prisma/client';

// ─── AWS deletion event names ─────────────────────────────────────────────────

const AWS_DELETE_EVENTS = new Set([
  'DeleteBucket',
  'DeleteDBInstance',
  'DeleteDBCluster',
  'TerminateInstances',
  'DeleteFunction',
  'DeleteSecurityGroup',
  'DeleteVpc',
  'DeleteSubnet',
  'DeleteInternetGateway',
  'DeleteRouteTable',
  'DeleteNetworkInterface',
  'DeleteVolume',
  'DeleteRole',
  'DeleteUser',
  'DeleteGroup',
  'DeleteKey',
  'DeleteAlias',
  'DeleteTrail',
  'DeleteCluster',
  'DeleteLoadBalancer',
  'DeleteTargetGroup',
  'DeleteTable',
  'DeleteTopic',
  'DeleteQueue',
  'DeleteDistribution',
  'DeleteCacheCluster',
  'DeleteStack',
  'DeleteRepository',
  'DeleteSecret',
]);

function isAwsDeletion(eventName: string): boolean {
  return AWS_DELETE_EVENTS.has(eventName) ||
    (eventName.startsWith('Delete') && !eventName.startsWith('DeleteAccount') && !eventName.startsWith('DeleteBucketPolicy'));
}

function isAzureDeletion(operationName: string): boolean {
  return operationName.toLowerCase().endsWith('/delete');
}

function isGcpDeletion(methodName: string): boolean {
  const lower = methodName.toLowerCase();
  return lower.includes('.delete') || lower.endsWith('delete');
}

// ─── Sub-resource parent extraction ──────────────────────────────────────────

function parentCandidates(resourceId: string): string[] {
  const candidates: string[] = [];
  // Strip one path segment at a time (up to 3 levels deep)
  const parts = resourceId.split('/');
  for (let strip = 2; strip <= 6 && parts.length - strip > 2; strip += 2) {
    candidates.push(parts.slice(0, parts.length - strip).join('/'));
  }
  return candidates;
}

// ─── Sub-resource key extraction ─────────────────────────────────────────────

function subResourceKey(resourceId: string, resourceType: string | null): string {
  if (resourceType) {
    // "Microsoft.Network/networkSecurityGroups/securityRules" → "securityRules"
    const parts = resourceType.split('/');
    if (parts.length > 1) return parts[parts.length - 1];
  }
  // Fall back to last two path segments of the ID
  const idParts = resourceId.split('/').filter(Boolean);
  if (idParts.length >= 2) return idParts[idParts.length - 2];
  return 'subResources';
}

// ─── Find inventory record (direct + parent fallback) ────────────────────────

async function findInventoryRecord(
  provider: string,
  targetId: string,
  resourceId: string | null,
  resourceName: string | null,
  onlyActive: boolean,
): Promise<{ id: string; configState: Prisma.JsonValue; nativeId: string } | null> {

  const accountWhere: Prisma.ResourceInventoryWhereInput = {};
  if (provider === 'AWS')        accountWhere.awsAccountId = targetId;
  else if (provider === 'AZURE') accountWhere.azureSubId   = targetId;
  else if (provider === 'GCP')   accountWhere.gcpProjectId = targetId;
  if (onlyActive) accountWhere.state = 'ACTIVE';

  const orConditions: Prisma.ResourceInventoryWhereInput[] = [];
  if (resourceId) {
    orConditions.push({ nativeId: { equals: resourceId, mode: 'insensitive' as const } });
    orConditions.push({ nativeId: { contains: resourceId, mode: 'insensitive' as const } });
  }
  if (resourceName) {
    orConditions.push({ resourceName: { equals: resourceName, mode: 'insensitive' as const } });
  }

  if (orConditions.length > 0) {
    const direct = await prisma.resourceInventory.findFirst({
      where:  { ...accountWhere, OR: orConditions },
      select: { id: true, configState: true, nativeId: true },
    });
    if (direct) return direct;
  }

  // Parent fallback — try progressively shorter resource ID paths
  if (resourceId) {
    for (const parentId of parentCandidates(resourceId)) {
      const parent = await prisma.resourceInventory.findFirst({
        where:  {
          ...accountWhere,
          OR: [
            { nativeId: { equals: parentId, mode: 'insensitive' as const } },
            { nativeId: { contains: parentId, mode: 'insensitive' as const } },
          ],
        },
        select: { id: true, configState: true, nativeId: true },
      });
      if (parent) return parent;
    }
  }

  return null;
}

// ─── Merge new state into configState ────────────────────────────────────────

function mergeConfigState(
  existing: Prisma.JsonValue,
  newValue: Record<string, unknown>,
  subKey: string | null,
): Record<string, unknown> {
  const base: Record<string, unknown> =
    existing && typeof existing === 'object' && !Array.isArray(existing)
      ? { ...(existing as Record<string, unknown>) }
      : {};

  if (subKey) {
    // Merge sub-resource: update or add the specific sub-resource entry within a keyed array/object
    const section = base[subKey];
    const resourceName = (newValue.name ?? newValue.id ?? newValue.resourceId) as string | undefined;

    if (Array.isArray(section) && resourceName) {
      // Replace the matching entry by name/id, or append
      const idx = (section as Record<string, unknown>[]).findIndex(
        (item) => item.name === resourceName || item.id === resourceName
      );
      if (idx >= 0) {
        const updated = [...section] as Record<string, unknown>[];
        updated[idx] = { ...updated[idx], ...newValue };
        base[subKey] = updated;
      } else {
        base[subKey] = [...section, newValue];
      }
    } else if (section && typeof section === 'object' && !Array.isArray(section)) {
      base[subKey] = { ...(section as Record<string, unknown>), ...newValue };
    } else {
      // No existing section — store as single-entry array
      base[subKey] = [newValue];
    }
    return base;
  }

  // Direct resource — shallow merge newValue into existing configState
  return { ...base, ...newValue };
}

// ─── Main sync function ───────────────────────────────────────────────────────

export interface InventorySyncParams {
  provider:     string;
  targetId:     string;
  eventName:    string;
  resourceId:   string | null;
  resourceName: string | null;
  resourceType: string | null;
  newValue:     Record<string, unknown> | null;
  eventTime:    Date;
}

export async function syncInventoryFromChange(p: InventorySyncParams): Promise<void> {
  const isDeletion =
    p.provider === 'AWS'   ? isAwsDeletion(p.eventName) :
    p.provider === 'AZURE' ? isAzureDeletion(p.eventName) :
    p.provider === 'GCP'   ? isGcpDeletion(p.eventName) :
    false;

  if (!p.resourceId && !p.resourceName) return;

  const now = p.eventTime ?? new Date();

  // ── DELETION ──────────────────────────────────────────────────────────────

  if (isDeletion) {
    const record = await findInventoryRecord(p.provider, p.targetId, p.resourceId, p.resourceName, true);
    if (!record) return;

    await prisma.resourceInventory.update({
      where: { id: record.id },
      data:  { state: 'DELETED', deletedAt: now, lastSeenAt: now },
    });
    await prisma.resourceSnapshot.create({
      data: {
        inventoryId: record.id,
        configState: record.configState as Prisma.InputJsonValue,
        changeType:  'DELETED',
        capturedAt:  now,
      },
    });
    return;
  }

  // ── MODIFICATION ─────────────────────────────────────────────────────────
  // Only update inventory if we have a newValue payload to apply.

  if (!p.newValue || Object.keys(p.newValue).length === 0) return;

  const record = await findInventoryRecord(p.provider, p.targetId, p.resourceId, p.resourceName, false);
  if (!record) return;

  // Determine if this is a sub-resource event (record matched via parent fallback)
  const isSubResource = p.resourceId
    ? !record.nativeId.toLowerCase().includes(p.resourceId.toLowerCase().split('/').pop() ?? '__x__')
      || record.nativeId.toLowerCase() !== p.resourceId.toLowerCase()
    : false;

  const subKey = isSubResource && p.resourceId
    ? subResourceKey(p.resourceId, p.resourceType)
    : null;

  const merged = mergeConfigState(record.configState, p.newValue, subKey);

  await prisma.resourceInventory.update({
    where: { id: record.id },
    data:  {
      configState: merged as Prisma.InputJsonValue,
      lastSeenAt:  now,
    },
  });

  await prisma.resourceSnapshot.create({
    data: {
      inventoryId: record.id,
      configState: merged as Prisma.InputJsonValue,
      changeType:  'MODIFIED',
      capturedAt:  now,
    },
  });
}
