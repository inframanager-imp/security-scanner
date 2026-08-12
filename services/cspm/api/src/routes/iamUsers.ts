/**
 * IAM Users table — one row per IAM user with effective permissions
 * (groups/policies), assumable roles, and access hygiene (MFA, password
 * age, access key age). Reads the `iam_user_access_inventory` finding the
 * IAM scanner emits once per user (see services/cspm/src/scanners/iam.ts
 * buildUserAccessInventory()) rather than re-deriving it here.
 *
 * GET /api/iam-users?accountId=<uuid>
 */

import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';

const router = Router();
router.use(authenticate);

interface IamUserPolicyRef {
  name: string;
  type: 'managed' | 'inline';
  isAdminEquivalent: boolean;
}
interface IamUserGroupPolicyRef {
  groupName: string;
  policyName: string;
  type: 'managed' | 'inline';
  isAdminEquivalent: boolean;
}
interface IamUserAssumableRole {
  roleName: string;
  isAdminEquivalent: boolean;
  assumableBy: 'explicit' | 'wildcard';
}
interface IamUserRow {
  userName: string;
  arn: string;
  groups: string[];
  directPolicies: IamUserPolicyRef[];
  groupPolicies: IamUserGroupPolicyRef[];
  assumableRoles: IamUserAssumableRole[];
  hasOpenEndedAccess: boolean;
  mfaEnabled: boolean;
  mfaMissing: boolean;
  passwordEnabled: boolean;
  passwordAgeDays: number | null;
  passwordStale: boolean;
  accessKeysActive: number;
  accessKeyAgeDays: number | null;
  keyStale: boolean;
  hasNeverUsedActiveKey: boolean;
  severity: string;
  discoveredAt: string;
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const { accountId } = req.query as Record<string, string>;
    if (!accountId) {
      res.status(400).json({ error: 'accountId is required' });
      return;
    }

    const account = await prisma.account.findUnique({ where: { id: accountId }, select: { id: true } });
    if (!account) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }

    const latestScan = await prisma.scan.findFirst({
      where:   { accountId, status: 'COMPLETED' },
      orderBy: { completedAt: 'desc' },
      select:  { id: true, completedAt: true },
    });

    if (!latestScan) {
      res.json({ data: [], meta: { lastScanAt: null } });
      return;
    }

    // Findings dedupe against existing OPEN/ACKNOWLEDGED ones across scans
    // (see workers/scanWorker.ts) — an unchanged user's inventory record
    // keeps pointing at whichever scan first created it, not necessarily
    // the latest one. Query by account + OPEN status, not scanId, so a
    // user whose profile hasn't changed since an earlier scan still shows up.
    const findings = await prisma.finding.findMany({
      where: {
        scan:          { accountId },
        checkId:       'iam_user_access_inventory',
        findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
      },
      orderBy: { discoveredAt: 'desc' },
    });

    const rows: IamUserRow[] = findings.map(f => {
      const e = f.evidence as Record<string, unknown>;
      return {
        userName:              (e.userName as string) ?? 'Unknown',
        arn:                   (e.arn as string) ?? '',
        groups:                (e.groups as string[]) ?? [],
        directPolicies:        (e.directPolicies as IamUserPolicyRef[]) ?? [],
        groupPolicies:         (e.groupPolicies as IamUserGroupPolicyRef[]) ?? [],
        assumableRoles:        (e.assumableRoles as IamUserAssumableRole[]) ?? [],
        hasOpenEndedAccess:    Boolean(e.hasOpenEndedAccess),
        mfaEnabled:            Boolean(e.mfaEnabled),
        mfaMissing:            Boolean(e.mfaMissing),
        passwordEnabled:       Boolean(e.passwordEnabled),
        passwordAgeDays:       (e.passwordAgeDays as number | null) ?? null,
        passwordStale:         Boolean(e.passwordStale),
        accessKeysActive:      (e.accessKeysActive as number) ?? 0,
        accessKeyAgeDays:      (e.accessKeyAgeDays as number | null) ?? null,
        keyStale:              Boolean(e.keyStale),
        hasNeverUsedActiveKey: Boolean(e.hasNeverUsedActiveKey),
        severity:              f.severity,
        discoveredAt:          f.discoveredAt.toISOString(),
      };
    });

    // Highest-risk users first: open-ended access, then most hygiene issues.
    rows.sort((a, b) => {
      if (a.hasOpenEndedAccess !== b.hasOpenEndedAccess) return a.hasOpenEndedAccess ? -1 : 1;
      const issueCount = (r: IamUserRow) => Number(r.mfaMissing) + Number(r.passwordStale) + Number(r.keyStale);
      return issueCount(b) - issueCount(a);
    });

    res.json({ data: rows, meta: { lastScanAt: latestScan.completedAt } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
