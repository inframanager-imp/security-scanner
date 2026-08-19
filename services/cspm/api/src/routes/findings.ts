import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';

const router = Router();
router.use(authenticate);

const updateFindingSchema = z.object({
  findingStatus: z.enum(['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE']),
});

// Severity rank for proper ordering (CRITICAL first)
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 3,
  LOW: 4,
  INFO: 5,
};

// GET /api/findings/prioritized — top N findings by riskScore, multi-cloud
router.get('/prioritized', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(Math.max(parseInt((req.query.limit as string) ?? '20', 10), 1), 200);
    const minRiskScore = req.query.minRiskScore !== undefined
      ? parseInt(req.query.minRiskScore as string, 10)
      : 50;

    const baseWhere: any = { findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] }, riskScore: { gte: minRiskScore } };
    if (req.query.accountId) baseWhere.scan = { accountId: req.query.accountId };

    const [aws, azure, gcp] = await Promise.all([
      prisma.finding.findMany({
        where: baseWhere,
        orderBy: [{ riskScore: { sort: 'desc', nulls: 'last' } as any }],
        take: limit,
        include: { scan: { select: { account: { select: { id: true, name: true, awsAccountId: true } } } } },
      }),
      prisma.azureFinding.findMany({
        where: { findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] }, riskScore: { gte: minRiskScore } },
        orderBy: [{ riskScore: { sort: 'desc', nulls: 'last' } as any }],
        take: limit,
        include: { scan: { select: { subscription: { select: { id: true, name: true, subscriptionId: true } } } } },
      }),
      prisma.gcpFinding.findMany({
        where: { findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] }, riskScore: { gte: minRiskScore } },
        orderBy: [{ riskScore: { sort: 'desc', nulls: 'last' } as any }],
        take: limit,
        include: { scan: { select: { project: { select: { id: true, name: true, projectId: true } } } } },
      }),
    ]);

    const merged = [
      ...aws.map((f) => ({
        ...f,
        provider: 'AWS' as const,
        account: f.scan?.account ?? null,
      })),
      ...azure.map((f) => ({
        ...f,
        provider: 'AZURE' as const,
        account: f.scan?.subscription
          ? { id: f.scan.subscription.id, name: f.scan.subscription.name, nativeId: f.scan.subscription.subscriptionId }
          : null,
      })),
      ...gcp.map((f) => ({
        ...f,
        provider: 'GCP' as const,
        account: f.scan?.project
          ? { id: f.scan.project.id, name: f.scan.project.name, nativeId: f.scan.project.projectId }
          : null,
      })),
    ]
      .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))
      .slice(0, limit);

    res.json({ data: merged });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/findings/services — distinct services for filter dropdowns
router.get('/services', async (req: Request, res: Response) => {
  try {
    const where: Record<string, unknown> = {};
    if (req.query.accountId) {
      where.scan = { accountId: req.query.accountId };
    }

    const rows = await prisma.finding.findMany({
      where,
      select: { service: true },
      distinct: ['service'],
      orderBy: { service: 'asc' },
    });

    res.json({ data: rows.map((r) => r.service) });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/findings
router.get('/', async (req: Request, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt((req.query.pageSize ?? req.query.limit) as string) || 20;
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = {};

    if (req.query.severity) where.severity = req.query.severity;

    // Multi-service: ?services=s3,ec2 OR ?service=s3 (single, legacy)
    if (req.query.services) {
      const svcList = String(req.query.services)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (svcList.length === 1) {
        where.service = svcList[0];
      } else if (svcList.length > 1) {
        where.service = { in: svcList };
      }
    } else if (req.query.service) {
      where.service = req.query.service;
    }

    if (req.query.findingStatus) where.findingStatus = req.query.findingStatus;

    if (req.query.accountId) {
      where.scan = { accountId: req.query.accountId };
    }

    if (req.query.search) {
      where.OR = [
        { title: { contains: req.query.search as string, mode: 'insensitive' } },
        { description: { contains: req.query.search as string, mode: 'insensitive' } },
        { service: { contains: req.query.search as string, mode: 'insensitive' } },
      ];
    }

    // Sort support
    const sortBy = String(req.query.sortBy || 'severity');
    const sortDir = req.query.sortOrder === 'asc' ? 'asc' : 'desc';

    const SORT_MAP: Record<string, string> = {
      service: 'service',
      status: 'findingStatus',
      discoveredAt: 'discoveredAt',
      title: 'title',
      riskScore: 'riskScore',
    };

    // riskScore filter: ?minRiskScore=70
    if (req.query.minRiskScore !== undefined) {
      const minRisk = parseInt(req.query.minRiskScore as string, 10);
      if (Number.isFinite(minRisk)) where.riskScore = { gte: minRisk };
    }
    if (req.query.reachability) where.reachability = req.query.reachability;

    let orderBy: object[];
    if (sortBy === 'severity') {
      const sevDir = req.query.sortOrder === 'desc' ? 'desc' : 'asc';
      orderBy = [{ severity: sevDir }, { discoveredAt: 'desc' }];
    } else if (sortBy === 'riskScore') {
      const dir = req.query.sortOrder === 'asc' ? 'asc' : 'desc';
      orderBy = [{ riskScore: { sort: dir, nulls: 'last' } as any }, { severity: 'asc' }];
    } else if (SORT_MAP[sortBy]) {
      orderBy = [{ [SORT_MAP[sortBy]]: sortDir }, { severity: 'asc' }];
    } else {
      orderBy = [{ severity: 'asc' }, { discoveredAt: 'desc' }];
    }

    const [findings, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        skip,
        take: limit,
        orderBy,
        include: {
          scan: {
            select: {
              id: true,
              account: {
                select: { id: true, name: true, awsAccountId: true },
              },
            },
          },
        },
      }),
      prisma.finding.count({ where }),
    ]);

    // Re-sort current page by true severity rank when sorting by severity
    let sorted = findings;
    if (sortBy === 'severity') {
      const dir = req.query.sortOrder === 'desc' ? -1 : 1;
      sorted = [...findings].sort(
        (a, b) =>
          dir *
          ((SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)),
      );
    }

    const mapped = sorted.map((f) => ({
      id: f.id,
      scanId: f.scanId,
      accountId: f.scan?.account?.id,
      accountName: f.scan?.account?.name,
      service: f.service,
      severity: f.severity,
      title: f.title,
      description: f.description,
      evidence: f.evidence,
      remediation: f.remediation,
      findingStatus: f.findingStatus,
      tags: f.tags,
      discoveredAt: f.discoveredAt,
    }));

    res.json({
      data: mapped,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/deduplicate', async (req: Request, res: Response) => {
  try {
    const { accountId } = req.body as { accountId?: string };

    const FINGERPRINT_KEYS = [
      'functionName', 'trailName', 'bucket', 'username', 'accessKeyId',
      'keyId', 'dbId', 'clusterId', 'secretName', 'sgId', 'instanceId',
      'naclId', 'vpcId', 'requirementId', 'peeringConnectionId',
      'resourceId', 'resourceName', 'arn', 'name', 'id',
    ];

    function resourceFingerprint(evidence: unknown): string {
      const e = (evidence ?? {}) as Record<string, unknown>;
      if (e.resourceId != null) return String(e.resourceId);
      for (const key of FINGERPRINT_KEYS) {
        if (e[key] != null) return String(e[key]);
      }
      return 'account-level';
    }

    const STATUS_PRIORITY: Record<string, number> = {
      OPEN: 0, ACKNOWLEDGED: 1, RESOLVED: 2, FALSE_POSITIVE: 3,
    };

    // Load all findings for the scope
    const all = await prisma.finding.findMany({
      where: accountId ? { scan: { accountId } } : {},
      select: {
        id: true,
        service: true,
        title: true,
        evidence: true,
        findingStatus: true,
        createdAt: true,
        scan: { select: { accountId: true } },
      },
      orderBy: { createdAt: 'asc' },
    });

    // Group by accountId::service::title::resource
    const groups = new Map<string, typeof all>();
    for (const f of all) {
      const key = [f.scan.accountId, f.service, f.title, resourceFingerprint(f.evidence)].join('::');
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(f);
    }

    const toDelete: string[] = [];
    for (const members of groups.values()) {
      if (members.length <= 1) continue;
      members.sort((a, b) => {
        const pa = STATUS_PRIORITY[a.findingStatus] ?? 99;
        const pb = STATUS_PRIORITY[b.findingStatus] ?? 99;
        if (pa !== pb) return pa - pb;
        return a.createdAt.getTime() - b.createdAt.getTime();
      });
      const [, ...duplicates] = members;
      toDelete.push(...duplicates.map((d) => d.id));
    }

    if (toDelete.length === 0) {
      res.json({ data: { deleted: 0, message: 'No duplicates found — database is clean.' } });
      return;
    }

    // Delete in batches
    let deleted = 0;
    const BATCH = 500;
    for (let i = 0; i < toDelete.length; i += BATCH) {
      const result = await prisma.finding.deleteMany({
        where: { id: { in: toDelete.slice(i, i + BATCH) } },
      });
      deleted += result.count;
    }

    res.json({
      data: {
        deleted,
        scanned: all.length,
        remaining: all.length - deleted,
        message: `Removed ${deleted} duplicate finding(s). ${all.length - deleted} unique findings remain.`,
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// PATCH /api/findings/:id
router.patch('/:id', async (req: Request, res: Response) => {
  try {
    const body = updateFindingSchema.parse(req.body);

    const existing = await prisma.finding.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'Finding not found' });
      return;
    }

    const finding = await prisma.finding.update({
      where: { id: req.params.id },
      data: { findingStatus: body.findingStatus },
    });

    res.json({ data: finding });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
