import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { enqueueScan, removeJob } from '../services/scanJobService';

const router = Router();
router.use(authenticate);

const createScanSchema = z.object({
  accountId: z.string().uuid(),
  services: z.array(z.string()).optional(),
  regions: z.array(z.string()).optional(),
});

// GET /api/scans
router.get('/', async (req: Request, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = {};
    if (req.query.accountId) where.accountId = req.query.accountId;
    if (req.query.status) where.status = req.query.status;

    const [scans, total] = await Promise.all([
      prisma.scan.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          summary: true,
          account: {
            select: { id: true, name: true, awsAccountId: true },
          },
        },
      }),
      prisma.scan.count({ where }),
    ]);

    res.json({
      data: scans,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/scans
router.post('/', async (req: Request, res: Response) => {
  try {
    const body = createScanSchema.parse(req.body);

    const account = await prisma.account.findUnique({ where: { id: body.accountId } });
    if (!account) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }

    const cred = await prisma.awsCredential.findUnique({ where: { accountId: body.accountId } });
    if (!cred) {
      res.status(400).json({ error: 'No credentials configured for this account' });
      return;
    }

    const services = body.services || [
      'cloudtrail', 'iam', 's3',
      'ec2', 'ebs', 'rds', 'kms', 'secretsmanager',
      'cloudwatch', 'vpc', 'lambda', 'ecr',
      'threatdetection',
      'elb', 'dynamodb', 'elasticache',
      'apigateway', 'waf', 'ssm',
      'cloudfront', 'acm',
      'sns', 'sqs', 'redshift', 'ecs',
    ];
    const regions = body.regions || [cred.defaultRegion, ...cred.additionalRegions];

    const scan = await prisma.scan.create({
      data: {
        accountId: body.accountId,
        status: 'QUEUED',
        triggeredBy: req.user!.id,
        services,
        regions,
      },
    });

    const jobId = await enqueueScan(scan.id, body.accountId, services, regions);

    const updatedScan = await prisma.scan.update({
      where: { id: scan.id },
      data: { jobId },
    });

    res.status(201).json({ data: updatedScan });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/scans/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: req.params.id },
      include: {
        summary: true,
        account: {
          select: { id: true, name: true, awsAccountId: true },
        },
      },
    });

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    const findingCounts = await prisma.finding.groupBy({
      by: ['severity'],
      where: { scanId: scan.id },
      _count: { id: true },
    });

    const severityCounts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    findingCounts.forEach((fc) => {
      severityCounts[fc.severity] = fc._count.id;
    });

    res.json({ data: { ...scan, findingsBySeverity: severityCounts } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/scans/:id (cancel)
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const scan = await prisma.scan.findUnique({ where: { id: req.params.id } });

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    if (scan.status !== 'QUEUED' && scan.status !== 'RUNNING') {
      res.status(400).json({ error: `Cannot cancel scan in status: ${scan.status}` });
      return;
    }

    if (scan.jobId) {
      try {
        await removeJob(scan.jobId);
      } catch {
        // Job may already be running or removed
      }
    }

    const updatedScan = await prisma.scan.update({
      where: { id: req.params.id },
      data: { status: 'CANCELLED' },
    });

    res.json({ data: updatedScan });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/scans/:id/findings
router.get('/:id/findings', async (req: Request, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt((req.query.pageSize ?? req.query.limit) as string) || 20;
    const skip = (page - 1) * limit;

    const scan = await prisma.scan.findUnique({ where: { id: req.params.id } });
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    const where: Record<string, unknown> = { scanId: req.params.id };
    if (req.query.severity) where.severity = req.query.severity;
    if (req.query.service) where.service = req.query.service;
    if (req.query.findingStatus) where.findingStatus = req.query.findingStatus;
    if (req.query.search) {
      where.OR = [
        { title: { contains: req.query.search as string, mode: 'insensitive' } },
        { description: { contains: req.query.search as string, mode: 'insensitive' } },
      ];
    }

    const [findings, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        skip,
        take: limit,
        orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
      }),
      prisma.finding.count({ where }),
    ]);

    res.json({
      data: findings,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/scans/:id/findings/export
router.get('/:id/findings/export', async (req: Request, res: Response) => {
  try {
    const format = (req.query.format as string) || 'json';

    const scan = await prisma.scan.findUnique({ where: { id: req.params.id } });
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    const findings = await prisma.finding.findMany({
      where: { scanId: req.params.id },
      orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
    });

    if (format === 'csv') {
      const headers = [
        'id',
        'service',
        'severity',
        'title',
        'description',
        'remediation',
        'findingStatus',
        'tags',
        'discoveredAt',
      ];

      const rows = findings.map((f) =>
        [
          f.id,
          f.service,
          f.severity,
          `"${f.title.replace(/"/g, '""')}"`,
          `"${f.description.replace(/"/g, '""')}"`,
          `"${f.remediation.replace(/"/g, '""')}"`,
          f.findingStatus,
          f.tags.join(';'),
          f.discoveredAt.toISOString(),
        ].join(',')
      );

      const csv = [headers.join(','), ...rows].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="scan-${req.params.id}-findings.csv"`
      );
      res.send(csv);
    } else {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="scan-${req.params.id}-findings.json"`
      );
      res.json({ data: findings });
    }
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
