import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';

const router = Router();
router.use(authenticate);

// GET /api/gcp/scans?projectId=X&status=Y&page=1&limit=20
router.get('/', async (req: Request, res: Response) => {
  try {
    const page  = parseInt(req.query.page  as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip  = (page - 1) * limit;

    const where: Record<string, unknown> = {};
    if (req.query.projectId) where.projectId = req.query.projectId;
    if (req.query.status)    where.status    = req.query.status;

    const [scans, total] = await Promise.all([
      prisma.gcpScan.findMany({
        where,
        skip,
        take:    limit,
        orderBy: { createdAt: 'desc' },
        include: {
          summary: true,
          project: { select: { id: true, name: true, projectId: true } },
        },
      }),
      prisma.gcpScan.count({ where }),
    ]);

    res.json({ data: scans, meta: { total, page, limit, totalPages: Math.ceil(total / limit) } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/gcp/scans/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const scan = await prisma.gcpScan.findUnique({
      where:   { id: req.params.id },
      include: {
        summary: true,
        project: { select: { id: true, name: true, projectId: true } },
      },
    });

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    res.json({ data: scan });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/gcp/scans/:id/findings?page=1&limit=20&severity=HIGH&service=iam
router.get('/:id/findings', async (req: Request, res: Response) => {
  try {
    const page  = parseInt(req.query.page     as string) || 1;
    const limit = parseInt(req.query.pageSize as string) || parseInt(req.query.limit as string) || 20;
    const skip  = (page - 1) * limit;

    const where: Record<string, unknown> = { scanId: req.params.id };
    if (req.query.severity) where.severity      = req.query.severity;
    if (req.query.service)  where.service       = req.query.service;
    if (req.query.status)   where.findingStatus = req.query.status;

    const [findings, total] = await Promise.all([
      prisma.gcpFinding.findMany({
        where,
        skip,
        take:    limit,
        orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
      }),
      prisma.gcpFinding.count({ where }),
    ]);

    res.json({ data: findings, meta: { total, page, limit, totalPages: Math.ceil(total / limit) } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/gcp/scans/:id/findings/export — CSV export
router.get('/:id/findings/export', async (req: Request, res: Response) => {
  try {
    const scan = await prisma.gcpScan.findUnique({
      where:   { id: req.params.id },
      include: { project: { select: { name: true } } },
    });
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    const findings = await prisma.gcpFinding.findMany({
      where:   { scanId: req.params.id },
      orderBy: [{ severity: 'asc' }, { service: 'asc' }],
    });

    const header = 'Severity,Service,Title,Description,Resource Name,Region,Status,Tags,Discovered At\n';
    const rows   = findings.map(f =>
      [
        f.severity,
        f.service,
        `"${f.title.replace(/"/g, '""')}"`,
        `"${f.description.replace(/"/g, '""')}"`,
        f.resourceName ?? '',
        f.region       ?? '',
        f.findingStatus,
        f.tags.join(';'),
        f.discoveredAt.toISOString(),
      ].join(',')
    ).join('\n');

    const filename = `gcp-scan-${req.params.id}-findings.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(header + rows);
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
