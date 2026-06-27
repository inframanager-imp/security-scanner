import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';

const router = Router();
router.use(authenticate);

// GET /api/azure/scans?subscriptionId=X&status=Y&page=1&limit=20
router.get('/', async (req: Request, res: Response) => {
  try {
    const page  = parseInt(req.query.page  as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip  = (page - 1) * limit;

    const where: Record<string, unknown> = {};
    if (req.query.subscriptionId) where.subscriptionId = req.query.subscriptionId;
    if (req.query.status)         where.status         = req.query.status;

    const [scans, total] = await Promise.all([
      prisma.azureScan.findMany({
        where,
        skip,
        take:    limit,
        orderBy: { createdAt: 'desc' },
        include: {
          summary:      true,
          subscription: { select: { id: true, name: true, subscriptionId: true } },
        },
      }),
      prisma.azureScan.count({ where }),
    ]);

    res.json({ data: scans, meta: { total, page, limit, totalPages: Math.ceil(total / limit) } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/azure/scans/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const scan = await prisma.azureScan.findUnique({
      where:   { id: req.params.id },
      include: {
        summary:      true,
        subscription: { select: { id: true, name: true, subscriptionId: true } },
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

// GET /api/azure/scans/:id/findings?page=1&limit=20&severity=HIGH&service=iam
router.get('/:id/findings', async (req: Request, res: Response) => {
  try {
    const page     = parseInt(req.query.page     as string) || 1;
    const limit    = parseInt(req.query.pageSize  as string) || parseInt(req.query.limit as string) || 20;
    const skip     = (page - 1) * limit;

    const where: Record<string, unknown> = { scanId: req.params.id };
    if (req.query.severity) where.severity      = req.query.severity;
    if (req.query.service)  where.service       = req.query.service;
    if (req.query.status)   where.findingStatus = req.query.status;

    const [findings, total] = await Promise.all([
      prisma.azureFinding.findMany({
        where,
        skip,
        take:    limit,
        orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
      }),
      prisma.azureFinding.count({ where }),
    ]);

    res.json({ data: findings, meta: { total, page, limit, totalPages: Math.ceil(total / limit) } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/azure/scans/:id/findings/export — CSV export
router.get('/:id/findings/export', async (req: Request, res: Response) => {
  try {
    const scan = await prisma.azureScan.findUnique({
      where:   { id: req.params.id },
      include: { subscription: { select: { name: true } } },
    });
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    const findings = await prisma.azureFinding.findMany({
      where:   { scanId: req.params.id },
      orderBy: [{ severity: 'asc' }, { service: 'asc' }],
    });

    const header = 'Severity,Service,Title,Description,Resource Group,Resource ID,Status,Tags,Discovered At\n';
    const rows   = findings.map(f =>
      [
        f.severity,
        f.service,
        `"${f.title.replace(/"/g, '""')}"`,
        `"${f.description.replace(/"/g, '""')}"`,
        f.resourceGroup ?? '',
        f.resourceId    ?? '',
        f.findingStatus,
        f.tags.join(';'),
        f.discoveredAt.toISOString(),
      ].join(',')
    ).join('\n');

    const filename = `azure-scan-${req.params.id}-findings.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(header + rows);
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/azure/scans/findings/cleanup-scanner-errors
// Removes INFO-severity findings that were created by scanner failures (ARM SDK errors)
router.delete('/findings/cleanup-scanner-errors', async (_req: Request, res: Response) => {
  try {
    const result = await prisma.azureFinding.deleteMany({
      where: {
        severity: 'INFO',
        OR: [
          { title:       { contains: 'scan error',     mode: 'insensitive' } },
          { title:       { contains: 'scanner error',  mode: 'insensitive' } },
          { description: { contains: 'crypto is not defined',              } },
          { description: { contains: 'Could not complete',                 } },
        ],
      },
    });
    res.json({ data: { deleted: result.count, message: result.count > 0 ? `Removed ${result.count} scanner-error finding${result.count !== 1 ? 's' : ''}` : 'No scanner-error findings found' } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH /api/azure/scans/findings/:findingId/status
router.patch('/findings/:findingId/status', async (req: Request, res: Response) => {
  try {
    const { status } = req.body as { status: string };
    const allowed = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'];
    if (!allowed.includes(status)) {
      res.status(400).json({ error: 'Invalid status value' });
      return;
    }
    const finding = await prisma.azureFinding.update({
      where: { id: req.params.findingId },
      data:  { findingStatus: status as any },
    });
    res.json({ data: finding });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
