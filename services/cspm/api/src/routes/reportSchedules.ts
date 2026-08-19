/**
 * Scheduled Report Routes
 *
 * GET    /api/report-schedules          — list all schedules
 * POST   /api/report-schedules          — create schedule
 * PUT    /api/report-schedules/:id      — update schedule
 * DELETE /api/report-schedules/:id      — delete schedule
 * POST   /api/report-schedules/:id/run  — trigger on-demand generation
 * GET    /api/report-schedules/:id/runs — run history
 * GET    /api/report-schedules/:id/preview — download HTML report immediately
 * GET    /api/report-schedules/compile     — ad-hoc report (no saved schedule needed);
 *                                             ?targetId= scopes to one account, omit for
 *                                             "All Accounts"; ?format=pdf for a real PDF
 *                                             download instead of HTML
 */

import { Router, Request, Response } from 'express';
import { prisma }                     from '../config/database';
import {
  computeNextRun,
  generateOnDemandReport,
  gatherExecutiveReportData,
  generateExecutiveReportHtml,
  renderHtmlToPdf,
}                                     from '../services/reportService';
import { logger }                     from '../config/logger';
import { authenticate }               from '../middleware/authenticate';

const router = Router();
router.use(authenticate);

const VALID_SECTIONS = ['SUMMARY', 'CONFIG_CHANGES', 'DRIFT', 'IAM_ESCALATION', 'POSTURE'];
const VALID_FREQS    = ['DAILY', 'WEEKLY', 'MONTHLY', 'ON_DEMAND'];

// ─── Ad-hoc compile (no saved schedule) ────────────────────────────────────────
// Must be declared before the /:id routes below so Express doesn't treat
// "compile" as an :id path param.

router.get('/compile', async (req: Request, res: Response) => {
  try {
    // AWS-only for now — see the doc comment on gatherExecutiveReportData.
    const targetId = typeof req.query.targetId === 'string' ? req.query.targetId : null;
    const wantsPdf = req.query.format === 'pdf';

    const data = await gatherExecutiveReportData(targetId);
    const html = generateExecutiveReportHtml(data);

    if (wantsPdf) {
      const pdf = await renderHtmlToPdf(html);
      const filename = `${data.title.replace(/[^a-z0-9]+/gi, '-')}-security-report.pdf`;
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(pdf);
      return;
    }

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    logger.error(`[reports] Ad-hoc compile failed: ${(err as Error).message}`);
    res.status(500).json({ error: 'Failed to compile report' });
  }
});

// ─── List schedules ───────────────────────────────────────────────────────────

router.get('/', async (_req: Request, res: Response) => {
  try {
    const schedules = await prisma.reportSchedule.findMany({
      orderBy: { createdAt: 'desc' },
      include: { _count: { select: { runs: true } } },
    });
    res.json(schedules);
  } catch (err) {
    logger.error('[reports] list failed', err);
    res.status(500).json({ error: 'Failed to list report schedules' });
  }
});

// ─── Create schedule ──────────────────────────────────────────────────────────

router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      name, provider, targetId, frequency = 'WEEKLY',
      dayOfWeek, dayOfMonth, hour = 8,
      sections = ['SUMMARY', 'CONFIG_CHANGES', 'POSTURE'],
      recipients = [],
      isActive = true,
    } = req.body as {
      name: string; provider?: string; targetId?: string;
      frequency?: string; dayOfWeek?: number; dayOfMonth?: number; hour?: number;
      sections?: string[]; recipients?: string[]; isActive?: boolean;
    };

    if (!name) return res.status(400).json({ error: 'name is required' });
    if (!VALID_FREQS.includes(frequency)) {
      return res.status(400).json({ error: `frequency must be one of: ${VALID_FREQS.join(', ')}` });
    }
    const invalidSections = sections.filter((s) => !VALID_SECTIONS.includes(s));
    if (invalidSections.length > 0) {
      return res.status(400).json({ error: `Invalid sections: ${invalidSections.join(', ')}` });
    }

    const nextRunAt = frequency !== 'ON_DEMAND'
      ? computeNextRun(frequency, hour, dayOfWeek, dayOfMonth)
      : null;

    const schedule = await prisma.reportSchedule.create({
      data: {
        name, provider, targetId, frequency, dayOfWeek, dayOfMonth, hour,
        sections, recipients, isActive, nextRunAt,
      },
    });

    res.status(201).json(schedule);
  } catch (err) {
    logger.error('[reports] create failed', err);
    res.status(500).json({ error: 'Failed to create report schedule' });
  }
});

// ─── Update schedule ──────────────────────────────────────────────────────────

router.put('/:id', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.reportSchedule.findUnique({ where: { id: req.params.id } });
    if (!existing) return res.status(404).json({ error: 'Not found' });

    const {
      name, provider, targetId, frequency, dayOfWeek, dayOfMonth, hour,
      sections, recipients, isActive,
    } = req.body as Partial<{
      name: string; provider: string; targetId: string;
      frequency: string; dayOfWeek: number; dayOfMonth: number; hour: number;
      sections: string[]; recipients: string[]; isActive: boolean;
    }>;

    const newFreq  = frequency   ?? existing.frequency;
    const newHour  = hour        ?? existing.hour;
    const newDow   = dayOfWeek   ?? existing.dayOfWeek;
    const newDom   = dayOfMonth  ?? existing.dayOfMonth;

    const nextRunAt = newFreq !== 'ON_DEMAND'
      ? computeNextRun(newFreq, newHour, newDow, newDom)
      : null;

    const updated = await prisma.reportSchedule.update({
      where: { id: req.params.id },
      data: {
        ...(name       !== undefined && { name }),
        ...(provider   !== undefined && { provider }),
        ...(targetId   !== undefined && { targetId }),
        ...(frequency  !== undefined && { frequency }),
        ...(dayOfWeek  !== undefined && { dayOfWeek }),
        ...(dayOfMonth !== undefined && { dayOfMonth }),
        ...(hour       !== undefined && { hour }),
        ...(sections   !== undefined && { sections }),
        ...(recipients !== undefined && { recipients }),
        ...(isActive   !== undefined && { isActive }),
        nextRunAt,
      },
    });

    res.json(updated);
  } catch (err) {
    logger.error('[reports] update failed', err);
    res.status(500).json({ error: 'Failed to update report schedule' });
  }
});

// ─── Delete schedule ──────────────────────────────────────────────────────────

router.delete('/:id', async (req: Request, res: Response) => {
  try {
    await prisma.reportSchedule.delete({ where: { id: req.params.id } });
    res.status(204).end();
  } catch (err) {
    logger.error('[reports] delete failed', err);
    res.status(500).json({ error: 'Failed to delete report schedule' });
  }
});

// ─── On-demand run ────────────────────────────────────────────────────────────

router.post('/:id/run', async (req: Request, res: Response) => {
  try {
    // fire-and-forget generation, respond immediately
    const schedule = await prisma.reportSchedule.findUnique({ where: { id: req.params.id } });
    if (!schedule) return res.status(404).json({ error: 'Not found' });

    void generateOnDemandReport(req.params.id).catch((err) => {
      logger.warn(`[reports] On-demand run failed for "${schedule.name}": ${(err as Error).message}`);
    });

    res.json({ message: 'Report generation started' });
  } catch (err) {
    logger.error('[reports] run failed', err);
    res.status(500).json({ error: 'Failed to trigger report' });
  }
});

// ─── Preview / download HTML report ──────────────────────────────────────────

router.get('/:id/preview', async (req: Request, res: Response) => {
  try {
    const html = await generateOnDemandReport(req.params.id);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline');
    res.send(html);
  } catch (err) {
    logger.error('[reports] preview failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Run history ──────────────────────────────────────────────────────────────

router.get('/:id/runs', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(50, parseInt(req.query.limit as string) || 20);
    const runs  = await prisma.reportRun.findMany({
      where:   { scheduleId: req.params.id },
      orderBy: { startedAt: 'desc' },
      take:    limit,
    });
    res.json(runs);
  } catch (err) {
    logger.error('[reports] runs failed', err);
    res.status(500).json({ error: 'Failed to load run history' });
  }
});

export default router;
