/**
 * Freeze Window Routes
 *
 * CRUD for FreezeWindow records.
 * Supports both recurring weekly schedules and one-time fixed date ranges.
 */

import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { logger } from '../config/logger';

const router = Router();

// ─── List all freeze windows ──────────────────────────────────────────────────

router.get('/', async (_req: Request, res: Response) => {
  try {
    const windows = await prisma.freezeWindow.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(windows);
  } catch (err) {
    logger.error('[freeze] list failed', err);
    res.status(500).json({ error: 'Failed to list freeze windows' });
  }
});

// ─── Get single freeze window ─────────────────────────────────────────────────

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const win = await prisma.freezeWindow.findUnique({ where: { id: req.params.id } });
    if (!win) return res.status(404).json({ error: 'Not found' });
    res.json(win);
  } catch (err) {
    logger.error('[freeze] get failed', err);
    res.status(500).json({ error: 'Failed to get freeze window' });
  }
});

// ─── Create freeze window ─────────────────────────────────────────────────────

router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      name,
      providers   = [],
      targetIds   = [],
      daysOfWeek  = [],
      startTime   = '00:00',
      endTime     = '23:59',
      timezone    = 'UTC',
      fixedStart,
      fixedEnd,
      isActive    = true,
    } = req.body as {
      name: string;
      providers?:  string[];
      targetIds?:  string[];
      daysOfWeek?: number[];
      startTime?:  string;
      endTime?:    string;
      timezone?:   string;
      fixedStart?: string;
      fixedEnd?:   string;
      isActive?:   boolean;
    };

    if (!name) {
      return res.status(400).json({ error: 'name is required' });
    }

    // Validate time format HH:MM
    const timeRx = /^\d{2}:\d{2}$/;
    if (!fixedStart && (!timeRx.test(startTime) || !timeRx.test(endTime))) {
      return res.status(400).json({ error: 'startTime and endTime must be HH:MM format' });
    }

    const created = await prisma.freezeWindow.create({
      data: {
        name, providers, targetIds, daysOfWeek,
        startTime, endTime, timezone,
        fixedStart: fixedStart ? new Date(fixedStart) : null,
        fixedEnd:   fixedEnd   ? new Date(fixedEnd)   : null,
        isActive,
      },
    });

    res.status(201).json(created);
  } catch (err) {
    logger.error('[freeze] create failed', err);
    res.status(500).json({ error: 'Failed to create freeze window' });
  }
});

// ─── Update freeze window ─────────────────────────────────────────────────────

router.put('/:id', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.freezeWindow.findUnique({ where: { id: req.params.id } });
    if (!existing) return res.status(404).json({ error: 'Not found' });

    const {
      name, providers, targetIds, daysOfWeek,
      startTime, endTime, timezone, fixedStart, fixedEnd, isActive,
    } = req.body as Partial<{
      name: string; providers: string[]; targetIds: string[];
      daysOfWeek: number[]; startTime: string; endTime: string;
      timezone: string; fixedStart: string; fixedEnd: string; isActive: boolean;
    }>;

    const updated = await prisma.freezeWindow.update({
      where: { id: req.params.id },
      data: {
        ...(name       !== undefined && { name }),
        ...(providers  !== undefined && { providers }),
        ...(targetIds  !== undefined && { targetIds }),
        ...(daysOfWeek !== undefined && { daysOfWeek }),
        ...(startTime  !== undefined && { startTime }),
        ...(endTime    !== undefined && { endTime }),
        ...(timezone   !== undefined && { timezone }),
        ...(fixedStart !== undefined && { fixedStart: fixedStart ? new Date(fixedStart) : null }),
        ...(fixedEnd   !== undefined && { fixedEnd:   fixedEnd   ? new Date(fixedEnd)   : null }),
        ...(isActive   !== undefined && { isActive }),
      },
    });

    res.json(updated);
  } catch (err) {
    logger.error('[freeze] update failed', err);
    res.status(500).json({ error: 'Failed to update freeze window' });
  }
});

// ─── Delete freeze window ─────────────────────────────────────────────────────

router.delete('/:id', async (req: Request, res: Response) => {
  try {
    await prisma.freezeWindow.delete({ where: { id: req.params.id } });
    res.status(204).end();
  } catch (err) {
    logger.error('[freeze] delete failed', err);
    res.status(500).json({ error: 'Failed to delete freeze window' });
  }
});

// ─── Toggle active state ──────────────────────────────────────────────────────

router.patch('/:id/toggle', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.freezeWindow.findUnique({ where: { id: req.params.id } });
    if (!existing) return res.status(404).json({ error: 'Not found' });

    const updated = await prisma.freezeWindow.update({
      where: { id: req.params.id },
      data:  { isActive: !existing.isActive },
      select: { id: true, name: true, isActive: true },
    });

    res.json(updated);
  } catch (err) {
    logger.error('[freeze] toggle failed', err);
    res.status(500).json({ error: 'Failed to toggle freeze window' });
  }
});

export default router;
