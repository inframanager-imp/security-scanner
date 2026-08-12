/**
 * Alert Configuration Routes
 *
 * CRUD for AlertConfig (channels, filters, scoping) and AlertLog history.
 * Test endpoint dispatches a synthetic change to verify connectivity.
 */

import { Router, Request, Response } from 'express';
import { AlertChannel } from '@prisma/client';
import { prisma } from '../config/database';
import { encryptAlertConfig, decryptAlertConfig } from '../services/alertService';
import { logger } from '../config/logger';

const router = Router();

// ─── List alert configs ───────────────────────────────────────────────────────

router.get('/', async (_req: Request, res: Response) => {
  try {
    const configs = await prisma.alertConfig.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true, name: true, isActive: true, channel: true,
        minSeverity: true, categories: true, providers: true,
        targetIds: true, onFreezeOnly: true, createdAt: true, updatedAt: true,
        // omit encryptedConfig from list view
      },
    });
    res.json(configs);
  } catch (err) {
    logger.error('[alerts] list failed', err);
    res.status(500).json({ error: 'Failed to list alert configs' });
  }
});

// ─── Get single config (with decrypted fields for editing) ───────────────────

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const cfg = await prisma.alertConfig.findUnique({ where: { id: req.params.id } });
    if (!cfg) return res.status(404).json({ error: 'Not found' });

    const decrypted = decryptAlertConfig(cfg.encryptedConfig as string);
    res.json({
      id: cfg.id, name: cfg.name, isActive: cfg.isActive, channel: cfg.channel,
      minSeverity: cfg.minSeverity, categories: cfg.categories,
      providers: cfg.providers, targetIds: cfg.targetIds, onFreezeOnly: cfg.onFreezeOnly,
      config: decrypted,
    });
  } catch (err) {
    logger.error('[alerts] get failed', err);
    res.status(500).json({ error: 'Failed to get alert config' });
  }
});

// ─── Create alert config ──────────────────────────────────────────────────────

router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      name, isActive = true, channel, minSeverity = 'LOW',
      categories = [], providers = [], targetIds = [], onFreezeOnly = false,
      config,
    } = req.body as {
      name: string; isActive?: boolean; channel: string; minSeverity?: string;
      categories?: string[]; providers?: string[]; targetIds?: string[];
      onFreezeOnly?: boolean; config: Record<string, string>;
    };

    if (!name || !channel || !config) {
      return res.status(400).json({ error: 'name, channel, and config are required' });
    }
    if (!Object.values(AlertChannel).includes(channel as AlertChannel)) {
      return res.status(400).json({ error: `channel must be one of: ${Object.values(AlertChannel).join(', ')}` });
    }

    const encryptedConfig = encryptAlertConfig(config);

    const created = await prisma.alertConfig.create({
      data: {
        name, isActive, channel: channel as AlertChannel, minSeverity, categories,
        providers, targetIds, onFreezeOnly, encryptedConfig,
      },
      select: { id: true, name: true, channel: true, isActive: true, createdAt: true },
    });

    res.status(201).json(created);
  } catch (err) {
    logger.error('[alerts] create failed', err);
    res.status(500).json({ error: 'Failed to create alert config' });
  }
});

// ─── Update alert config ──────────────────────────────────────────────────────

router.put('/:id', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.alertConfig.findUnique({ where: { id: req.params.id } });
    if (!existing) return res.status(404).json({ error: 'Not found' });

    const {
      name, isActive, channel, minSeverity, categories,
      providers, targetIds, onFreezeOnly, config,
    } = req.body as Partial<{
      name: string; isActive: boolean; channel: string; minSeverity: string;
      categories: string[]; providers: string[]; targetIds: string[];
      onFreezeOnly: boolean; config: Record<string, string>;
    }>;

    if (channel !== undefined && !Object.values(AlertChannel).includes(channel as AlertChannel)) {
      return res.status(400).json({ error: `channel must be one of: ${Object.values(AlertChannel).join(', ')}` });
    }

    const encryptedConfig = config
      ? encryptAlertConfig(config)
      : (existing.encryptedConfig as string);

    const updated = await prisma.alertConfig.update({
      where: { id: req.params.id },
      data: {
        ...(name        !== undefined && { name }),
        ...(isActive    !== undefined && { isActive }),
        ...(channel     !== undefined && { channel: channel as AlertChannel }),
        ...(minSeverity !== undefined && { minSeverity }),
        ...(categories  !== undefined && { categories }),
        ...(providers   !== undefined && { providers }),
        ...(targetIds   !== undefined && { targetIds }),
        ...(onFreezeOnly !== undefined && { onFreezeOnly }),
        encryptedConfig,
      },
      select: { id: true, name: true, channel: true, isActive: true, updatedAt: true },
    });

    res.json(updated);
  } catch (err) {
    logger.error('[alerts] update failed', err);
    res.status(500).json({ error: 'Failed to update alert config' });
  }
});

// ─── Delete alert config ──────────────────────────────────────────────────────

router.delete('/:id', async (req: Request, res: Response) => {
  try {
    await prisma.alertConfig.delete({ where: { id: req.params.id } });
    res.status(204).end();
  } catch (err) {
    logger.error('[alerts] delete failed', err);
    res.status(500).json({ error: 'Failed to delete alert config' });
  }
});

// ─── Test alert config (send synthetic notification) ─────────────────────────

router.post('/:id/test', async (req: Request, res: Response) => {
  try {
    const cfg = await prisma.alertConfig.findUnique({ where: { id: req.params.id } });
    if (!cfg) return res.status(404).json({ error: 'Not found' });

    // Build a synthetic ConfigChange record shape for testing
    const syntheticChange = {
      id:           'test-' + Date.now(),
      provider:     (cfg.providers[0] as string | undefined) ?? 'AWS',
      awsAccountId: null,
      azureSubId:   null,
      gcpProjectId: null,
      sourceEventId: 'test-event',
      eventName:    'TestAlert:SendTestNotification',
      eventTime:    new Date(),
      category:     'IDENTITY_ACCESS',
      severity:     cfg.minSeverity,
      riskScore:    75,
      summary:      'This is a test alert from your AWS Scanner alert configuration.',
      actor:        'test@example.com',
      actorType:    'USER',
      sourceIp:     '127.0.0.1',
      resourceType: 'AlertConfig',
      resourceId:   cfg.id,
      resourceName: cfg.name,
      previousValue: null,
      newValue:     null,
      changeStatus: 'OPEN',
      freezeViolation: false,
      createdAt:    new Date(),
      updatedAt:    new Date(),
    };

    const { decryptAlertConfig: dec, buildSlackPayload, buildEmailHtml,
            sendSlack, sendSmtp, sendO365, sendGmail } = await import('../services/alertService');

    const channelCfg = dec(cfg.encryptedConfig as string);
    const subject    = `[TEST] AWS Scanner Alert — ${syntheticChange.severity} — ${syntheticChange.resourceType}`;

    if (cfg.channel === 'SLACK') {
      const payload = buildSlackPayload(syntheticChange as Parameters<typeof buildSlackPayload>[0], false);
      await sendSlack(channelCfg, payload);
    } else if (cfg.channel === 'EMAIL_SMTP') {
      const html = buildEmailHtml(syntheticChange as Parameters<typeof buildEmailHtml>[0], false);
      await sendSmtp(channelCfg, subject, html);
    } else if (cfg.channel === 'EMAIL_O365') {
      const html = buildEmailHtml(syntheticChange as Parameters<typeof buildEmailHtml>[0], false);
      await sendO365(channelCfg, subject, html);
    } else if (cfg.channel === 'EMAIL_GMAIL') {
      const html = buildEmailHtml(syntheticChange as Parameters<typeof buildEmailHtml>[0], false);
      await sendGmail(channelCfg, subject, html);
    }

    res.json({ success: true, message: `Test alert sent via ${cfg.channel}` });
  } catch (err) {
    logger.error('[alerts] test failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Alert log history ────────────────────────────────────────────────────────

router.get('/:id/logs', async (req: Request, res: Response) => {
  try {
    const page     = Math.max(1, parseInt(req.query.page as string)     || 1);
    const pageSize = Math.min(100, parseInt(req.query.pageSize as string) || 20);

    const [total, logs] = await Promise.all([
      prisma.alertLog.count({ where: { configId: req.params.id } }),
      prisma.alertLog.findMany({
        where:   { configId: req.params.id },
        orderBy: { sentAt: 'desc' },
        skip:    (page - 1) * pageSize,
        take:    pageSize,
        select: {
          id: true, status: true, subject: true, errorMessage: true, sentAt: true,
          change: {
            select: {
              id: true, severity: true, category: true, summary: true,
              resourceType: true, resourceName: true, provider: true,
            },
          },
        },
      }),
    ]);

    res.json({ total, page, pageSize, logs });
  } catch (err) {
    logger.error('[alerts] logs failed', err);
    res.status(500).json({ error: 'Failed to load alert logs' });
  }
});

// ─── Global alert log (all configs) ──────────────────────────────────────────

router.get('/logs/recent', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(200, parseInt(req.query.limit as string) || 50);

    const logs = await prisma.alertLog.findMany({
      orderBy: { sentAt: 'desc' },
      take:    limit,
      select: {
        id: true, status: true, subject: true, errorMessage: true, sentAt: true,
        config: { select: { id: true, name: true, channel: true } },
        change: {
          select: {
            id: true, severity: true, category: true, provider: true,
            resourceType: true, resourceName: true,
          },
        },
      },
    });

    res.json(logs);
  } catch (err) {
    logger.error('[alerts] recent logs failed', err);
    res.status(500).json({ error: 'Failed to load recent alert logs' });
  }
});

export default router;
