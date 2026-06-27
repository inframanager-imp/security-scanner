/**
 * External Integration Routes (Webhook / ServiceNow / Jira)
 *
 * GET    /api/integrations              — list configs
 * GET    /api/integrations/:id          — get with decrypted fields
 * POST   /api/integrations              — create
 * PUT    /api/integrations/:id          — update
 * DELETE /api/integrations/:id          — delete
 * POST   /api/integrations/:id/test     — send synthetic test event
 * GET    /api/integrations/:id/logs     — delivery log history
 * GET    /api/integrations/logs/recent  — global recent logs
 */

import { Router, Request, Response }            from 'express';
import { prisma }                               from '../config/database';
import { encryptIntegrationConfig, decryptIntegrationConfig } from '../services/integrationService';
import { logger }                               from '../config/logger';

const router = Router();

const VALID_TYPES = ['WEBHOOK', 'SERVICENOW', 'JIRA'];

// ─── List integrations ────────────────────────────────────────────────────────

router.get('/', async (_req: Request, res: Response) => {
  try {
    const configs = await prisma.integrationConfig.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true, name: true, integrationType: true, isActive: true,
        minSeverity: true, providers: true, targetIds: true, onFreezeOnly: true,
        createdAt: true, updatedAt: true,
        _count: { select: { logs: true } },
      },
    });
    res.json(configs);
  } catch (err) {
    logger.error('[integrations] list failed', err);
    res.status(500).json({ error: 'Failed to list integrations' });
  }
});

// ─── Get single integration ───────────────────────────────────────────────────

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const cfg = await prisma.integrationConfig.findUnique({ where: { id: req.params.id } });
    if (!cfg) return res.status(404).json({ error: 'Not found' });

    const decrypted = decryptIntegrationConfig(cfg.encryptedConfig);
    res.json({
      id: cfg.id, name: cfg.name, integrationType: cfg.integrationType,
      isActive: cfg.isActive, minSeverity: cfg.minSeverity,
      providers: cfg.providers, targetIds: cfg.targetIds, onFreezeOnly: cfg.onFreezeOnly,
      config: decrypted,
    });
  } catch (err) {
    logger.error('[integrations] get failed', err);
    res.status(500).json({ error: 'Failed to get integration' });
  }
});

// ─── Create integration ───────────────────────────────────────────────────────

router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      name, integrationType, isActive = true, minSeverity = 'HIGH',
      providers = [], targetIds = [], onFreezeOnly = false, config,
    } = req.body as {
      name: string; integrationType: string; isActive?: boolean; minSeverity?: string;
      providers?: string[]; targetIds?: string[]; onFreezeOnly?: boolean;
      config: Record<string, string>;
    };

    if (!name || !integrationType || !config) {
      return res.status(400).json({ error: 'name, integrationType, and config are required' });
    }
    if (!VALID_TYPES.includes(integrationType)) {
      return res.status(400).json({ error: `integrationType must be: ${VALID_TYPES.join(', ')}` });
    }

    const encryptedConfig = encryptIntegrationConfig(config);
    const created = await prisma.integrationConfig.create({
      data: { name, integrationType, isActive, minSeverity, providers, targetIds, onFreezeOnly, encryptedConfig },
      select: { id: true, name: true, integrationType: true, isActive: true, createdAt: true },
    });

    res.status(201).json(created);
  } catch (err) {
    logger.error('[integrations] create failed', err);
    res.status(500).json({ error: 'Failed to create integration' });
  }
});

// ─── Update integration ───────────────────────────────────────────────────────

router.put('/:id', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.integrationConfig.findUnique({ where: { id: req.params.id } });
    if (!existing) return res.status(404).json({ error: 'Not found' });

    const {
      name, integrationType, isActive, minSeverity, providers, targetIds, onFreezeOnly, config,
    } = req.body as Partial<{
      name: string; integrationType: string; isActive: boolean; minSeverity: string;
      providers: string[]; targetIds: string[]; onFreezeOnly: boolean;
      config: Record<string, string>;
    }>;

    const encryptedConfig = config
      ? encryptIntegrationConfig(config)
      : existing.encryptedConfig;

    const updated = await prisma.integrationConfig.update({
      where: { id: req.params.id },
      data: {
        ...(name            !== undefined && { name }),
        ...(integrationType !== undefined && { integrationType }),
        ...(isActive        !== undefined && { isActive }),
        ...(minSeverity     !== undefined && { minSeverity }),
        ...(providers       !== undefined && { providers }),
        ...(targetIds       !== undefined && { targetIds }),
        ...(onFreezeOnly    !== undefined && { onFreezeOnly }),
        encryptedConfig,
      },
      select: { id: true, name: true, integrationType: true, isActive: true, updatedAt: true },
    });

    res.json(updated);
  } catch (err) {
    logger.error('[integrations] update failed', err);
    res.status(500).json({ error: 'Failed to update integration' });
  }
});

// ─── Delete integration ───────────────────────────────────────────────────────

router.delete('/:id', async (req: Request, res: Response) => {
  try {
    await prisma.integrationConfig.delete({ where: { id: req.params.id } });
    res.status(204).end();
  } catch (err) {
    logger.error('[integrations] delete failed', err);
    res.status(500).json({ error: 'Failed to delete integration' });
  }
});

// ─── Test integration ─────────────────────────────────────────────────────────

router.post('/:id/test', async (req: Request, res: Response) => {
  try {
    const cfg = await prisma.integrationConfig.findUnique({ where: { id: req.params.id } });
    if (!cfg) return res.status(404).json({ error: 'Not found' });

    const { dispatchIntegrations } = await import('../services/integrationService');

    // Synthetic ConfigChange for testing
    const testChange = {
      id:            'test-' + Date.now(),
      provider:      (cfg.providers[0] as string | undefined) ?? 'AWS',
      awsAccountId:  null,
      azureSubId:    null,
      gcpProjectId:  null,
      sourceEventId: 'test-event',
      eventName:     'TestIntegration:Connectivity',
      eventTime:     new Date(),
      category:      'OTHER',
      changeAction:  'MODIFIED',
      severity:      cfg.minSeverity,
      riskScore:     50,
      summary:       `Test notification from Cloud Scanner integration "${cfg.name}"`,
      actor:         'scanner@test',
      actorType:     'SERVICE',
      sourceIp:      '127.0.0.1',
      region:        null,
      resourceType:  'IntegrationConfig',
      resourceId:    cfg.id,
      resourceName:  cfg.name,
      previousValue: null,
      newValue:      null,
      changeStatus:  'OPEN',
      freezeViolation: false,
      acknowledgedBy:  null,
      acknowledgedAt:  null,
      notes:           null,
      createdAt:     new Date(),
      updatedAt:     new Date(),
      alertLogs:     [],
      integrationLogs: [],
      iamEscalations: [],
    } as Parameters<typeof dispatchIntegrations>[0];

    await dispatchIntegrations(testChange);
    res.json({ success: true, message: `Test dispatched via ${cfg.integrationType}` });
  } catch (err) {
    logger.error('[integrations] test failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Delivery logs per integration ───────────────────────────────────────────

router.get('/:id/logs', async (req: Request, res: Response) => {
  try {
    const page     = Math.max(1, parseInt(req.query.page     as string) || 1);
    const pageSize = Math.min(100, parseInt(req.query.pageSize as string) || 20);

    const [total, logs] = await Promise.all([
      prisma.integrationLog.count({ where: { configId: req.params.id } }),
      prisma.integrationLog.findMany({
        where:   { configId: req.params.id },
        orderBy: { sentAt: 'desc' },
        skip:    (page - 1) * pageSize,
        take:    pageSize,
        select: {
          id: true, status: true, externalId: true, errorMessage: true, sentAt: true,
          change: { select: { id: true, severity: true, category: true, eventName: true, provider: true } },
        },
      }),
    ]);

    res.json({ total, page, pageSize, logs });
  } catch (err) {
    logger.error('[integrations] logs failed', err);
    res.status(500).json({ error: 'Failed to load integration logs' });
  }
});

// ─── Global recent logs ───────────────────────────────────────────────────────

router.get('/logs/recent', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(200, parseInt(req.query.limit as string) || 50);
    const logs  = await prisma.integrationLog.findMany({
      orderBy: { sentAt: 'desc' },
      take:    limit,
      select: {
        id: true, status: true, externalId: true, errorMessage: true, sentAt: true,
        config: { select: { id: true, name: true, integrationType: true } },
        change: { select: { id: true, severity: true, provider: true, eventName: true } },
      },
    });
    res.json(logs);
  } catch (err) {
    logger.error('[integrations] recent logs failed', err);
    res.status(500).json({ error: 'Failed to load recent logs' });
  }
});

export default router;
