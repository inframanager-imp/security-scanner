/**
 * Config Sync Webhook (BCDD-F09 — event-driven detection)
 *
 * POST /api/config-sync/webhook/:provider/:targetId
 *
 * Deliberately NOT behind the app's user `authenticate` middleware — the
 * caller here is a cloud provider's event system (AWS EventBridge, Azure
 * Event Grid, GCP Pub/Sub push), not a logged-in user, so it can't carry a
 * user JWT. Protected instead by a shared secret configured out-of-band.
 *
 * Wiring this up cloud-side (do this yourself — see the security note below):
 *   AWS:   An EventBridge rule matching CloudTrail config-change events,
 *          targeting an API Destination that POSTs here with the secret header.
 *   Azure: An Event Grid subscription on the subscription's Activity Log,
 *          with a webhook endpoint set to this URL + the secret header.
 *   GCP:   A Pub/Sub push subscription on the Audit Log sink's topic,
 *          pointed at this URL (push subscriptions carry auth via OIDC token
 *          or you can put the secret in the endpoint URL's query string).
 *
 * This app has no public ingress by default (local docker-compose) — you
 * must put it behind a reachable HTTPS endpoint yourself (reverse proxy /
 * tunnel / load balancer) before any of the above can reach it. Until then,
 * the existing 30s poll (configSyncMonitorService.ts) is what actually
 * detects drift — this webhook only shortens that wait when wired up.
 */

import { Router, Request, Response } from 'express';
import { logger } from '../config/logger';
import { triggerImmediateSync } from '../services/configSyncMonitorService';

const router = Router();

const VALID_PROVIDERS = ['AWS', 'AZURE', 'GCP'];

router.post('/:provider/:targetId', async (req: Request, res: Response) => {
  const secret = process.env.CONFIG_SYNC_WEBHOOK_SECRET;
  if (!secret) {
    return res.status(503).json({ error: 'Webhook not configured (CONFIG_SYNC_WEBHOOK_SECRET unset)' });
  }
  if (req.headers['x-webhook-secret'] !== secret) {
    return res.status(401).json({ error: 'Invalid or missing X-Webhook-Secret header' });
  }

  const provider = (req.params.provider || '').toUpperCase();
  const { targetId } = req.params;
  if (!VALID_PROVIDERS.includes(provider) || !targetId) {
    return res.status(400).json({ error: `provider must be one of ${VALID_PROVIDERS.join(' | ')}, targetId is required` });
  }

  try {
    await triggerImmediateSync(provider, targetId);
    res.status(202).json({ triggered: true, provider, targetId });
  } catch (err) {
    logger.error(`[config-sync-webhook] Trigger failed for ${provider}:${targetId}: ${(err as Error).message}`);
    res.status(500).json({ error: 'Failed to trigger sync' });
  }
});

export default router;
