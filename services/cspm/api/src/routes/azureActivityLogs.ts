import { Router, Request, Response } from 'express';
import { prisma }                    from '../config/database';
import { authenticate }              from '../middleware/authenticate';
import { decryptAzureCredentials }   from '../services/azureCredentialService';
import AzureClient                   from '../../../src/azure/client';

const router = Router();
router.use(authenticate);

/** Map Azure Activity Log event level to a severity string */
function levelToSeverity(level?: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  switch ((level ?? '').toLowerCase()) {
    case 'critical': return 'CRITICAL';
    case 'error':    return 'HIGH';
    case 'warning':  return 'MEDIUM';
    case 'informational':
    default:         return 'INFO';
  }
}

/**
 * GET /api/azure/activity-logs
 *
 * Query params:
 *   subscriptionId  — internal DB id of the AzureSubscription  (required)
 *   startTime       — ISO-8601 (default: 24 h ago)
 *   endTime         — ISO-8601 (default: now)
 *   maxResults      — number (default: 200, max: 1000)
 */
router.get('/', async (req: Request, res: Response) => {
  try {
    const { subscriptionId } = req.query as Record<string, string>;
    if (!subscriptionId) {
      res.status(400).json({ error: 'subscriptionId query parameter is required' });
      return;
    }

    const sub = await prisma.azureSubscription.findUnique({ where: { id: subscriptionId } });
    if (!sub) {
      res.status(404).json({ error: 'Subscription not found' });
      return;
    }

    const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId } });
    if (!cred) {
      res.status(400).json({ error: 'No credentials configured for this subscription' });
      return;
    }

    const endTime   = req.query.endTime   ? new Date(req.query.endTime   as string) : new Date();
    const startTime = req.query.startTime ? new Date(req.query.startTime as string) : new Date(endTime.getTime() - 24 * 60 * 60 * 1000);
    const maxResults = Math.min(parseInt(req.query.maxResults as string) || 200, 1000);

    const decrypted = decryptAzureCredentials(cred);
    const client    = new AzureClient({
      subscriptionId: sub.subscriptionId,
      tenantId:       decrypted.tenantId,
      clientId:       decrypted.clientId,
      clientSecret:   decrypted.clientSecret,
      authMethod:     cred.authMethod as 'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY',
    });

    const monitorClient = client.monitor();

    const filter = [
      `eventTimestamp ge '${startTime.toISOString()}'`,
      `eventTimestamp le '${endTime.toISOString()}'`,
    ].join(' and ');

    const events: {
      id:            string;
      eventTimestamp: string | null;
      operationName:  string | null;
      status:         string | null;
      caller:         string | null;
      level:          string | null;
      severity:       'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
      resourceGroup:  string | null;
      resourceId:     string | null;
      description:    string | null;
      category:       string | null;
    }[] = [];

    for await (const event of monitorClient.activityLogs.list(filter)) {
      if (events.length >= maxResults) break;

      events.push({
        id:             event.eventDataId ?? `${Date.now()}-${events.length}`,
        eventTimestamp: event.eventTimestamp?.toISOString() ?? null,
        operationName:  event.operationName?.value ?? null,
        status:         event.status?.value ?? null,
        caller:         event.caller ?? null,
        level:          event.level ?? null,
        severity:       levelToSeverity(event.level),
        resourceGroup:  event.resourceGroupName ?? null,
        resourceId:     event.resourceId ?? null,
        description:    event.description ?? null,
        category:       event.category?.value ?? null,
      });
    }

    // Summary by severity
    const summary = {
      critical: events.filter(e => e.severity === 'CRITICAL').length,
      high:     events.filter(e => e.severity === 'HIGH').length,
      medium:   events.filter(e => e.severity === 'MEDIUM').length,
      low:      events.filter(e => e.severity === 'LOW').length,
      info:     events.filter(e => e.severity === 'INFO').length,
      total:    events.length,
    };

    res.json({
      data: {
        events,
        summary,
        timeRange: { startTime: startTime.toISOString(), endTime: endTime.toISOString() },
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
