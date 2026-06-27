import { Router, Request, Response } from 'express';
import { authenticate } from '../middleware/authenticate';
import { prisma } from '../config/database';
import {
  startMonitoring,
  stopMonitoring,
  isMonitoring,
  getLastCheck,
} from '../services/threatMonitorService';

const router = Router();
router.use(authenticate);

/**
 * POST /api/threats/monitor/:accountId/start
 * Enable real-time threat monitoring for an account.
 */
router.post('/monitor/:accountId/start', async (req: Request, res: Response) => {
  const { accountId } = req.params;

  // Verify account exists
  const account = await prisma.account.findUnique({ where: { id: accountId }, select: { id: true, name: true } });
  if (!account) {
    res.status(404).json({ error: 'Account not found' });
    return;
  }

  // Verify credentials exist
  const cred = await prisma.awsCredential.findUnique({ where: { accountId }, select: { id: true } });
  if (!cred) {
    res.status(422).json({ error: 'No AWS credentials configured for this account' });
    return;
  }

  await startMonitoring(accountId);
  res.json({ data: { accountId, monitoring: true, message: `Real-time threat monitoring started for ${account.name}` } });
});

/**
 * POST /api/threats/monitor/:accountId/stop
 * Disable real-time threat monitoring for an account.
 */
router.post('/monitor/:accountId/stop', async (req: Request, res: Response) => {
  const { accountId } = req.params;

  const account = await prisma.account.findUnique({ where: { id: accountId }, select: { id: true, name: true } });
  if (!account) {
    res.status(404).json({ error: 'Account not found' });
    return;
  }

  await stopMonitoring(accountId);
  res.json({ data: { accountId, monitoring: false, message: `Real-time threat monitoring stopped for ${account.name}` } });
});

/**
 * GET /api/threats/monitor/:accountId/status
 * Get monitoring status and last check time for an account.
 */
router.get('/monitor/:accountId/status', async (req: Request, res: Response) => {
  const { accountId } = req.params;

  const [active, lastCheck] = await Promise.all([
    isMonitoring(accountId),
    getLastCheck(accountId).catch(() => null),
  ]);

  res.json({
    data: {
      accountId,
      monitoring: active,
      lastCheck: lastCheck?.toISOString() ?? null,
    },
  });
});

/**
 * GET /api/threats/monitor/all
 * Get monitoring status for all accounts the user has access to.
 */
router.get('/monitor/all', async (req: Request, res: Response) => {
  const accounts = await prisma.account.findMany({ select: { id: true, name: true, awsAccountId: true } });

  const statuses = await Promise.all(
    accounts.map(async (acc) => {
      const [active, lastCheck] = await Promise.all([
        isMonitoring(acc.id),
        getLastCheck(acc.id).catch(() => null),
      ]);
      return {
        accountId:    acc.id,
        name:         acc.name,
        awsAccountId: acc.awsAccountId,
        monitoring:   active,
        lastCheck:    lastCheck?.toISOString() ?? null,
      };
    }),
  );

  res.json({ data: statuses });
});

export default router;
