import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { encryptAzureCredentials, decryptAzureCredentials } from '../services/azureCredentialService';
import AzureClient from '../../../src/azure/client';
import { azureScanQueue } from '../workers/azureScanWorker';
import { AZURE_SERVICES } from '../../../src/azure/engine';
import { triggerInitialPipeline } from '../services/inventoryPipeline';

const router = Router();
router.use(authenticate);

const createSubscriptionSchema = z.object({
  name:           z.string().min(1).max(255),
  subscriptionId: z.string().min(1),
  tenantId:       z.string().optional(),
  description:    z.string().optional(),
});

const updateSubscriptionSchema = z.object({
  name:        z.string().min(1).max(255).optional(),
  description: z.string().optional(),
});

const credentialSchema = z.object({
  authMethod:   z.enum(['SERVICE_PRINCIPAL', 'MANAGED_IDENTITY']),
  tenantId:     z.string().optional(),
  clientId:     z.string().optional(),
  clientSecret: z.string().optional(),
});

const scanSchema = z.object({
  services: z.array(z.string()).optional(),
});

// GET /api/azure/subscriptions
router.get('/', async (req: Request, res: Response) => {
  try {
    const page  = parseInt(req.query.page  as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip  = (page - 1) * limit;

    const [subscriptions, total] = await Promise.all([
      prisma.azureSubscription.findMany({
        skip,
        take: limit,
        orderBy: { name: 'asc' },
        include: {
          credential: { select: { id: true, authMethod: true } },
          scans: {
            orderBy: { createdAt: 'desc' },
            take: 1,
            include: { summary: true },
          },
        },
      }),
      prisma.azureSubscription.count(),
    ]);

    // Fallback summary for in-progress/failed scans
    const needFallback = subscriptions.filter(s => s.scans[0] && !s.scans[0].summary).map(s => s.id);
    const fallbackMap  = new Map<string, NonNullable<(typeof subscriptions)[0]['scans'][0]['summary']>>();
    if (needFallback.length > 0) {
      const completed = await prisma.azureScan.findMany({
        where:    { subscriptionId: { in: needFallback }, status: 'COMPLETED', summary: { isNot: null } },
        orderBy:  { createdAt: 'desc' },
        include:  { summary: true },
        distinct: ['subscriptionId'],
      });
      for (const s of completed) {
        if (s.summary) fallbackMap.set(s.subscriptionId, s.summary);
      }
    }

    const data = subscriptions.map(sub => {
      const latestScan = sub.scans[0] ?? null;
      const summary    = latestScan?.summary ?? fallbackMap.get(sub.id) ?? null;
      return {
        id:               sub.id,
        name:             sub.name,
        subscriptionId:   sub.subscriptionId,
        tenantId:         sub.tenantId,
        description:      sub.description,
        createdAt:        sub.createdAt,
        updatedAt:        sub.updatedAt,
        hasCredentials:   !!sub.credential,
        inventoryStatus:  sub.inventoryStatus,
        inventoryInitAt:  sub.inventoryInitAt,
        lastDiscoveryAt:  sub.lastDiscoveryAt,
        lastConfigSyncAt: sub.lastConfigSyncAt,
        pipelineError:    sub.pipelineError,
        latestScan:       latestScan ? {
          id:          latestScan.id,
          status:      latestScan.status,
          createdAt:   latestScan.createdAt,
          completedAt: latestScan.completedAt,
          startedAt:   latestScan.startedAt,
          summary,
        } : null,
      };
    });

    res.json({ data, meta: { total, page, limit, totalPages: Math.ceil(total / limit) } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/azure/subscriptions
router.post('/', async (req: Request, res: Response) => {
  try {
    const body = createSubscriptionSchema.parse(req.body);

    const sub = await prisma.azureSubscription.create({
      data: {
        name:           body.name,
        subscriptionId: body.subscriptionId,
        tenantId:       body.tenantId,
        description:    body.description,
        createdById:    req.user!.id,
      },
    });

    res.status(201).json({ data: sub });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/azure/subscriptions/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const sub = await prisma.azureSubscription.findUnique({
      where: { id: req.params.id },
      include: {
        credential: {
          select: {
            id:         true,
            authMethod: true,
            createdAt:  true,
            updatedAt:  true,
          },
        },
        scans: {
          orderBy: { createdAt: 'desc' },
          take:    10,
          include: { summary: true },
        },
      },
    });

    if (!sub) {
      res.status(404).json({ error: 'Subscription not found' });
      return;
    }

    const latestScan = sub.scans[0] ?? null;

    let fallbackSummary:      typeof latestScan.summary | null = null;
    let lastSuccessfulScanId: string | null = null;

    if (latestScan && !latestScan.summary) {
      const prevCompleted = sub.scans.find(s => s.status === 'COMPLETED' && s.summary);
      if (prevCompleted) {
        fallbackSummary      = prevCompleted.summary;
        lastSuccessfulScanId = prevCompleted.id;
      } else {
        const prev = await prisma.azureScan.findFirst({
          where:   { subscriptionId: req.params.id, status: 'COMPLETED', summary: { isNot: null } },
          orderBy: { createdAt: 'desc' },
          include: { summary: true },
        });
        fallbackSummary      = prev?.summary ?? null;
        lastSuccessfulScanId = prev?.id ?? null;
      }
    } else if (latestScan?.status === 'COMPLETED') {
      lastSuccessfulScanId = latestScan.id;
    }

    res.json({
      data: {
        id:                  sub.id,
        name:                sub.name,
        subscriptionId:      sub.subscriptionId,
        tenantId:            sub.tenantId,
        description:         sub.description,
        createdAt:           sub.createdAt,
        updatedAt:           sub.updatedAt,
        hasCredentials:      !!sub.credential,
        credential:          sub.credential,
        scans:               sub.scans,
        lastSuccessfulScanId,
        latestScan: latestScan ? {
          id:           latestScan.id,
          status:       latestScan.status,
          createdAt:    latestScan.createdAt,
          completedAt:  latestScan.completedAt,
          startedAt:    latestScan.startedAt,
          durationMs:   latestScan.durationMs,
          services:     latestScan.services,
          errorMessage: latestScan.errorMessage ?? null,
          summary:      latestScan.summary ?? fallbackSummary ?? null,
        } : null,
      },
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/azure/subscriptions/:id
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const body = updateSubscriptionSchema.parse(req.body);

    const existing = await prisma.azureSubscription.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'Subscription not found' });
      return;
    }

    const sub = await prisma.azureSubscription.update({
      where: { id: req.params.id },
      data:  body,
    });

    res.json({ data: sub });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/azure/subscriptions/:id
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.azureSubscription.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'Subscription not found' });
      return;
    }

    await prisma.azureSubscription.delete({ where: { id: req.params.id } });

    res.json({ data: { message: 'Subscription deleted successfully' } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/azure/subscriptions/:id/credentials
router.post('/:id/credentials', async (req: Request, res: Response) => {
  try {
    const body = credentialSchema.parse(req.body);

    const sub = await prisma.azureSubscription.findUnique({ where: { id: req.params.id } });
    if (!sub) {
      res.status(404).json({ error: 'Subscription not found' });
      return;
    }

    const encrypted = encryptAzureCredentials({
      tenantId:     body.tenantId,
      clientId:     body.clientId,
      clientSecret: body.clientSecret,
    });

    const credential = await prisma.azureCredential.upsert({
      where:  { subscriptionId: req.params.id },
      create: {
        subscriptionId:          req.params.id,
        authMethod:              body.authMethod,
        encryptedTenantId:       encrypted.encryptedTenantId,
        encryptedClientId:       encrypted.encryptedClientId,
        encryptedClientSecret:   encrypted.encryptedClientSecret,
      },
      update: {
        authMethod:              body.authMethod,
        encryptedTenantId:       encrypted.encryptedTenantId,
        encryptedClientId:       encrypted.encryptedClientId,
        encryptedClientSecret:   encrypted.encryptedClientSecret,
      },
    });

    res.json({
      data: {
        id:             credential.id,
        subscriptionId: credential.subscriptionId,
        authMethod:     credential.authMethod,
        createdAt:      credential.createdAt,
        updatedAt:      credential.updatedAt,
      },
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/azure/subscriptions/:id/credentials/verify
router.post('/:id/credentials/verify', async (req: Request, res: Response) => {
  try {
    const sub = await prisma.azureSubscription.findUnique({ where: { id: req.params.id } });
    if (!sub) { res.status(404).json({ error: 'Subscription not found' }); return; }

    const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId: req.params.id } });
    if (!cred) { res.status(404).json({ error: 'Credentials not found' }); return; }

    const decrypted = decryptAzureCredentials(cred);

    if (cred.authMethod === 'MANAGED_IDENTITY') {
      res.json({ data: { valid: true } });
      return;
    }

    if (!decrypted.tenantId || !decrypted.clientId || !decrypted.clientSecret) {
      res.json({ data: { valid: false, error: 'Missing tenantId, clientId or clientSecret' } });
      return;
    }

    // Use native https to bypass undici/MSAL which has known WSL network issues
    const result = await new Promise<{ valid: boolean; error?: string }>((resolve) => {
      const https = require('https') as typeof import('https');
      const qs = require('querystring') as typeof import('querystring');
      const body = qs.stringify({
        grant_type:    'client_credentials',
        client_id:     decrypted.clientId!,
        client_secret: decrypted.clientSecret!,
        scope:         'https://management.azure.com/.default',
      });
      const req2 = https.request({
        hostname: 'login.microsoftonline.com',
        path:     `/${decrypted.tenantId}/oauth2/v2.0/token`,
        method:   'POST',
        headers:  { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
      }, (r) => {
        let data = '';
        r.on('data', (c: Buffer) => { data += c; });
        r.on('end', () => {
          try {
            const json = JSON.parse(data) as Record<string, unknown>;
            if (json.access_token) {
              resolve({ valid: true });
            } else {
              resolve({ valid: false, error: String(json.error_description ?? json.error ?? 'Unknown error') });
            }
          } catch {
            resolve({ valid: false, error: 'Invalid response from Azure AD' });
          }
        });
      });
      req2.on('error', (e: Error) => resolve({ valid: false, error: e.message }));
      req2.setTimeout(15000, () => { req2.destroy(); resolve({ valid: false, error: 'Request timed out after 15s' }); });
      req2.write(body);
      req2.end();
    });

    res.json({ data: result });

    if (result.valid) {
      const sub = await prisma.azureSubscription.findUnique({
        where: { id: req.params.id },
        select: { inventoryStatus: true },
      });
      if (sub && sub.inventoryStatus !== 'READY') {
        triggerInitialPipeline('AZURE', req.params.id);
      }
    }
  } catch (err) {
    res.json({ data: { valid: false, error: (err as Error).message } });
  }
});

// POST /api/azure/subscriptions/:id/scan
router.post('/:id/scan', async (req: Request, res: Response) => {
  try {
    const body = scanSchema.parse(req.body);

    const sub = await prisma.azureSubscription.findUnique({ where: { id: req.params.id } });
    if (!sub) {
      res.status(404).json({ error: 'Subscription not found' });
      return;
    }

    const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId: req.params.id } });
    if (!cred) {
      res.status(400).json({ error: 'No credentials configured for this subscription' });
      return;
    }

    const services = body.services ?? AZURE_SERVICES;

    const scan = await prisma.azureScan.create({
      data: {
        subscriptionId: req.params.id,
        status:         'QUEUED',
        services,
      },
    });

    const job = await azureScanQueue.add('azure-scan', {
      scanId:         scan.id,
      subscriptionId: req.params.id,
      services,
    });

    await prisma.azureScan.update({
      where: { id: scan.id },
      data:  { jobId: job.id },
    });

    res.status(202).json({
      data: {
        scanId:  scan.id,
        jobId:   job.id,
        status:  'QUEUED',
        services,
      },
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/azure/subscriptions/:id/services — distinct service names for filter dropdown
router.get('/:id/services', async (req: Request, res: Response) => {
  try {
    const rows = await prisma.azureFinding.findMany({
      where:    { scan: { subscriptionId: req.params.id } },
      select:   { service: true },
      distinct: ['service'],
      orderBy:  { service: 'asc' },
    });
    res.json({ data: rows.map((r) => r.service) });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/azure/subscriptions/:id/findings
// Returns all findings across all scans for a subscription (deduped by worker, so no double-count)
router.get('/:id/findings', async (req: Request, res: Response) => {
  try {
    const page     = parseInt(req.query.page     as string) || 1;
    const limit    = parseInt(req.query.pageSize as string) || parseInt(req.query.limit as string) || 20;
    const skip     = (page - 1) * limit;

    const where: Record<string, unknown> = { scan: { subscriptionId: req.params.id } };
    if (req.query.severity) where.severity      = req.query.severity;
    if (req.query.services) {
      const svcs = Array.isArray(req.query.services) ? req.query.services : (req.query.services as string).split(',');
      where.service = { in: svcs };
    } else if (req.query.service) {
      where.service = { contains: req.query.service as string, mode: 'insensitive' };
    }
    if (req.query.status)   where.findingStatus = req.query.status;
    if (req.query.search) {
      const s = req.query.search as string;
      where.OR = [
        { title:       { contains: s, mode: 'insensitive' } },
        { description: { contains: s, mode: 'insensitive' } },
        { resourceId:  { contains: s, mode: 'insensitive' } },
        { resourceGroup: { contains: s, mode: 'insensitive' } },
      ];
    }

    const [findings, total] = await Promise.all([
      prisma.azureFinding.findMany({
        where,
        skip,
        take:    limit,
        orderBy: [{ severity: 'asc' }, { discoveredAt: 'desc' }],
      }),
      prisma.azureFinding.count({ where }),
    ]);

    res.json({ data: findings, meta: { total, page, limit, totalPages: Math.ceil(total / limit) } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
