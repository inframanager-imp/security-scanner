import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { encryptGcpCredentials, decryptGcpCredentials } from '../services/gcpCredentialService';
import GcpClient from '../../../src/gcp/client';
import { gcpScanQueue } from '../workers/gcpScanWorker';
import { GCP_SERVICES } from '../../../src/gcp/engine';
import { triggerInitialPipeline } from '../services/inventoryPipeline';

const router = Router();
router.use(authenticate);

const createProjectSchema = z.object({
  name:        z.string().min(1).max(255),
  projectId:   z.string().min(1),
  description: z.string().optional(),
});

const updateProjectSchema = z.object({
  name:        z.string().min(1).max(255).optional(),
  description: z.string().optional(),
});

const credentialSchema = z.object({
  authMethod:          z.enum(['SERVICE_ACCOUNT_KEY', 'WORKLOAD_IDENTITY']),
  serviceAccountKey:   z.string().optional(),  // full JSON string
  serviceAccountEmail: z.string().optional(),
});

const scanSchema = z.object({
  services: z.array(z.string()).optional(),
});

// GET /api/gcp/projects
router.get('/', async (req: Request, res: Response) => {
  try {
    const page  = parseInt(req.query.page  as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip  = (page - 1) * limit;

    const [projects, total] = await Promise.all([
      prisma.gcpProject.findMany({
        skip,
        take:    limit,
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
      prisma.gcpProject.count(),
    ]);

    // Fallback summary for in-progress/failed scans
    const needFallback = projects.filter(p => p.scans[0] && !p.scans[0].summary).map(p => p.id);
    const fallbackMap  = new Map<string, NonNullable<(typeof projects)[0]['scans'][0]['summary']>>();
    if (needFallback.length > 0) {
      const completed = await prisma.gcpScan.findMany({
        where:    { projectId: { in: needFallback }, status: 'COMPLETED', summary: { isNot: null } },
        orderBy:  { createdAt: 'desc' },
        include:  { summary: true },
        distinct: ['projectId'],
      });
      for (const s of completed) {
        if (s.summary) fallbackMap.set(s.projectId, s.summary);
      }
    }

    const data = projects.map(proj => {
      const latestScan = proj.scans[0] ?? null;
      const summary    = latestScan?.summary ?? fallbackMap.get(proj.id) ?? null;
      return {
        id:               proj.id,
        name:             proj.name,
        projectId:        proj.projectId,
        description:      proj.description,
        createdAt:        proj.createdAt,
        updatedAt:        proj.updatedAt,
        hasCredentials:   !!proj.credential,
        inventoryStatus:  proj.inventoryStatus,
        inventoryInitAt:  proj.inventoryInitAt,
        lastDiscoveryAt:  proj.lastDiscoveryAt,
        lastConfigSyncAt: proj.lastConfigSyncAt,
        pipelineError:    proj.pipelineError,
        latestScan: latestScan ? {
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

// POST /api/gcp/projects
router.post('/', async (req: Request, res: Response) => {
  try {
    const body = createProjectSchema.parse(req.body);

    const proj = await prisma.gcpProject.create({
      data: {
        name:        body.name,
        projectId:   body.projectId,
        description: body.description,
        createdById: req.user!.id,
      },
    });

    res.status(201).json({ data: proj });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/gcp/projects/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const proj = await prisma.gcpProject.findUnique({
      where: { id: req.params.id },
      include: {
        credential: {
          select: {
            id:                  true,
            authMethod:          true,
            serviceAccountEmail: true,
            createdAt:           true,
            updatedAt:           true,
          },
        },
        scans: {
          orderBy: { createdAt: 'desc' },
          take:    10,
          include: { summary: true },
        },
      },
    });

    if (!proj) {
      res.status(404).json({ error: 'GCP project not found' });
      return;
    }

    const latestScan = proj.scans[0] ?? null;

    let fallbackSummary:      typeof latestScan.summary | null = null;
    let lastSuccessfulScanId: string | null = null;

    if (latestScan && !latestScan.summary) {
      const prevCompleted = proj.scans.find(s => s.status === 'COMPLETED' && s.summary);
      if (prevCompleted) {
        fallbackSummary      = prevCompleted.summary;
        lastSuccessfulScanId = prevCompleted.id;
      } else {
        const prev = await prisma.gcpScan.findFirst({
          where:   { projectId: req.params.id, status: 'COMPLETED', summary: { isNot: null } },
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
        id:                  proj.id,
        name:                proj.name,
        projectId:           proj.projectId,
        description:         proj.description,
        createdAt:           proj.createdAt,
        updatedAt:           proj.updatedAt,
        hasCredentials:      !!proj.credential,
        credential:          proj.credential,
        scans:               proj.scans,
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

// PUT /api/gcp/projects/:id
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const body = updateProjectSchema.parse(req.body);

    const existing = await prisma.gcpProject.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'GCP project not found' });
      return;
    }

    const proj = await prisma.gcpProject.update({
      where: { id: req.params.id },
      data:  body,
    });

    res.json({ data: proj });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/gcp/projects/:id
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.gcpProject.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'GCP project not found' });
      return;
    }

    await prisma.gcpProject.delete({ where: { id: req.params.id } });

    res.json({ data: { message: 'GCP project deleted successfully' } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/gcp/projects/:id/credentials
router.post('/:id/credentials', async (req: Request, res: Response) => {
  try {
    const body = credentialSchema.parse(req.body);

    const proj = await prisma.gcpProject.findUnique({ where: { id: req.params.id } });
    if (!proj) {
      res.status(404).json({ error: 'GCP project not found' });
      return;
    }

    const encrypted = encryptGcpCredentials({
      serviceAccountKey:   body.serviceAccountKey,
      serviceAccountEmail: body.serviceAccountEmail,
    });

    const credential = await prisma.gcpCredential.upsert({
      where:  { projectId: req.params.id },
      create: {
        projectId:                req.params.id,
        authMethod:               body.authMethod,
        encryptedServiceAccountKey: encrypted.encryptedServiceAccountKey,
        serviceAccountEmail:      encrypted.serviceAccountEmail,
      },
      update: {
        authMethod:               body.authMethod,
        encryptedServiceAccountKey: encrypted.encryptedServiceAccountKey,
        serviceAccountEmail:      encrypted.serviceAccountEmail,
      },
    });

    res.json({
      data: {
        id:                  credential.id,
        projectId:           credential.projectId,
        authMethod:          credential.authMethod,
        serviceAccountEmail: credential.serviceAccountEmail,
        createdAt:           credential.createdAt,
        updatedAt:           credential.updatedAt,
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

// POST /api/gcp/projects/:id/credentials/verify
router.post('/:id/credentials/verify', async (req: Request, res: Response) => {
  try {
    const proj = await prisma.gcpProject.findUnique({ where: { id: req.params.id } });
    if (!proj) {
      res.status(404).json({ error: 'GCP project not found' });
      return;
    }

    const cred = await prisma.gcpCredential.findUnique({ where: { projectId: req.params.id } });
    if (!cred) {
      res.status(404).json({ error: 'Credentials not found' });
      return;
    }

    const decrypted = decryptGcpCredentials(cred);

    let credentials: Record<string, unknown> | undefined;
    if (decrypted.serviceAccountKey) {
      try {
        credentials = JSON.parse(decrypted.serviceAccountKey);
      } catch {
        res.json({ data: { valid: false, error: 'Invalid service account key JSON' } });
        return;
      }
    }

    const client = new GcpClient({
      projectId:   proj.projectId,
      credentials,
    });

    const result = await client.verifyCredentials();
    res.json({ data: result });

    if (result.valid) {
      const proj = await prisma.gcpProject.findUnique({
        where: { id: req.params.id },
        select: { inventoryStatus: true },
      });
      if (proj && proj.inventoryStatus !== 'READY') {
        triggerInitialPipeline('GCP', req.params.id);
      }
    }
  } catch (err) {
    res.json({ data: { valid: false, error: (err as Error).message } });
  }
});

// POST /api/gcp/projects/:id/scan
router.post('/:id/scan', async (req: Request, res: Response) => {
  try {
    const body = scanSchema.parse(req.body);

    const proj = await prisma.gcpProject.findUnique({ where: { id: req.params.id } });
    if (!proj) {
      res.status(404).json({ error: 'GCP project not found' });
      return;
    }

    const cred = await prisma.gcpCredential.findUnique({ where: { projectId: req.params.id } });
    if (!cred) {
      res.status(400).json({ error: 'No credentials configured for this project' });
      return;
    }

    const services = body.services ?? GCP_SERVICES;

    const scan = await prisma.gcpScan.create({
      data: {
        projectId: req.params.id,
        status:    'QUEUED',
        services,
      },
    });

    const job = await gcpScanQueue.add('gcp-scan', {
      scanId:    scan.id,
      projectId: req.params.id,
      services,
    });

    await prisma.gcpScan.update({
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

export default router;
