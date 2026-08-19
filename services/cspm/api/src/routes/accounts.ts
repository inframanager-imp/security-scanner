import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import * as credentialService from '../services/credentialService';
import AWSClient from '../../../src/aws/client';
import { triggerInitialPipeline } from '../services/inventoryPipeline';

const router = Router();
router.use(authenticate);

const createAccountSchema = z.object({
  name: z.string().min(1).max(255),
  awsAccountId: z.string().regex(/^\d{12}$/, 'AWS Account ID must be 12 digits'),
  description: z.string().optional(),
});

const updateAccountSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().optional(),
});

const credentialSchema = z.object({
  authMethod: z.enum(['ACCESS_KEY', 'ASSUME_ROLE']),
  accessKeyId: z.string().optional(),
  secretAccessKey: z.string().optional(),
  roleArn: z.string().optional(),
  externalId: z.string().optional(),
  defaultRegion: z.string().default('us-east-1'),
  additionalRegions: z.array(z.string()).default([]),
});

const setupAccountSchema = z.object({
  name: z.string().min(1).max(255),
  accessKeyId: z.string().min(16).max(128),
  secretAccessKey: z.string().min(1),
  region: z.string().default('us-east-1'),
});

// POST /api/accounts/setup — Create account + credentials in one step, auto-fetches AWS Account ID
router.post('/setup', async (req: Request, res: Response) => {
  try {
    const { name, accessKeyId, secretAccessKey, region } = setupAccountSchema.parse(req.body);

    // Verify credentials and fetch real AWS Account ID via STS
    let awsAccountId: string;
    try {
      const client = new AWSClient(region, undefined, { accessKeyId, secretAccessKey });
      awsAccountId = await client.getAccountId();
      await client.cleanup();
    } catch (err) {
      res.status(400).json({ error: `Invalid AWS credentials: ${(err as Error).message}` });
      return;
    }

    // Create account + credential atomically
    const encrypted = credentialService.encryptCredentials({ accessKeyId, secretAccessKey });

    const account = await prisma.account.create({
      data: {
        name,
        awsAccountId,
        createdById: req.user!.id,
        credential: {
          create: {
            authMethod: 'ACCESS_KEY',
            encryptedAccessKeyId: encrypted.encryptedAccessKeyId,
            encryptedSecretAccessKey: encrypted.encryptedSecretAccessKey,
            defaultRegion: region,
            additionalRegions: [],
          },
        },
      },
      include: { credential: true },
    });

    res.status(201).json({
      data: {
        id: account.id,
        name: account.name,
        awsAccountId: account.awsAccountId,
        hasCredentials: true,
        createdAt: account.createdAt,
      },
    });

    // Kick off pipeline in background (fire-and-forget)
    triggerInitialPipeline('AWS', account.id);
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// GET /api/accounts
router.get('/', async (req: Request, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip = (page - 1) * limit;

    const [accounts, total] = await Promise.all([
      prisma.account.findMany({
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          credential: { select: { id: true } },
          scans: {
            orderBy: { createdAt: 'desc' },
            take: 1,
            include: { summary: true },
          },
        },
      }),
      prisma.account.count(),
    ]);

    const needFallback = accounts.filter((a) => a.scans[0] && !a.scans[0].summary).map((a) => a.id);
    const fallbackMap = new Map<string, NonNullable<(typeof accounts)[0]['scans'][0]['summary']>>();
    if (needFallback.length > 0) {
      const completed = await prisma.scan.findMany({
        where: { accountId: { in: needFallback }, status: 'COMPLETED', summary: { isNot: null } },
        orderBy: { createdAt: 'desc' },
        include: { summary: true },
        distinct: ['accountId'],
      });
      for (const s of completed) {
        if (s.summary) fallbackMap.set(s.accountId, s.summary);
      }
    }

    const accountsWithSummary = accounts.map((account) => {
      const latestScan = account.scans[0] || null;
      const summary = latestScan?.summary ?? fallbackMap.get(account.id) ?? null;
      return {
        id: account.id,
        name: account.name,
        awsAccountId: account.awsAccountId,
        description: account.description,
        createdAt: account.createdAt,
        updatedAt: account.updatedAt,
        hasCredentials: !!account.credential,
        inventoryStatus:  account.inventoryStatus,
        inventoryInitAt:  account.inventoryInitAt,
        lastDiscoveryAt:  account.lastDiscoveryAt,
        lastConfigSyncAt: account.lastConfigSyncAt,
        pipelineError:    account.pipelineError,
        latestScan: latestScan ? {
          id: latestScan.id,
          status: latestScan.status,
          createdAt: latestScan.createdAt,
          completedAt: latestScan.completedAt,
          startedAt: latestScan.startedAt,
          summary,
        } : null,
      };
    });

    res.json({
      data: accountsWithSummary,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/accounts
router.post('/', async (req: Request, res: Response) => {
  try {
    const body = createAccountSchema.parse(req.body);

    const account = await prisma.account.create({
      data: {
        name: body.name,
        awsAccountId: body.awsAccountId,
        description: body.description,
        createdById: req.user!.id,
      },
    });

    res.status(201).json({ data: account });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/accounts/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const account = await prisma.account.findUnique({
      where: { id: req.params.id },
      include: {
        scans: {
          orderBy: { createdAt: 'desc' },
          take: 10,
          include: { summary: true },
        },
        credential: {
          select: {
            id: true,
            authMethod: true,
            roleArn: true,
            defaultRegion: true,
            additionalRegions: true,
            createdAt: true,
            updatedAt: true,
          },
        },
      },
    });

    if (!account) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }

    const latestScan = account.scans[0] || null;

    let fallbackSummary: typeof latestScan.summary | null = null;
    let lastSuccessfulScanId: string | null = null;

    if (latestScan && !latestScan.summary) {
      const prevCompleted = account.scans.find((s) => s.status === 'COMPLETED' && s.summary);
      if (prevCompleted) {
        fallbackSummary    = prevCompleted.summary;
        lastSuccessfulScanId = prevCompleted.id;
      } else {
        // Not in the top-10 — query directly
        const prev = await prisma.scan.findFirst({
          where: { accountId: req.params.id, status: 'COMPLETED', summary: { isNot: null } },
          orderBy: { createdAt: 'desc' },
          include: { summary: true },
        });
        fallbackSummary    = prev?.summary ?? null;
        lastSuccessfulScanId = prev?.id ?? null;
      }
    } else if (latestScan?.status === 'COMPLETED') {
      // Latest scan succeeded — it IS the last successful scan
      lastSuccessfulScanId = latestScan.id;
    }

    res.json({
      data: {
        id: account.id,
        name: account.name,
        awsAccountId: account.awsAccountId,
        description: account.description,
        createdAt: account.createdAt,
        updatedAt: account.updatedAt,
        hasCredentials: !!account.credential,
        credential: account.credential,
        scans: account.scans,
        lastSuccessfulScanId,
        latestScan: latestScan ? {
          id: latestScan.id,
          status: latestScan.status,
          createdAt: latestScan.createdAt,
          completedAt: latestScan.completedAt,
          startedAt: latestScan.startedAt,
          durationMs: latestScan.durationMs,
          services: latestScan.services,
          regions: latestScan.regions,
          errorMessage: latestScan.errorMessage ?? null,
          summary: latestScan.summary ?? fallbackSummary ?? null,
        } : null,
      },
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/accounts/:id/credentials
router.get('/:id/credentials', async (req: Request, res: Response) => {
  try {
    const cred = await prisma.awsCredential.findUnique({
      where: { accountId: req.params.id },
    });

    if (!cred) {
      res.status(404).json({ error: 'Credentials not found' });
      return;
    }

    res.json({
      data: {
        id: cred.id,
        accountId: cred.accountId,
        authMethod: cred.authMethod,
        roleArn: cred.roleArn,
        externalId: cred.externalId,
        defaultRegion: cred.defaultRegion,
        additionalRegions: cred.additionalRegions,
        createdAt: cred.createdAt,
        updatedAt: cred.updatedAt,
      },
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/accounts/:id
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const body = updateAccountSchema.parse(req.body);

    const existing = await prisma.account.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }

    const account = await prisma.account.update({
      where: { id: req.params.id },
      data: body,
    });

    res.json({ data: account });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/accounts/:id
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.account.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }

    await prisma.account.delete({ where: { id: req.params.id } });

    res.json({ data: { message: 'Account deleted successfully' } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/accounts/:id/credentials
router.post('/:id/credentials', async (req: Request, res: Response) => {
  try {
    const body = credentialSchema.parse(req.body);

    const account = await prisma.account.findUnique({ where: { id: req.params.id } });
    if (!account) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }

    const encrypted = credentialService.encryptCredentials({
      accessKeyId: body.accessKeyId,
      secretAccessKey: body.secretAccessKey,
    });

    const credential = await prisma.awsCredential.upsert({
      where: { accountId: req.params.id },
      create: {
        accountId: req.params.id,
        authMethod: body.authMethod,
        encryptedAccessKeyId: encrypted.encryptedAccessKeyId,
        encryptedSecretAccessKey: encrypted.encryptedSecretAccessKey,
        roleArn: body.roleArn,
        externalId: body.externalId,
        defaultRegion: body.defaultRegion,
        additionalRegions: body.additionalRegions,
      },
      update: {
        authMethod: body.authMethod,
        encryptedAccessKeyId: encrypted.encryptedAccessKeyId,
        encryptedSecretAccessKey: encrypted.encryptedSecretAccessKey,
        roleArn: body.roleArn,
        externalId: body.externalId,
        defaultRegion: body.defaultRegion,
        additionalRegions: body.additionalRegions,
      },
    });

    // Return without raw credentials
    res.json({
      data: {
        id: credential.id,
        accountId: credential.accountId,
        authMethod: credential.authMethod,
        roleArn: credential.roleArn,
        externalId: credential.externalId,
        defaultRegion: credential.defaultRegion,
        additionalRegions: credential.additionalRegions,
        createdAt: credential.createdAt,
        updatedAt: credential.updatedAt,
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

// DELETE /api/accounts/:id/credentials
router.delete('/:id/credentials', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.awsCredential.findUnique({
      where: { accountId: req.params.id },
    });

    if (!existing) {
      res.status(404).json({ error: 'Credentials not found' });
      return;
    }

    await prisma.awsCredential.delete({ where: { accountId: req.params.id } });

    res.json({ data: { message: 'Credentials deleted successfully' } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/accounts/:id/credentials/verify
router.post('/:id/credentials/verify', async (req: Request, res: Response) => {
  try {
    const cred = await prisma.awsCredential.findUnique({
      where: { accountId: req.params.id },
    });

    if (!cred) {
      res.status(404).json({ error: 'Credentials not found' });
      return;
    }

    const decrypted = credentialService.decryptCredentials(cred);

    let client: AWSClient;

    if (cred.authMethod === 'ACCESS_KEY') {
      if (!decrypted.accessKeyId || !decrypted.secretAccessKey) {
        res.json({ data: { valid: false, error: 'Missing access key credentials' } });
        return;
      }
      client = new AWSClient(cred.defaultRegion, undefined, {
        accessKeyId: decrypted.accessKeyId,
        secretAccessKey: decrypted.secretAccessKey,
      });
    } else {
      // ASSUME_ROLE
      if (!decrypted.accessKeyId || !decrypted.secretAccessKey) {
        res.json({ data: { valid: false, error: 'Missing access key credentials for role assumption' } });
        return;
      }
      client = new AWSClient(cred.defaultRegion, undefined, {
        accessKeyId: decrypted.accessKeyId,
        secretAccessKey: decrypted.secretAccessKey,
      });
      if (cred.roleArn) {
        await client.assumeRole(cred.roleArn, 'verify-session');
      }
    }

    const awsAccountId = await client.getAccountId();
    await client.cleanup();

    res.json({ data: { valid: true, awsAccountId } });

    const acct = await prisma.account.findUnique({
      where: { id: req.params.id },
      select: { inventoryStatus: true },
    });
    if (acct && acct.inventoryStatus !== 'READY') {
      triggerInitialPipeline('AWS', req.params.id);
    }
  } catch (err) {
    res.json({ data: { valid: false, error: (err as Error).message } });
  }
});

export default router;
