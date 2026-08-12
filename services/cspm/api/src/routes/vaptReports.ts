/**
 * VAPT-style security report — one professional HTML document per
 * account/subscription/project, combining the executive summary, the
 * Compliance tab's Framework Score Overview, and the full open findings
 * list. See services/vaptReportService.ts + vaptReportTemplate.ts.
 *
 * GET /api/reports/vapt?provider=AWS|AZURE|GCP&targetId=<uuid>
 *     &tags=a,b&region=us-east-1,eu-west-1&resourceGroup=rg-prod
 *   tags          — all providers, OR-match (finding has ANY of these tags)
 *   region        — AWS only, best-effort (see vaptReportService.ts)
 *   resourceGroup — Azure only
 *
 * GET /api/reports/vapt/filters?provider=AWS|AZURE|GCP&targetId=<uuid>
 *   Returns the real distinct tag/region/resource-group values available for
 *   this target, so the filter UI only ever offers values that exist.
 */

import { Router, Request, Response } from 'express';
import { authenticate } from '../middleware/authenticate';
import { buildVaptReportModel, getVaptFilterOptions, type ReportProvider, type VaptReportFilters } from '../services/vaptReportService';
import { generateVaptReportHtml } from '../services/vaptReportTemplate';
import { logger } from '../config/logger';

const router = Router();
router.use(authenticate);

const VALID_PROVIDERS: ReportProvider[] = ['AWS', 'AZURE', 'GCP'];

function parseProvider(req: Request, res: Response): ReportProvider | null {
  const provider = req.query.provider as string;
  if (!provider || !VALID_PROVIDERS.includes(provider as ReportProvider)) {
    res.status(400).json({ error: 'provider must be one of AWS, AZURE, GCP' });
    return null;
  }
  return provider as ReportProvider;
}

function parseCsv(value: unknown): string[] | undefined {
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  const list = value.split(',').map(s => s.trim()).filter(Boolean);
  return list.length > 0 ? list : undefined;
}

router.get('/vapt', async (req: Request, res: Response) => {
  try {
    const provider = parseProvider(req, res);
    if (!provider) return;

    const targetId = req.query.targetId as string;
    if (!targetId) {
      res.status(400).json({ error: 'targetId is required' });
      return;
    }

    const filters: VaptReportFilters = {
      tags:          parseCsv(req.query.tags),
      region:        parseCsv(req.query.region),
      resourceGroup: parseCsv(req.query.resourceGroup),
    };

    const model = await buildVaptReportModel(provider, targetId, filters);
    const html = generateVaptReportHtml(model);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline');
    res.send(html);
  } catch (err) {
    logger.error('[vapt-report] generation failed', err);
    const message = (err as Error).message;
    const notFound = /not found/i.test(message);
    res.status(notFound ? 404 : 500).json({ error: message });
  }
});

router.get('/vapt/filters', async (req: Request, res: Response) => {
  try {
    const provider = parseProvider(req, res);
    if (!provider) return;

    const targetId = req.query.targetId as string;
    if (!targetId) {
      res.status(400).json({ error: 'targetId is required' });
      return;
    }

    const options = await getVaptFilterOptions(provider, targetId);
    res.json({ data: options });
  } catch (err) {
    const message = (err as Error).message;
    const notFound = /not found/i.test(message);
    res.status(notFound ? 404 : 500).json({ error: message });
  }
});

export default router;
