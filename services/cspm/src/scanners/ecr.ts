// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
/**
 * ECR Container Image Scanner
 *
 * Independently scans Amazon ECR images WITHOUT relying on AWS Inspector
 * or ECR's built-in scanning. Workflow:
 *
 *  1. Obtain ECR registry auth token via GetAuthorizationToken
 *  2. For each repository → recent images → Docker Registry API v2 manifest
 *  3. Download image layers (skip layers > MAX_LAYER_COMPRESSED)
 *  4. Decompress (gzip) + parse tar to extract package manifests:
 *       - var/lib/dpkg/status   → Debian / Ubuntu OS packages
 *       - lib/apk/db/installed  → Alpine OS packages
 *       - etc/os-release        → distro detection
 *       - package.json / package-lock.json → Node.js (npm)
 *       - requirements.txt / Pipfile.lock / poetry.lock → Python (PyPI)
 *       - Gemfile.lock          → Ruby (RubyGems)
 *       - go.sum                → Go modules
 *  5. Query OSV batch API (https://api.osv.dev/v1/querybatch) for CVEs
 *  6. Emit one finding per CVE (CRITICAL/HIGH) + summary for MEDIUM/LOW
 */

import {
  GetAuthorizationTokenCommand,
  DescribeRepositoriesCommand,
  DescribeImagesCommand,
  GetRegistryScanningConfigurationCommand,
  GetLifecyclePolicyCommand,
  GetRepositoryPolicyCommand,
  type Repository,
  type ImageDetail,
} from '@aws-sdk/client-ecr';
import { gunzipSync } from 'zlib';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// ─── Limits ──────────────────────────────────────────────────────────────────

const MAX_IMAGES_PER_REPO   = 3;
const MAX_LAYER_COMPRESSED  = 80  * 1024 * 1024; // 80 MB — skip larger layers
const FILE_SIZE_LIMIT       = 5   * 1024 * 1024; // 5 MB per extracted file
const MAX_PKGS_PER_IMAGE    = 300;               // cap to keep OSV calls reasonable
const OSV_BATCH_SIZE        = 40;                // OSV querybatch limit
const OSV_DELAY_MS          = 200;               // ms between OSV batch calls
const MAX_CVE_PER_SEVERITY  = 15;               // max individual findings per sev/image

// ─── Files to extract from image layers ──────────────────────────────────────

const EXACT_TARGETS = new Set([
  'var/lib/dpkg/status',     // Debian / Ubuntu
  'lib/apk/db/installed',    // Alpine
  'etc/os-release',          // distro identification
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'requirements.txt',
  'Pipfile.lock',
  'poetry.lock',
  'Gemfile.lock',
  'go.sum',
  'go.mod',
]);

// Match these basenames under any app directory (e.g. /app/, /srv/, /code/)
const BASENAME_TARGETS = new Set([
  'package.json', 'package-lock.json',
  'requirements.txt', 'Pipfile.lock', 'poetry.lock',
  'Gemfile.lock', 'go.sum',
]);

function isTarget(rawPath: string): boolean {
  const p = rawPath.replace(/^\.\//, '').replace(/^\//, '');
  if (EXACT_TARGETS.has(p)) return true;
  const base = p.split('/').pop() ?? '';
  if (BASENAME_TARGETS.has(base)) {
    // Only accept one level deep from root OR under common app directories
    const depth = p.split('/').length;
    if (depth <= 2) return true;
    const firstDir = p.split('/')[0];
    if (['app', 'srv', 'code', 'src', 'opt', 'home', 'usr'].includes(firstDir)) return true;
  }
  return false;
}

// ─── Minimal tar parser ───────────────────────────────────────────────────────

function parseTar(buf: Buffer): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  let offset = 0;
  let pendingLongName: string | null = null;

  while (offset + 512 <= buf.length) {
    const hdr = buf.subarray(offset, offset + 512);
    // End-of-archive: two zero blocks
    if (hdr.every(b => b === 0)) break;

    // Size (octal, bytes 124–135)
    const sizeOct = hdr.subarray(124, 136).toString().replace(/[\0 ]/g, '');
    const size    = sizeOct ? parseInt(sizeOct, 8) : 0;
    const blocks  = Math.ceil(size / 512);

    // Type flag (byte 156)
    const type = String.fromCharCode(hdr[156]) || '0';

    // Name (bytes 0–99)
    const nameRaw = hdr.subarray(0, 100);
    const nameEnd = nameRaw.indexOf(0);
    let name = nameRaw.subarray(0, nameEnd < 0 ? 100 : nameEnd).toString('utf8');

    // UStar prefix (bytes 345–499)
    const magic = hdr.subarray(257, 262).toString();
    if (magic.startsWith('ustar')) {
      const pfxRaw = hdr.subarray(345, 500);
      const pfxEnd = pfxRaw.indexOf(0);
      const pfx = pfxRaw.subarray(0, pfxEnd < 0 ? 155 : pfxEnd).toString('utf8');
      if (pfx) name = pfx + '/' + name;
    }

    // Apply GNU long name
    if (pendingLongName !== null) {
      name = pendingLongName;
      pendingLongName = null;
    }

    offset += 512; // past header

    if (type === 'L' || type === 'K') {
      // GNU long filename
      pendingLongName = buf.subarray(offset, offset + size).toString('utf8').replace(/\0/g, '');
    } else if (type === '0' || type === '' || type === '\0') {
      const clean = name.replace(/^\.\//, '').replace(/^\//, '');
      if (size > 0 && size <= FILE_SIZE_LIMIT && isTarget(clean)) {
        files.set(clean, buf.subarray(offset, offset + size));
      }
    }

    offset += blocks * 512;
  }

  return files;
}

// ─── Package parsers ──────────────────────────────────────────────────────────

interface Pkg { name: string; version: string; ecosystem: string }

/** Debian/Ubuntu: var/lib/dpkg/status */
function parseDebianStatus(content: string): Pkg[] {
  const pkgs: Pkg[] = [];
  for (const entry of content.split(/\n\n+/)) {
    const nameM    = entry.match(/^Package:\s*(.+)$/m);
    const versionM = entry.match(/^Version:\s*(.+)$/m);
    const statusM  = entry.match(/^Status:\s*(.+)$/m);
    if (!nameM || !versionM) continue;
    const status = statusM?.[1] ?? '';
    if (status.includes('deinstall') || status.includes('purge')) continue;
    // Strip epoch (e.g. "1:2.3.4-5" → "2.3.4-5")
    const version = versionM[1].trim().replace(/^\d+:/, '');
    pkgs.push({ name: nameM[1].trim(), version, ecosystem: 'Debian' });
  }
  return pkgs;
}

/** Alpine: lib/apk/db/installed */
function parseAlpineInstalled(content: string): Pkg[] {
  const pkgs: Pkg[] = [];
  for (const entry of content.split(/\n\n+/)) {
    let name = '', version = '';
    for (const line of entry.split('\n')) {
      if (line.startsWith('P:')) name    = line.slice(2).trim();
      if (line.startsWith('V:')) version = line.slice(2).trim();
    }
    if (name && version) pkgs.push({ name, version, ecosystem: 'Alpine' });
  }
  return pkgs;
}

/** Node.js: package-lock.json (v2/v3) or package.json */
function parseNodeDeps(content: string): Pkg[] {
  const pkgs: Pkg[] = [];
  try {
    const json = JSON.parse(content);
    if (json.packages) {
      // package-lock.json v2/v3
      for (const [pkgPath, info] of Object.entries(json.packages as Record<string, any>)) {
        if (pkgPath === '') continue; // root
        if (pkgPath.includes('/node_modules/') && pkgPath.indexOf('node_modules') !== pkgPath.lastIndexOf('node_modules')) continue;
        const namePart = pkgPath.split('/node_modules/').pop() ?? '';
        if (!namePart) continue;
        const version = String(info.version ?? '');
        if (version && /^\d/.test(version)) {
          pkgs.push({ name: namePart, version, ecosystem: 'npm' });
        }
      }
    } else if (json.dependencies) {
      // package.json
      for (const [name, ver] of Object.entries(json.dependencies as Record<string, string>)) {
        const version = String(ver).replace(/^[~^>=<! ]+/, '').split(/\s/)[0];
        if (version && /^\d/.test(version)) {
          pkgs.push({ name, version, ecosystem: 'npm' });
        }
      }
    }
  } catch { /* ignore */ }
  return pkgs;
}

/** Python: requirements.txt */
function parsePythonRequirements(content: string): Pkg[] {
  const pkgs: Pkg[] = [];
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const clean = line.split('#')[0].trim();
    const m = clean.match(/^([A-Za-z0-9_\-\.]+)\s*[=~><!]+\s*([0-9][^\s,;]*)/);
    if (m) pkgs.push({ name: m[1], version: m[2], ecosystem: 'PyPI' });
  }
  return pkgs;
}

/** Python: Pipfile.lock */
function parsePipfileLock(content: string): Pkg[] {
  const pkgs: Pkg[] = [];
  try {
    const json = JSON.parse(content);
    for (const section of ['default', 'develop']) {
      for (const [name, info] of Object.entries((json[section] ?? {}) as Record<string, any>)) {
        const version = String(info.version ?? '').replace(/^==/, '');
        if (version && /\d/.test(version)) pkgs.push({ name, version, ecosystem: 'PyPI' });
      }
    }
  } catch { /* ignore */ }
  return pkgs;
}

/** Python: poetry.lock */
function parsePoetryLock(content: string): Pkg[] {
  const pkgs: Pkg[] = [];
  const blocks = content.split(/\[\[package\]\]/);
  for (const block of blocks) {
    const nameM = block.match(/^name\s*=\s*"([^"]+)"/m);
    const verM  = block.match(/^version\s*=\s*"([^"]+)"/m);
    if (nameM && verM) pkgs.push({ name: nameM[1], version: verM[1], ecosystem: 'PyPI' });
  }
  return pkgs;
}

/** Ruby: Gemfile.lock */
function parseGemfileLock(content: string): Pkg[] {
  const pkgs: Pkg[] = [];
  let inSpecs = false;
  for (const line of content.split('\n')) {
    const t = line.trim();
    if (t === 'specs:')   { inSpecs = true;  continue; }
    if (t === '' && inSpecs) { inSpecs = false; continue; }
    if (/^[A-Z]/.test(t)) { inSpecs = false; continue; }
    if (inSpecs) {
      const m = line.match(/^    ([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)/);
      if (m) pkgs.push({ name: m[1], version: m[2], ecosystem: 'RubyGems' });
    }
  }
  return pkgs;
}

/** Go: go.sum */
function parseGoSum(content: string): Pkg[] {
  const seen = new Set<string>();
  const pkgs: Pkg[] = [];
  for (const line of content.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;
    const [mod, verRaw] = parts;
    if (!mod || !verRaw || verRaw.endsWith('/go.mod')) continue;
    const ver = verRaw.split('/')[0];
    const key = `${mod}@${ver}`;
    if (seen.has(key)) continue;
    seen.add(key);
    pkgs.push({ name: mod, version: ver, ecosystem: 'Go' });
  }
  return pkgs;
}

/** Extract packages from all files found in a layer */
function extractPackages(files: Map<string, Buffer>): { pkgs: Pkg[]; osInfo: string } {
  const allPkgs: Pkg[] = [];
  let osInfo = 'Unknown';

  for (const [path, buf] of files) {
    const content = buf.toString('utf8');
    const base = path.split('/').pop() ?? '';

    if (path === 'etc/os-release') {
      const nameM = content.match(/^PRETTY_NAME="?([^"\n]+)"?/m);
      if (nameM) osInfo = nameM[1].trim();
      continue;
    }

    try {
      if (path.endsWith('var/lib/dpkg/status'))   allPkgs.push(...parseDebianStatus(content));
      else if (path.endsWith('lib/apk/db/installed')) allPkgs.push(...parseAlpineInstalled(content));
      else if (base === 'package-lock.json')       allPkgs.push(...parseNodeDeps(content));
      else if (base === 'package.json') {
        // Only use package.json if we didn't already get package-lock.json for same dir
        const lockPath = path.replace('package.json', 'package-lock.json');
        if (!files.has(lockPath))                  allPkgs.push(...parseNodeDeps(content));
      }
      else if (base === 'requirements.txt')        allPkgs.push(...parsePythonRequirements(content));
      else if (base === 'Pipfile.lock')            allPkgs.push(...parsePipfileLock(content));
      else if (base === 'poetry.lock')             allPkgs.push(...parsePoetryLock(content));
      else if (base === 'Gemfile.lock')            allPkgs.push(...parseGemfileLock(content));
      else if (base === 'go.sum')                  allPkgs.push(...parseGoSum(content));
    } catch (err) {
      logger.debug(`Failed to parse ${path}`, { error: (err as Error).message });
    }
  }

  return { pkgs: allPkgs, osInfo };
}

// ─── OSV API ──────────────────────────────────────────────────────────────────

interface OSVVuln {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
}

function osvSeverity(vuln: OSVVuln): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  const dbSev = vuln.database_specific?.severity?.toUpperCase();
  if (dbSev === 'CRITICAL') return 'CRITICAL';
  if (dbSev === 'HIGH')     return 'HIGH';
  if (dbSev === 'MEDIUM')   return 'MEDIUM';
  if (dbSev === 'LOW')      return 'LOW';

  let maxScore = 0;
  for (const s of vuln.severity ?? []) {
    const m = String(s.score).match(/(\d+\.\d+)/);
    if (m) maxScore = Math.max(maxScore, parseFloat(m[1]));
  }
  if (maxScore >= 9.0) return 'CRITICAL';
  if (maxScore >= 7.0) return 'HIGH';
  if (maxScore >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function osvFixedVersion(vuln: OSVVuln): string {
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return '';
}

async function queryOSVBatch(pkgs: Pkg[]): Promise<Map<string, OSVVuln[]>> {
  const results = new Map<string, OSVVuln[]>();

  for (let i = 0; i < pkgs.length; i += OSV_BATCH_SIZE) {
    const batch = pkgs.slice(i, i + OSV_BATCH_SIZE);
    try {
      const resp = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queries: batch.map(p => ({
            version: p.version,
            package: { name: p.name, ecosystem: p.ecosystem },
          })),
        }),
      });
      if (!resp.ok) continue;
      const data = (await resp.json()) as { results: Array<{ vulns?: OSVVuln[] }> };
      for (let j = 0; j < batch.length; j++) {
        const vulns = data.results[j]?.vulns ?? [];
        if (vulns.length > 0) {
          const key = `${batch[j].ecosystem}:${batch[j].name}@${batch[j].version}`;
          results.set(key, vulns);
        }
      }
    } catch (err) {
      logger.debug('OSV batch query error', { error: (err as Error).message });
    }
    if (i + OSV_BATCH_SIZE < pkgs.length) {
      await new Promise(r => setTimeout(r, OSV_DELAY_MS));
    }
  }

  return results;
}

// ─── Docker Registry API helpers ──────────────────────────────────────────────

interface RegistryAuth { token: string; registryUrl: string }

async function fetchManifest(
  registryUrl: string,
  repoName: string,
  reference: string,
  auth: string,
): Promise<any | null> {
  const url = `${registryUrl}/v2/${repoName}/manifests/${reference}`;
  try {
    const resp = await fetch(url, {
      headers: {
        Authorization: auth,
        Accept: [
          'application/vnd.docker.distribution.manifest.v2+json',
          'application/vnd.docker.distribution.manifest.list.v2+json',
          'application/vnd.oci.image.manifest.v1+json',
          'application/vnd.oci.image.index.v1+json',
        ].join(','),
      },
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

/** Handle manifest list (multi-arch) — pick linux/amd64 or first entry */
async function resolveManifest(
  registryUrl: string,
  repoName: string,
  reference: string,
  auth: string,
): Promise<any | null> {
  const manifest = await fetchManifest(registryUrl, repoName, reference, auth);
  if (!manifest) return null;

  const mType = manifest.mediaType ?? '';

  // Manifest list or OCI index → pick linux/amd64
  if (
    mType.includes('manifest.list') ||
    mType.includes('image.index') ||
    Array.isArray(manifest.manifests)
  ) {
    const manifests: any[] = manifest.manifests ?? [];
    const preferred =
      manifests.find(
        (m: any) =>
          m.platform?.os === 'linux' &&
          (m.platform?.architecture === 'amd64' || m.platform?.architecture === 'arm64'),
      ) ?? manifests[0];
    if (!preferred) return null;
    return fetchManifest(registryUrl, repoName, preferred.digest, auth);
  }

  return manifest;
}

/** Download a single layer blob and extract target files */
async function scanLayer(
  registryUrl: string,
  repoName: string,
  digest: string,
  layerSize: number,
  auth: string,
): Promise<Map<string, Buffer>> {
  const empty = new Map<string, Buffer>();
  if (layerSize > MAX_LAYER_COMPRESSED) {
    logger.debug(`Skipping large layer ${digest.slice(-12)} (${Math.round(layerSize / 1024 / 1024)}MB)`);
    return empty;
  }

  const url = `${registryUrl}/v2/${repoName}/blobs/${digest}`;
  let buf: Buffer;
  try {
    const resp = await fetch(url, { headers: { Authorization: auth } });
    if (!resp.ok) return empty;
    buf = Buffer.from(await resp.arrayBuffer());
  } catch (err) {
    logger.debug(`Layer download failed ${digest.slice(-12)}`, { error: (err as Error).message });
    return empty;
  }

  try {
    const decompressed = gunzipSync(buf);
    return parseTar(decompressed);
  } catch {
    // Some layers are uncompressed tars
    try { return parseTar(buf); } catch { return empty; }
  }
}

// ─── Repository policy helpers (ported from Prowler's IAM policy lib) ─────────

const RESTRICTIVE_CONDITION_KEYS = new Set([
  'aws:principalarn', 'aws:principalaccount', 'aws:principalorgid', 'aws:principalorgpaths',
  'aws:sourceaccount', 'aws:sourcearn', 'aws:sourceowner', 'aws:sourcevpc', 'aws:sourcevpce',
]);

function extractPrincipals(principal: any): string[] {
  if (typeof principal === 'string') return [principal];
  if (Array.isArray(principal)) return principal.filter((p: any) => typeof p === 'string');
  if (principal && typeof principal === 'object') {
    const values = principal.AWS ?? [];
    if (typeof values === 'string') return [values];
    if (Array.isArray(values)) return values.filter((p: any) => typeof p === 'string');
  }
  return [];
}

/** True when an allow-list condition operator scopes the statement to specific principals/accounts. */
function hasRestrictiveCondition(condition: any): boolean {
  if (!condition || typeof condition !== 'object') return false;
  for (const [operator, block] of Object.entries(condition)) {
    const op = operator.toLowerCase();
    const isAllowListOperator =
      op.startsWith('stringequals') || op.startsWith('stringlike') ||
      op.startsWith('arnequals') || op.startsWith('arnlike');
    if (!isAllowListOperator || !block || typeof block !== 'object') continue;
    for (const [key, rawValues] of Object.entries(block as Record<string, any>)) {
      if (!RESTRICTIVE_CONDITION_KEYS.has(key.toLowerCase())) continue;
      const values = Array.isArray(rawValues) ? rawValues : [rawValues];
      if (values.length === 0 || values.includes('*')) continue;
      return true;
    }
  }
  return false;
}

/** A policy is public when an Allow statement has a wildcard principal without a restrictive condition. */
function isPolicyPublic(policy: any): boolean {
  const raw = policy?.Statement;
  const statements: any[] = Array.isArray(raw) ? raw : raw ? [raw] : [];
  for (const statement of statements) {
    if (statement?.Effect !== 'Allow') continue;
    if (!extractPrincipals(statement.Principal).includes('*')) continue;
    if (!hasRestrictiveCondition(statement.Condition)) return true;
  }
  return false;
}

// ─── Main Scanner ─────────────────────────────────────────────────────────────

export class ECRScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'ECR');
  }

  async scan(options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const lastScanAt = options?.lastScanAt ?? null;
    try {
      logger.info(
        lastScanAt
          ? `Starting ECR scan (smart-skip: images pushed before ${lastScanAt.toISOString()} will be skipped)`
          : 'Starting ECR full image vulnerability scan...',
      );

      // Step 1: List repositories and run configuration checks (no registry auth needed)
      const repos = await this.listAllRepositories();
      logger.info(`ECR: scanning ${repos.length} repositories`);

      findings.push(...(await this.checkRegistryScanningConfiguration(repos)));

      // Step 2: Get registry auth for image-layer CVE scanning
      const auth = await this.getRegistryAuth();
      if (!auth) {
        logger.warn('Could not obtain ECR registry auth token — skipping image CVE scanning');
      }

      for (const repo of repos) {
        findings.push(...(await this.checkRepositoryConfiguration(repo)));
        if (auth) {
          findings.push(...(await this.scanRepository(repo, auth, lastScanAt)));
        }
      }

      logger.info(`ECR scan complete. ${findings.length} findings.`);
    } catch (err) {
      logger.error('ECR scan failed', { error: (err as Error).message });
    }
    return findings;
  }

  // ── Auth ────────────────────────────────────────────────────────────────────

  private async getRegistryAuth(): Promise<RegistryAuth | null> {
    try {
      const result = await retry(() =>
        this.client.ecr.send(new GetAuthorizationTokenCommand({})),
      );
      const authData = result.authorizationData?.[0];
      if (!authData?.authorizationToken || !authData.proxyEndpoint) return null;

      // authorizationToken is base64("AWS:password")
      const token = 'Basic ' + authData.authorizationToken;
      return { token, registryUrl: authData.proxyEndpoint };
    } catch (err) {
      logger.debug('Could not get ECR auth token', { error: (err as Error).message });
      return null;
    }
  }

  // ── Repositories ────────────────────────────────────────────────────────────

  private async listAllRepositories(): Promise<Repository[]> {
    const repos: Repository[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(() =>
        this.client.ecr.send(new DescribeRepositoriesCommand({ nextToken, maxResults: 100 })),
      );
      repos.push(...(result.repositories ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return repos;
  }

  /** Returns all images sorted newest-first */
  private async getAllImages(repositoryName: string): Promise<ImageDetail[]> {
    try {
      const result = await retry(() =>
        this.client.ecr.send(
          new DescribeImagesCommand({ repositoryName, maxResults: 100, filter: { tagStatus: 'ANY' } }),
        ),
      );
      return (result.imageDetails ?? []).sort(
        (a, b) => (b.imagePushedAt?.getTime() ?? 0) - (a.imagePushedAt?.getTime() ?? 0),
      );
    } catch {
      return [];
    }
  }

  // ── Configuration checks (ported from Prowler) ──────────────────────────────

  // ecr_registry_scan_images_on_push_enabled — registry-level scanning configuration
  private async checkRegistryScanningConfiguration(repos: Repository[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    // Prowler only evaluates the registry when it is in use (repositories exist)
    if (repos.length === 0) return findings;
    const registryId = repos[0].registryId ?? 'default';

    let scanType = 'BASIC';
    let rules: any[] = [];
    try {
      const result: any = await this.client.ecr.send(new GetRegistryScanningConfigurationCommand({}));
      scanType = result?.scanningConfiguration?.scanType ?? 'BASIC';
      rules = result?.scanningConfiguration?.rules ?? [];
    } catch (err) {
      const message = (err as Error).message || '';
      if (!message.includes('feature is disabled')) {
        logger.debug('Could not get ECR registry scanning configuration', { error: message });
        return findings;
      }
      // Feature disabled → BASIC scanning with no registry-level rules
    }

    if (rules.length === 0) {
      findings.push(
        this.emit(
          'ecr_registry_scan_images_on_push_enabled',
          { resourceId: `${registryId}::registry-scan-config`, registryId, scanType, rules: [] },
          {
            message: `ECR registry ${registryId} has ${scanType} scanning without scan on push enabled at the registry level.`,
          },
        ),
      );
      return findings;
    }

    // A rule with no repository filters, or with a wildcard "*" filter, covers all repositories
    const coversAllRepositories = rules.some((rule: any) => {
      const filters: any[] = rule?.repositoryFilters ?? [];
      return filters.length === 0 || filters.some((f: any) => f?.filter === '*');
    });
    if (!coversAllRepositories) {
      findings.push(
        this.emit(
          'ecr_registry_scan_images_on_push_enabled',
          { resourceId: `${registryId}::registry-scan-config`, registryId, scanType, rules },
          {
            message: `ECR registry ${registryId} has ${scanType} scanning with scan on push enabled but limited by repository filters, so not all repositories are covered.`,
          },
        ),
      );
    }

    return findings;
  }

  // ecr_repositories_tag_immutability / ecr_repositories_lifecycle_policy_enabled /
  // ecr_repositories_not_publicly_accessible
  private async checkRepositoryConfiguration(repo: Repository): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const repoName = repo.repositoryName ?? 'Unknown';

    // ecr_repositories_tag_immutability
    if (repo.imageTagMutability === 'MUTABLE') {
      findings.push(
        this.emit(
          'ecr_repositories_tag_immutability',
          { resourceId: `${repoName}::tag-immutability`, repositoryName: repoName, imageTagMutability: 'MUTABLE' },
          {
            message: `Repository "${repoName}" does not have image tag immutability configured, so a trusted tag can be repointed to a different image.`,
            remediation: `aws ecr put-image-tag-mutability --repository-name ${repoName} --image-tag-mutability IMMUTABLE`,
          },
        ),
      );
    }

    // ecr_repositories_lifecycle_policy_enabled
    // (direct send: LifecyclePolicyNotFoundException is the expected FAIL path, retry() would re-issue it)
    try {
      await this.client.ecr.send(new GetLifecyclePolicyCommand({ repositoryName: repoName }));
    } catch (err) {
      const error = err as any;
      if (error?.name === 'LifecyclePolicyNotFoundException' || String(error?.message ?? '').includes('LifecyclePolicyNotFound')) {
        findings.push(
          this.emit(
            'ecr_repositories_lifecycle_policy_enabled',
            { resourceId: `${repoName}::lifecycle-policy`, repositoryName: repoName, lifecyclePolicy: null },
            {
              message: `Repository "${repoName}" does not have a lifecycle policy configured.`,
              remediation: `aws ecr put-lifecycle-policy --repository-name ${repoName} --lifecycle-policy-text '{"rules":[{"rulePriority":1,"selection":{"tagStatus":"untagged","countType":"imageCountMoreThan","countNumber":1},"action":{"type":"expire"}}]}'`,
            },
          ),
        );
      } else {
        logger.debug(`Could not get lifecycle policy for ECR repository ${repoName}`, { error: (err as Error).message });
      }
    }

    // ecr_repositories_not_publicly_accessible
    try {
      const result: any = await this.client.ecr.send(new GetRepositoryPolicyCommand({ repositoryName: repoName }));
      if (result?.policyText) {
        const policy = JSON.parse(result.policyText);
        if (isPolicyPublic(policy)) {
          findings.push(
            this.emit(
              'ecr_repositories_not_publicly_accessible',
              { resourceId: `${repoName}::repository-policy`, repositoryName: repoName, policy },
              {
                message: `Repository "${repoName}" is publicly accessible: its repository policy allows a wildcard principal without restrictive conditions.`,
                remediation: `Remove wildcard principals from the policy of "${repoName}" or delete it: aws ecr delete-repository-policy --repository-name ${repoName}`,
              },
            ),
          );
        }
      }
    } catch (err) {
      const error = err as any;
      // No repository policy at all → not publicly accessible
      if (error?.name !== 'RepositoryPolicyNotFoundException' && !String(error?.message ?? '').includes('RepositoryPolicyNotFound')) {
        logger.debug(`Could not get repository policy for ECR repository ${repoName}`, { error: (err as Error).message });
      }
    }

    return findings;
  }

  // ── Per-repository scanning ─────────────────────────────────────────────────

  private async scanRepository(
    repo: Repository,
    auth: RegistryAuth,
    lastScanAt: Date | null,
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const repoName = repo.repositoryName ?? 'Unknown';

    // Config check: scan-on-push (emitted always; visible in Reports page)
    if (!repo.imageScanningConfiguration?.scanOnPush) {
      findings.push(
        this.emit(
          'ecr_repositories_scan_images_on_push_enabled',
          { resourceId: `${repoName}::scan-on-push`, repositoryName: repoName },
          {
            message: `Repository "${repoName}" does not have scan-on-push enabled. Enable it as a baseline alongside this independent layer scan.`,
            remediation: `aws ecr put-image-scanning-configuration --repository-name ${repoName} --image-scanning-configuration scanOnPush=true`,
          },
        ),
      );
    }

    const allImages = await this.getAllImages(repoName);
    if (allImages.length === 0) return findings;

    const latestImage = allImages[0];
    const latestPushedAt = latestImage.imagePushedAt ?? null;

    // Smart-skip: if the newest image was pushed before (or at) the last scan, skip CVE scanning
    if (lastScanAt && latestPushedAt && latestPushedAt.getTime() <= lastScanAt.getTime()) {
      logger.info(
        `ECR: skipping CVE scan for "${repoName}" — latest image pushed ${latestPushedAt.toISOString()} ≤ last scan ${lastScanAt.toISOString()}`,
      );
      return findings;
    }

    // If lastScanAt is set, only scan the single newest image (the one just pushed)
    // If no lastScanAt (first scan), scan up to MAX_IMAGES_PER_REPO
    const imagesToScan = lastScanAt ? [latestImage] : allImages.slice(0, MAX_IMAGES_PER_REPO);

    if (lastScanAt && latestPushedAt) {
      logger.info(
        `ECR: new image detected in "${repoName}" (pushed ${latestPushedAt.toISOString()}) — scanning latest only`,
      );
    }

    // Scan selected images for CVEs
    for (const image of imagesToScan) {
      findings.push(...(await this.scanImage(repo, image, auth)));
    }

    return findings;
  }

  // ── Per-image scanning ──────────────────────────────────────────────────────

  private async scanImage(
    repo: Repository,
    image: ImageDetail,
    auth: RegistryAuth,
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const repoName = repo.repositoryName ?? 'Unknown';
    const tag      = image.imageTags?.[0];
    const digest   = image.imageDigest ?? '';
    const shortDigest = digest.slice(-12);
    const imageRef = tag ? `${repoName}:${tag}` : `${repoName}@${digest.slice(0, 19)}`;
    const reference = tag ?? digest;

    logger.info(`ECR: scanning image ${imageRef}`);

    // Get image manifest to enumerate layers
    const manifest = await resolveManifest(auth.registryUrl, repoName, reference, auth.token);
    if (!manifest) {
      logger.debug(`No manifest for ${imageRef}`);
      return findings;
    }

    const layers: Array<{ digest: string; size: number }> = (manifest.layers ?? []).map(
      (l: any) => ({ digest: l.digest, size: l.size ?? 0 }),
    );

    if (layers.length === 0) {
      logger.debug(`No layers in manifest for ${imageRef}`);
      return findings;
    }

    // Collect files across all layers (later layers override earlier ones — union-fs model)
    const allFiles = new Map<string, Buffer>();
    for (const layer of layers) {
      const layerFiles = await scanLayer(
        auth.registryUrl, repoName, layer.digest, layer.size, auth.token,
      );
      for (const [path, buf] of layerFiles) {
        allFiles.set(path, buf);
      }
    }

    if (allFiles.size === 0) {
      logger.debug(`No target package files found in ${imageRef}`);
      return findings;
    }

    logger.debug(`Extracted ${allFiles.size} package manifest files from ${imageRef}`);

    // Extract packages from collected files
    const { pkgs: rawPkgs, osInfo } = extractPackages(allFiles);

    if (rawPkgs.length === 0) {
      logger.debug(`No packages parsed from ${imageRef}`);
      return findings;
    }

    // Deduplicate by ecosystem:name@version and cap total
    const seen = new Set<string>();
    const pkgs = rawPkgs.filter(p => {
      const k = `${p.ecosystem}:${p.name}@${p.version}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    }).slice(0, MAX_PKGS_PER_IMAGE);

    logger.info(`ECR ${imageRef}: querying OSV for ${pkgs.length} packages (OS: ${osInfo})`);

    // Query OSV batch
    const osvResults = await queryOSVBatch(pkgs);

    if (osvResults.size === 0) {
      logger.debug(`No CVEs found in ${imageRef}`);
      return findings;
    }

    // Build findings
    const bySeverity: Record<string, Array<{ pkg: Pkg; vuln: OSVVuln; sev: string; fixed: string }>> = {
      CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [],
    };

    for (const [key, vulns] of osvResults) {
      const pkg = pkgs.find(p => `${p.ecosystem}:${p.name}@${p.version}` === key)!;
      for (const vuln of vulns) {
        const sev   = osvSeverity(vuln);
        const fixed = osvFixedVersion(vuln);
        bySeverity[sev]?.push({ pkg, vuln, sev, fixed });
      }
    }

    const imageBase = {
      repositoryName: repoName,
      imageTag: tag ?? '',
      imageDigest: digest,
      operatingSystem: osInfo,
    };

    // CRITICAL — one finding per CVE (capped)
    for (const item of bySeverity.CRITICAL.slice(0, MAX_CVE_PER_SEVERITY)) {
      findings.push(
        this.emit(
          'ecr_repositories_scan_vulnerabilities_in_latest_image',
          {
            resourceId: `${repoName}::${shortDigest}::${item.pkg.name}::${item.vuln.id}`,
            ...imageBase,
            packageName: item.pkg.name,
            packageType: item.pkg.ecosystem,
            installedVersion: item.pkg.version,
            fixedVersion: item.fixed,
            cveId: item.vuln.id,
          },
          {
            message: `Image "${imageRef}" — ${item.pkg.ecosystem} package "${item.pkg.name}@${item.pkg.version}" has CRITICAL vulnerability ${item.vuln.id}: ${item.vuln.summary ?? 'See advisory'}.`,
            remediation: item.fixed
              ? `Rebuild "${imageRef}" with ${item.pkg.name} upgraded to ${item.fixed}.`
              : `No fix available yet. Monitor ${item.vuln.id} and rebuild when a patch is released.`,
            tags: [item.pkg.ecosystem.toLowerCase()],
          },
        ),
      );
    }

    // HIGH — one finding per CVE (capped)
    for (const item of bySeverity.HIGH.slice(0, MAX_CVE_PER_SEVERITY)) {
      findings.push(
        this.emit(
          'ecr_image_high_severity_cves',
          {
            resourceId: `${repoName}::${shortDigest}::${item.pkg.name}::${item.vuln.id}`,
            ...imageBase,
            packageName: item.pkg.name,
            packageType: item.pkg.ecosystem,
            installedVersion: item.pkg.version,
            fixedVersion: item.fixed,
            cveId: item.vuln.id,
          },
          {
            message: `Image "${imageRef}" — ${item.pkg.ecosystem} package "${item.pkg.name}@${item.pkg.version}" has HIGH vulnerability ${item.vuln.id}: ${item.vuln.summary ?? 'See advisory'}.`,
            remediation: item.fixed
              ? `Rebuild "${imageRef}" with ${item.pkg.name} upgraded to ${item.fixed}.`
              : `Monitor ${item.vuln.id} and rebuild when a patch is released.`,
            tags: [item.pkg.ecosystem.toLowerCase()],
          },
        ),
      );
    }

    // MEDIUM + LOW — one consolidated summary finding each
    for (const sev of ['MEDIUM', 'LOW'] as const) {
      const items = bySeverity[sev];
      if (items.length === 0) continue;
      const listed = items.slice(0, 5).map(i => `${i.pkg.name} (${i.vuln.id})`).join(', ');
      const overflow = items.length > 5 ? ` + ${items.length - 5} more` : '';
      findings.push(
        this.emit(
          'ecr_image_medium_low_cves',
          {
            resourceId: `${repoName}::${shortDigest}::${sev.toLowerCase()}-summary`,
            ...imageBase,
            count: items.length,
            affectedPackages: items.slice(0, 10).map(i => `${i.pkg.name}@${i.pkg.version}`),
          },
          {
            message: `Image "${imageRef}" has ${items.length} ${sev} CVE(s): ${listed}${overflow}.`,
            remediation: `Rebuild "${imageRef}" with updated base image and dependencies.`,
            severity: sev === 'MEDIUM' ? 'MEDIUM' : 'LOW',
          },
        ),
      );
    }

    // Overflow notice if we capped CRITICAL/HIGH
    const critTotal = bySeverity.CRITICAL.length;
    const highTotal = bySeverity.HIGH.length;
    if (critTotal > MAX_CVE_PER_SEVERITY || highTotal > MAX_CVE_PER_SEVERITY) {
      const extra = (critTotal - MAX_CVE_PER_SEVERITY) + (highTotal - MAX_CVE_PER_SEVERITY);
      findings.push(
        this.emit(
          'ecr_image_high_severity_cves',
          {
            resourceId: `${repoName}::${shortDigest}::overflow-summary`,
            ...imageBase,
            criticalTotal: critTotal,
            highTotal,
          },
          {
            message: `Image "${imageRef}" has ${critTotal} CRITICAL and ${highTotal} HIGH CVEs total. ${extra} additional findings were omitted — rebuild with updated dependencies to resolve all.`,
          },
        ),
      );
    }

    return findings;
  }
}

export default ECRScanner;
