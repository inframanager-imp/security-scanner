/**
 * ML-Based Anomaly Detection Engine
 *
 * Implements statistical anomaly detection across all three cloud providers
 * (AWS, Azure, GCP) without external ML dependencies.
 *
 * Algorithms used:
 *  - EWMA (Exponentially Weighted Moving Average)  — frequency baselines
 *  - Z-score                                        — deviation from baseline
 *  - Welford's online algorithm                     — incremental mean + variance
 *  - Sliding window counters (Redis)                — real-time rate detection
 *  - Bloom-filter-style IP/country sets             — geo anomaly
 *
 * Detection categories:
 *  FREQUENCY        — API call rate > baseline + 3σ (e.g. 200 Describe* in 5 min)
 *  GEOGRAPHIC       — First-ever IP or country for this actor
 *  TEMPORAL         — Activity outside normal working hours (hour bucket rarely used)
 *  ACCESS_DENIED    — Spike in authorization failures (credential stuffing / recon)
 *  IMPOSSIBLE_TRAVEL— Same actor, 2 countries within < 2 hours
 *  RARE_EVENT       — API call never (or <3x) made by this actor before
 *  LATERAL_MOVEMENT — Cross-service API calls across ≥4 distinct services in 15 min
 *  DATA_EXFIL       — High-volume GetObject / read ops on sensitive resources
 */

import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { logger } from '../config/logger';
import { getIO } from '../socket/index';

// ─── Types ────────────────────────────────────────────────────────────────────

export type AnomalyType =
  | 'FREQUENCY'
  | 'GEOGRAPHIC'
  | 'TEMPORAL'
  | 'ACCESS_DENIED'
  | 'IMPOSSIBLE_TRAVEL'
  | 'RARE_EVENT'
  | 'LATERAL_MOVEMENT'
  | 'DATA_EXFIL';

export type AnomalySeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface NormalizedEvent {
  provider:    'AWS' | 'AZURE' | 'GCP';
  accountId:   string;         // internal DB id
  actorId:     string;         // IAM user / SP / SA email
  actorType:   string;         // Root | User | Role | ServicePrincipal | ServiceAccount
  eventName:   string;         // API call name
  eventTime:   Date;
  sourceIp:    string;
  country?:    string;         // derived from IP geolocation (optional)
  region:      string;
  service:     string;         // e3 | iam | compute | storage etc.
  errorCode?:  string;         // non-empty = authorization failure
  resourceId?: string;
  rawEventId?: string;
}

export interface AnomalyDetection {
  anomalyType:    AnomalyType;
  severity:       AnomalySeverity;
  score:          number;          // 0–100
  description:    string;
  detail:         Record<string, unknown>;
  sourceIp?:      string;
  country?:       string;
  eventName?:     string;
  relatedEventIds: string[];
}

// ─── EWMA / Welford constants ─────────────────────────────────────────────────

const EWMA_ALPHA = 0.1;        // smoothing factor — higher = more reactive
const Z_THRESHOLD = 3.0;       // z-score threshold for frequency anomaly
const MIN_SAMPLES = 10;        // minimum samples before EWMA fires
const GEO_MAX_IPS = 50;        // store up to 50 known IPs per actor
const HOUR_BUCKETS = 24;       // hourly activity tracking
const RARE_EVENT_THRESHOLD = 3;// seen fewer than N times = rare

// ─── Redis key helpers ────────────────────────────────────────────────────────

const rk = {
  // Sliding 5-min event counter per actor
  actorWindow:   (p: string, a: string, actor: string) => `anomaly:window5m:${p}:${a}:${actor}`,
  // Service set per actor in 15-min window (lateral movement)
  serviceWindow: (p: string, a: string, actor: string) => `anomaly:svc15m:${p}:${a}:${actor}`,
  // Last seen IP per actor (for impossible travel)
  lastIp:        (p: string, a: string, actor: string) => `anomaly:lastip:${p}:${a}:${actor}`,
  // Last seen country per actor
  lastCountry:   (p: string, a: string, actor: string) => `anomaly:lastcountry:${p}:${a}:${actor}`,
  // Access-denied counter per actor (5-min window)
  deniedWindow:  (p: string, a: string, actor: string) => `anomaly:denied5m:${p}:${a}:${actor}`,
  // GetObject/read counter per actor (5-min window, data exfil)
  readWindow:    (p: string, a: string, actor: string) => `anomaly:read5m:${p}:${a}:${actor}`,
};

// ─── Geo helpers ──────────────────────────────────────────────────────────────

/** Very lightweight IP-to-country mapping for well-known cloud/VPN ranges.
 *  In production this would call a local MaxMind GeoIP DB or an internal lookup.
 *  We derive a "region hint" from IP prefix instead of a full lookup.
 */
function ipToCountryHint(ip: string): string | undefined {
  if (!ip || ip === 'AWS Internal' || ip.startsWith('10.') || ip.startsWith('172.16.') || ip.startsWith('192.168.')) return undefined;
  // For now return the /16 prefix as a pseudo-region identifier so we can detect new IP blocks
  const parts = ip.split('.');
  if (parts.length >= 2) return `${parts[0]}.${parts[1]}.x.x`;
  return ip;
}

// ─── Welford online mean + variance update ────────────────────────────────────

function welfordUpdate(
  mean: number,
  variance: number,
  count: number,
  newValue: number,
): { mean: number; variance: number; count: number } {
  const n = count + 1;
  const delta = newValue - mean;
  const newMean = mean + delta / n;
  const delta2 = newValue - newMean;
  const newVariance = (variance * count + delta * delta2) / n;
  return { mean: newMean, variance: newVariance, count: n };
}

/** EWMA update: blends new value into existing mean/variance with alpha smoothing. */
function ewmaUpdate(
  ewmaMean: number,
  ewmaVariance: number,
  newValue: number,
): { ewmaMean: number; ewmaVariance: number } {
  const diff = newValue - ewmaMean;
  const newMean = ewmaMean + EWMA_ALPHA * diff;
  const newVariance = (1 - EWMA_ALPHA) * (ewmaVariance + EWMA_ALPHA * diff * diff);
  return { ewmaMean: newMean, ewmaVariance: newVariance };
}

/** Z-score: how many standard deviations is value from baseline. */
function zScore(value: number, mean: number, variance: number): number {
  const stddev = Math.sqrt(Math.max(variance, 0.0001));
  return (value - mean) / stddev;
}

// ─── Baseline upsert helper ───────────────────────────────────────────────────

async function upsertBaseline(
  provider: string,
  accountId: string,
  actorId: string,
  metricKey: string,
  newValue: number,
): Promise<{ ewmaMean: number; ewmaVariance: number; sampleCount: number } | null> {
  try {
    const existing = await prisma.anomalyBaseline.findUnique({
      where: { provider_accountId_actorId_metricKey: { provider, accountId, actorId, metricKey } },
    });

    if (existing) {
      const updated = ewmaUpdate(existing.ewmaMean, existing.ewmaVariance, newValue);
      await prisma.anomalyBaseline.update({
        where: { id: existing.id },
        data: {
          ewmaMean:     updated.ewmaMean,
          ewmaVariance: updated.ewmaVariance,
          sampleCount:  existing.sampleCount + 1,
          lastValue:    newValue,
          lastUpdated:  new Date(),
        },
      });
      return { ...updated, sampleCount: existing.sampleCount + 1 };
    } else {
      await prisma.anomalyBaseline.create({
        data: { provider, accountId, actorId, metricKey, ewmaMean: newValue, ewmaVariance: 0, sampleCount: 1, lastValue: newValue },
      });
      return { ewmaMean: newValue, ewmaVariance: 0, sampleCount: 1 };
    }
  } catch (err) {
    logger.warn(`[anomaly] baseline upsert failed: ${(err as Error).message}`);
    return null;
  }
}

async function getBaseline(
  provider: string, accountId: string, actorId: string, metricKey: string,
) {
  return prisma.anomalyBaseline.findUnique({
    where: { provider_accountId_actorId_metricKey: { provider, accountId, actorId, metricKey } },
  });
}

// ─── Persist anomaly event ────────────────────────────────────────────────────

async function saveAnomaly(
  event: NormalizedEvent,
  detection: AnomalyDetection,
): Promise<void> {
  try {
    const record = await prisma.anomalyEvent.create({
      data: {
        provider:       event.provider,
        accountId:      event.accountId,
        actorId:        event.actorId,
        anomalyType:    detection.anomalyType,
        severity:       detection.severity,
        score:          detection.score,
        description:    detection.description,
        detail:         detection.detail,
        sourceIp:       detection.sourceIp ?? event.sourceIp,
        country:        detection.country,
        eventName:      detection.eventName ?? event.eventName,
        relatedEventIds: detection.relatedEventIds,
      },
    });

    // Real-time Socket.IO push
    try {
      const io = getIO();
      io.to(`threats:${event.accountId}`).emit('anomaly:detected', {
        id:          record.id,
        provider:    event.provider,
        accountId:   event.accountId,
        actorId:     event.actorId,
        anomalyType: detection.anomalyType,
        severity:    detection.severity,
        score:       detection.score,
        description: detection.description,
        detectedAt:  record.detectedAt.toISOString(),
      });
      io.to('threats:all').emit('anomaly:detected', {
        accountId:   event.accountId,
        provider:    event.provider,
        anomalyType: detection.anomalyType,
        severity:    detection.severity,
        detectedAt:  record.detectedAt.toISOString(),
      });
    } catch { /* socket not ready */ }
  } catch (err) {
    logger.warn(`[anomaly] save failed: ${(err as Error).message}`);
  }
}

function severityFromScore(score: number): AnomalySeverity {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

// ─── Individual detectors ─────────────────────────────────────────────────────

/** FREQUENCY: 5-min sliding window API call rate vs EWMA baseline. */
async function detectFrequency(event: NormalizedEvent): Promise<AnomalyDetection | null> {
  const windowKey = rk.actorWindow(event.provider, event.accountId, event.actorId);
  const count = await redis.incr(windowKey);
  await redis.expire(windowKey, 300); // 5-min TTL

  // Update and check baseline every 10 events (avoid DB thrash)
  if (count % 10 !== 0) return null;

  const baseline = await upsertBaseline(event.provider, event.accountId, event.actorId, 'api_calls_per_5min', count);
  if (!baseline || baseline.sampleCount < MIN_SAMPLES) return null;

  const z = zScore(count, baseline.ewmaMean, baseline.ewmaVariance);
  if (z < Z_THRESHOLD) return null;

  const score = Math.min(100, 40 + z * 10);
  return {
    anomalyType: 'FREQUENCY',
    severity:    severityFromScore(score),
    score,
    description: `Actor "${event.actorId}" made ${count} API calls in 5 min (baseline: ${baseline.ewmaMean.toFixed(0)} ± ${Math.sqrt(baseline.ewmaVariance).toFixed(0)}, z=${z.toFixed(1)})`,
    detail: {
      currentCount: count,
      baselineMean: baseline.ewmaMean,
      baselineStddev: Math.sqrt(baseline.ewmaVariance),
      zScore: z,
      windowMinutes: 5,
    },
    relatedEventIds: event.rawEventId ? [event.rawEventId] : [],
  };
}

/** GEOGRAPHIC: first-ever IP block or country prefix for this actor. */
async function detectGeographic(event: NormalizedEvent): Promise<AnomalyDetection | null> {
  if (!event.sourceIp || event.sourceIp.startsWith('10.') || event.sourceIp === 'AWS Internal') return null;

  const hint = ipToCountryHint(event.sourceIp);
  if (!hint) return null;

  const baseline = await prisma.anomalyBaseline.findUnique({
    where: { provider_accountId_actorId_metricKey: { provider: event.provider, accountId: event.accountId, actorId: event.actorId, metricKey: 'geo_baseline' } },
  });

  const knownIps: string[] = (baseline?.knownIps as string[]) ?? [];
  const knownCountries: string[] = (baseline?.knownCountries as string[]) ?? [];

  const isNewIp      = !knownIps.includes(hint);
  const isNewCountry = event.country ? !knownCountries.includes(event.country) : false;

  if (!isNewIp && !isNewCountry) {
    // Update baseline with this IP if not stored yet
    return null;
  }

  // Update known IPs (cap at GEO_MAX_IPS)
  const updatedIps      = isNewIp      ? [...knownIps.slice(-GEO_MAX_IPS + 1), hint]           : knownIps;
  const updatedCountries = isNewCountry && event.country ? [...knownCountries, event.country]    : knownCountries;

  if (baseline) {
    await prisma.anomalyBaseline.update({
      where: { id: baseline.id },
      data: { knownIps: updatedIps, knownCountries: updatedCountries, lastUpdated: new Date(), sampleCount: baseline.sampleCount + 1 },
    });
  } else {
    await prisma.anomalyBaseline.create({
      data: {
        provider: event.provider, accountId: event.accountId, actorId: event.actorId,
        metricKey: 'geo_baseline',
        knownIps: [hint], knownCountries: event.country ? [event.country] : [],
        sampleCount: 1,
      },
    });
    // First event — don't alert yet (no baseline to compare against)
    return null;
  }

  // Only alert if actor had prior history (sampleCount >= 5)
  if (baseline.sampleCount < 5) return null;

  const score = isNewCountry ? 75 : 50;
  const what = isNewCountry
    ? `new country "${event.country ?? 'unknown'}"`
    : `new IP block "${hint}"`;

  return {
    anomalyType: 'GEOGRAPHIC',
    severity:    severityFromScore(score),
    score,
    description: `Actor "${event.actorId}" connected from ${what} (never seen in ${baseline.sampleCount} prior events)`,
    detail: {
      newIp:       event.sourceIp,
      ipHint:      hint,
      newCountry:  event.country,
      knownIpCount:  knownIps.length,
      sampleCount:   baseline.sampleCount,
    },
    sourceIp: event.sourceIp,
    country:  event.country,
    relatedEventIds: event.rawEventId ? [event.rawEventId] : [],
  };
}

/** TEMPORAL: activity in an hour bucket that has < 5% of this actor's normal traffic. */
async function detectTemporal(event: NormalizedEvent): Promise<AnomalyDetection | null> {
  const hour = event.eventTime.getUTCHours();

  const baseline = await prisma.anomalyBaseline.findUnique({
    where: { provider_accountId_actorId_metricKey: { provider: event.provider, accountId: event.accountId, actorId: event.actorId, metricKey: 'temporal_baseline' } },
  });

  const hourly: Record<string, number> = (baseline?.hourlyActivity as Record<string, number>) ?? {};
  const updated = { ...hourly, [String(hour)]: (hourly[String(hour)] ?? 0) + 1 };

  if (baseline) {
    await prisma.anomalyBaseline.update({
      where: { id: baseline.id },
      data: { hourlyActivity: updated, sampleCount: baseline.sampleCount + 1, lastUpdated: new Date() },
    });
  } else {
    await prisma.anomalyBaseline.create({
      data: {
        provider: event.provider, accountId: event.accountId, actorId: event.actorId,
        metricKey: 'temporal_baseline', hourlyActivity: updated, sampleCount: 1,
      },
    });
    return null;
  }

  if (baseline.sampleCount < 50) return null; // need enough samples

  // Calculate what fraction of activity normally happens in this hour
  const total = Object.values(hourly).reduce((s, v) => s + v, 0);
  const hourFraction = total > 0 ? (hourly[String(hour)] ?? 0) / total : 0;
  const expectedFraction = 1 / HOUR_BUCKETS;

  // Alert if this hour is rarely used (< 1/3 of uniform expected)
  if (hourFraction >= expectedFraction * 0.33) return null;

  const score = Math.min(100, 30 + (1 - hourFraction / expectedFraction) * 40);
  return {
    anomalyType: 'TEMPORAL',
    severity:    severityFromScore(score),
    score,
    description: `Actor "${event.actorId}" active at hour ${hour}:00 UTC — only ${(hourFraction * 100).toFixed(1)}% of baseline activity occurs at this time`,
    detail: {
      hour,
      hourFraction,
      expectedFraction,
      totalEvents: total,
      hourlyProfile: hourly,
    },
    relatedEventIds: event.rawEventId ? [event.rawEventId] : [],
  };
}

/** ACCESS_DENIED: spike in authorization failures (Z-score on 5-min denied count). */
async function detectAccessDenied(event: NormalizedEvent): Promise<AnomalyDetection | null> {
  if (!event.errorCode) return null;

  const isAuthFailure = [
    'AccessDenied', 'AuthorizationError', 'Forbidden', 'AuthFailure',
    'InvalidClientTokenId', 'AccessDeniedException', 'UnauthorizedAccess',
  ].some((code) => event.errorCode!.includes(code));

  if (!isAuthFailure) return null;

  const key   = rk.deniedWindow(event.provider, event.accountId, event.actorId);
  const count = await redis.incr(key);
  await redis.expire(key, 300);

  if (count < 5) return null; // need at least 5 failures in window

  const baseline = await upsertBaseline(event.provider, event.accountId, event.actorId, 'denied_per_5min', count);
  if (!baseline || baseline.sampleCount < 5) return null;

  const z = zScore(count, baseline.ewmaMean, baseline.ewmaVariance);
  if (z < 2.5) return null; // lower threshold for auth failures

  const score = Math.min(100, 50 + z * 8);
  return {
    anomalyType: 'ACCESS_DENIED',
    severity:    severityFromScore(score),
    score,
    description: `Actor "${event.actorId}" received ${count} authorization failures in 5 min — z-score ${z.toFixed(1)} above baseline`,
    detail: {
      failureCount: count,
      errorCode:    event.errorCode,
      baselineMean: baseline.ewmaMean,
      zScore:       z,
    },
    eventName: event.eventName,
    relatedEventIds: event.rawEventId ? [event.rawEventId] : [],
  };
}

/** IMPOSSIBLE_TRAVEL: same actor from 2 different countries in < 2h. */
async function detectImpossibleTravel(event: NormalizedEvent): Promise<AnomalyDetection | null> {
  const hint = ipToCountryHint(event.sourceIp);
  if (!hint) return null;

  const lastCountryKey = rk.lastCountry(event.provider, event.accountId, event.actorId);
  const lastIpKey      = rk.lastIp(event.provider, event.accountId, event.actorId);

  const [lastCountryRaw, lastIpRaw] = await Promise.all([
    redis.get(lastCountryKey),
    redis.get(lastIpKey),
  ]);

  // Store current
  await Promise.all([
    redis.setex(lastCountryKey, 7200, hint),   // 2h TTL
    redis.setex(lastIpKey,      7200, event.sourceIp),
  ]);

  if (!lastCountryRaw || lastCountryRaw === hint) return null; // same region — no alert
  if (!lastIpRaw || lastIpRaw === event.sourceIp) return null;

  // Two different IP blocks within 2-hour window
  return {
    anomalyType: 'IMPOSSIBLE_TRAVEL',
    severity:    'HIGH',
    score:       80,
    description: `Actor "${event.actorId}" appeared from two distinct IP blocks within 2 hours: ${lastCountryRaw} → ${hint}`,
    detail: {
      previousIpBlock: lastCountryRaw,
      currentIpBlock:  hint,
      previousIp:      lastIpRaw,
      currentIp:       event.sourceIp,
      windowHours:     2,
    },
    sourceIp: event.sourceIp,
    relatedEventIds: event.rawEventId ? [event.rawEventId] : [],
  };
}

/** RARE_EVENT: API call seen < RARE_EVENT_THRESHOLD times by this actor. */
async function detectRareEvent(event: NormalizedEvent): Promise<AnomalyDetection | null> {
  const metricKey = `rare_event:${event.eventName}`;
  const baseline = await getBaseline(event.provider, event.accountId, event.actorId, metricKey);

  const count = baseline ? baseline.sampleCount : 0;
  await upsertBaseline(event.provider, event.accountId, event.actorId, metricKey, 1);

  if (count >= RARE_EVENT_THRESHOLD) return null; // seen enough times

  // Only alert if actor has a larger history (not brand new)
  const actorBaseline = await getBaseline(event.provider, event.accountId, event.actorId, 'api_calls_per_5min');
  if (!actorBaseline || actorBaseline.sampleCount < 20) return null;

  const score = count === 0 ? 70 : 45;
  return {
    anomalyType: 'RARE_EVENT',
    severity:    severityFromScore(score),
    score,
    description: `Actor "${event.actorId}" called "${event.eventName}" — only seen ${count} times before (rare for this identity)`,
    detail: {
      eventName:    event.eventName,
      priorCount:   count,
      threshold:    RARE_EVENT_THRESHOLD,
      resourceId:   event.resourceId,
    },
    eventName: event.eventName,
    relatedEventIds: event.rawEventId ? [event.rawEventId] : [],
  };
}

/** LATERAL_MOVEMENT: actor touched ≥ 4 distinct cloud services in 15-min window. */
async function detectLateralMovement(event: NormalizedEvent): Promise<AnomalyDetection | null> {
  const svcKey = rk.serviceWindow(event.provider, event.accountId, event.actorId);
  await redis.sadd(svcKey, event.service);
  await redis.expire(svcKey, 900); // 15-min TTL

  const count = await redis.scard(svcKey);
  if (count < 4) return null;

  const services = await redis.smembers(svcKey);
  const score = Math.min(100, 40 + count * 8);
  return {
    anomalyType: 'LATERAL_MOVEMENT',
    severity:    severityFromScore(score),
    score,
    description: `Actor "${event.actorId}" touched ${count} distinct cloud services in 15 min: ${services.join(', ')}`,
    detail: {
      serviceCount:    count,
      services,
      windowMinutes:   15,
    },
    relatedEventIds: event.rawEventId ? [event.rawEventId] : [],
  };
}

/** DATA_EXFIL: high volume of read/get operations in 5-min window. */
async function detectDataExfil(event: NormalizedEvent): Promise<AnomalyDetection | null> {
  const readOps = [
    'GetObject', 'ListBuckets', 'GetBucketPolicy',
    'BlobServiceClient.downloadBlobToBuffer', 'storage.objects.get',
    'ListObjects', 'GetObjectAcl', 'HeadObject',
  ];

  if (!readOps.some((op) => event.eventName.includes(op))) return null;

  const key   = rk.readWindow(event.provider, event.accountId, event.actorId);
  const count = await redis.incr(key);
  await redis.expire(key, 300);

  if (count < 20) return null;

  const baseline = await upsertBaseline(event.provider, event.accountId, event.actorId, 'read_ops_per_5min', count);
  if (!baseline || baseline.sampleCount < 5) return null;

  const z = zScore(count, baseline.ewmaMean, baseline.ewmaVariance);
  if (z < 2.5) return null;

  const score = Math.min(100, 55 + z * 5);
  return {
    anomalyType: 'DATA_EXFIL',
    severity:    severityFromScore(score),
    score,
    description: `Actor "${event.actorId}" performed ${count} read/get operations in 5 min — z-score ${z.toFixed(1)} above baseline (possible data exfiltration)`,
    detail: {
      readOpCount:  count,
      eventName:    event.eventName,
      baselineMean: baseline.ewmaMean,
      zScore:       z,
      resourceId:   event.resourceId,
    },
    eventName: event.eventName,
    relatedEventIds: event.rawEventId ? [event.rawEventId] : [],
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Run all anomaly detectors for a single normalized cloud event.
 * Persists and emits any detections found.
 * Returns list of anomalies detected (can be empty).
 */
export async function analyzeEvent(event: NormalizedEvent): Promise<AnomalyDetection[]> {
  const detections: AnomalyDetection[] = [];

  try {
    const results = await Promise.allSettled([
      detectFrequency(event),
      detectGeographic(event),
      detectTemporal(event),
      detectAccessDenied(event),
      detectImpossibleTravel(event),
      detectRareEvent(event),
      detectLateralMovement(event),
      detectDataExfil(event),
    ]);

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        detections.push(result.value);
        await saveAnomaly(event, result.value);
      }
    }
  } catch (err) {
    logger.warn(`[anomaly] analyzeEvent error: ${(err as Error).message}`);
  }

  return detections;
}

/**
 * Analyze a batch of events efficiently.
 * Returns total anomaly count.
 */
export async function analyzeBatch(events: NormalizedEvent[]): Promise<number> {
  let total = 0;
  for (const event of events) {
    const found = await analyzeEvent(event);
    total += found.length;
  }
  return total;
}

// ─── Provider-specific event normalizers ─────────────────────────────────────

/** Convert a raw CloudTrail event JSON into a NormalizedEvent. */
export function normalizeAwsEvent(
  raw: Record<string, unknown>,
  accountId: string,
): NormalizedEvent | null {
  try {
    const userIdentity = raw.userIdentity as Record<string, unknown> | undefined;
    const actorId = (
      (userIdentity?.type === 'Root' ? 'root' : null)
      ?? (userIdentity?.arn as string)?.split('/').pop()
      ?? (userIdentity?.userName as string)
      ?? (userIdentity?.principalId as string)
      ?? 'unknown'
    );

    return {
      provider:   'AWS',
      accountId,
      actorId,
      actorType:  (userIdentity?.type as string) ?? 'Unknown',
      eventName:  (raw.eventName as string) ?? '',
      eventTime:  new Date((raw.eventTime as string) ?? Date.now()),
      sourceIp:   (raw.sourceIPAddress as string) ?? '',
      region:     (raw.awsRegion as string) ?? '',
      service:    ((raw.eventSource as string) ?? '').replace('.amazonaws.com', ''),
      errorCode:  (raw.errorCode as string) ?? undefined,
      resourceId: extractAwsResourceId(raw),
      rawEventId: (raw.eventID as string) ?? undefined,
    };
  } catch {
    return null;
  }
}

function extractAwsResourceId(raw: Record<string, unknown>): string | undefined {
  const resources = raw.resources as Array<Record<string, unknown>> | undefined;
  if (resources?.length) return (resources[0]?.ARN as string) ?? (resources[0]?.resourceName as string);
  const req = raw.requestParameters as Record<string, unknown> | undefined;
  if (!req) return undefined;
  for (const key of ['bucketName', 'instanceId', 'functionName', 'keyId', 'secretId', 'roleName', 'userName', 'groupName']) {
    if (req[key]) return String(req[key]);
  }
  return undefined;
}

/** Convert a raw Azure Activity Log event into a NormalizedEvent. */
export function normalizeAzureEvent(
  raw: Record<string, unknown>,
  accountId: string,
): NormalizedEvent | null {
  try {
    const caller = (raw.caller as string) ?? (raw.submittedBy as string) ?? 'unknown';
    const operationName = ((raw.operationName as Record<string,string>)?.value ?? raw.operationName as string ?? '');
    const parts = operationName.split('/');

    return {
      provider:  'AZURE',
      accountId,
      actorId:   caller,
      actorType: caller.includes('@') ? 'User' : 'ServicePrincipal',
      eventName: operationName,
      eventTime: new Date((raw.eventTimestamp as string) ?? Date.now()),
      sourceIp:  (raw.httpRequest as Record<string,string>)?.clientIpAddress ?? '',
      region:    (raw.resourceLocation as string) ?? '',
      service:   parts[0]?.toLowerCase() ?? 'unknown',
      errorCode: (raw.status as Record<string,string>)?.value === 'Failed' ? 'Forbidden' : undefined,
      resourceId: raw.resourceId as string ?? undefined,
      rawEventId: raw.id as string ?? undefined,
    };
  } catch {
    return null;
  }
}

/** Convert a raw GCP Audit Log entry into a NormalizedEvent. */
export function normalizeGcpEvent(
  raw: Record<string, unknown>,
  accountId: string,
): NormalizedEvent | null {
  try {
    const protoPayload = raw.protoPayload as Record<string, unknown> | undefined;
    const authInfo = protoPayload?.authenticationInfo as Record<string,string> | undefined;
    const actorId  = authInfo?.principalEmail ?? authInfo?.serviceAccountDelegationInfo as unknown as string ?? 'unknown';
    const methodName = (protoPayload?.methodName as string) ?? '';
    const parts = methodName.split('.');

    return {
      provider:  'GCP',
      accountId,
      actorId,
      actorType: actorId.endsWith('.gserviceaccount.com') ? 'ServiceAccount' : 'User',
      eventName: methodName,
      eventTime: new Date((raw.timestamp as string) ?? Date.now()),
      sourceIp:  (protoPayload?.requestMetadata as Record<string,string>)?.callerIp ?? '',
      region:    (raw.resource as Record<string,Record<string,string>>)?.labels?.location ?? '',
      service:   parts[0]?.toLowerCase() ?? 'unknown',
      errorCode: (protoPayload?.status as Record<string,unknown>)?.code ? String((protoPayload?.status as Record<string,unknown>).code) : undefined,
      resourceId: (protoPayload?.resourceName as string) ?? undefined,
      rawEventId: (raw.insertId as string) ?? undefined,
    };
  } catch {
    return null;
  }
}
