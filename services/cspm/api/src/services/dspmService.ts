/**
 * DSPM Service — Sensitive Data Discovery
 *
 * For each storage resource (S3 bucket / Azure blob container / GCS bucket),
 * sample a configurable number of objects, run the classifier bundle, and
 * persist DataClassification rows + update ResourceInventory.dataSensitivity.
 *
 * If the storage is publicly exposed AND we found HIGH-confidence sensitive
 * data, emit a CRITICAL Finding (scope: most recent scan for the account).
 *
 * Phase 6 implements AWS S3 fully. Azure / GCP storage are scaffolded so the
 * pipeline runs end-to-end across providers; their object-list/get calls can
 * be plugged in later without changing this orchestrator.
 */

import {
  S3Client,
  ListObjectsV2Command,
  GetObjectCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { prisma } from '../config/database';
import { logger } from '../config/logger';
import * as credentialService from './credentialService';
import {
  classifyText,
  aggregateByDataType,
  confidenceFromMatches,
  sensitivityForDataTypes,
  CLASSIFIER_VERSION,
  type DataType,
} from './classifiers/dataClassifiers';

type Provider = 'AWS' | 'AZURE' | 'GCP';

const DEFAULT_SAMPLE_OBJECTS = 25;
const MAX_OBJECT_BYTES = 256 * 1024; // 256 KB per object
const EXPIRES_DAYS = 30;

export interface DspmResult {
  resourcesScanned: number;
  classifications: number;
  findingsEmitted: number;
}

export async function runDspmScanForAccount(provider: Provider, accountId: string): Promise<DspmResult> {
  if (provider === 'AWS')   return runAwsDspm(accountId);
  if (provider === 'AZURE') return runAzureDspm(accountId);
  return runGcpDspm(accountId);
}

// ─── AWS: scan S3 buckets ────────────────────────────────────────────────────

async function runAwsDspm(accountId: string): Promise<DspmResult> {
  const cred = await prisma.awsCredential.findUnique({ where: { accountId } });
  if (!cred) return zero();
  const decrypted = credentialService.decryptCredentials(cred);

  let credentials = {
    accessKeyId: decrypted.accessKeyId!,
    secretAccessKey: decrypted.secretAccessKey!,
    sessionToken: undefined as string | undefined,
  };
  if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
    const sts = new STSClient({ region: cred.defaultRegion, credentials });
    const out = await sts.send(new AssumeRoleCommand({
      RoleArn: cred.roleArn,
      RoleSessionName: `dspm-${accountId.slice(0, 16)}`,
      DurationSeconds: 900,
      ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
    }));
    if (!out.Credentials) throw new Error('STS AssumeRole returned no credentials');
    credentials = {
      accessKeyId: out.Credentials.AccessKeyId!,
      secretAccessKey: out.Credentials.SecretAccessKey!,
      sessionToken: out.Credentials.SessionToken,
    };
  }

  const buckets = await prisma.resourceInventory.findMany({
    where: { awsAccountId: accountId, resourceType: 'AWS::S3::Bucket', state: 'ACTIVE' },
    take: 100,
  });

  let resourcesScanned = 0;
  let classifications = 0;
  let findingsEmitted = 0;

  for (const bucket of buckets) {
    const bucketName = bucket.nativeId.split(':').pop()?.split('/').pop() ?? bucket.nativeId;
    const region = bucket.region ?? cred.defaultRegion;
    const s3 = new S3Client({ region, credentials });

    try {
      const result = await scanBucket(s3, bucketName, DEFAULT_SAMPLE_OBJECTS);
      resourcesScanned++;
      if (result.aggregates.length === 0) {
        // No sensitive data; clear any previous dataSensitivity
        await prisma.resourceInventory.update({
          where: { id: bucket.id },
          data: { dataSensitivity: 'LOW' },
        });
        continue;
      }

      const sensitivity = sensitivityForDataTypes(result.aggregates.map((a) => a.type));
      await prisma.resourceInventory.update({
        where: { id: bucket.id },
        data: { dataSensitivity: sensitivity },
      });

      for (const agg of result.aggregates) {
        const confidence = confidenceFromMatches(agg.matches, result.sampledObjects);
        await prisma.dataClassification.upsert({
          where: { resourceInventoryId_dataType: { resourceInventoryId: bucket.id, dataType: agg.type } },
          update: {
            confidence,
            sampleCount: agg.matches,
            totalObjectsSampled: result.sampledObjects,
            evidence: {
              labels: agg.labels,
              examples: agg.examples,
              samplePaths: result.samplePaths.slice(0, 10),
              classifierVersion: CLASSIFIER_VERSION,
            } as any,
            classifiedAt: new Date(),
            expiresAt: new Date(Date.now() + EXPIRES_DAYS * 86_400_000),
          },
          create: {
            provider: 'AWS',
            accountId,
            resourceInventoryId: bucket.id,
            dataType: agg.type,
            confidence,
            sampleCount: agg.matches,
            totalObjectsSampled: result.sampledObjects,
            evidence: {
              labels: agg.labels,
              examples: agg.examples,
              samplePaths: result.samplePaths.slice(0, 10),
              classifierVersion: CLASSIFIER_VERSION,
            } as any,
            expiresAt: new Date(Date.now() + EXPIRES_DAYS * 86_400_000),
          },
        });
        classifications++;
      }

      // Emit CRITICAL Finding if bucket is internet-exposed AND high-confidence sensitive
      const exposure = await prisma.exposurePath.findUnique({
        where: { resourceInventoryId_exposureType: { resourceInventoryId: bucket.id, exposureType: 'PUBLIC_INTERNET' } },
      });
      const hasHighConfidenceSensitive =
        result.aggregates.some((a) => sensitivityForDataTypes([a.type]) === 'CRITICAL' && confidenceFromMatches(a.matches, result.sampledObjects) === 'HIGH');
      if (exposure && hasHighConfidenceSensitive) {
        await emitDspmFinding(accountId, bucket, result.aggregates);
        findingsEmitted++;
      }
    } catch (err) {
      logger.debug('dspm.bucket.failed', {
        accountId, bucketName, error: (err as Error).message,
      });
    }
  }

  return { resourcesScanned, classifications, findingsEmitted };
}

async function scanBucket(
  s3: S3Client,
  bucket: string,
  maxObjects: number,
): Promise<{ aggregates: ReturnType<typeof aggregateByDataType>; sampledObjects: number; samplePaths: string[] }> {
  const samplePaths: string[] = [];
  let aggregateResults: ReturnType<typeof classifyText> = [];
  let sampled = 0;

  const list = await s3.send(new ListObjectsV2Command({ Bucket: bucket, MaxKeys: maxObjects * 4 }));
  const candidates = (list.Contents ?? []).filter((o) => (o.Size ?? 0) > 16 && (o.Size ?? 0) < MAX_OBJECT_BYTES * 4).slice(0, maxObjects);

  for (const obj of candidates) {
    if (!obj.Key) continue;
    try {
      const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: obj.Key }));
      const contentType = head.ContentType ?? '';
      // Skip binary unless small enough to be text-like
      if (/image|video|audio|font|application\/octet-stream/.test(contentType) && (obj.Size ?? 0) > 8192) continue;

      const getResp = await s3.send(new GetObjectCommand({
        Bucket: bucket,
        Key: obj.Key,
        Range: `bytes=0-${MAX_OBJECT_BYTES - 1}`,
      }));
      const body = await getResp.Body?.transformToString('utf-8').catch(() => null);
      if (!body) continue;

      const hits = classifyText(body);
      if (hits.length > 0) {
        aggregateResults = aggregateResults.concat(hits);
        samplePaths.push(obj.Key);
      }
      sampled++;
    } catch {
      // Per-object errors are expected (encryption, ACL, etc.) — skip
    }
  }

  return { aggregates: aggregateByDataType(aggregateResults), sampledObjects: sampled, samplePaths };
}

async function emitDspmFinding(
  accountId: string,
  bucket: { id: string; nativeId: string; resourceType: string; region: string | null },
  aggregates: ReturnType<typeof aggregateByDataType>,
): Promise<void> {
  // Attach to the latest scan for this account; if none, skip (the UI surfaces via DataClassification anyway).
  const scan = await prisma.scan.findFirst({
    where: { accountId },
    orderBy: { createdAt: 'desc' },
  });
  if (!scan) return;

  const dataTypes = aggregates.map((a) => a.type).join(', ');
  const evidence = {
    resourceId: bucket.nativeId,
    bucket: bucket.nativeId,
    dataTypes: aggregates.map((a) => ({ type: a.type, matches: a.matches, labels: a.labels })),
    classifierVersion: CLASSIFIER_VERSION,
  };
  await prisma.finding.create({
    data: {
      scanId: scan.id,
      service: 's3-dspm',
      severity: 'CRITICAL',
      title: 'Public S3 Bucket Contains Sensitive Data',
      description: `Bucket "${bucket.nativeId}" is publicly accessible and contains sensitive data types (${dataTypes}) detected by DSPM. This is a confirmed exposure of regulated data and should be remediated immediately.`,
      evidence: evidence as any,
      remediation: 'Restrict public access on the bucket (Block Public Access) and audit access logs for prior reads. Move sensitive data to a private bucket with appropriate access controls and encryption.',
      tags: ['dspm', 'data-exposure', 'critical', 's3'],
      findingStatus: 'OPEN',
      discoveredAt: new Date(),
    },
  });
}

// ─── Azure / GCP stubs ───────────────────────────────────────────────────────

async function runAzureDspm(subscriptionId: string): Promise<DspmResult> {
  logger.info('dspm.azure.stub', { subscriptionId });
  return zero();
}

async function runGcpDspm(projectId: string): Promise<DspmResult> {
  logger.info('dspm.gcp.stub', { projectId });
  return zero();
}

function zero(): DspmResult {
  return { resourcesScanned: 0, classifications: 0, findingsEmitted: 0 };
}
