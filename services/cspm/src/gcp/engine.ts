import GcpClient, { GcpClientOptions } from './client';
import { GcpIAMScanner }              from './scanners/iamScanner';
import { GcpStorageScanner }          from './scanners/storageScanner';
import { GcpComputeScanner }          from './scanners/computeScanner';
import { GcpSQLScanner }              from './scanners/sqlScanner';
import { GcpGKEScanner }              from './scanners/gkeScanner';
import { GcpCloudRunScanner }         from './scanners/cloudRunScanner';
import { GcpBigQueryScanner }         from './scanners/bigQueryScanner';
import { GcpKMSScanner }              from './scanners/kmsScanner';
import { GcpSecretManagerScanner }    from './scanners/secretManagerScanner';
import { GcpCloudFunctionsScanner }   from './scanners/cloudFunctionsScanner';
import { GcpPubSubScanner }           from './scanners/pubSubScanner';
import { GcpArtifactRegistryScanner } from './scanners/artifactRegistryScanner';
import { GcpLoggingScanner }          from './scanners/loggingScanner';
import { GcpApiKeysScanner }          from './scanners/apikeysScanner';
import { GcpDnsScanner }              from './scanners/dnsScanner';
import { GcpDataprocScanner }         from './scanners/dataprocScanner';
import { GcpGeminiScanner }           from './scanners/geminiScanner';
import { ScanningResult, ScanReport } from '../utils/types';

export interface GcpScanOptions {
  services?:   string[];
  credentials: GcpClientOptions;
}

export const GCP_SERVICES = [
  'iam',
  'storage',
  'compute',
  'sql',
  'gke',
  'cloudrun',
  'bigquery',
  'kms',
  'secretmanager',
  'cloudfunctions',
  'pubsub',
  'artifactregistry',
  'logging',
  'apikeys',
  'dns',
  'dataproc',
  'gemini',
];

export class GcpScanEngine {
  async executeScan(options: GcpScanOptions): Promise<ScanReport> {
    const startTime = Date.now();
    const findings:  ScanningResult[] = [];
    const services   = options.services ?? GCP_SERVICES;

    const client = new GcpClient(options.credentials);

    const scannerMap: Record<string, () => Promise<ScanningResult[]>> = {
      iam:              () => new GcpIAMScanner(client).scan(),
      storage:          () => new GcpStorageScanner(client).scan(),
      compute:          () => new GcpComputeScanner(client).scan(),
      sql:              () => new GcpSQLScanner(client).scan(),
      gke:              () => new GcpGKEScanner(client).scan(),
      cloudrun:         () => new GcpCloudRunScanner(client).scan(),
      bigquery:         () => new GcpBigQueryScanner(client).scan(),
      kms:              () => new GcpKMSScanner(client).scan(),
      secretmanager:    () => new GcpSecretManagerScanner(client).scan(),
      cloudfunctions:   () => new GcpCloudFunctionsScanner(client).scan(),
      pubsub:           () => new GcpPubSubScanner(client).scan(),
      artifactregistry: () => new GcpArtifactRegistryScanner(client).scan(),
      logging:          () => new GcpLoggingScanner(client).scan(),
      apikeys:          () => new GcpApiKeysScanner(client).scan(),
      dns:              () => new GcpDnsScanner(client).scan(),
      dataproc:         () => new GcpDataprocScanner(client).scan(),
      gemini:           () => new GcpGeminiScanner(client).scan(),
    };

    for (const svc of services) {
      const runner = scannerMap[svc];
      if (!runner) continue;
      try {
        const results = await runner();
        findings.push(...results);
      } catch (err) {
        findings.push({
          id:          `gcp-${svc}-error-${Date.now()}`,
          timestamp:   new Date(),
          service:     `GCP-${svc}`,
          severity:    'INFO',
          title:       `Scanner error — ${svc}`,
          description: `The ${svc} scanner encountered an unexpected error: ${(err as Error).message}`,
          evidence:    { error: (err as Error).message },
          remediation: `Verify that the service account has the required permissions for GCP ${svc}.`,
          status:      'OPEN',
          tags:        ['scanner-error'],
        });
      }
    }

    const duration = Date.now() - startTime;

    return {
      id:            `gcp-${Date.now()}`,
      timestamp:     new Date(),
      account:       options.credentials.projectId,
      regions:       ['gcp-global'],
      services,
      totalFindings: findings.length,
      findings,
      summary: {
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high:     findings.filter(f => f.severity === 'HIGH').length,
        medium:   findings.filter(f => f.severity === 'MEDIUM').length,
        low:      findings.filter(f => f.severity === 'LOW').length,
        info:     findings.filter(f => f.severity === 'INFO').length,
      },
      duration,
    };
  }
}

export default GcpScanEngine;
