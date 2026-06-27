import { ScanningResult } from '../../utils/types';
import AzureClient from '../client';

export abstract class AzureBaseScanner {
  protected client: AzureClient;
  protected serviceName: string;

  constructor(client: AzureClient, serviceName: string) {
    this.client = client;
    this.serviceName = serviceName;
  }

  abstract scan(): Promise<ScanningResult[]>;

  protected finding(
    title: string,
    description: string,
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
    evidence: Record<string, unknown>,
    remediation: string,
    tags: string[] = [],
  ): ScanningResult {
    return {
      id: `${this.serviceName}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      timestamp: new Date(),
      service: this.serviceName,
      severity,
      title,
      description,
      evidence,
      remediation,
      status: 'OPEN',
      tags,
    };
  }
}
