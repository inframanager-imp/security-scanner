import { ScanningResult } from '../utils/types';
import AWSClient from '../aws/client';

export interface ScannerOptions {
  region?: string;
  verbose?: boolean;
  parallel?: number;
  timeout?: number;
  /** When set, ECR scanner skips repos whose latest image was pushed before this date */
  lastScanAt?: Date;
}

export abstract class BaseScanner {
  protected client: AWSClient;
  protected serviceName: string;

  constructor(client: AWSClient, serviceName: string) {
    this.client = client;
    this.serviceName = serviceName;
  }

  abstract scan(options?: ScannerOptions): Promise<ScanningResult[]>;

  protected createFinding(
    title: string,
    description: string,
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
    evidence: any,
    remediation: string,
    tags?: string[]
  ): ScanningResult {
    return {
      id: `${this.serviceName}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      service: this.serviceName,
      severity,
      title,
      description,
      evidence,
      remediation,
      status: 'OPEN',
      tags: tags || []
    };
  }
}

export default BaseScanner;
