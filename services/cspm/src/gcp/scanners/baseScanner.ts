import { ScanningResult } from '../../utils/types';
import GcpClient from '../client';

export abstract class GcpBaseScanner {
  protected client:      GcpClient;
  protected serviceName: string;

  constructor(client: GcpClient, serviceName: string) {
    this.client      = client;
    this.serviceName = serviceName;
  }

  abstract scan(): Promise<ScanningResult[]>;

  protected finding(
    title:       string,
    description: string,
    severity:    'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
    evidence:    Record<string, unknown>,
    remediation: string,
    tags:        string[] = [],
  ): ScanningResult {
    return {
      id:          `${this.serviceName}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      timestamp:   new Date(),
      service:     this.serviceName,
      severity,
      title,
      description,
      evidence,
      remediation,
      status:      'OPEN',
      tags,
    };
  }

  /** Collect all pages from a GCP list API */
  protected async paginate<T>(
    fn: (pageToken?: string) => Promise<{ data: { items?: T[]; nextPageToken?: string | null } }>,
  ): Promise<T[]> {
    const all: T[] = [];
    let token: string | undefined;
    do {
      const res = await fn(token);
      all.push(...(res.data.items ?? []));
      token = res.data.nextPageToken ?? undefined;
    } while (token);
    return all;
  }
}
