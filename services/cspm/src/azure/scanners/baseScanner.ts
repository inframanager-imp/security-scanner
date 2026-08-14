import { ScanningResult } from '../../utils/types';
import AzureClient from '../client';
import { getCheckMetadata } from '../../checks/registry';
import { CheckSeverity } from '../../checks/types';

export abstract class AzureBaseScanner {
  protected client: AzureClient;
  protected serviceName: string;

  constructor(client: AzureClient, serviceName: string) {
    this.client = client;
    this.serviceName = serviceName;
  }

  abstract scan(): Promise<ScanningResult[]>;

  /**
   * Emit a finding for a registered check. Title/severity/remediation/tags come
   * from the check registry (single source of truth); pass `message` for the
   * resource-specific description and `remediation` only when the generic
   * guidance needs resource-specific commands substituted in.
   */
  protected emit(
    checkId: string,
    evidence: any,
    opts?: {
      message?: string;
      remediation?: string;
      severity?: CheckSeverity;
      tags?: string[];
    }
  ): ScanningResult {
    const meta = getCheckMetadata(checkId);
    return {
      id: `${this.serviceName}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      checkId,
      service: this.serviceName,
      severity: opts?.severity ?? meta.severity,
      title: meta.title,
      description: opts?.message ?? meta.description,
      evidence,
      remediation: opts?.remediation ?? meta.remediation,
      status: 'OPEN',
      tags: opts?.tags ? [...new Set([...(meta.tags ?? []), ...opts.tags])] : (meta.tags ?? []),
    };
  }

  /** @deprecated Migrate to emit(checkId, ...) — kept only for scanners not yet in the registry. */
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
