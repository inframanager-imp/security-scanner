export interface ScanningResult {
  id: string;
  timestamp: Date;
  /** Stable registry check ID (prowler-compatible), e.g. s3_bucket_default_encryption */
  checkId?: string;
  service: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  evidence: any;
  remediation: string;
  status?: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
  tags?: string[];
}

export interface ScanOptions {
  region?: string;
  regions?: string[];
  services?: string[];
  severity?: string;
  dryRun?: boolean;
  verbose?: boolean;
  profile?: string;
  configFile?: string;
  outputFormat?: 'json' | 'html' | 'csv' | 'console';
  outputFile?: string;
  parallel?: number;
  timeout?: number;
  // When set, ECR scanner skips repos whose latest image hasn't changed since this time
  lastScanAt?: Date;
  // For programmatic use (Web UI): pass pre-built client with explicit credentials
  _explicitCredentials?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
    region: string;
  };
}

export interface ScanReport {
  id: string;
  timestamp: Date;
  account: string;
  regions: string[];
  services: string[];
  totalFindings: number;
  findings: ScanningResult[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  duration?: number;
  metadata?: Record<string, any>;
}

export class ScanError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: any
  ) {
    super(message);
    this.name = 'ScanError';
  }
}

export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function calculateSeverity(
  criticalCount: number,
  highCount: number,
  mediumCount: number
): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  if (criticalCount > 0) return 'CRITICAL';
  if (highCount > 0) return 'HIGH';
  if (mediumCount > 0) return 'MEDIUM';
  return 'LOW';
}
