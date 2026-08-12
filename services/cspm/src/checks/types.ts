export type CheckSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type CheckProvider = 'aws' | 'azure' | 'gcp';

/**
 * Static metadata for a security check. One entry per check, keyed by a stable
 * checkId that never changes even if the title is reworded. Where an equivalent
 * Prowler check exists, the checkId matches Prowler's naming
 * (<service>_<resource>_<condition>, e.g. s3_bucket_default_encryption) so
 * external compliance mappings can be reused directly.
 */
export interface CheckMetadata {
  checkId: string;
  provider: CheckProvider;
  /** Engine service key as used by getAvailableServices(), e.g. 's3' */
  service: string;
  title: string;
  severity: CheckSeverity;
  /** What the check verifies, resource-agnostic; per-resource detail is passed at emit time */
  description: string;
  /** Generic remediation guidance; emit-time override may add resource-specific commands */
  remediation: string;
  tags?: string[];
  /** frameworkId -> control ids, e.g. { cis_2_0_aws: ['2.1.1'], nist_800_53_r5: ['SC-8'] } */
  compliance?: Record<string, string[]>;
  references?: string[];
}
