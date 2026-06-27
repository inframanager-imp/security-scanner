// Export all types and interfaces
export { ScanningResult, ScanOptions, ScanReport, ScanError } from './utils/types';
export { ScanEngine } from './scanners/engine';
export { CloudTrailScanner } from './scanners/cloudtrail';
export { IAMScanner } from './scanners/iam';
export { S3Scanner } from './scanners/s3';
export { EC2Scanner } from './scanners/ec2';
export { RDSScanner } from './scanners/rds';
export { KMSScanner } from './scanners/kms';
export { SecretsManagerScanner } from './scanners/secretsmanager';
export { JSONReporter, CSVReporter, ConsoleReporter } from './reporters/reporters';
export { HTMLReporter } from './reporters/htmlreporter';
export { AWSClient } from './aws/client';
export { CredentialsManager } from './aws/credentials';
export { default as logger } from './utils/logger';
export { default as cache } from './utils/cache';

// If running as CLI
if (require.main === module) {
  require('./cli/index');
}
