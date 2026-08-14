import { CheckMetadata } from '../../types';
import { apikeysChecks } from './apikeys';
import { computeChecks } from './compute';
import { dataprocChecks } from './dataproc';
import { dnsChecks } from './dns';
import { geminiChecks } from './gemini';
import { iamChecks } from './iam';
import { loggingChecks } from './logging';
import { sqlChecks } from './sql';

/**
 * GCP check registry barrel. Mirrors the AWS pattern under
 * src/checks/registry/aws/index.ts: one named import per service file,
 * spread into a single exported array.
 *
 * Per-service files are added by the Prowler-parity porting agents incrementally.
 */
export const gcpChecks: CheckMetadata[] = [
  ...apikeysChecks,
  ...computeChecks,
  ...dataprocChecks,
  ...dnsChecks,
  ...geminiChecks,
  ...iamChecks,
  ...loggingChecks,
  ...sqlChecks,
];
