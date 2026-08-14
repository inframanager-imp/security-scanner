import { CheckMetadata } from '../../types';
import { appinsightsChecks } from './appinsights';
import { appserviceChecks } from './appservice';
import { cosmosChecks } from './cosmos';
import { databricksChecks } from './databricks';
import { defenderChecks } from './defender';
import { entraChecks } from './entra';
import { functionsChecks } from './functions';
import { keyvaultChecks } from './keyvault';
import { monitorChecks } from './monitor';
import { networkChecks } from './network';
import { nsgChecks } from './nsg';
import { policyChecks } from './policy';
import { postgresChecks } from './postgres';
import { sqlChecks } from './sql';
import { storageChecks } from './storage';
import { vmChecks } from './vm';

/**
 * Azure check registry barrel. Mirrors the AWS pattern under
 * src/checks/registry/aws/index.ts: one named import per service file,
 * spread into a single exported array.
 *
 * Per-service files (e.g. ./defender.ts, ./vm.ts) are added by the
 * Prowler-parity porting agents.
 */
export const azureChecks: CheckMetadata[] = [
  ...appinsightsChecks,
  ...appserviceChecks,
  ...cosmosChecks,
  ...databricksChecks,
  ...defenderChecks,
  ...entraChecks,
  ...functionsChecks,
  ...keyvaultChecks,
  ...monitorChecks,
  ...networkChecks,
  ...nsgChecks,
  ...policyChecks,
  ...postgresChecks,
  ...sqlChecks,
  ...storageChecks,
  ...vmChecks,
];
