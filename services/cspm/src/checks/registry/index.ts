import { CheckMetadata } from '../types';
import { awsChecks } from './aws';
import { azureChecks } from './azure';
import { gcpChecks } from './gcp';

const byId = new Map<string, CheckMetadata>();
for (const checks of [awsChecks, azureChecks, gcpChecks]) {
  for (const check of checks) {
    if (byId.has(check.checkId)) {
      throw new Error(`Duplicate checkId in registry: ${check.checkId}`);
    }
    byId.set(check.checkId, check);
  }
}

export function getCheckMetadata(checkId: string): CheckMetadata {
  const meta = byId.get(checkId);
  if (!meta) {
    throw new Error(`Unknown checkId "${checkId}" — add it under src/checks/registry`);
  }
  return meta;
}

export function hasCheck(checkId: string): boolean {
  return byId.has(checkId);
}

export function allChecks(): CheckMetadata[] {
  return [...byId.values()];
}

export function checksForService(provider: CheckMetadata['provider'], service: string): CheckMetadata[] {
  return [...byId.values()].filter((c) => c.provider === provider && c.service === service);
}

/**
 * Inverted compliance index: frameworkId -> controlId -> checkIds.
 * Built from CheckMetadata.compliance; complianceService scores controls
 * against this instead of matching finding titles.
 */
export function complianceIndex(): Record<string, Record<string, string[]>> {
  const index: Record<string, Record<string, string[]>> = {};
  for (const check of byId.values()) {
    for (const [framework, controls] of Object.entries(check.compliance ?? {})) {
      index[framework] ??= {};
      for (const control of controls) {
        (index[framework][control] ??= []).push(check.checkId);
      }
    }
  }
  return index;
}
