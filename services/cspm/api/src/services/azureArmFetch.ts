/**
 * azureArmFetch
 *
 * Fetches the current state of an Azure resource directly from the ARM REST API.
 * Used after a write event to capture the real new configState for inventory sync,
 * because Azure Activity Log `properties` is operation metadata, not resource config.
 *
 * Strategy:
 *   1. Extract the resource type from the ARM resource ID path
 *   2. Look up the correct API version for that type
 *   3. GET https://management.azure.com{resourceId}?api-version={version}
 *   4. Return the parsed resource JSON, or null on any error (non-fatal)
 *
 * For sub-resources (e.g. /securityRules/ruleName), we fetch the sub-resource
 * directly so the response contains the actual rule config, not the parent NSG.
 */

import * as https  from 'https';
import * as zlib   from 'zlib';
import type { TokenCredential } from '@azure/identity';
import { logger } from '../config/logger';

// ─── API version table ────────────────────────────────────────────────────────

const API_VERSIONS: [string, string][] = [
  // Network
  ['microsoft.network/networksecuritygroups/securityrules',       '2023-09-01'],
  ['microsoft.network/networksecuritygroups',                     '2023-09-01'],
  ['microsoft.network/virtualnetworks/subnets',                   '2023-09-01'],
  ['microsoft.network/virtualnetworks',                           '2023-09-01'],
  ['microsoft.network/publicipaddresses',                         '2023-09-01'],
  ['microsoft.network/loadbalancers',                             '2023-09-01'],
  ['microsoft.network/applicationgateways',                       '2023-09-01'],
  ['microsoft.network/firewallpolicies',                          '2023-09-01'],
  ['microsoft.network/azurefirewalls',                            '2023-09-01'],
  ['microsoft.network/routetables',                               '2023-09-01'],
  ['microsoft.network/privateendpoints',                          '2023-09-01'],
  ['microsoft.network/dnszones',                                  '2018-05-01'],
  ['microsoft.network/networkinterfaces',                         '2023-09-01'],
  ['microsoft.network/virtualnetworkgateways',                    '2023-09-01'],
  ['microsoft.network/connections',                               '2023-09-01'],
  ['microsoft.network',                                           '2023-09-01'],
  // Compute
  ['microsoft.compute/virtualmachines/extensions',                '2023-09-01'],
  ['microsoft.compute/virtualmachines',                           '2023-09-01'],
  ['microsoft.compute/virtualmachinescalesets',                   '2023-09-01'],
  ['microsoft.compute/disks',                                     '2023-10-02'],
  ['microsoft.compute/snapshots',                                 '2023-10-02'],
  ['microsoft.compute/images',                                    '2023-09-01'],
  ['microsoft.compute',                                           '2023-09-01'],
  // Storage
  ['microsoft.storage/storageaccounts/blobservices/containers',   '2023-05-01'],
  ['microsoft.storage/storageaccounts/blobservices',              '2023-05-01'],
  ['microsoft.storage/storageaccounts',                           '2023-05-01'],
  ['microsoft.storage',                                           '2023-05-01'],
  // IAM / Authorization
  ['microsoft.authorization/roleassignments',                     '2022-04-01'],
  ['microsoft.authorization/roledefinitions',                     '2022-04-01'],
  ['microsoft.authorization/policyassignments',                   '2023-04-01'],
  ['microsoft.authorization/policysetdefinitions',                '2023-04-01'],
  ['microsoft.authorization/policydefinitions',                   '2023-04-01'],
  ['microsoft.authorization',                                     '2022-04-01'],
  // Key Vault
  ['microsoft.keyvault/vaults/secrets',                           '2023-07-01'],
  ['microsoft.keyvault/vaults/keys',                              '2023-07-01'],
  ['microsoft.keyvault/vaults',                                   '2023-07-01'],
  ['microsoft.keyvault',                                          '2023-07-01'],
  // Databases
  ['microsoft.sql/servers/databases',                             '2023-05-01-preview'],
  ['microsoft.sql/servers/firewallrules',                         '2023-05-01-preview'],
  ['microsoft.sql/servers',                                       '2023-05-01-preview'],
  ['microsoft.sql',                                               '2023-05-01-preview'],
  ['microsoft.dbforpostgresql/flexibleservers',                   '2023-06-01-preview'],
  ['microsoft.dbformysql/flexibleservers',                        '2023-12-30'],
  ['microsoft.documentdb/databaseaccounts',                       '2024-02-15-preview'],
  ['microsoft.documentdb',                                        '2024-02-15-preview'],
  // Web / App Service
  ['microsoft.web/sites/config',                                  '2023-12-01'],
  ['microsoft.web/sites',                                         '2023-12-01'],
  ['microsoft.web/serverfarms',                                   '2023-12-01'],
  ['microsoft.web',                                               '2023-12-01'],
  // Container
  ['microsoft.containerservice/managedclusters',                  '2024-02-01'],
  ['microsoft.containerservice',                                   '2024-02-01'],
  ['microsoft.containerregistry/registries',                      '2023-11-01-preview'],
  ['microsoft.containerregistry',                                 '2023-11-01-preview'],
  // Monitoring / Logging
  ['microsoft.insights/diagnosticsettings',                       '2021-05-01-preview'],
  ['microsoft.insights/activitylogalerts',                        '2020-10-01'],
  ['microsoft.insights/metricalerts',                             '2018-03-01'],
  ['microsoft.operationalinsights/workspaces',                    '2023-09-01'],
  ['microsoft.operationalinsights',                               '2023-09-01'],
  // Identity
  ['microsoft.managedidentity/userassignedidentities',            '2023-07-31-preview'],
  ['microsoft.managedidentity',                                   '2023-07-31-preview'],
  // Misc
  ['microsoft.redis/redis',                                       '2023-08-01'],
  ['microsoft.servicebus/namespaces',                             '2022-10-01-preview'],
  ['microsoft.eventhub/namespaces',                               '2024-01-01'],
  ['microsoft.iothub/iothubs',                                    '2023-06-30'],
  ['microsoft.search/searchservices',                             '2023-11-01'],
  ['microsoft.cognitiveservices/accounts',                        '2023-10-01-preview'],
  ['microsoft.apimanagement/service',                             '2023-09-01-preview'],
  ['microsoft.automation/automationaccounts',                     '2023-11-01'],
  ['microsoft.recoveryservices/vaults',                           '2024-04-01'],
  ['microsoft.datafactory/factories',                             '2018-06-01'],
];

function resolveApiVersion(resourceId: string): string {
  const lower = resourceId.toLowerCase();
  const providersIdx = lower.indexOf('/providers/');
  if (providersIdx === -1) return '2022-09-01'; // fallback

  const afterProviders = lower.slice(providersIdx + '/providers/'.length);
  const segments = afterProviders.split('/');

  const candidates: string[] = [];
  let key = '';
  for (let i = 0; i < segments.length; i++) {
    if (i === 0 || i % 2 === 1) {
      key = key ? `${key}/${segments[i]}` : segments[i];
      candidates.push(key);
    }
  }

  // Match longest candidate first
  for (let i = candidates.length - 1; i >= 0; i--) {
    for (const [pattern, version] of API_VERSIONS) {
      if (candidates[i] === pattern) return version;
    }
  }

  // Prefix fallback
  for (let i = candidates.length - 1; i >= 0; i--) {
    for (const [pattern, version] of API_VERSIONS) {
      if (candidates[i].startsWith(pattern)) return version;
    }
  }

  return '2022-09-01';
}

// ─── Direct HTTPS GET against ARM ────────────────────────────────────────────

async function armGet(token: string, resourceId: string, apiVersion: string): Promise<Record<string, unknown> | null> {
  const path = `${resourceId}?api-version=${apiVersion}`;

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'management.azure.com',
      path,
      method:  'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept:        'application/json',
      },
      timeout: 15_000,
    }, (res) => {
      const chunks: Buffer[] = [];
      const enc = (res.headers['content-encoding'] ?? '').toLowerCase();
      let stream: import('stream').Readable = res;
      if      (enc === 'gzip')    stream = res.pipe(zlib.createGunzip());
      else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
      else if (enc === 'br')      stream = res.pipe(zlib.createBrotliDecompress());

      stream.on('data', (c: Buffer) => chunks.push(c));
      stream.on('error', () => resolve(null));
      stream.on('end', () => {
        try {
          const body = Buffer.concat(chunks).toString('utf8');
          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            logger.debug(`[armFetch] ${res.statusCode} for ${resourceId.slice(-80)}`);
            resolve(null);
            return;
          }
          const json = JSON.parse(body) as Record<string, unknown>;
          resolve(json);
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Fetches the current state of an Azure resource from ARM.
 * Returns the full resource JSON (id, name, type, properties, tags, etc.)
 * or null if the resource doesn't exist or the call fails.
 *
 * Non-throwing — always returns null on any error so callers can
 * continue with degraded (metadata-only) state.
 */
export async function fetchAzureResourceState(
  credential: TokenCredential,
  resourceId: string,
): Promise<Record<string, unknown> | null> {
  try {
    const tokenResponse = await credential.getToken('https://management.azure.com/.default');
    if (!tokenResponse?.token) return null;

    const apiVersion = resolveApiVersion(resourceId);
    const result = await armGet(tokenResponse.token, resourceId, apiVersion);

    if (result) {
      logger.debug(`[armFetch] fetched ${resourceId.split('/providers/')[1]?.slice(0, 60)} (api=${apiVersion})`);
    }
    return result;
  } catch (err) {
    logger.debug(`[armFetch] failed for ${resourceId.slice(-60)}: ${(err as Error).message}`);
    return null;
  }
}
