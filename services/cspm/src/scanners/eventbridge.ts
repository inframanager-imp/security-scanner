// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  EventBridgeClient,
  ListEventBusesCommand,
  DescribeEventBusCommand,
  ListEndpointsCommand,
} from '@aws-sdk/client-eventbridge';
import {
  SchemasClient,
  ListRegistriesCommand,
  GetResourcePolicyCommand,
} from '@aws-sdk/client-schemas';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** Condition keys that scope a statement to a specific account/org/source (port of Prowler's restrictive-condition logic). */
const RESTRICTIVE_CONDITION_KEYS = new Set([
  'aws:sourceaccount',
  'aws:sourcearn',
  'aws:sourceowner',
  'aws:sourcevpc',
  'aws:sourcevpce',
  'aws:principalaccount',
  'aws:principalarn',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:resourceaccount',
  'aws:sourceip',
  'aws:vpcsourceip',
]);

function hasPublicPrincipal(statement: any): boolean {
  const principal = statement?.Principal;
  if (principal === '*' || principal === 'arn:aws:iam::*:root') return true;
  if (principal && typeof principal === 'object') {
    for (const key of ['AWS', 'CanonicalUser']) {
      const value = principal[key];
      const values: any[] = Array.isArray(value) ? value : value !== undefined ? [value] : [];
      if (values.some((v) => v === '*' || v === 'arn:aws:iam::*:root')) return true;
    }
  }
  return false;
}

function hasRestrictiveCondition(statement: any): boolean {
  const condition = statement?.Condition;
  if (!condition || typeof condition !== 'object') return false;
  for (const operator of Object.keys(condition)) {
    const block = condition[operator];
    if (block && typeof block === 'object') {
      for (const key of Object.keys(block)) {
        if (RESTRICTIVE_CONDITION_KEYS.has(key.toLowerCase())) return true;
      }
    }
  }
  return false;
}

/**
 * Simplified port of Prowler's is_policy_public. With crossAccountAllowed=false
 * a statement is also flagged when its AWS principals reference accounts other
 * than the audited account (trusted accounts default to the audited account).
 */
function isPolicyPublic(policy: any, accountId: string, crossAccountAllowed: boolean): boolean {
  for (const statement of policy?.Statement ?? []) {
    if (statement?.Effect !== 'Allow') continue;
    let publicAccess = hasPublicPrincipal(statement);

    const principal = statement?.Principal;
    if (!publicAccess && !crossAccountAllowed && accountId && principal && typeof principal === 'object') {
      const aws = principal.AWS;
      const values: any[] = Array.isArray(aws) ? aws : typeof aws === 'string' ? [aws] : [];
      if (values.length > 0 && !values.every((p) => typeof p === 'string' && p.includes(accountId))) {
        publicAccess = true;
      }
    }

    if (publicAccess && !hasRestrictiveCondition(statement)) return true;
  }
  return false;
}

export class EventBridgeScanner extends BaseScanner {
  private events: EventBridgeClient;
  private schemas: SchemasClient;

  constructor(client: AWSClient) {
    super(client, 'EventBridge');
    this.events = new EventBridgeClient(client.getClientConfig());
    this.schemas = new SchemasClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting EventBridge security scan...');

      let accountId = '';
      try {
        accountId = await this.client.getAccountId();
      } catch (error) {
        logger.debug('EventBridge: unable to resolve account ID', { error: (error as Error).message });
      }

      const buses = await this.listEventBuses();
      logger.info(`EventBridge: scanning ${buses.length} event bus(es)`);
      for (const bus of buses) {
        try {
          findings.push(...(await this.validateBus(bus, accountId)));
        } catch (error) {
          logger.debug(`Failed to scan EventBridge bus ${bus.Name}`, { error: (error as Error).message });
        }
      }

      try {
        findings.push(...(await this.validateEndpoints()));
      } catch (error) {
        logger.debug('Failed to scan EventBridge global endpoints', { error: (error as Error).message });
      }

      try {
        findings.push(...(await this.validateSchemaRegistries(accountId)));
      } catch (error) {
        logger.debug('Failed to scan EventBridge schema registries', { error: (error as Error).message });
      }

      logger.info(`EventBridge scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('EventBridge scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listEventBuses(): Promise<any[]> {
    const buses: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.events.send(new ListEventBusesCommand({ NextToken: nextToken }));
      });
      buses.push(...(result.EventBuses ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return buses;
  }

  private async validateBus(bus: any, accountId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const busName: string = bus.Name ?? '';
    const busArn: string = bus.Arn ?? busName;

    const result = await retry(async () => {
      return await this.events.send(new DescribeEventBusCommand({ Name: busName }));
    });
    if (!result.Policy) return findings; // no resource policy attached

    let policy: any;
    try {
      policy = JSON.parse(result.Policy);
    } catch (error) {
      logger.debug(`Failed to parse EventBridge bus policy for ${busName}`, { error: (error as Error).message });
      return findings;
    }

    // eventbridge_bus_exposed: policy must not grant access to everyone
    if (isPolicyPublic(policy, accountId, true)) {
      findings.push(this.emit(
        'eventbridge_bus_exposed',
        { resourceId: busArn, busName, busArn },
        {
          message: `EventBridge event bus "${busName}" is exposed to everyone through its resource policy`,
        }
      ));
    }

    // eventbridge_bus_cross_account_access: policy must not allow other accounts
    if (isPolicyPublic(policy, accountId, false)) {
      findings.push(this.emit(
        'eventbridge_bus_cross_account_access',
        { resourceId: `${busArn}::cross-account`, busName, busArn },
        {
          message: `EventBridge event bus "${busName}" allows cross-account access through its resource policy`,
        }
      ));
    }

    return findings;
  }

  private async validateEndpoints(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const endpoints: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.events.send(new ListEndpointsCommand({ NextToken: nextToken }));
      });
      endpoints.push(...(result.Endpoints ?? []));
      nextToken = result.NextToken;
    } while (nextToken);

    for (const endpoint of endpoints) {
      const endpointName: string = endpoint.Name ?? '';
      const replicationState: string = endpoint.ReplicationConfig?.State ?? 'DISABLED';

      // eventbridge_global_endpoint_event_replication_enabled
      if (replicationState === 'DISABLED') {
        findings.push(this.emit(
          'eventbridge_global_endpoint_event_replication_enabled',
          { resourceId: endpoint.Arn ?? endpointName, endpointName, replicationState },
          {
            message: `EventBridge global endpoint "${endpointName}" does not have event replication enabled`,
          }
        ));
      }
    }

    return findings;
  }

  private async validateSchemaRegistries(accountId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const registries: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.schemas.send(new ListRegistriesCommand({ NextToken: nextToken }));
      });
      registries.push(...(result.Registries ?? []));
      nextToken = result.NextToken;
    } while (nextToken);

    for (const registry of registries) {
      const registryName: string = registry.RegistryName ?? '';
      // Skip AWS-owned registries (e.g. aws.events), matching Prowler
      if (!registryName || registryName.startsWith('aws.')) continue;

      let policy: any;
      try {
        const result = await retry(async () => {
          return await this.schemas.send(new GetResourcePolicyCommand({ RegistryName: registryName }));
        });
        if (!result.Policy) continue;
        policy = typeof result.Policy === 'string' ? JSON.parse(result.Policy) : result.Policy;
      } catch (error) {
        // NotFoundException means no resource policy attached
        logger.debug(`No resource policy for EventBridge schema registry ${registryName}`, { error: (error as Error).message });
        continue;
      }

      // eventbridge_schema_registry_cross_account_access
      if (isPolicyPublic(policy, accountId, false)) {
        findings.push(this.emit(
          'eventbridge_schema_registry_cross_account_access',
          { resourceId: registry.RegistryArn ?? registryName, registryName },
          {
            message: `EventBridge schema registry "${registryName}" allows cross-account access through its resource policy`,
          }
        ));
      }
    }

    return findings;
  }
}

export default EventBridgeScanner;
