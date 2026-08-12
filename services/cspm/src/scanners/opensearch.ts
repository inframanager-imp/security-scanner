// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  OpenSearchClient,
  ListDomainNamesCommand,
  DescribeDomainCommand,
} from '@aws-sdk/client-opensearch';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** Condition keys that scope a statement enough that it is not considered public. */
const RESTRICTIVE_CONDITION_KEYS = [
  'aws:sourceip',
  'aws:sourcevpc',
  'aws:sourcevpce',
  'aws:sourceaccount',
  'aws:sourcearn',
  'aws:sourceowner',
  'aws:principalorgid',
  'aws:principalaccount',
  'aws:principalarn',
];

function hasPublicPrincipal(statement: any): boolean {
  const principal = statement?.Principal;
  if (principal === '*') return true;
  if (principal && typeof principal === 'object') {
    const aws = principal.AWS;
    if (aws === '*') return true;
    if (Array.isArray(aws) && aws.includes('*')) return true;
  }
  return false;
}

function hasRestrictiveCondition(statement: any): boolean {
  const condition = statement?.Condition;
  if (!condition || typeof condition !== 'object') return false;
  for (const operatorValue of Object.values(condition)) {
    if (operatorValue && typeof operatorValue === 'object') {
      for (const key of Object.keys(operatorValue as object)) {
        if (RESTRICTIVE_CONDITION_KEYS.includes(key.toLowerCase())) return true;
      }
    }
  }
  return false;
}

/** Simplified port of Prowler's is_policy_public(): Allow + wildcard principal + no scoping condition. */
function isPolicyPublic(policy: any): boolean {
  const rawStatements = policy?.Statement;
  const statements: any[] = Array.isArray(rawStatements) ? rawStatements : rawStatements ? [rawStatements] : [];
  return statements.some(
    (s) => s?.Effect === 'Allow' && hasPublicPrincipal(s) && !hasRestrictiveCondition(s)
  );
}

export class OpenSearchScanner extends BaseScanner {
  private opensearch: OpenSearchClient;

  constructor(client: AWSClient) {
    super(client, 'OpenSearch');
    this.opensearch = new OpenSearchClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting OpenSearch security scan...');

      const domainNames = await this.listDomainNames();
      for (const domainName of domainNames) {
        logger.debug(`Scanning OpenSearch domain: ${domainName}`);
        try {
          const domainFindings = await this.validateDomain(domainName);
          findings.push(...domainFindings);
        } catch (error) {
          logger.debug(`Failed to scan OpenSearch domain ${domainName}`, { error: (error as Error).message });
        }
      }

      logger.info(`OpenSearch scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('OpenSearch scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listDomainNames(): Promise<string[]> {
    const result = await retry(async () => {
      return await this.opensearch.send(new ListDomainNamesCommand({}));
    });
    return (result.DomainNames ?? [])
      .map((d) => d.DomainName)
      .filter((name): name is string => !!name);
  }

  private async validateDomain(domainName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const result = await retry(async () => {
      return await this.opensearch.send(new DescribeDomainCommand({ DomainName: domainName }));
    });
    const status: any = result.DomainStatus;
    if (!status) return findings;

    const vpcId: string = status.VPCOptions?.VPCId ?? '';

    // opensearch_service_domains_not_publicly_accessible
    // Domains inside a VPC are treated as privately reachable
    if (!vpcId) {
      let accessPolicy: any = null;
      if (status.AccessPolicies) {
        try {
          accessPolicy = JSON.parse(status.AccessPolicies);
        } catch (error) {
          logger.debug(`Failed to parse access policy for OpenSearch domain ${domainName}`, { error: (error as Error).message });
        }
      }
      if (accessPolicy && isPolicyPublic(accessPolicy)) {
        findings.push(this.emit(
          'opensearch_service_domains_not_publicly_accessible',
          { domain: domainName, vpc: false, accessPolicy },
          {
            message: `OpenSearch domain "${domainName}" is publicly accessible via its access policy`,
            remediation: `Place domain "${domainName}" in a VPC or replace the wildcard-principal access policy with narrowly scoped principals and conditions`,
          }
        ));
      }
    }

    // opensearch_service_domains_encryption_at_rest_enabled
    if (!status.EncryptionAtRestOptions?.Enabled) {
      findings.push(this.emit(
        'opensearch_service_domains_encryption_at_rest_enabled',
        { domain: domainName, encryptionAtRest: false },
        { message: `OpenSearch domain "${domainName}" does not have encryption at rest enabled` }
      ));
    }

    // opensearch_service_domains_https_communications_enforced
    if (!status.DomainEndpointOptions?.EnforceHTTPS) {
      findings.push(this.emit(
        'opensearch_service_domains_https_communications_enforced',
        { domain: domainName, enforceHTTPS: false },
        { message: `OpenSearch domain "${domainName}" does not enforce HTTPS for all traffic` }
      ));
    }

    // opensearch_service_domains_node_to_node_encryption_enabled
    if (!status.NodeToNodeEncryptionOptions?.Enabled) {
      findings.push(this.emit(
        'opensearch_service_domains_node_to_node_encryption_enabled',
        { domain: domainName, nodeToNodeEncryption: false },
        { message: `OpenSearch domain "${domainName}" does not have node-to-node encryption enabled` }
      ));
    }

    const advancedSecurity: any = status.AdvancedSecurityOptions ?? {};

    // opensearch_service_domains_access_control_enabled
    if (!advancedSecurity.Enabled) {
      findings.push(this.emit(
        'opensearch_service_domains_access_control_enabled',
        { domain: domainName, fineGrainedAccessControl: false },
        { message: `OpenSearch domain "${domainName}" does not have fine-grained access control enabled` }
      ));
    }

    // opensearch_service_domains_internal_user_database_enabled
    if (advancedSecurity.InternalUserDatabaseEnabled) {
      findings.push(this.emit(
        'opensearch_service_domains_internal_user_database_enabled',
        { domain: domainName, internalUserDatabase: true },
        { message: `OpenSearch domain "${domainName}" has the internal user database enabled instead of federated authentication` }
      ));
    }

    // opensearch_service_domains_use_cognito_authentication_for_kibana
    const cognitoEnabled = status.CognitoOptions?.Enabled === true;
    const samlEnabled = advancedSecurity.SAMLOptions?.Enabled === true;
    if (!cognitoEnabled && !samlEnabled) {
      findings.push(this.emit(
        'opensearch_service_domains_use_cognito_authentication_for_kibana',
        { domain: domainName, cognitoEnabled, samlEnabled },
        { message: `OpenSearch domain "${domainName}" has neither Amazon Cognito nor SAML authentication enabled for Dashboards/Kibana` }
      ));
    }

    // opensearch_service_domains_audit_logging_enabled
    const logPublishingOptions: any = status.LogPublishingOptions ?? {};
    const auditLogsEnabled = logPublishingOptions.AUDIT_LOGS?.Enabled === true;
    if (!auditLogsEnabled) {
      findings.push(this.emit(
        'opensearch_service_domains_audit_logging_enabled',
        { domain: domainName, auditLogs: false },
        { message: `OpenSearch domain "${domainName}" does not have audit logging (AUDIT_LOGS) enabled` }
      ));
    }

    // opensearch_service_domains_cloudwatch_logging_enabled: search and index
    // slow logs must both be published to CloudWatch Logs
    const searchSlowLogsEnabled = logPublishingOptions.SEARCH_SLOW_LOGS?.Enabled === true;
    const indexSlowLogsEnabled = logPublishingOptions.INDEX_SLOW_LOGS?.Enabled === true;
    if (!searchSlowLogsEnabled || !indexSlowLogsEnabled) {
      let message: string;
      if (indexSlowLogsEnabled) {
        message = `OpenSearch domain "${domainName}" has INDEX_SLOW_LOGS enabled but SEARCH_SLOW_LOGS disabled`;
      } else if (searchSlowLogsEnabled) {
        message = `OpenSearch domain "${domainName}" has SEARCH_SLOW_LOGS enabled but INDEX_SLOW_LOGS disabled`;
      } else {
        message = `OpenSearch domain "${domainName}" has SEARCH_SLOW_LOGS and INDEX_SLOW_LOGS disabled`;
      }
      findings.push(this.emit(
        'opensearch_service_domains_cloudwatch_logging_enabled',
        { domain: domainName, searchSlowLogs: searchSlowLogsEnabled, indexSlowLogs: indexSlowLogsEnabled },
        { message }
      ));
    }

    // opensearch_service_domains_updated_to_the_latest_service_software_version
    if (status.ServiceSoftwareOptions?.UpdateAvailable === true) {
      findings.push(this.emit(
        'opensearch_service_domains_updated_to_the_latest_service_software_version',
        { domain: domainName, engineVersion: status.EngineVersion, updateAvailable: true },
        { message: `OpenSearch domain "${domainName}" (version ${status.EngineVersion ?? 'unknown'}) has a service software update available` }
      ));
    }

    const clusterConfig: any = status.ClusterConfig ?? {};

    // opensearch_service_domains_fault_tolerant_data_nodes
    const instanceCount: number = clusterConfig.InstanceCount ?? 0;
    const zoneAwareness: boolean = clusterConfig.ZoneAwarenessEnabled === true;
    if (!(instanceCount >= 3 && zoneAwareness)) {
      let message: string;
      if (instanceCount >= 3 && !zoneAwareness) {
        message = `OpenSearch domain "${domainName}" has ${instanceCount} data nodes but cross-zone replication (Zone Awareness) is not enabled`;
      } else if (instanceCount < 3 && zoneAwareness) {
        message = `OpenSearch domain "${domainName}" has Zone Awareness enabled but only ${instanceCount} data node(s)`;
      } else {
        message = `OpenSearch domain "${domainName}" has fewer than 3 data nodes and cross-zone replication (Zone Awareness) is not enabled`;
      }
      findings.push(this.emit(
        'opensearch_service_domains_fault_tolerant_data_nodes',
        { domain: domainName, instanceCount, zoneAwarenessEnabled: zoneAwareness },
        { message }
      ));
    }

    // opensearch_service_domains_fault_tolerant_master_nodes
    const dedicatedMasterEnabled: boolean = clusterConfig.DedicatedMasterEnabled === true;
    const dedicatedMasterCount: number = clusterConfig.DedicatedMasterCount ?? 0;
    if (!dedicatedMasterEnabled) {
      findings.push(this.emit(
        'opensearch_service_domains_fault_tolerant_master_nodes',
        { domain: domainName, dedicatedMasterEnabled: false },
        { message: `OpenSearch domain "${domainName}" has dedicated master nodes disabled` }
      ));
    } else if (dedicatedMasterCount < 3) {
      findings.push(this.emit(
        'opensearch_service_domains_fault_tolerant_master_nodes',
        { domain: domainName, dedicatedMasterEnabled: true, dedicatedMasterCount },
        { message: `OpenSearch domain "${domainName}" has only ${dedicatedMasterCount} dedicated master node(s); at least 3 are required for fault tolerance` }
      ));
    }

    return findings;
  }
}

export default OpenSearchScanner;
