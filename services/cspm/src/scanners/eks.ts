// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  EKSClient,
  ListClustersCommand,
  DescribeClusterCommand,
} from '@aws-sdk/client-eks';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const REQUIRED_LOG_TYPES = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'];
const OLDEST_SUPPORTED_MAJOR = 1;
const OLDEST_SUPPORTED_MINOR = 28;

export class EKSScanner extends BaseScanner {
  private eks: EKSClient;

  constructor(client: AWSClient) {
    super(client, 'EKS');
    this.eks = new EKSClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting EKS security scan...');

      const clusterNames = await this.listClusters();
      for (const clusterName of clusterNames) {
        logger.debug(`Scanning EKS cluster: ${clusterName}`);
        try {
          const clusterFindings = await this.validateCluster(clusterName);
          findings.push(...clusterFindings);
        } catch (error) {
          logger.debug(`Failed to scan EKS cluster ${clusterName}`, { error: (error as Error).message });
        }
      }

      logger.info(`EKS scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('EKS scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listClusters(): Promise<string[]> {
    const clusters: string[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.eks.send(new ListClustersCommand({ nextToken }));
      });
      clusters.push(...(result.clusters ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return clusters;
  }

  private async validateCluster(clusterName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const result = await retry(async () => {
      return await this.eks.send(new DescribeClusterCommand({ name: clusterName }));
    });
    const cluster: any = result.cluster;
    if (!cluster) return findings;

    const vpcConfig: any = cluster.resourcesVpcConfig ?? {};

    // eks_cluster_not_publicly_accessible: public endpoint open to 0.0.0.0/0
    const publicAccessCidrs: string[] = vpcConfig.publicAccessCidrs ?? [];
    if (vpcConfig.endpointPublicAccess && publicAccessCidrs.includes('0.0.0.0/0')) {
      findings.push(this.emit(
        'eks_cluster_not_publicly_accessible',
        { cluster: clusterName, endpointPublicAccess: true, publicAccessCidrs },
        {
          message: `EKS cluster "${clusterName}" API server endpoint is publicly accessible from 0.0.0.0/0`,
          remediation: `Restrict public access CIDRs for cluster "${clusterName}" to trusted admin ranges, or disable public endpoint access entirely`,
        }
      ));
    }

    // eks_cluster_private_nodes_enabled: private endpoint access must be enabled
    if (!vpcConfig.endpointPrivateAccess) {
      findings.push(this.emit(
        'eks_cluster_private_nodes_enabled',
        { cluster: clusterName, endpointPrivateAccess: vpcConfig.endpointPrivateAccess ?? false },
        {
          message: `EKS cluster "${clusterName}" does not have private endpoint access enabled for the Kubernetes API server`,
          remediation: `Enable private endpoint access on cluster "${clusterName}" so control plane traffic stays within the VPC`,
        }
      ));
    }

    // eks_cluster_network_policy_enabled: cluster security group must be set
    if (!vpcConfig.clusterSecurityGroupId) {
      findings.push(this.emit(
        'eks_cluster_network_policy_enabled',
        { cluster: clusterName, clusterSecurityGroupId: null },
        {
          message: `EKS cluster "${clusterName}" does not have a cluster security group set, so pod network traffic is not restricted by a Network Policy`,
        }
      ));
    }

    // eks_cluster_uses_a_supported_version: version >= 1.28
    const version: string = cluster.version ?? '';
    if (version && version.includes('.')) {
      const parts = version.split('.');
      const major = parseInt(parts[0], 10);
      const minor = parseInt(parts[1], 10);
      if (!isNaN(major) && !isNaN(minor)) {
        if (major < OLDEST_SUPPORTED_MAJOR || (major === OLDEST_SUPPORTED_MAJOR && minor < OLDEST_SUPPORTED_MINOR)) {
          findings.push(this.emit(
            'eks_cluster_uses_a_supported_version',
            { cluster: clusterName, version, oldestSupportedVersion: `${OLDEST_SUPPORTED_MAJOR}.${OLDEST_SUPPORTED_MINOR}` },
            {
              message: `EKS cluster "${clusterName}" is using Kubernetes version ${version}; it should be ${OLDEST_SUPPORTED_MAJOR}.${OLDEST_SUPPORTED_MINOR} or higher`,
              remediation: `Upgrade cluster "${clusterName}" to a supported Kubernetes version (${OLDEST_SUPPORTED_MAJOR}.${OLDEST_SUPPORTED_MINOR}+), upgrading node groups and add-ons alongside the control plane`,
            }
          ));
        }
      }
    }

    // eks_cluster_deletion_protection_enabled: only flag when the API explicitly reports it disabled
    if (cluster.deletionProtection === false) {
      findings.push(this.emit(
        'eks_cluster_deletion_protection_enabled',
        { cluster: clusterName, deletionProtection: false },
        {
          message: `EKS cluster "${clusterName}" has deletion protection disabled`,
        }
      ));
    }

    // eks_control_plane_logging_all_types_enabled: all five log types must be enabled
    const clusterLogging: any[] = cluster.logging?.clusterLogging ?? [];
    const enabledLogTypes = new Set<string>();
    for (const entry of clusterLogging) {
      if (entry?.enabled) {
        for (const logType of entry.types ?? []) {
          enabledLogTypes.add(logType);
        }
      }
    }
    const missingLogTypes = REQUIRED_LOG_TYPES.filter((t) => !enabledLogTypes.has(t));
    if (missingLogTypes.length > 0) {
      findings.push(this.emit(
        'eks_control_plane_logging_all_types_enabled',
        { cluster: clusterName, enabledLogTypes: [...enabledLogTypes], missingLogTypes },
        {
          message: `EKS cluster "${clusterName}" does not have all required control plane log types enabled. Missing: ${missingLogTypes.join(', ')}`,
          remediation: `Enable the ${missingLogTypes.join(', ')} control plane log type(s) on cluster "${clusterName}"`,
        }
      ));
    }

    // eks_cluster_kms_cmk_encryption_in_secrets_enabled: encryptionConfig must be present
    const encryptionConfig: any[] = cluster.encryptionConfig ?? [];
    if (encryptionConfig.length === 0) {
      findings.push(this.emit(
        'eks_cluster_kms_cmk_encryption_in_secrets_enabled',
        { cluster: clusterName, encryptionConfig: false },
        {
          message: `EKS cluster "${clusterName}" does not have KMS encryption for Kubernetes secrets enabled`,
        }
      ));
    }

    return findings;
  }
}

export default EKSScanner;
