// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  KafkaClient,
  ListClustersV2Command,
  ListKafkaVersionsCommand,
} from '@aws-sdk/client-kafka';
import { KafkaConnectClient, ListConnectorsCommand } from '@aws-sdk/client-kafkaconnect';
import { KMSClient, DescribeKeyCommand } from '@aws-sdk/client-kms';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class KafkaScanner extends BaseScanner {
  private kafka: KafkaClient;
  private kafkaconnect: KafkaConnectClient;
  private kms: KMSClient;

  constructor(client: AWSClient) {
    super(client, 'MSK');
    this.kafka = new KafkaClient(client.getClientConfig());
    this.kafkaconnect = new KafkaConnectClient(client.getClientConfig());
    this.kms = new KMSClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting MSK security scan...');

      const clusters = await this.listClusters();
      const latestKafkaVersion = await this.getLatestKafkaVersion();

      for (const cluster of clusters) {
        const clusterName: string = cluster.ClusterName ?? '';
        logger.debug(`Scanning MSK cluster: ${clusterName}`);
        try {
          // Serverless clusters are private, always encrypted (at rest and in
          // transit), require authentication and have AWS-managed versions, so
          // every ported check passes for them by default (Prowler parity).
          if (cluster.ClusterType !== 'PROVISIONED' || !cluster.Provisioned) {
            continue;
          }
          const clusterFindings = await this.validateProvisionedCluster(cluster, latestKafkaVersion);
          findings.push(...clusterFindings);
        } catch (error) {
          logger.debug(`Failed to scan MSK cluster ${clusterName}`, { error: (error as Error).message });
        }
      }

      try {
        findings.push(...await this.validateConnectors());
      } catch (error) {
        logger.debug('Failed to scan MSK Connect connectors', { error: (error as Error).message });
      }

      logger.info(`MSK scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('MSK scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  // kafka_connector_in_transit_encryption_enabled: MSK Connect connectors must
  // require TLS between the connector and the Kafka cluster
  private async validateConnectors(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const connectors: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.kafkaconnect.send(new ListConnectorsCommand({ nextToken }));
      });
      connectors.push(...(result.connectors ?? []));
      nextToken = result.nextToken;
    } while (nextToken);

    for (const connector of connectors) {
      const connectorName: string = connector.connectorName ?? '';
      const connectorArn: string = connector.connectorArn ?? '';
      const encryptionType: string = connector.kafkaClusterEncryptionInTransit?.encryptionType ?? 'PLAINTEXT';
      if (encryptionType !== 'TLS') {
        findings.push(this.emit(
          'kafka_connector_in_transit_encryption_enabled',
          { connector: connectorName, arn: connectorArn, encryptionType },
          {
            message: `MSK Connect connector "${connectorName}" does not have encryption in transit enabled (encryption type: ${encryptionType})`,
            remediation: `Re-create connector "${connectorName}" with Kafka cluster encryption in transit set to TLS; the encryption setting cannot be changed on an existing connector`,
          }
        ));
      }
    }

    return findings;
  }

  private async listClusters(): Promise<any[]> {
    const clusters: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.kafka.send(new ListClustersV2Command({ NextToken: nextToken }));
      });
      clusters.push(...(result.ClusterInfoList ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return clusters;
  }

  /**
   * Prowler compares against the last entry returned by ListKafkaVersions.
   * Returns null when the version list cannot be retrieved, in which case the
   * latest-version check is skipped.
   */
  private async getLatestKafkaVersion(): Promise<string | null> {
    try {
      const versions: string[] = [];
      let nextToken: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.kafka.send(new ListKafkaVersionsCommand({ NextToken: nextToken }));
        });
        for (const version of result.KafkaVersions ?? []) {
          if (version.Version) {
            versions.push(version.Version);
          }
        }
        nextToken = result.NextToken;
      } while (nextToken);
      return versions.length > 0 ? versions[versions.length - 1] : null;
    } catch (error) {
      logger.debug('Failed to list Kafka versions; skipping latest-version check', { error: (error as Error).message });
      return null;
    }
  }

  private async validateProvisionedCluster(cluster: any, latestKafkaVersion: string | null): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const clusterName: string = cluster.ClusterName ?? '';
    const clusterArn: string = cluster.ClusterArn ?? '';
    const provisioned: any = cluster.Provisioned ?? {};

    // kafka_cluster_is_public: public access type other than DISABLED
    const publicAccessType: string =
      provisioned.BrokerNodeGroupInfo?.ConnectivityInfo?.PublicAccess?.Type ?? 'SERVICE_PROVIDED_EIPS';
    if (publicAccessType !== 'DISABLED') {
      findings.push(this.emit(
        'kafka_cluster_is_public',
        { cluster: clusterName, arn: clusterArn, publicAccessType },
        {
          message: `MSK cluster "${clusterName}" is publicly accessible (public access type: ${publicAccessType})`,
          remediation: `Set the public access type to DISABLED on cluster "${clusterName}" so brokers are only reachable from within the VPC`,
        }
      ));
    }

    // kafka_cluster_unrestricted_access_disabled: unauthenticated access enabled
    const unauthenticatedAccess: boolean = provisioned.ClientAuthentication?.Unauthenticated?.Enabled ?? false;
    if (unauthenticatedAccess) {
      findings.push(this.emit(
        'kafka_cluster_unrestricted_access_disabled',
        { cluster: clusterName, arn: clusterArn, unauthenticatedAccessEnabled: true },
        {
          message: `MSK cluster "${clusterName}" has unauthenticated (unrestricted) client access enabled`,
          remediation: `Disable unauthenticated access on cluster "${clusterName}" and require IAM, SASL/SCRAM or mutual TLS client authentication`,
        }
      ));
    }

    // kafka_cluster_in_transit_encryption_enabled: client-broker TLS and in-cluster encryption
    const clientBroker: string = provisioned.EncryptionInfo?.EncryptionInTransit?.ClientBroker ?? 'PLAINTEXT';
    const inCluster: boolean = provisioned.EncryptionInfo?.EncryptionInTransit?.InCluster ?? false;
    if (!(clientBroker === 'TLS' && inCluster)) {
      findings.push(this.emit(
        'kafka_cluster_in_transit_encryption_enabled',
        { cluster: clusterName, arn: clusterArn, clientBroker, inClusterEncryption: inCluster },
        {
          message: `MSK cluster "${clusterName}" does not have encryption in transit fully enabled (client-broker: ${clientBroker}, in-cluster: ${inCluster})`,
          remediation: `Set client-broker encryption to TLS and enable in-cluster encryption on cluster "${clusterName}"`,
        }
      ));
    }

    // kafka_cluster_mutual_tls_authentication_enabled: TLS client authentication
    const tlsAuthentication: boolean = provisioned.ClientAuthentication?.Tls?.Enabled ?? false;
    if (!tlsAuthentication) {
      findings.push(this.emit(
        'kafka_cluster_mutual_tls_authentication_enabled',
        { cluster: clusterName, arn: clusterArn, tlsAuthenticationEnabled: false },
        {
          message: `MSK cluster "${clusterName}" does not have mutual TLS authentication enabled`,
        }
      ));
    }

    // kafka_cluster_enhanced_monitoring_enabled: monitoring level above DEFAULT
    const enhancedMonitoring: string = provisioned.EnhancedMonitoring ?? 'DEFAULT';
    if (enhancedMonitoring === 'DEFAULT') {
      findings.push(this.emit(
        'kafka_cluster_enhanced_monitoring_enabled',
        { cluster: clusterName, arn: clusterArn, enhancedMonitoring },
        {
          message: `MSK cluster "${clusterName}" does not have enhanced monitoring enabled (monitoring level is DEFAULT)`,
        }
      ));
    }

    // kafka_cluster_uses_latest_version: compare with latest listed Kafka version
    const kafkaVersion: string = provisioned.CurrentBrokerSoftwareInfo?.KafkaVersion ?? '';
    if (latestKafkaVersion && kafkaVersion && kafkaVersion !== latestKafkaVersion) {
      findings.push(this.emit(
        'kafka_cluster_uses_latest_version',
        { cluster: clusterName, arn: clusterArn, kafkaVersion, latestKafkaVersion },
        {
          message: `MSK cluster "${clusterName}" is running Kafka version ${kafkaVersion}, not the latest supported version (${latestKafkaVersion})`,
          remediation: `Upgrade cluster "${clusterName}" from Kafka ${kafkaVersion} to ${latestKafkaVersion} during a maintenance window`,
        }
      ));
    }

    // kafka_cluster_encryption_at_rest_uses_cmk: data volume key must be a customer-managed KMS key
    const dataVolumeKmsKeyId: string = provisioned.EncryptionInfo?.EncryptionAtRest?.DataVolumeKMSKeyId ?? '';
    if (!dataVolumeKmsKeyId) {
      findings.push(this.emit(
        'kafka_cluster_encryption_at_rest_uses_cmk',
        { cluster: clusterName, arn: clusterArn, dataVolumeKmsKeyId: null },
        {
          message: `MSK cluster "${clusterName}" does not have encryption at rest configured with a customer managed KMS key`,
        }
      ));
    } else {
      try {
        const keyResult = await retry(async () => {
          return await this.kms.send(new DescribeKeyCommand({ KeyId: dataVolumeKmsKeyId }));
        });
        const keyManager: string = keyResult.KeyMetadata?.KeyManager ?? '';
        if (keyManager !== 'CUSTOMER') {
          findings.push(this.emit(
            'kafka_cluster_encryption_at_rest_uses_cmk',
            { cluster: clusterName, arn: clusterArn, dataVolumeKmsKeyId, keyManager },
            {
              message: `MSK cluster "${clusterName}" encrypts data at rest with an AWS-managed key, not a customer managed key (CMK)`,
            }
          ));
        }
      } catch (error) {
        // Cannot determine the key manager (e.g. access denied); skip rather than emit a false positive
        logger.debug(`Failed to describe KMS key for MSK cluster ${clusterName}`, { error: (error as Error).message });
      }
    }

    return findings;
  }
}

export default KafkaScanner;
