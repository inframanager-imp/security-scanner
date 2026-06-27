import {
  DescribeCacheClustersCommand,
  DescribeReplicationGroupsCommand,
  type CacheCluster,
  type ReplicationGroup,
} from '@aws-sdk/client-elasticache';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class ElastiCacheScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'ElastiCache');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting ElastiCache security scan...');

    const [clusters, replicationGroups] = await Promise.allSettled([
      this.listClusters(),
      this.listReplicationGroups(),
    ]);

    const clusterList = clusters.status === 'fulfilled' ? clusters.value : [];
    const rgList      = replicationGroups.status === 'fulfilled' ? replicationGroups.value : [];

    logger.info(`ElastiCache: ${clusterList.length} cluster(s), ${rgList.length} replication group(s)`);

    for (const cluster of clusterList) findings.push(...this.scanCluster(cluster));
    for (const rg of rgList)           findings.push(...this.scanReplicationGroup(rg));

    logger.info(`ElastiCache scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listClusters(): Promise<CacheCluster[]> {
    const clusters: CacheCluster[] = [];
    let marker: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.elasticache.send(new DescribeCacheClustersCommand({ Marker: marker, MaxRecords: 100 }))
        );
        clusters.push(...(result.CacheClusters ?? []));
        marker = result.Marker;
      } while (marker);
    } catch { /* no permission */ }
    return clusters;
  }

  private async listReplicationGroups(): Promise<ReplicationGroup[]> {
    const rgs: ReplicationGroup[] = [];
    let marker: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.elasticache.send(new DescribeReplicationGroupsCommand({ Marker: marker, MaxRecords: 100 }))
        );
        rgs.push(...(result.ReplicationGroups ?? []));
        marker = result.Marker;
      } while (marker);
    } catch { /* no permission */ }
    return rgs;
  }

  private scanCluster(cluster: CacheCluster): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const id     = cluster.CacheClusterId ?? 'Unknown';
    const engine = cluster.Engine ?? 'unknown';

    // 1. Encryption in transit
    if (!cluster.TransitEncryptionEnabled) {
      findings.push(this.createFinding(
        'ElastiCache Cluster Encryption In Transit Disabled',
        `ElastiCache ${engine} cluster "${id}" does not have in-transit encryption enabled. ` +
        `Data between clients and the cluster is transmitted in plaintext.`,
        'HIGH',
        { resourceId: id, clusterId: id, engine },
        `Recreate the cluster with transit encryption: aws elasticache create-cache-cluster ... --transit-encryption-enabled`,
        ['elasticache', 'encryption'],
      ));
    }

    // 2. Encryption at rest
    if (!cluster.AtRestEncryptionEnabled) {
      findings.push(this.createFinding(
        'ElastiCache Cluster Encryption At Rest Disabled',
        `ElastiCache ${engine} cluster "${id}" does not have at-rest encryption enabled. ` +
        `Cached data stored on disk is not encrypted.`,
        'HIGH',
        { resourceId: `${id}::at-rest`, clusterId: id, engine },
        `Recreate the cluster with at-rest encryption: aws elasticache create-cache-cluster ... --at-rest-encryption-enabled`,
        ['elasticache', 'encryption'],
      ));
    }

    // 3. Not in VPC
    if (!cluster.CacheSubnetGroupName) {
      findings.push(this.createFinding(
        'ElastiCache Cluster Not in VPC',
        `ElastiCache cluster "${id}" is not deployed in a VPC. ` +
        `Clusters outside VPC have weaker network isolation and are harder to secure.`,
        'CRITICAL',
        { resourceId: `${id}::no-vpc`, clusterId: id },
        `Migrate the cluster to a VPC. Create a new cluster in a VPC and migrate your application.`,
        ['elasticache', 'network'],
      ));
    }

    // 4. No automated backups (Redis only)
    if (engine === 'redis' && (cluster.SnapshotRetentionLimit ?? 0) === 0) {
      findings.push(this.createFinding(
        'ElastiCache Redis Automatic Backups Disabled',
        `Redis cluster "${id}" has automatic snapshot retention set to 0 (disabled). ` +
        `Data cannot be restored in the event of cluster failure or accidental flushing.`,
        'MEDIUM',
        { resourceId: `${id}::backups`, clusterId: id },
        `Enable automatic backups with a retention period: ` +
        `aws elasticache modify-cache-cluster --cache-cluster-id ${id} --snapshot-retention-limit 7`,
        ['elasticache', 'backup'],
      ));
    }

    return findings;
  }

  private scanReplicationGroup(rg: ReplicationGroup): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const id = rg.ReplicationGroupId ?? 'Unknown';

    // Auth token check (Redis AUTH)
    if (!rg.AuthTokenEnabled) {
      findings.push(this.createFinding(
        'ElastiCache Redis AUTH Token Not Configured',
        `Redis replication group "${id}" does not require an AUTH token. ` +
        `Any client with network access to the Redis endpoint can connect without authentication.`,
        'CRITICAL',
        { resourceId: `${id}::auth`, replicationGroupId: id },
        `Enable Redis AUTH: aws elasticache modify-replication-group --replication-group-id ${id} --auth-token <token> --apply-immediately`,
        ['elasticache', 'authentication'],
      ));
    }

    // Multi-AZ
    if (rg.MultiAZ !== 'enabled') {
      findings.push(this.createFinding(
        'ElastiCache Replication Group Not Multi-AZ',
        `Redis replication group "${id}" is not configured for Multi-AZ failover. ` +
        `A single AZ failure would cause downtime.`,
        'MEDIUM',
        { resourceId: `${id}::multi-az`, replicationGroupId: id },
        `Enable Multi-AZ: aws elasticache modify-replication-group --replication-group-id ${id} --multi-az-enabled --apply-immediately`,
        ['elasticache', 'availability'],
      ));
    }

    return findings;
  }
}

export default ElastiCacheScanner;
