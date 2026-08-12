// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DescribeCacheClustersCommand,
  DescribeReplicationGroupsCommand,
  DescribeCacheSubnetGroupsCommand,
  type CacheCluster,
  type ReplicationGroup,
} from '@aws-sdk/client-elasticache';
import { DescribeRouteTablesCommand } from '@aws-sdk/client-ec2';
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

    for (const cluster of clusterList) {
      findings.push(...this.scanCluster(cluster));
      try {
        findings.push(...(await this.checkClusterPublicSubnet(cluster)));
      } catch (error) {
        logger.debug(`Failed to check subnets for ElastiCache cluster ${cluster.CacheClusterId}`, { error: (error as Error).message });
      }
    }
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
      findings.push(this.emit(
        'elasticache_redis_cluster_in_transit_encryption_enabled',
        { resourceId: id, clusterId: id, engine },
        {
          message: `ElastiCache ${engine} cluster "${id}" does not have in-transit encryption enabled. ` +
            `Data between clients and the cluster is transmitted in plaintext.`,
        }
      ));
    }

    // 2. Encryption at rest
    if (!cluster.AtRestEncryptionEnabled) {
      findings.push(this.emit(
        'elasticache_redis_cluster_rest_encryption_enabled',
        { resourceId: `${id}::at-rest`, clusterId: id, engine },
        {
          message: `ElastiCache ${engine} cluster "${id}" does not have at-rest encryption enabled. ` +
            `Cached data stored on disk is not encrypted.`,
        }
      ));
    }

    // 3. Not in VPC
    if (!cluster.CacheSubnetGroupName) {
      findings.push(this.emit(
        'elasticache_cluster_in_vpc',
        { resourceId: `${id}::no-vpc`, clusterId: id },
        {
          message: `ElastiCache cluster "${id}" is not deployed in a VPC. ` +
            `Clusters outside VPC have weaker network isolation and are harder to secure.`,
        }
      ));
    }

    // 4. No automated backups (Redis only)
    if (engine === 'redis' && (cluster.SnapshotRetentionLimit ?? 0) === 0) {
      findings.push(this.emit(
        'elasticache_redis_cluster_backup_enabled',
        { resourceId: `${id}::backups`, clusterId: id },
        {
          message: `Redis cluster "${id}" has automatic snapshot retention set to 0 (disabled). ` +
            `Data cannot be restored in the event of cluster failure or accidental flushing.`,
          remediation: `Enable automatic backups with a retention period: ` +
            `aws elasticache modify-cache-cluster --cache-cluster-id ${id} --snapshot-retention-limit 7`,
        }
      ));
    }

    return findings;
  }

  // elasticache_cluster_uses_public_subnet: any subnet of the cache subnet group
  // whose route table has a default route to an Internet gateway is public
  private async checkClusterPublicSubnet(cluster: CacheCluster): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const id     = cluster.CacheClusterId ?? 'Unknown';
    const engine = cluster.Engine ?? 'unknown';
    const subnetGroupName = cluster.CacheSubnetGroupName;
    if (!subnetGroupName) return findings;

    const subnetGroupResult = await retry(() =>
      this.client.elasticache.send(new DescribeCacheSubnetGroupsCommand({ CacheSubnetGroupName: subnetGroupName }))
    );

    const publicSubnets: string[] = [];
    for (const subnetGroup of subnetGroupResult.CacheSubnetGroups ?? []) {
      const vpcId: string = subnetGroup.VpcId ?? '';
      for (const subnet of subnetGroup.Subnets ?? []) {
        const subnetId: string = subnet.SubnetIdentifier ?? '';
        if (!subnetId) continue;
        try {
          if (await this.isSubnetPublic(subnetId, vpcId)) {
            publicSubnets.push(subnetId);
          }
        } catch (error) {
          logger.debug(`Failed to evaluate route tables for subnet ${subnetId}`, { error: (error as Error).message });
        }
      }
    }

    if (publicSubnets.length > 0) {
      const resourceLabel = engine === 'redis' ? 'Redis node' : `${engine} cluster`;
      findings.push(this.emit(
        'elasticache_cluster_uses_public_subnet',
        { resourceId: `${id}::public-subnet`, clusterId: id, engine, subnetGroup: subnetGroupName, publicSubnets },
        {
          message: `ElastiCache ${resourceLabel} "${id}" is using public subnet(s): ${publicSubnets.join(', ')}. ` +
            `Caches in public subnets can be exposed to direct Internet access.`,
          remediation: `Move cluster "${id}" to a cache subnet group containing only private subnets without Internet gateway routes.`,
        }
      ));
    }

    return findings;
  }

  private async isSubnetPublic(subnetId: string, vpcId: string): Promise<boolean> {
    let routeTablesResult = await retry(() =>
      this.client.ec2.send(new DescribeRouteTablesCommand({
        Filters: [{ Name: 'association.subnet-id', Values: [subnetId] }],
      }))
    );

    // A subnet with no explicit route table association uses the VPC main route table
    if (!routeTablesResult.RouteTables || routeTablesResult.RouteTables.length === 0) {
      const mainFilters: any[] = [{ Name: 'association.main', Values: ['true'] }];
      if (vpcId) {
        mainFilters.push({ Name: 'vpc-id', Values: [vpcId] });
      }
      routeTablesResult = await retry(() =>
        this.client.ec2.send(new DescribeRouteTablesCommand({ Filters: mainFilters }))
      );
    }

    for (const routeTable of routeTablesResult.RouteTables ?? []) {
      for (const route of routeTable.Routes ?? []) {
        if (route.GatewayId && route.GatewayId.includes('igw') && route.DestinationCidrBlock === '0.0.0.0/0') {
          return true;
        }
      }
    }
    return false;
  }

  private scanReplicationGroup(rg: ReplicationGroup): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const id = rg.ReplicationGroupId ?? 'Unknown';

    // Auth token check (Redis AUTH)
    if (!rg.AuthTokenEnabled) {
      findings.push(this.emit(
        'elasticache_redis_replication_group_auth_enabled',
        { resourceId: `${id}::auth`, replicationGroupId: id },
        {
          message: `Redis replication group "${id}" does not require an AUTH token. ` +
            `Any client with network access to the Redis endpoint can connect without authentication.`,
          remediation: `Enable Redis AUTH: aws elasticache modify-replication-group --replication-group-id ${id} --auth-token <token> --apply-immediately`,
        }
      ));
    }

    // Automatic minor version upgrades
    if (!rg.AutoMinorVersionUpgrade) {
      findings.push(this.emit(
        'elasticache_redis_cluster_auto_minor_version_upgrades',
        { resourceId: `${id}::auto-minor-version-upgrade`, replicationGroupId: id },
        {
          message: `Redis replication group "${id}" does not have automatic minor version upgrades enabled. ` +
            `Nodes may keep running engine versions with known CVEs and stability bugs.`,
          remediation: `Enable automatic minor version upgrades: aws elasticache modify-replication-group --replication-group-id ${id} --auto-minor-version-upgrade --apply-immediately`,
        }
      ));
    }

    // Automatic failover
    if (rg.AutomaticFailover !== 'enabled') {
      findings.push(this.emit(
        'elasticache_redis_cluster_automatic_failover_enabled',
        { resourceId: `${id}::automatic-failover`, replicationGroupId: id, automaticFailover: rg.AutomaticFailover ?? 'disabled' },
        {
          message: `Redis replication group "${id}" does not have automatic failover enabled. ` +
            `A primary node or AZ outage would stop writes until a replica is promoted manually.`,
          remediation: `Enable automatic failover: aws elasticache modify-replication-group --replication-group-id ${id} --automatic-failover-enabled --apply-immediately`,
        }
      ));
    }

    // Multi-AZ
    if (rg.MultiAZ !== 'enabled') {
      findings.push(this.emit(
        'elasticache_redis_cluster_multi_az_enabled',
        { resourceId: `${id}::multi-az`, replicationGroupId: id },
        {
          message: `Redis replication group "${id}" is not configured for Multi-AZ failover. ` +
            `A single AZ failure would cause downtime.`,
          remediation: `Enable Multi-AZ: aws elasticache modify-replication-group --replication-group-id ${id} --multi-az-enabled --apply-immediately`,
        }
      ));
    }

    return findings;
  }
}

export default ElastiCacheScanner;
