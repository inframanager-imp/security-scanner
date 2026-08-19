import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const elasticacheChecks: CheckMetadata[] = [
  {
    checkId: 'elasticache_redis_cluster_in_transit_encryption_enabled',
    provider: 'aws',
    service: 'elasticache',
    title: 'ElastiCache Cluster Encryption In Transit Disabled',
    severity: 'HIGH',
    description: 'Checks that ElastiCache clusters have in-transit encryption enabled so data between clients and the cluster is not transmitted in plaintext.',
    remediation: 'Recreate the cluster with transit encryption: aws elasticache create-cache-cluster ... --transit-encryption-enabled',
    tags: ['elasticache', 'encryption'],
  },
  {
    checkId: 'elasticache_redis_cluster_rest_encryption_enabled',
    provider: 'aws',
    service: 'elasticache',
    title: 'ElastiCache Cluster Encryption At Rest Disabled',
    severity: 'HIGH',
    description: 'Checks that ElastiCache clusters have at-rest encryption enabled so cached data stored on disk is encrypted.',
    remediation: 'Recreate the cluster with at-rest encryption: aws elasticache create-cache-cluster ... --at-rest-encryption-enabled',
    tags: ['elasticache', 'encryption'],
  },
  {
    checkId: 'elasticache_cluster_in_vpc',
    provider: 'aws',
    service: 'elasticache',
    title: 'ElastiCache Cluster Not in VPC',
    severity: 'CRITICAL',
    description: 'Checks that ElastiCache clusters are deployed in a VPC; clusters outside VPC have weaker network isolation and are harder to secure.',
    remediation: 'Migrate the cluster to a VPC. Create a new cluster in a VPC and migrate your application.',
    tags: ['elasticache', 'network'],
  },
  {
    checkId: 'elasticache_redis_cluster_backup_enabled',
    provider: 'aws',
    service: 'elasticache',
    title: 'ElastiCache Redis Automatic Backups Disabled',
    severity: 'MEDIUM',
    description: 'Checks that ElastiCache Redis clusters have automatic snapshot retention enabled so data can be restored in the event of cluster failure or accidental flushing.',
    remediation: 'Enable automatic backups with a retention period: aws elasticache modify-cache-cluster --cache-cluster-id <cluster-id> --snapshot-retention-limit 7',
    tags: ['elasticache', 'backup'],
  },
  {
    checkId: 'elasticache_redis_replication_group_auth_enabled',
    provider: 'aws',
    service: 'elasticache',
    title: 'ElastiCache Redis AUTH Token Not Configured',
    severity: 'CRITICAL',
    description: 'Checks that Redis replication groups require an AUTH token; without it, any client with network access to the Redis endpoint can connect without authentication.',
    remediation: 'Enable Redis AUTH: aws elasticache modify-replication-group --replication-group-id <replication-group-id> --auth-token <token> --apply-immediately',
    tags: ['elasticache', 'authentication'],
  },
  {
    checkId: 'elasticache_redis_cluster_multi_az_enabled',
    provider: 'aws',
    service: 'elasticache',
    title: 'ElastiCache Replication Group Not Multi-AZ',
    severity: 'MEDIUM',
    description: 'Checks that Redis replication groups are configured for Multi-AZ failover so a single AZ failure does not cause downtime.',
    remediation: 'Enable Multi-AZ: aws elasticache modify-replication-group --replication-group-id <replication-group-id> --multi-az-enabled --apply-immediately',
    tags: ['elasticache', 'availability'],
  },
];
