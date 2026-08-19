/**
 * Resource Discovery Service
 *
 * Discovers cloud resources and maintains a versioned inventory with snapshots.
 * Supports AWS (via Config Service), Azure (via ARM clients), GCP (via googleapis).
 *
 * For each resource found:
 *   1. Upsert ResourceInventory (current config state, lastSeenAt, state=ACTIVE)
 *   2. Compare config with previous; if changed → create ResourceSnapshot (MODIFIED)
 *   3. If new → create ResourceSnapshot (CREATED)
 *   4. Mark stale resources (not seen this run) → state=DELETED, create snapshot
 *   5. Derive ResourceDependency edges from config attributes
 */

import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { EC2Client, DescribeInstancesCommand, DescribeVpcsCommand, DescribeSubnetsCommand,
  DescribeSecurityGroupsCommand, DescribeNetworkInterfacesCommand, DescribeInternetGatewaysCommand,
  DescribeRouteTablesCommand, DescribeAddressesCommand, DescribeVolumesCommand } from '@aws-sdk/client-ec2';
import { S3Client, ListBucketsCommand, GetBucketLocationCommand, GetBucketTaggingCommand, GetPublicAccessBlockCommand } from '@aws-sdk/client-s3';
import {
  IAMClient, ListRolesCommand, ListUsersCommand, ListPoliciesCommand, ListGroupsCommand, GetPolicyVersionCommand,
  ListAttachedRolePoliciesCommand, ListRolePoliciesCommand, GetRolePolicyCommand,
  ListAttachedUserPoliciesCommand, ListUserPoliciesCommand, GetUserPolicyCommand,
} from '@aws-sdk/client-iam';
import { RDSClient, DescribeDBInstancesCommand, DescribeDBClustersCommand } from '@aws-sdk/client-rds';
import { LambdaClient, ListFunctionsCommand } from '@aws-sdk/client-lambda';
import { EKSClient, ListClustersCommand as EksListClustersCommand, DescribeClusterCommand } from '@aws-sdk/client-eks';
import { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand } from '@aws-sdk/client-elastic-load-balancing-v2';
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from '@aws-sdk/client-dynamodb';
import { KMSClient, ListKeysCommand, DescribeKeyCommand } from '@aws-sdk/client-kms';
import { SNSClient, ListTopicsCommand } from '@aws-sdk/client-sns';
import { SQSClient, ListQueuesCommand } from '@aws-sdk/client-sqs';
import { CloudFrontClient, ListDistributionsCommand } from '@aws-sdk/client-cloudfront';
import { ElastiCacheClient, DescribeCacheClustersCommand } from '@aws-sdk/client-elasticache';
import { prisma }     from '../config/database';
import { Prisma }     from '@prisma/client';
import * as credentialService  from './credentialService';
import { decryptAzureCredentials } from './azureCredentialService';
import { decryptGcpCredentials }   from './gcpCredentialService';
import AzureClient  from '../../../src/azure/client';
import GcpClient    from '../../../src/gcp/client';
import { DependencyType } from '@prisma/client';
import { logger } from '../config/logger';
import { mapWithConcurrency } from './concurrency';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

interface AwsCreds { accessKeyId: string; secretAccessKey: string; sessionToken?: string }

async function getAwsCredentials(accountId: string, region: string): Promise<AwsCreds> {
  const cred = await prisma.awsCredential.findUnique({ where: { accountId } });
  if (!cred) throw new Error('No credentials for account');
  const dec = credentialService.decryptCredentials(cred);
  if (!dec.accessKeyId || !dec.secretAccessKey) throw new Error('Missing access key credentials');

  let credentials: AwsCreds = {
    accessKeyId:     dec.accessKeyId,
    secretAccessKey: dec.secretAccessKey,
    sessionToken:    undefined,
  };

  if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
    const sts = new STSClient({ region, credentials });
    const assumed = await sts.send(new AssumeRoleCommand({
      RoleArn: cred.roleArn, RoleSessionName: 'resource-discovery',
      DurationSeconds: 900,
      ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
    }));
    if (!assumed.Credentials) throw new Error('STS AssumeRole returned no credentials');
    credentials = {
      accessKeyId:     assumed.Credentials.AccessKeyId!,
      secretAccessKey: assumed.Credentials.SecretAccessKey!,
      sessionToken:    assumed.Credentials.SessionToken,
    };
  }
  return credentials;
}

interface DiscoveredItem {
  nativeId: string; resourceType: string; resourceName?: string;
  region?: string; tags?: Record<string, string>; configState: Record<string, unknown>;
}

function tagListToMap(tags?: { Key?: string; Value?: string }[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tags ?? []) if (t.Key) out[t.Key] = t.Value ?? '';
  return out;
}

async function listAwsResourcesDirect(creds: AwsCreds, region: string): Promise<DiscoveredItem[]> {
  const cfg = { region, credentials: creds };
  const items: DiscoveredItem[] = [];

  const safe = async (label: string, fn: () => Promise<void>) => {
    try { await fn(); } catch (e) {
      logger.error(`[resource-discovery] ${label} failed:`, (e as Error).message);
    }
  };

  await safe('EC2 instances', async () => {
    const c = new EC2Client(cfg);
    let nextToken: string | undefined;
    do {
      const resp = await c.send(new DescribeInstancesCommand({ NextToken: nextToken }));
      nextToken = resp.NextToken;
      for (const res of resp.Reservations ?? []) for (const i of res.Instances ?? []) {
        if (!i.InstanceId) continue;
        const tags = tagListToMap(i.Tags);
        items.push({ nativeId: i.InstanceId, resourceType: 'AWS::EC2::Instance', resourceName: tags.Name, region, tags, configState: i as unknown as Record<string, unknown> });
      }
    } while (nextToken);
  });

  await safe('EC2 VPCs', async () => {
    const c = new EC2Client(cfg);
    const resp = await c.send(new DescribeVpcsCommand({}));
    for (const v of resp.Vpcs ?? []) {
      if (!v.VpcId) continue;
      const tags = tagListToMap(v.Tags);
      items.push({ nativeId: v.VpcId, resourceType: 'AWS::EC2::VPC', resourceName: tags.Name, region, tags, configState: v as unknown as Record<string, unknown> });
    }
  });

  await safe('EC2 subnets', async () => {
    const c = new EC2Client(cfg);
    const resp = await c.send(new DescribeSubnetsCommand({}));
    for (const s of resp.Subnets ?? []) {
      if (!s.SubnetId) continue;
      const tags = tagListToMap(s.Tags);
      items.push({ nativeId: s.SubnetId, resourceType: 'AWS::EC2::Subnet', resourceName: tags.Name, region, tags, configState: s as unknown as Record<string, unknown> });
    }
  });

  await safe('EC2 security groups', async () => {
    const c = new EC2Client(cfg);
    const resp = await c.send(new DescribeSecurityGroupsCommand({}));
    for (const g of resp.SecurityGroups ?? []) {
      if (!g.GroupId) continue;
      const tags = tagListToMap(g.Tags);
      items.push({ nativeId: g.GroupId, resourceType: 'AWS::EC2::SecurityGroup', resourceName: g.GroupName, region, tags, configState: g as unknown as Record<string, unknown> });
    }
  });

  await safe('EC2 network interfaces', async () => {
    const c = new EC2Client(cfg);
    const resp = await c.send(new DescribeNetworkInterfacesCommand({}));
    for (const n of resp.NetworkInterfaces ?? []) {
      if (!n.NetworkInterfaceId) continue;
      const tags = tagListToMap(n.TagSet);
      items.push({ nativeId: n.NetworkInterfaceId, resourceType: 'AWS::EC2::NetworkInterface', resourceName: n.Description, region, tags, configState: n as unknown as Record<string, unknown> });
    }
  });

  await safe('EC2 internet gateways', async () => {
    const c = new EC2Client(cfg);
    const resp = await c.send(new DescribeInternetGatewaysCommand({}));
    for (const g of resp.InternetGateways ?? []) {
      if (!g.InternetGatewayId) continue;
      const tags = tagListToMap(g.Tags);
      items.push({ nativeId: g.InternetGatewayId, resourceType: 'AWS::EC2::InternetGateway', resourceName: tags.Name, region, tags, configState: g as unknown as Record<string, unknown> });
    }
  });

  await safe('EC2 route tables', async () => {
    const c = new EC2Client(cfg);
    const resp = await c.send(new DescribeRouteTablesCommand({}));
    for (const rt of resp.RouteTables ?? []) {
      if (!rt.RouteTableId) continue;
      const tags = tagListToMap(rt.Tags);
      items.push({ nativeId: rt.RouteTableId, resourceType: 'AWS::EC2::RouteTable', resourceName: tags.Name, region, tags, configState: rt as unknown as Record<string, unknown> });
    }
  });

  await safe('EC2 elastic IPs', async () => {
    const c = new EC2Client(cfg);
    const resp = await c.send(new DescribeAddressesCommand({}));
    for (const a of resp.Addresses ?? []) {
      const id = a.AllocationId ?? a.PublicIp;
      if (!id) continue;
      const tags = tagListToMap(a.Tags);
      items.push({ nativeId: id, resourceType: 'AWS::EC2::EIP', resourceName: tags.Name ?? a.PublicIp, region, tags, configState: a as unknown as Record<string, unknown> });
    }
  });

  await safe('EC2 volumes', async () => {
    const c = new EC2Client(cfg);
    let nextToken: string | undefined;
    do {
      const resp = await c.send(new DescribeVolumesCommand({ NextToken: nextToken }));
      nextToken = resp.NextToken;
      for (const v of resp.Volumes ?? []) {
        if (!v.VolumeId) continue;
        const tags = tagListToMap(v.Tags);
        items.push({ nativeId: v.VolumeId, resourceType: 'AWS::EC2::Volume', resourceName: tags.Name, region, tags, configState: v as unknown as Record<string, unknown> });
      }
    } while (nextToken);
  });

  await safe('S3 buckets', async () => {
    const c = new S3Client(cfg);
    const resp = await c.send(new ListBucketsCommand({}));
    const buckets = (resp.Buckets ?? []).filter((b) => b.Name);

    await mapWithConcurrency(buckets, 10, async (b) => {
      const bucketName = b.Name!;
      let bucketRegion = region;
      let tags: Record<string, string> = {};
      let publicAccessBlock: unknown = null;
      try {
        const loc = await c.send(new GetBucketLocationCommand({ Bucket: bucketName }));
        bucketRegion = loc.LocationConstraint || 'us-east-1';
      } catch { /* ignore — some buckets are inaccessible cross-account/policy-restricted */ }
      try {
        const tagResp = await c.send(new GetBucketTaggingCommand({ Bucket: bucketName }));
        tags = tagListToMap(tagResp.TagSet);
      } catch { /* no tags or no permission — not fatal */ }
      try {
        const pabResp = await c.send(new GetPublicAccessBlockCommand({ Bucket: bucketName }));
        publicAccessBlock = pabResp.PublicAccessBlockConfiguration ?? null;
      } catch {
        publicAccessBlock = { BlockPublicAcls: false, BlockPublicPolicy: false, IgnorePublicAcls: false, RestrictPublicBuckets: false };
      }
      items.push({
        nativeId: bucketName, resourceType: 'AWS::S3::Bucket', resourceName: bucketName, region: bucketRegion, tags,
        configState: { ...b, PublicAccessBlock: publicAccessBlock } as unknown as Record<string, unknown>,
      });
    });
  });

  await safe('IAM roles', async () => {
    const c = new IAMClient(cfg);
    let marker: string | undefined;
    const roles: Array<{ Arn: string; RoleName: string; [k: string]: unknown }> = [];
    do {
      const resp = await c.send(new ListRolesCommand({ Marker: marker }));
      marker = resp.IsTruncated ? resp.Marker : undefined;
      for (const role of resp.Roles ?? []) if (role.Arn) roles.push(role as any);
    } while (marker);

    await mapWithConcurrency(roles, 10, async (role) => {
      let attachedPolicies: unknown[] = [];
      const inlinePolicies: Record<string, unknown> = {};
      try {
        const attachedResp = await c.send(new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName }));
        attachedPolicies = attachedResp.AttachedPolicies ?? [];
      } catch { /* non-fatal — this role's managed-policy grants just won't flatten */ }
      try {
        const inlineResp = await c.send(new ListRolePoliciesCommand({ RoleName: role.RoleName }));
        for (const pname of inlineResp.PolicyNames ?? []) {
          try {
            const p = await c.send(new GetRolePolicyCommand({ RoleName: role.RoleName, PolicyName: pname }));
            inlinePolicies[pname] = p.PolicyDocument ? JSON.parse(decodeURIComponent(p.PolicyDocument)) : null;
          } catch { /* non-fatal */ }
        }
      } catch { /* non-fatal */ }
      items.push({
        nativeId: role.Arn, resourceType: 'AWS::IAM::Role', resourceName: role.RoleName as string,
        configState: { ...role, attachedPolicies, inlinePolicies } as unknown as Record<string, unknown>,
      });
    });
  });

  await safe('IAM users', async () => {
    const c = new IAMClient(cfg);
    let marker: string | undefined;
    const users: Array<{ Arn: string; UserName: string; [k: string]: unknown }> = [];
    do {
      const resp = await c.send(new ListUsersCommand({ Marker: marker }));
      marker = resp.IsTruncated ? resp.Marker : undefined;
      for (const u of resp.Users ?? []) if (u.Arn) users.push(u as any);
    } while (marker);

    await mapWithConcurrency(users, 10, async (u) => {
      let attachedPolicies: unknown[] = [];
      const inlinePolicies: Record<string, unknown> = {};
      try {
        const attachedResp = await c.send(new ListAttachedUserPoliciesCommand({ UserName: u.UserName }));
        attachedPolicies = attachedResp.AttachedPolicies ?? [];
      } catch { /* non-fatal */ }
      try {
        const inlineResp = await c.send(new ListUserPoliciesCommand({ UserName: u.UserName }));
        for (const pname of inlineResp.PolicyNames ?? []) {
          try {
            const p = await c.send(new GetUserPolicyCommand({ UserName: u.UserName, PolicyName: pname }));
            inlinePolicies[pname] = p.PolicyDocument ? JSON.parse(decodeURIComponent(p.PolicyDocument)) : null;
          } catch { /* non-fatal */ }
        }
      } catch { /* non-fatal */ }
      items.push({
        nativeId: u.Arn, resourceType: 'AWS::IAM::User', resourceName: u.UserName,
        configState: { ...u, attachedPolicies, inlinePolicies } as unknown as Record<string, unknown>,
      });
    });
  });

  await safe('IAM policies', async () => {
    const c = new IAMClient(cfg);
    let marker: string | undefined;
    do {
      const resp = await c.send(new ListPoliciesCommand({ Scope: 'Local', Marker: marker }));
      marker = resp.IsTruncated ? resp.Marker : undefined;
      for (const p of resp.Policies ?? []) {
        if (!p.Arn) continue;
        let document: unknown = null;
        if (p.Arn && p.DefaultVersionId) {
          try {
            const versionResp = await c.send(new GetPolicyVersionCommand({ PolicyArn: p.Arn, VersionId: p.DefaultVersionId }));
            const raw = versionResp.PolicyVersion?.Document;
            document = raw ? JSON.parse(decodeURIComponent(raw)) : null;
          } catch { /* non-fatal — leave document null, that policy's grants just won't flatten */ }
        }
        items.push({ nativeId: p.Arn, resourceType: 'AWS::IAM::Policy', resourceName: p.PolicyName, configState: { ...p, Document: document } as unknown as Record<string, unknown> });
      }
    } while (marker);
  });

  await safe('IAM groups', async () => {
    const c = new IAMClient(cfg);
    let marker: string | undefined;
    do {
      const resp = await c.send(new ListGroupsCommand({ Marker: marker }));
      marker = resp.IsTruncated ? resp.Marker : undefined;
      for (const g of resp.Groups ?? []) {
        if (!g.Arn) continue;
        items.push({ nativeId: g.Arn, resourceType: 'AWS::IAM::Group', resourceName: g.GroupName, configState: g as unknown as Record<string, unknown> });
      }
    } while (marker);
  });

  await safe('RDS instances', async () => {
    const c = new RDSClient(cfg);
    const resp = await c.send(new DescribeDBInstancesCommand({}));
    for (const db of resp.DBInstances ?? []) {
      if (!db.DBInstanceArn) continue;
      const tags = tagListToMap(db.TagList);
      items.push({ nativeId: db.DBInstanceArn, resourceType: 'AWS::RDS::DBInstance', resourceName: db.DBInstanceIdentifier, region, tags, configState: db as unknown as Record<string, unknown> });
    }
  });

  await safe('RDS clusters', async () => {
    const c = new RDSClient(cfg);
    const resp = await c.send(new DescribeDBClustersCommand({}));
    for (const db of resp.DBClusters ?? []) {
      if (!db.DBClusterArn) continue;
      const tags = tagListToMap(db.TagList);
      items.push({ nativeId: db.DBClusterArn, resourceType: 'AWS::RDS::DBCluster', resourceName: db.DBClusterIdentifier, region, tags, configState: db as unknown as Record<string, unknown> });
    }
  });

  await safe('Lambda functions', async () => {
    const c = new LambdaClient(cfg);
    let marker: string | undefined;
    do {
      const resp = await c.send(new ListFunctionsCommand({ Marker: marker }));
      marker = resp.NextMarker;
      for (const fn of resp.Functions ?? []) {
        if (!fn.FunctionArn) continue;
        items.push({ nativeId: fn.FunctionArn, resourceType: 'AWS::Lambda::Function', resourceName: fn.FunctionName, region, configState: fn as unknown as Record<string, unknown> });
      }
    } while (marker);
  });

  await safe('EKS clusters', async () => {
    const c = new EKSClient(cfg);
    const list = await c.send(new EksListClustersCommand({}));
    for (const name of list.clusters ?? []) {
      try {
        const desc = await c.send(new DescribeClusterCommand({ name }));
        if (!desc.cluster?.arn) continue;
        items.push({ nativeId: desc.cluster.arn, resourceType: 'AWS::EKS::Cluster', resourceName: name, region, tags: desc.cluster.tags, configState: desc.cluster as unknown as Record<string, unknown> });
      } catch (e) { logger.error('[resource-discovery] EKS describe failed:', (e as Error).message); }
    }
  });

  await safe('ELBv2 load balancers', async () => {
    const c = new ElasticLoadBalancingV2Client(cfg);
    const resp = await c.send(new DescribeLoadBalancersCommand({}));
    for (const lb of resp.LoadBalancers ?? []) {
      if (!lb.LoadBalancerArn) continue;
      items.push({ nativeId: lb.LoadBalancerArn, resourceType: 'AWS::ElasticLoadBalancingV2::LoadBalancer', resourceName: lb.LoadBalancerName, region, configState: lb as unknown as Record<string, unknown> });
    }
  });

  await safe('DynamoDB tables', async () => {
    const c = new DynamoDBClient(cfg);
    let start: string | undefined;
    do {
      const list = await c.send(new ListTablesCommand({ ExclusiveStartTableName: start }));
      start = list.LastEvaluatedTableName;
      for (const name of list.TableNames ?? []) {
        try {
          const desc = await c.send(new DescribeTableCommand({ TableName: name }));
          const t = desc.Table;
          if (!t?.TableArn) continue;
          items.push({ nativeId: t.TableArn, resourceType: 'AWS::DynamoDB::Table', resourceName: name, region, configState: t as unknown as Record<string, unknown> });
        } catch (e) { logger.error('[resource-discovery] DynamoDB describe failed:', (e as Error).message); }
      }
    } while (start);
  });

  await safe('KMS keys', async () => {
    const c = new KMSClient(cfg);
    let marker: string | undefined;
    do {
      const resp = await c.send(new ListKeysCommand({ Marker: marker }));
      marker = resp.Truncated ? resp.NextMarker : undefined;
      for (const k of resp.Keys ?? []) {
        if (!k.KeyArn) continue;
        try {
          const desc = await c.send(new DescribeKeyCommand({ KeyId: k.KeyId }));
          // Skip AWS-managed keys — only customer-managed keys are meaningful to inventory.
          if (desc.KeyMetadata?.KeyManager !== 'CUSTOMER') continue;
          items.push({ nativeId: k.KeyArn, resourceType: 'AWS::KMS::Key', resourceName: k.KeyId, region, configState: (desc.KeyMetadata ?? {}) as unknown as Record<string, unknown> });
        } catch (e) { logger.error('[resource-discovery] KMS describe failed:', (e as Error).message); }
      }
    } while (marker);
  });

  await safe('SNS topics', async () => {
    const c = new SNSClient(cfg);
    let nextToken: string | undefined;
    do {
      const resp = await c.send(new ListTopicsCommand({ NextToken: nextToken }));
      nextToken = resp.NextToken;
      for (const t of resp.Topics ?? []) {
        if (!t.TopicArn) continue;
        items.push({ nativeId: t.TopicArn, resourceType: 'AWS::SNS::Topic', resourceName: t.TopicArn.split(':').pop(), region, configState: t as unknown as Record<string, unknown> });
      }
    } while (nextToken);
  });

  await safe('SQS queues', async () => {
    const c = new SQSClient(cfg);
    const resp = await c.send(new ListQueuesCommand({}));
    for (const url of resp.QueueUrls ?? []) {
      items.push({ nativeId: url, resourceType: 'AWS::SQS::Queue', resourceName: url.split('/').pop(), region, configState: { QueueUrl: url } });
    }
  });

  await safe('CloudFront distributions', async () => {
    const c = new CloudFrontClient({ ...cfg, region: 'us-east-1' }); // CloudFront is a global service
    const resp = await c.send(new ListDistributionsCommand({}));
    for (const d of resp.DistributionList?.Items ?? []) {
      if (!d.ARN) continue;
      items.push({ nativeId: d.ARN, resourceType: 'AWS::CloudFront::Distribution', resourceName: d.DomainName, configState: d as unknown as Record<string, unknown> });
    }
  });

  await safe('ElastiCache clusters', async () => {
    const c = new ElastiCacheClient(cfg);
    const resp = await c.send(new DescribeCacheClustersCommand({}));
    for (const cl of resp.CacheClusters ?? []) {
      if (!cl.CacheClusterId) continue;
      items.push({ nativeId: cl.CacheClusterId, resourceType: 'AWS::ElastiCache::CacheCluster', resourceName: cl.CacheClusterId, region, configState: cl as unknown as Record<string, unknown> });
    }
  });

  return items;
}

// ─── Dependency extraction helpers ───────────────────────────────────────────

interface DepEdge { nativeId: string; depType: DependencyType; description: string }

function extractAwsDeps(config: Record<string, unknown>): DepEdge[] {
  const edges: DepEdge[] = [];
  const cfg = (config.configuration ?? config) as Record<string, unknown>;

  // VPC membership
  if (cfg.vpcId && typeof cfg.vpcId === 'string') {
    edges.push({ nativeId: cfg.vpcId, depType: 'NETWORK', description: 'Member of VPC' });
  }
  // Subnet
  if (cfg.subnetId && typeof cfg.subnetId === 'string') {
    edges.push({ nativeId: cfg.subnetId, depType: 'NETWORK', description: 'Placed in subnet' });
  }
  // Security groups
  const sgs = cfg.securityGroups as { groupId?: string }[] | undefined;
  if (Array.isArray(sgs)) {
    sgs.forEach((sg) => {
      if (sg.groupId) edges.push({ nativeId: sg.groupId, depType: 'NETWORK', description: 'Attached security group' });
    });
  }
  // IAM instance profile
  const iam = cfg.iamInstanceProfile as { arn?: string } | undefined;
  if (iam?.arn) {
    edges.push({ nativeId: iam.arn, depType: 'IAM', description: 'IAM instance profile' });
  }
  // KMS key
  if (cfg.kmsKeyId && typeof cfg.kmsKeyId === 'string') {
    edges.push({ nativeId: cfg.kmsKeyId as string, depType: 'OTHER', description: 'Encrypted with KMS key' });
  }
  // DB subnet group → VPC
  if (cfg.dbSubnetGroup && typeof (cfg.dbSubnetGroup as Record<string, unknown>).vpcId === 'string') {
    edges.push({ nativeId: (cfg.dbSubnetGroup as Record<string, unknown>).vpcId as string, depType: 'NETWORK', description: 'DB in VPC' });
  }
  return edges;
}

function extractAzureDeps(resourceId: string, config: Record<string, unknown>): DepEdge[] {
  const edges: DepEdge[] = [];
  const props = (config.properties ?? config) as Record<string, unknown>;

  // Subnet reference → parent VNet
  const subnetRef = (props.subnet as Record<string, unknown>)?.id as string | undefined;
  if (subnetRef) edges.push({ nativeId: subnetRef, depType: 'NETWORK', description: 'Connected to subnet' });

  // VNet reference
  const vnetRef = (props.virtualNetwork as Record<string, unknown>)?.id as string | undefined;
  if (vnetRef) edges.push({ nativeId: vnetRef, depType: 'NETWORK', description: 'Member of virtual network' });

  // NSG reference
  const nsgRef = (props.networkSecurityGroup as Record<string, unknown>)?.id as string | undefined;
  if (nsgRef) edges.push({ nativeId: nsgRef, depType: 'NETWORK', description: 'Protected by NSG' });

  // Managed identity
  const identityId = (config.identity as Record<string, unknown>)?.principalId as string | undefined;
  if (identityId) edges.push({ nativeId: identityId, depType: 'IAM', description: 'Uses managed identity' });

  // Storage account reference
  const storageRef = (props.storageAccount as Record<string, unknown>)?.id as string | undefined;
  if (storageRef) edges.push({ nativeId: storageRef, depType: 'STORAGE', description: 'Uses storage account' });

  // Key vault reference
  const kvRef = (props.keyVaultId as string) ?? ((props.keyVault as Record<string, unknown>)?.id as string | undefined);
  if (kvRef) edges.push({ nativeId: kvRef, depType: 'OTHER', description: 'Uses key vault' });

  return edges;
}

function extractGcpDeps(config: Record<string, unknown>): DepEdge[] {
  const edges: DepEdge[] = [];

  // Network/subnetwork
  if (config.network && typeof config.network === 'string') {
    edges.push({ nativeId: config.network, depType: 'NETWORK', description: 'Connected to network' });
  }
  if (config.subnetwork && typeof config.subnetwork === 'string') {
    edges.push({ nativeId: config.subnetwork, depType: 'NETWORK', description: 'In subnetwork' });
  }
  // Service account
  if (config.serviceAccount && typeof config.serviceAccount === 'string') {
    edges.push({ nativeId: config.serviceAccount, depType: 'IAM', description: 'Runs as service account' });
  }
  // Network interfaces
  const nics = config.networkInterfaces as { network?: string; subnetwork?: string }[] | undefined;
  if (Array.isArray(nics)) {
    nics.forEach((nic) => {
      if (nic.network) edges.push({ nativeId: nic.network, depType: 'NETWORK', description: 'Network interface in network' });
    });
  }
  return edges;
}

// ─── Upsert + snapshot logic ──────────────────────────────────────────────────

interface UpsertResourceParams {
  provider:      string;
  awsAccountId?: string;
  azureSubId?:   string;
  gcpProjectId?: string;
  nativeId:      string;
  resourceType:  string;
  resourceName?: string;
  region?:       string;
  resourceGroup?: string;
  tags?:         Record<string, string> | null;
  configState:   Record<string, unknown>;
}

async function upsertResource(p: UpsertResourceParams, seenIds: Set<string>): Promise<void> {
  const existing = await prisma.resourceInventory.findUnique({
    where: { nativeId_provider: { nativeId: p.nativeId, provider: p.provider } },
  });

  const now        = new Date();
  const jsonConfig = p.configState as unknown as Prisma.InputJsonValue;
  const jsonTags   = p.tags ? (p.tags as unknown as Prisma.InputJsonValue) : undefined;

  if (!existing) {
    // New resource — create + snapshot(CREATED)
    const created = await prisma.resourceInventory.create({
      data: {
        provider:      p.provider,
        awsAccountId:  p.awsAccountId,
        azureSubId:    p.azureSubId,
        gcpProjectId:  p.gcpProjectId,
        nativeId:      p.nativeId,
        resourceType:  p.resourceType,
        resourceName:  p.resourceName,
        region:        p.region,
        resourceGroup: p.resourceGroup,
        tags:          jsonTags,
        configState:   jsonConfig,
        state:         'ACTIVE',
        discoveredAt:  now,
        lastSeenAt:    now,
      },
    });
    await prisma.resourceSnapshot.create({
      data: { inventoryId: created.id, configState: jsonConfig, changeType: 'CREATED', capturedAt: now },
    });
    seenIds.add(created.id);
    return;
  }

  seenIds.add(existing.id);

  const prevConfig = existing.configState as Record<string, unknown>;
  const changed    = !deepEqual(prevConfig, p.configState);

  await prisma.resourceInventory.update({
    where: { id: existing.id },
    data: {
      resourceName:  p.resourceName  ?? existing.resourceName,
      region:        p.region        ?? existing.region,
      resourceGroup: p.resourceGroup ?? existing.resourceGroup,
      tags:          jsonTags,
      configState:   jsonConfig,
      state:         'ACTIVE',
      lastSeenAt:    now,
    },
  });

  if (changed) {
    await prisma.resourceSnapshot.create({
      data: { inventoryId: existing.id, configState: jsonConfig, changeType: 'MODIFIED', capturedAt: now },
    });
  }
}

async function upsertDeps(fromNativeId: string, provider: string, edges: DepEdge[]): Promise<void> {
  if (edges.length === 0) return;

  const from = await prisma.resourceInventory.findUnique({
    where: { nativeId_provider: { nativeId: fromNativeId, provider } },
    select: { id: true },
  });
  if (!from) return;

  for (const edge of edges) {
    const to = await prisma.resourceInventory.findUnique({
      where: { nativeId_provider: { nativeId: edge.nativeId, provider } },
      select: { id: true },
    });
    if (!to || to.id === from.id) continue;

    await prisma.resourceDependency.upsert({
      where: { fromId_toId_depType: { fromId: from.id, toId: to.id, depType: edge.depType } },
      update: { description: edge.description },
      create: {
        fromId:      from.id,
        toId:        to.id,
        depType:     edge.depType,
        description: edge.description,
        provider,
      },
    });
  }
}

// ─── AWS Discovery ─────────────────────────────────────────────────────────────

export async function discoverAwsResources(
  accountId:  string,
  region?:    string,
): Promise<{ discovered: number; updated: number; deleted: number }> {
  const cred = await prisma.awsCredential.findUnique({ where: { accountId } });
  const r    = region ?? cred?.defaultRegion ?? 'us-east-1';
  const creds = await getAwsCredentials(accountId, r);

  const seenIds = new Set<string>();
  let discovered = 0;

  const found = await listAwsResourcesDirect(creds, r);
  for (const item of found) {
    await upsertResource({
      provider:     'AWS',
      awsAccountId: accountId,
      nativeId:     item.nativeId,
      resourceType: item.resourceType,
      resourceName: item.resourceName,
      region:       item.region,
      tags:         item.tags,
      configState:  item.configState,
    }, seenIds);
    discovered++;
  }

  // Dependency pass — iterate all active resources for this account
  const allResources = await prisma.resourceInventory.findMany({
    where: { awsAccountId: accountId, state: 'ACTIVE' },
    select: { id: true, nativeId: true, configState: true },
  });
  for (const res of allResources) {
    const edges = extractAwsDeps(res.configState as Record<string, unknown>);
    await upsertDeps(res.nativeId, 'AWS', edges);
  }

  // Mark resources not seen this run as DELETED
  const now = new Date();
  const allActive = await prisma.resourceInventory.findMany({
    where: { awsAccountId: accountId, state: 'ACTIVE' },
    select: { id: true },
  });
  const toDelete = allActive.filter((r) => !seenIds.has(r.id));
  let deleted = 0;
  for (const res of toDelete) {
    await prisma.resourceInventory.update({
      where: { id: res.id },
      data: { state: 'DELETED', deletedAt: now, lastSeenAt: now },
    });
    const inv = await prisma.resourceInventory.findUnique({ where: { id: res.id }, select: { configState: true } });
    if (inv) {
      await prisma.resourceSnapshot.create({
        data: { inventoryId: res.id, configState: inv.configState as unknown as Prisma.InputJsonValue, changeType: 'DELETED', capturedAt: now },
      });
    }
    deleted++;
  }

  return { discovered, updated: 0, deleted };
}

// ─── Azure Discovery ──────────────────────────────────────────────────────────

export async function discoverAzureResources(
  subscriptionInternalId: string,
): Promise<{ discovered: number; updated: number; deleted: number }> {
  const sub  = await prisma.azureSubscription.findUnique({ where: { id: subscriptionInternalId } });
  if (!sub) throw new Error('Azure subscription not found');
  const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId: subscriptionInternalId } });
  if (!cred) throw new Error('No Azure credentials configured');

  const dec   = decryptAzureCredentials(cred);
  const azure = new AzureClient({
    subscriptionId: sub.subscriptionId,
    tenantId:       dec.tenantId,
    clientId:       dec.clientId,
    clientSecret:   dec.clientSecret,
    authMethod:     cred.authMethod as 'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY',
  });

  const seenIds  = new Set<string>();
  let discovered = 0;

  // Helper to extract resource group from Azure resource ID
  const rgFromId = (id: string): string | undefined => {
    const m = id.match(/resourceGroups\/([^/]+)/i);
    return m?.[1];
  };

  // Discover VMs
  try {
    const compute = azure.compute();
    for await (const vm of compute.virtualMachines.listAll()) {
      if (!vm.id) continue;
      const config: Record<string, unknown> = {
        vmSize:         vm.hardwareProfile?.vmSize,
        location:       vm.location,
        provisioningState: vm.provisioningState,
        osType:         vm.storageProfile?.osDisk?.osType,
        networkInterfaces: (vm.networkProfile?.networkInterfaces ?? []).map((nic) => ({ id: nic.id })),
        properties:     { subnet: null, networkSecurityGroup: null },
      };
      await upsertResource({
        provider: 'AZURE', azureSubId: subscriptionInternalId,
        nativeId:      vm.id,
        resourceType:  'Microsoft.Compute/virtualMachines',
        resourceName:  vm.name ?? undefined,
        region:        vm.location,
        resourceGroup: rgFromId(vm.id),
        tags:          vm.tags as Record<string, string> | null,
        configState:   config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip if no access */ }

  // Discover VNets
  try {
    const network = azure.network();
    for await (const vnet of network.virtualNetworks.listAll()) {
      if (!vnet.id) continue;
      const config: Record<string, unknown> = {
        location:       vnet.location,
        addressSpace:   vnet.addressSpace?.addressPrefixes,
        subnets:        (vnet.subnets ?? []).map((s) => ({ id: s.id, name: s.name, addressPrefix: s.addressPrefix })),
        provisioningState: vnet.provisioningState,
      };
      await upsertResource({
        provider: 'AZURE', azureSubId: subscriptionInternalId,
        nativeId:      vnet.id,
        resourceType:  'Microsoft.Network/virtualNetworks',
        resourceName:  vnet.name ?? undefined,
        region:        vnet.location,
        resourceGroup: rgFromId(vnet.id),
        tags:          vnet.tags as Record<string, string> | null,
        configState:   config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Discover NSGs
  try {
    const network = azure.network();
    for await (const nsg of network.networkSecurityGroups.listAll()) {
      if (!nsg.id) continue;
      const config: Record<string, unknown> = {
        location:         nsg.location,
        provisioningState: nsg.provisioningState,
        securityRules:    (nsg.securityRules ?? []).map((r) => ({
          name: r.name, direction: r.direction, access: r.access,
          protocol: r.protocol, priority: r.priority,
          sourceAddressPrefix: r.sourceAddressPrefix,
          destinationPortRange: r.destinationPortRange,
        })),
      };
      await upsertResource({
        provider: 'AZURE', azureSubId: subscriptionInternalId,
        nativeId:      nsg.id,
        resourceType:  'Microsoft.Network/networkSecurityGroups',
        resourceName:  nsg.name ?? undefined,
        region:        nsg.location,
        resourceGroup: rgFromId(nsg.id),
        tags:          nsg.tags as Record<string, string> | null,
        configState:   config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Discover Storage Accounts
  try {
    const storage = azure.storage();
    for await (const account of storage.storageAccounts.list()) {
      if (!account.id) continue;
      const config: Record<string, unknown> = {
        kind:             account.kind,
        location:         account.location,
        sku:              account.sku?.name,
        provisioningState: account.provisioningState,
        allowBlobPublicAccess: (account as unknown as Record<string, unknown>).allowBlobPublicAccess,
        minimumTlsVersion: (account as unknown as Record<string, unknown>).minimumTlsVersion,
        supportsHttpsTrafficOnly: account.enableHttpsTrafficOnly,
      };
      await upsertResource({
        provider: 'AZURE', azureSubId: subscriptionInternalId,
        nativeId:      account.id,
        resourceType:  'Microsoft.Storage/storageAccounts',
        resourceName:  account.name ?? undefined,
        region:        account.location,
        resourceGroup: rgFromId(account.id),
        tags:          account.tags as Record<string, string> | null,
        configState:   config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Discover Key Vaults
  try {
    const kv = azure.keyVault();
    for await (const vault of kv.vaults.list()) {
      if (!vault.id) continue;
      const vaultAny = vault as Record<string, unknown>;
      const vaultProps = (vaultAny.properties ?? {}) as Record<string, unknown>;
      const config: Record<string, unknown> = {
        location:         vault.location,
        sku:              (vaultProps.sku as Record<string, unknown>)?.name,
        tenantId:         vaultProps.tenantId,
        enableSoftDelete: vaultProps.enableSoftDelete,
        enablePurgeProtection: vaultProps.enablePurgeProtection,
      };
      await upsertResource({
        provider: 'AZURE', azureSubId: subscriptionInternalId,
        nativeId:      vault.id,
        resourceType:  'Microsoft.KeyVault/vaults',
        resourceName:  vault.name ?? undefined,
        region:        vault.location,
        resourceGroup: rgFromId(vault.id),
        tags:          vault.tags as Record<string, string> | null,
        configState:   config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Discover SQL Servers
  try {
    const sql = azure.sql();
    for await (const server of sql.servers.list()) {
      if (!server.id) continue;
      const config: Record<string, unknown> = {
        location:          server.location,
        version:           server.version,
        state:             server.state,
        fullyQualifiedDomainName: server.fullyQualifiedDomainName,
        minimalTlsVersion: server.minimalTlsVersion,
        publicNetworkAccess: server.publicNetworkAccess,
      };
      await upsertResource({
        provider: 'AZURE', azureSubId: subscriptionInternalId,
        nativeId:      server.id,
        resourceType:  'Microsoft.Sql/servers',
        resourceName:  server.name ?? undefined,
        region:        server.location,
        resourceGroup: rgFromId(server.id),
        tags:          server.tags as Record<string, string> | null,
        configState:   config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Dependency pass
  const allResources = await prisma.resourceInventory.findMany({
    where: { azureSubId: subscriptionInternalId, state: 'ACTIVE' },
    select: { nativeId: true, configState: true },
  });
  for (const res of allResources) {
    const edges = extractAzureDeps(res.nativeId, res.configState as Record<string, unknown>);
    await upsertDeps(res.nativeId, 'AZURE', edges);
  }

  // Mark deleted
  const now = new Date();
  const allActive = await prisma.resourceInventory.findMany({
    where: { azureSubId: subscriptionInternalId, state: 'ACTIVE' },
    select: { id: true },
  });
  const toDelete = allActive.filter((r) => !seenIds.has(r.id));
  let deleted = 0;
  for (const res of toDelete) {
    await prisma.resourceInventory.update({
      where: { id: res.id },
      data: { state: 'DELETED', deletedAt: now, lastSeenAt: now },
    });
    const inv = await prisma.resourceInventory.findUnique({ where: { id: res.id }, select: { configState: true } });
    if (inv) {
      await prisma.resourceSnapshot.create({
        data: { inventoryId: res.id, configState: inv.configState as unknown as Prisma.InputJsonValue, changeType: 'DELETED', capturedAt: now },
      });
    }
    deleted++;
  }

  return { discovered, updated: 0, deleted };
}

// ─── GCP Discovery ────────────────────────────────────────────────────────────

export async function discoverGcpResources(
  projectInternalId: string,
): Promise<{ discovered: number; updated: number; deleted: number }> {
  const project = await prisma.gcpProject.findUnique({ where: { id: projectInternalId } });
  if (!project) throw new Error('GCP project not found');
  const cred = await prisma.gcpCredential.findUnique({ where: { projectId: projectInternalId } });
  if (!cred) throw new Error('No GCP credentials configured');

  const dec = decryptGcpCredentials(cred);
  const gcp = new GcpClient({
    projectId:   project.projectId,
    credentials: dec.serviceAccountKey ? JSON.parse(dec.serviceAccountKey) as Record<string, unknown> : undefined,
    authMethod:  cred.authMethod as 'SERVICE_ACCOUNT_KEY' | 'WORKLOAD_IDENTITY',
  });

  const seenIds  = new Set<string>();
  let discovered = 0;
  const pid      = project.projectId;

  // Discover Compute Instances
  try {
    const compute = gcp.compute();
    const resp    = await compute.instances.aggregatedList({ project: pid, maxResults: 500 });
    const items   = resp.data.items ?? {};
    for (const [zone, zoneData] of Object.entries(items)) {
      for (const inst of (zoneData as Record<string, unknown[]>).instances ?? []) {
        const i   = inst as Record<string, unknown>;
        const config: Record<string, unknown> = {
          machineType:   i.machineType,
          status:        i.status,
          zone,
          networkInterfaces: i.networkInterfaces,
          serviceAccounts:   i.serviceAccounts,
          tags:          i.tags,
          metadata:      i.metadata,
        };
        const name   = String(i.name ?? '');
        const selfLink = String(i.selfLink ?? `projects/${pid}/zones/${zone}/instances/${name}`);
        await upsertResource({
          provider: 'GCP', gcpProjectId: projectInternalId,
          nativeId:     selfLink,
          resourceType: 'compute.googleapis.com/Instance',
          resourceName: name,
          region:       zone,
          configState:  config,
        }, seenIds);
        discovered++;
      }
    }
  } catch { /* skip */ }

  // Discover VPC Networks
  try {
    const compute = gcp.compute();
    const resp    = await compute.networks.list({ project: pid });
    for (const net of resp.data.items ?? []) {
      const config: Record<string, unknown> = {
        autoCreateSubnetworks: net.autoCreateSubnetworks,
        routingConfig:         net.routingConfig,
        subnetworks:           net.subnetworks,
        selfLink:              net.selfLink,
      };
      await upsertResource({
        provider: 'GCP', gcpProjectId: projectInternalId,
        nativeId:     net.selfLink ?? net.name ?? '',
        resourceType: 'compute.googleapis.com/Network',
        resourceName: net.name ?? undefined,
        configState:  config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Discover Firewall rules
  try {
    const compute = gcp.compute();
    const resp    = await compute.firewalls.list({ project: pid });
    for (const fw of resp.data.items ?? []) {
      const config: Record<string, unknown> = {
        direction:  fw.direction,
        priority:   fw.priority,
        network:    fw.network,
        allowed:    fw.allowed,
        denied:     fw.denied,
        sourceRanges: fw.sourceRanges,
        targetTags: fw.targetTags,
        disabled:   fw.disabled,
      };
      await upsertResource({
        provider: 'GCP', gcpProjectId: projectInternalId,
        nativeId:     fw.selfLink ?? fw.name ?? '',
        resourceType: 'compute.googleapis.com/Firewall',
        resourceName: fw.name ?? undefined,
        configState:  config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Discover Storage Buckets
  try {
    const storage = gcp.storage();
    const resp    = await storage.buckets.list({ project: pid });
    for (const bucket of resp.data.items ?? []) {
      const config: Record<string, unknown> = {
        location:             bucket.location,
        storageClass:         bucket.storageClass,
        uniformBucketLevelAccess: (bucket.iamConfiguration as Record<string, unknown>)?.uniformBucketLevelAccess,
        retentionPolicy:      bucket.retentionPolicy,
        versioning:           bucket.versioning,
        logging:              bucket.logging,
      };
      await upsertResource({
        provider: 'GCP', gcpProjectId: projectInternalId,
        nativeId:     `//storage.googleapis.com/${bucket.name}`,
        resourceType: 'storage.googleapis.com/Bucket',
        resourceName: bucket.name ?? undefined,
        region:       bucket.location ?? undefined,
        configState:  config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Discover SQL Instances
  try {
    const sql  = gcp.sqladmin();
    const resp = await sql.instances.list({ project: pid });
    for (const inst of resp.data.items ?? []) {
      const config: Record<string, unknown> = {
        databaseVersion:    inst.databaseVersion,
        region:             inst.region,
        state:              inst.state,
        backendType:        inst.backendType,
        settings:           inst.settings,
        ipAddresses:        inst.ipAddresses,
        connectionName:     inst.connectionName,
      };
      await upsertResource({
        provider: 'GCP', gcpProjectId: projectInternalId,
        nativeId:     `//sqladmin.googleapis.com/projects/${pid}/instances/${inst.name}`,
        resourceType: 'sqladmin.googleapis.com/Instance',
        resourceName: inst.name ?? undefined,
        region:       inst.region ?? undefined,
        configState:  config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Discover GKE Clusters
  try {
    const container = gcp.container();
    const resp      = await container.projects.locations.clusters.list({ parent: `projects/${pid}/locations/-` });
    for (const cluster of resp.data.clusters ?? []) {
      const config: Record<string, unknown> = {
        status:           cluster.status,
        location:         cluster.location,
        currentMasterVersion: cluster.currentMasterVersion,
        nodePools:        (cluster.nodePools ?? []).map((np) => ({ name: np.name, status: np.status })),
        network:          cluster.network,
        subnetwork:       cluster.subnetwork,
        privateClusterConfig: cluster.privateClusterConfig,
      };
      await upsertResource({
        provider: 'GCP', gcpProjectId: projectInternalId,
        nativeId:     cluster.selfLink ?? `//container.googleapis.com/projects/${pid}/clusters/${cluster.name}`,
        resourceType: 'container.googleapis.com/Cluster',
        resourceName: cluster.name ?? undefined,
        region:       cluster.location ?? undefined,
        configState:  config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // IAM Service Accounts
  try {
    const iam  = gcp.iam();
    const resp = await iam.projects.serviceAccounts.list({ name: `projects/${pid}` });
    for (const sa of resp.data.accounts ?? []) {
      const config: Record<string, unknown> = {
        email:       sa.email,
        displayName: sa.displayName,
        disabled:    sa.disabled,
        projectId:   sa.projectId,
      };
      await upsertResource({
        provider: 'GCP', gcpProjectId: projectInternalId,
        nativeId:     sa.name ?? sa.email ?? '',
        resourceType: 'iam.googleapis.com/ServiceAccount',
        resourceName: sa.displayName ?? sa.email ?? undefined,
        configState:  config,
      }, seenIds);
      discovered++;
    }
  } catch { /* skip */ }

  // Dependency pass
  const allResources = await prisma.resourceInventory.findMany({
    where: { gcpProjectId: projectInternalId, state: 'ACTIVE' },
    select: { nativeId: true, configState: true },
  });
  for (const res of allResources) {
    const edges = extractGcpDeps(res.configState as Record<string, unknown>);
    await upsertDeps(res.nativeId, 'GCP', edges);
  }

  // Mark deleted
  const now = new Date();
  const allActive = await prisma.resourceInventory.findMany({
    where: { gcpProjectId: projectInternalId, state: 'ACTIVE' },
    select: { id: true },
  });
  const toDelete = allActive.filter((r) => !seenIds.has(r.id));
  let deleted = 0;
  for (const res of toDelete) {
    await prisma.resourceInventory.update({
      where: { id: res.id },
      data: { state: 'DELETED', deletedAt: now, lastSeenAt: now },
    });
    const inv = await prisma.resourceInventory.findUnique({ where: { id: res.id }, select: { configState: true } });
    if (inv) {
      await prisma.resourceSnapshot.create({
        data: { inventoryId: res.id, configState: inv.configState as unknown as Prisma.InputJsonValue, changeType: 'DELETED', capturedAt: now },
      });
    }
    deleted++;
  }

  return { discovered, updated: 0, deleted };
}
