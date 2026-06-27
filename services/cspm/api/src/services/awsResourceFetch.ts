/**
 * AWS Resource State Fetcher
 *
 * Given AWS credentials + a CloudTrail event context, fetches the CURRENT full
 * resource configuration from the appropriate AWS service API.
 *
 * Used to populate ConfigChange.newValue with the real post-change resource
 * state (instead of just the raw requestParameters from CloudTrail).
 * Combined with ConfigChange.previousValue (from ResourceInventory.configState),
 * this enables accurate before→after diffs.
 */

import {
  S3Client,
  GetBucketPolicyCommand,
  GetBucketAclCommand,
  GetBucketVersioningCommand,
  GetPublicAccessBlockCommand,
  GetBucketEncryptionCommand,
  GetBucketLoggingCommand,
  GetBucketReplicationCommand,
  GetBucketLifecycleConfigurationCommand,
} from '@aws-sdk/client-s3';
import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  DescribeVpcsCommand,
  DescribeRouteTablesCommand,
  DescribeInternetGatewaysCommand,
  DescribeNetworkAclsCommand,
  DescribeSubnetsCommand,
} from '@aws-sdk/client-ec2';
import {
  IAMClient,
  GetUserCommand,
  GetRoleCommand,
  GetGroupCommand,
  ListAttachedUserPoliciesCommand,
  ListAttachedRolePoliciesCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
  GetRoleCommand as GetRoleCmd,
} from '@aws-sdk/client-iam';
import {
  RDSClient,
  DescribeDBInstancesCommand,
  DescribeDBClustersCommand,
} from '@aws-sdk/client-rds';
import {
  LambdaClient,
  GetFunctionConfigurationCommand,
} from '@aws-sdk/client-lambda';
import {
  KMSClient,
  DescribeKeyCommand,
  GetKeyPolicyCommand,
  GetKeyRotationStatusCommand,
} from '@aws-sdk/client-kms';
import {
  CloudTrailClient,
  GetTrailCommand,
  GetTrailStatusCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeListenersCommand,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import {
  ElastiCacheClient,
  DescribeCacheClustersCommand,
  DescribeReplicationGroupsCommand,
} from '@aws-sdk/client-elasticache';
import {
  SQSClient,
  GetQueueAttributesCommand,
} from '@aws-sdk/client-sqs';
import {
  SNSClient,
  GetTopicAttributesCommand,
} from '@aws-sdk/client-sns';
import {
  RedshiftClient,
  DescribeClustersCommand,
} from '@aws-sdk/client-redshift';

export interface AwsFetchContext {
  credentials: {
    accessKeyId:     string;
    secretAccessKey: string;
    sessionToken?:   string;
  };
  region: string;
}

// ─── Resource type → fetch function mapping ──────────────────────────────────

type FetchFn = (ctx: AwsFetchContext, id: string, params: Record<string, unknown>) => Promise<Record<string, unknown> | null>;

const FETCHERS: Record<string, FetchFn> = {
  // ── S3 ──────────────────────────────────────────────────────────────────────
  'AWS::S3::Bucket': fetchS3Bucket,

  // ── EC2 ─────────────────────────────────────────────────────────────────────
  'AWS::EC2::SecurityGroup':    fetchSecurityGroup,
  'AWS::EC2::Instance':         fetchEc2Instance,
  'AWS::EC2::VPC':              fetchVpc,
  'AWS::EC2::RouteTable':       fetchRouteTable,
  'AWS::EC2::InternetGateway':  fetchInternetGateway,
  'AWS::EC2::NetworkAcl':       fetchNetworkAcl,
  'AWS::EC2::Subnet':           fetchSubnet,

  // ── IAM ─────────────────────────────────────────────────────────────────────
  'AWS::IAM::User':   fetchIamUser,
  'AWS::IAM::Role':   fetchIamRole,
  'AWS::IAM::Group':  fetchIamGroup,

  // ── RDS ─────────────────────────────────────────────────────────────────────
  'AWS::RDS::DBInstance': fetchRdsInstance,
  'AWS::RDS::DBCluster':  fetchRdsCluster,

  // ── Lambda ───────────────────────────────────────────────────────────────────
  'AWS::Lambda::Function': fetchLambdaFunction,

  // ── KMS ──────────────────────────────────────────────────────────────────────
  'AWS::KMS::Key': fetchKmsKey,

  // ── CloudTrail ────────────────────────────────────────────────────────────────
  'AWS::CloudTrail::Trail': fetchCloudTrailTrail,

  // ── ELBv2 ────────────────────────────────────────────────────────────────────
  'AWS::ElasticLoadBalancingV2::LoadBalancer': fetchElbV2,
  'AWS::ElasticLoadBalancingV2::Listener':     fetchElbV2Listener,

  // ── ElastiCache ───────────────────────────────────────────────────────────────
  'AWS::ElastiCache::CacheCluster':     fetchElastiCacheCluster,
  'AWS::ElastiCache::ReplicationGroup': fetchElastiCacheReplicationGroup,

  // ── SQS ──────────────────────────────────────────────────────────────────────
  'AWS::SQS::Queue': fetchSqsQueue,

  // ── SNS ──────────────────────────────────────────────────────────────────────
  'AWS::SNS::Topic': fetchSnsTopic,

  // ── Redshift ─────────────────────────────────────────────────────────────────
  'AWS::Redshift::Cluster': fetchRedshiftCluster,
};

// Event name → resource type fallback (when CloudTrail doesn't provide resource type)
const EVENT_TO_RESOURCE_TYPE: Record<string, string> = {
  // S3
  PutBucketPolicy: 'AWS::S3::Bucket', DeleteBucketPolicy: 'AWS::S3::Bucket',
  PutBucketAcl: 'AWS::S3::Bucket', PutBucketVersioning: 'AWS::S3::Bucket',
  PutBucketPublicAccessBlock: 'AWS::S3::Bucket', DeleteBucket: 'AWS::S3::Bucket',
  PutBucketReplication: 'AWS::S3::Bucket', DeleteBucketReplication: 'AWS::S3::Bucket',
  PutBucketEncryption: 'AWS::S3::Bucket', PutBucketLogging: 'AWS::S3::Bucket',
  CreateBucket: 'AWS::S3::Bucket',
  // EC2
  AuthorizeSecurityGroupIngress: 'AWS::EC2::SecurityGroup',
  AuthorizeSecurityGroupEgress:  'AWS::EC2::SecurityGroup',
  RevokeSecurityGroupIngress:    'AWS::EC2::SecurityGroup',
  RevokeSecurityGroupEgress:     'AWS::EC2::SecurityGroup',
  CreateSecurityGroup:           'AWS::EC2::SecurityGroup',
  RunInstances: 'AWS::EC2::Instance', TerminateInstances: 'AWS::EC2::Instance',
  ModifyInstanceAttribute: 'AWS::EC2::Instance',
  CreateRoute: 'AWS::EC2::RouteTable', ReplaceRoute: 'AWS::EC2::RouteTable',
  DeleteRoute: 'AWS::EC2::RouteTable',
  AttachInternetGateway: 'AWS::EC2::InternetGateway',
  CreateNetworkAclEntry: 'AWS::EC2::NetworkAcl',
  DeleteNetworkAclEntry: 'AWS::EC2::NetworkAcl',
  // IAM
  AttachUserPolicy: 'AWS::IAM::User', DetachUserPolicy: 'AWS::IAM::User',
  PutUserPolicy: 'AWS::IAM::User', DeleteUserPolicy: 'AWS::IAM::User',
  AttachRolePolicy: 'AWS::IAM::Role', DetachRolePolicy: 'AWS::IAM::Role',
  PutRolePolicy: 'AWS::IAM::Role', UpdateAssumeRolePolicy: 'AWS::IAM::Role',
  CreateRole: 'AWS::IAM::Role', DeleteRole: 'AWS::IAM::Role',
  // RDS
  CreateDBInstance: 'AWS::RDS::DBInstance', ModifyDBInstance: 'AWS::RDS::DBInstance',
  DeleteDBInstance: 'AWS::RDS::DBInstance',
  CreateDBCluster: 'AWS::RDS::DBCluster', ModifyDBCluster: 'AWS::RDS::DBCluster',
  // Lambda
  UpdateFunctionConfiguration: 'AWS::Lambda::Function',
  UpdateFunctionCode: 'AWS::Lambda::Function',
  // KMS
  EnableKeyRotation: 'AWS::KMS::Key', DisableKeyRotation: 'AWS::KMS::Key',
  PutKeyPolicy: 'AWS::KMS::Key', ScheduleKeyDeletion: 'AWS::KMS::Key',
  DisableKey: 'AWS::KMS::Key',
  // CloudTrail
  UpdateTrail: 'AWS::CloudTrail::Trail', StopLogging: 'AWS::CloudTrail::Trail',
  DeleteTrail: 'AWS::CloudTrail::Trail',
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Fetches the current full resource configuration from the AWS service API.
 * Returns null for deletions (resource no longer exists) or on error.
 */
export async function fetchAwsResourceState(
  ctx: AwsFetchContext,
  resourceType: string | null,
  resourceId:   string | null,
  eventName:    string,
  requestParams: Record<string, unknown>,
): Promise<Record<string, unknown> | null> {
  // Don't fetch for pure delete events — resource is gone
  const isDelete = eventName.startsWith('Delete') || eventName.startsWith('Terminate') ||
                   eventName.startsWith('Remove') || eventName === 'ScheduleKeyDeletion';
  if (isDelete) return null;

  const rType = resourceType ?? EVENT_TO_RESOURCE_TYPE[eventName] ?? null;
  if (!rType) return null;

  const fetcher = FETCHERS[rType];
  if (!fetcher) return null;

  const id = normalizeId(resourceId, rType, requestParams);
  if (!id) return null;

  try {
    return await fetcher(ctx, id, requestParams);
  } catch {
    // Resource may not be accessible or may have been deleted between event and fetch
    return null;
  }
}

// ─── ID normalisation ─────────────────────────────────────────────────────────

function normalizeId(
  resourceId: string | null,
  resourceType: string,
  params: Record<string, unknown>,
): string | null {
  // Extract name from ARN: arn:aws:s3:::bucket-name → bucket-name
  const raw = resourceId ?? '';
  const fromArn = raw.includes('arn:') ? raw.split(':').pop() ?? raw : raw;

  // Fallback: pull from requestParameters
  if (!fromArn) {
    if (resourceType === 'AWS::S3::Bucket')          return (params.bucketName as string) ?? null;
    if (resourceType === 'AWS::EC2::SecurityGroup')   return (params.groupId as string) ?? null;
    if (resourceType === 'AWS::IAM::User')            return (params.userName as string) ?? null;
    if (resourceType === 'AWS::IAM::Role')            return (params.roleName as string) ?? null;
    if (resourceType === 'AWS::IAM::Group')           return (params.groupName as string) ?? null;
    if (resourceType === 'AWS::RDS::DBInstance')      return (params.dbInstanceIdentifier as string) ?? null;
    if (resourceType === 'AWS::RDS::DBCluster')       return (params.dbClusterIdentifier as string) ?? null;
    if (resourceType === 'AWS::Lambda::Function')     return (params.functionName as string) ?? null;
    if (resourceType === 'AWS::KMS::Key')             return (params.keyId as string) ?? null;
    if (resourceType === 'AWS::CloudTrail::Trail')    return (params.name as string) ?? null;
    return null;
  }

  return fromArn || null;
}

// ─── Per-resource fetch implementations ──────────────────────────────────────

async function fetchS3Bucket(ctx: AwsFetchContext, bucket: string): Promise<Record<string, unknown> | null> {
  const client = new S3Client({ region: ctx.region, credentials: ctx.credentials });
  const config: Record<string, unknown> = { bucketName: bucket };

  const safeGet = async <T>(cmd: () => Promise<T>): Promise<T | null> => {
    try { return await cmd(); } catch { return null; }
  };

  const [policy, acl, versioning, publicAccess, encryption, logging, replication, lifecycle] = await Promise.all([
    safeGet(() => client.send(new GetBucketPolicyCommand({ Bucket: bucket }))),
    safeGet(() => client.send(new GetBucketAclCommand({ Bucket: bucket }))),
    safeGet(() => client.send(new GetBucketVersioningCommand({ Bucket: bucket }))),
    safeGet(() => client.send(new GetPublicAccessBlockCommand({ Bucket: bucket }))),
    safeGet(() => client.send(new GetBucketEncryptionCommand({ Bucket: bucket }))),
    safeGet(() => client.send(new GetBucketLoggingCommand({ Bucket: bucket }))),
    safeGet(() => client.send(new GetBucketReplicationCommand({ Bucket: bucket }))),
    safeGet(() => client.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket }))),
  ]);

  if (policy?.Policy) {
    try { config.policy = JSON.parse(policy.Policy) as unknown; } catch { config.policy = policy.Policy; }
  }
  if (acl?.Grants)              config.acl             = acl.Grants;
  if (acl?.Owner)               config.owner           = acl.Owner;
  if (versioning?.Status)       config.versioning      = versioning.Status;
  if (versioning?.MFADelete)    config.mfaDelete       = versioning.MFADelete;
  if (publicAccess?.PublicAccessBlockConfiguration) config.publicAccessBlock = publicAccess.PublicAccessBlockConfiguration;
  if (encryption?.ServerSideEncryptionConfiguration) config.encryption = encryption.ServerSideEncryptionConfiguration;
  if (logging?.LoggingEnabled)  config.logging         = logging.LoggingEnabled;
  if (replication?.ReplicationConfiguration) config.replication = replication.ReplicationConfiguration;
  if (lifecycle?.Rules)         config.lifecycleRules  = lifecycle.Rules;

  return config;
}

async function fetchSecurityGroup(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new EC2Client({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeSecurityGroupsCommand({
    GroupIds: [id],
  }));
  const sg = resp.SecurityGroups?.[0];
  if (!sg) return null;
  return {
    groupId:       sg.GroupId,
    groupName:     sg.GroupName,
    description:   sg.Description,
    vpcId:         sg.VpcId,
    ingressRules:  sg.IpPermissions,
    egressRules:   sg.IpPermissionsEgress,
    tags:          sg.Tags,
  };
}

async function fetchEc2Instance(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new EC2Client({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeInstancesCommand({ InstanceIds: [id] }));
  const instance = resp.Reservations?.[0]?.Instances?.[0];
  if (!instance) return null;
  return {
    instanceId:        instance.InstanceId,
    instanceType:      instance.InstanceType,
    state:             instance.State?.Name,
    subnetId:          instance.SubnetId,
    vpcId:             instance.VpcId,
    securityGroups:    instance.SecurityGroups,
    iamProfile:        instance.IamInstanceProfile?.Arn,
    keyName:           instance.KeyName,
    publicIp:          instance.PublicIpAddress,
    privateIp:         instance.PrivateIpAddress,
    monitoring:        instance.Monitoring?.State,
    ebsOptimized:      instance.EbsOptimized,
    sourceDestCheck:   instance.SourceDestCheck,
    metadataOptions:   instance.MetadataOptions,
    tags:              instance.Tags,
  };
}

async function fetchVpc(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new EC2Client({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeVpcsCommand({ VpcIds: [id] }));
  const vpc = resp.Vpcs?.[0];
  if (!vpc) return null;
  return {
    vpcId:           vpc.VpcId,
    cidrBlock:       vpc.CidrBlock,
    state:           vpc.State,
    isDefault:       vpc.IsDefault,
    dhcpOptionsId:   vpc.DhcpOptionsId,
    instanceTenancy: vpc.InstanceTenancy,
    tags:            vpc.Tags,
  };
}

async function fetchRouteTable(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new EC2Client({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeRouteTablesCommand({ RouteTableIds: [id] }));
  const rt = resp.RouteTables?.[0];
  if (!rt) return null;
  return {
    routeTableId: rt.RouteTableId,
    vpcId:        rt.VpcId,
    routes:       rt.Routes,
    associations: rt.Associations,
    tags:         rt.Tags,
  };
}

async function fetchInternetGateway(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new EC2Client({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeInternetGatewaysCommand({ InternetGatewayIds: [id] }));
  const igw = resp.InternetGateways?.[0];
  if (!igw) return null;
  return {
    internetGatewayId: igw.InternetGatewayId,
    attachments:       igw.Attachments,
    tags:              igw.Tags,
  };
}

async function fetchNetworkAcl(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new EC2Client({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeNetworkAclsCommand({ NetworkAclIds: [id] }));
  const acl = resp.NetworkAcls?.[0];
  if (!acl) return null;
  return {
    networkAclId: acl.NetworkAclId,
    vpcId:        acl.VpcId,
    isDefault:    acl.IsDefault,
    entries:      acl.Entries,
    associations: acl.Associations,
    tags:         acl.Tags,
  };
}

async function fetchSubnet(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new EC2Client({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeSubnetsCommand({ SubnetIds: [id] }));
  const subnet = resp.Subnets?.[0];
  if (!subnet) return null;
  return {
    subnetId:                subnet.SubnetId,
    vpcId:                   subnet.VpcId,
    cidrBlock:               subnet.CidrBlock,
    availabilityZone:        subnet.AvailabilityZone,
    mapPublicIpOnLaunch:     subnet.MapPublicIpOnLaunch,
    assignIpv6AddressOnCreation: subnet.AssignIpv6AddressOnCreation,
    state:                   subnet.State,
    tags:                    subnet.Tags,
  };
}

async function fetchIamUser(ctx: AwsFetchContext, userName: string): Promise<Record<string, unknown> | null> {
  const client = new IAMClient({ region: 'us-east-1', credentials: ctx.credentials });
  const [userResp, policiesResp] = await Promise.all([
    client.send(new GetUserCommand({ UserName: userName })),
    client.send(new ListAttachedUserPoliciesCommand({ UserName: userName })),
  ]);
  const user = userResp.User;
  if (!user) return null;
  return {
    userId:              user.UserId,
    userName:            user.UserName,
    arn:                 user.Arn,
    path:                user.Path,
    createDate:          user.CreateDate,
    passwordLastUsed:    user.PasswordLastUsed,
    permissionsBoundary: user.PermissionsBoundary,
    attachedPolicies:    policiesResp.AttachedPolicies,
    tags:                user.Tags,
  };
}

async function fetchIamRole(ctx: AwsFetchContext, roleName: string): Promise<Record<string, unknown> | null> {
  const client = new IAMClient({ region: 'us-east-1', credentials: ctx.credentials });
  const [roleResp, attachedResp, inlineResp] = await Promise.all([
    client.send(new GetRoleCmd({ RoleName: roleName })),
    client.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName })),
    client.send(new ListRolePoliciesCommand({ RoleName: roleName })),
  ]);
  const role = roleResp.Role;
  if (!role) return null;

  // Fetch inline policy documents
  const inlinePolicies: Record<string, unknown> = {};
  for (const pname of inlineResp.PolicyNames ?? []) {
    try {
      const p = await client.send(new GetRolePolicyCommand({ RoleName: roleName, PolicyName: pname }));
      inlinePolicies[pname] = p.PolicyDocument ? decodeURIComponent(p.PolicyDocument) : null;
    } catch { /* non-fatal */ }
  }

  let trustPolicy: unknown = role.AssumeRolePolicyDocument;
  if (typeof trustPolicy === 'string') {
    try { trustPolicy = JSON.parse(decodeURIComponent(trustPolicy)); } catch { /* keep as string */ }
  }

  return {
    roleId:              role.RoleId,
    roleName:            role.RoleName,
    arn:                 role.Arn,
    path:                role.Path,
    maxSessionDuration:  role.MaxSessionDuration,
    permissionsBoundary: role.PermissionsBoundary,
    trustPolicy,
    attachedPolicies:    attachedResp.AttachedPolicies,
    inlinePolicies,
    tags:                role.Tags,
  };
}

async function fetchIamGroup(ctx: AwsFetchContext, groupName: string): Promise<Record<string, unknown> | null> {
  const client = new IAMClient({ region: 'us-east-1', credentials: ctx.credentials });
  const resp = await client.send(new GetGroupCommand({ GroupName: groupName }));
  const group = resp.Group;
  if (!group) return null;
  return {
    groupId:   group.GroupId,
    groupName: group.GroupName,
    arn:       group.Arn,
    path:      group.Path,
    users:     (resp.Users ?? []).map((u) => u.UserName),
  };
}

async function fetchRdsInstance(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new RDSClient({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: id }));
  const db = resp.DBInstances?.[0];
  if (!db) return null;
  return {
    dbInstanceIdentifier:  db.DBInstanceIdentifier,
    dbInstanceClass:       db.DBInstanceClass,
    engine:                db.Engine,
    engineVersion:         db.EngineVersion,
    dbInstanceStatus:      db.DBInstanceStatus,
    masterUsername:        db.MasterUsername,
    dbName:                db.DBName,
    endpoint:              db.Endpoint,
    allocatedStorage:      db.AllocatedStorage,
    storageType:           db.StorageType,
    storageEncrypted:      db.StorageEncrypted,
    kmsKeyId:              db.KmsKeyId,
    multiAZ:               db.MultiAZ,
    autoMinorVersionUpgrade: db.AutoMinorVersionUpgrade,
    backupRetentionPeriod: db.BackupRetentionPeriod,
    preferredBackupWindow: db.PreferredBackupWindow,
    preferredMaintenanceWindow: db.PreferredMaintenanceWindow,
    publiclyAccessible:    db.PubliclyAccessible,
    deletionProtection:    db.DeletionProtection,
    enabledCloudwatchLogsExports: db.EnabledCloudwatchLogsExports,
    monitoringInterval:    db.MonitoringInterval,
    performanceInsightsEnabled: db.PerformanceInsightsEnabled,
    vpcSecurityGroups:     db.VpcSecurityGroups,
    dbParameterGroups:     db.DBParameterGroups,
    dbSubnetGroup:         db.DBSubnetGroup?.DBSubnetGroupName,
    tags:                  db.TagList,
  };
}

async function fetchRdsCluster(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new RDSClient({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeDBClustersCommand({ DBClusterIdentifier: id }));
  const cluster = resp.DBClusters?.[0];
  if (!cluster) return null;
  return {
    dbClusterIdentifier:   cluster.DBClusterIdentifier,
    engine:                cluster.Engine,
    engineVersion:         cluster.EngineVersion,
    status:                cluster.Status,
    masterUsername:        cluster.MasterUsername,
    databaseName:          cluster.DatabaseName,
    storageEncrypted:      cluster.StorageEncrypted,
    kmsKeyId:              cluster.KmsKeyId,
    multiAZ:               cluster.MultiAZ,
    backupRetentionPeriod: cluster.BackupRetentionPeriod,
    deletionProtection:    cluster.DeletionProtection,
    iamDatabaseAuthenticationEnabled: cluster.IAMDatabaseAuthenticationEnabled,
    enabledCloudwatchLogsExports: cluster.EnabledCloudwatchLogsExports,
    tags:                  cluster.TagList,
  };
}

async function fetchLambdaFunction(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new LambdaClient({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new GetFunctionConfigurationCommand({ FunctionName: id }));
  return {
    functionName:      resp.FunctionName,
    runtime:           resp.Runtime,
    handler:           resp.Handler,
    codeSize:          resp.CodeSize,
    description:       resp.Description,
    timeout:           resp.Timeout,
    memorySize:        resp.MemorySize,
    role:              resp.Role,
    environment:       resp.Environment?.Variables,
    kmsKeyArn:         resp.KMSKeyArn,
    tracingConfig:     resp.TracingConfig?.Mode,
    vpcConfig:         resp.VpcConfig,
    deadLetterConfig:  resp.DeadLetterConfig?.TargetArn,
    architectures:     resp.Architectures,
    ephemeralStorage:  resp.EphemeralStorage?.Size,
    snapStart:         resp.SnapStart,
    loggingConfig:     resp.LoggingConfig,
  };
}

async function fetchKmsKey(ctx: AwsFetchContext, keyId: string): Promise<Record<string, unknown> | null> {
  const client = new KMSClient({ region: ctx.region, credentials: ctx.credentials });
  const [keyResp, policyResp, rotationResp] = await Promise.all([
    client.send(new DescribeKeyCommand({ KeyId: keyId })),
    client.send(new GetKeyPolicyCommand({ KeyId: keyId, PolicyName: 'default' })),
    client.send(new GetKeyRotationStatusCommand({ KeyId: keyId })).catch(() => null),
  ]);
  const meta = keyResp.KeyMetadata;
  if (!meta) return null;
  let policy: unknown = policyResp.Policy;
  if (typeof policy === 'string') { try { policy = JSON.parse(policy); } catch { /* keep as string */ } }
  return {
    keyId:                meta.KeyId,
    arn:                  meta.Arn,
    description:          meta.Description,
    keyState:             meta.KeyState,
    keyUsage:             meta.KeyUsage,
    keySpec:              meta.KeySpec,
    origin:               meta.Origin,
    keyManager:           meta.KeyManager,
    multiRegion:          meta.MultiRegion,
    pendingDeletionWindowInDays: meta.PendingDeletionWindowInDays,
    deletionDate:         meta.DeletionDate,
    validTo:              meta.ValidTo,
    rotationEnabled:      rotationResp?.KeyRotationEnabled ?? null,
    policy,
  };
}

async function fetchCloudTrailTrail(ctx: AwsFetchContext, trailNameOrArn: string): Promise<Record<string, unknown> | null> {
  const client = new CloudTrailClient({ region: ctx.region, credentials: ctx.credentials });
  const [trailResp, statusResp] = await Promise.all([
    client.send(new GetTrailCommand({ Name: trailNameOrArn })),
    client.send(new GetTrailStatusCommand({ Name: trailNameOrArn })).catch(() => null),
  ]);
  const trail = trailResp.Trail;
  if (!trail) return null;
  return {
    trailARN:                trail.TrailARN,
    name:                    trail.Name,
    s3BucketName:            trail.S3BucketName,
    s3KeyPrefix:             trail.S3KeyPrefix,
    snsTopicARN:             trail.SnsTopicARN,
    includeGlobalServiceEvents: trail.IncludeGlobalServiceEvents,
    isMultiRegionTrail:      trail.IsMultiRegionTrail,
    isOrganizationTrail:     trail.IsOrganizationTrail,
    logFileValidationEnabled: trail.LogFileValidationEnabled,
    cloudWatchLogsLogGroupArn: trail.CloudWatchLogsLogGroupArn,
    kmsKeyId:                trail.KmsKeyId,
    hasCustomEventSelectors: trail.HasCustomEventSelectors,
    isLogging:               statusResp?.IsLogging ?? null,
    latestDeliveryTime:      statusResp?.LatestDeliveryTime ?? null,
  };
}

async function fetchElbV2(ctx: AwsFetchContext, arn: string): Promise<Record<string, unknown> | null> {
  const client = new ElasticLoadBalancingV2Client({ region: ctx.region, credentials: ctx.credentials });
  const [lbResp, listenersResp] = await Promise.all([
    client.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: [arn] })),
    client.send(new DescribeListenersCommand({ LoadBalancerArn: arn })).catch(() => null),
  ]);
  const lb = lbResp.LoadBalancers?.[0];
  if (!lb) return null;
  return {
    loadBalancerArn:      lb.LoadBalancerArn,
    loadBalancerName:     lb.LoadBalancerName,
    dnsName:              lb.DNSName,
    type:                 lb.Type,
    scheme:               lb.Scheme,
    state:                lb.State?.Code,
    vpcId:                lb.VpcId,
    availabilityZones:    lb.AvailabilityZones,
    securityGroups:       lb.SecurityGroups,
    ipAddressType:        lb.IpAddressType,
    listeners:            (listenersResp?.Listeners ?? []).map((l) => ({
      listenerArn:   l.ListenerArn,
      port:          l.Port,
      protocol:      l.Protocol,
      sslPolicy:     l.SslPolicy,
      defaultActions: l.DefaultActions,
    })),
  };
}

async function fetchElbV2Listener(ctx: AwsFetchContext, arn: string): Promise<Record<string, unknown> | null> {
  const client = new ElasticLoadBalancingV2Client({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeListenersCommand({ ListenerArns: [arn] }));
  const listener = resp.Listeners?.[0];
  if (!listener) return null;
  return {
    listenerArn:     listener.ListenerArn,
    loadBalancerArn: listener.LoadBalancerArn,
    port:            listener.Port,
    protocol:        listener.Protocol,
    sslPolicy:       listener.SslPolicy,
    certificates:    listener.Certificates,
    defaultActions:  listener.DefaultActions,
  };
}

async function fetchElastiCacheCluster(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new ElastiCacheClient({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeCacheClustersCommand({
    CacheClusterId: id, ShowCacheNodeInfo: true,
  }));
  const cluster = resp.CacheClusters?.[0];
  if (!cluster) return null;
  return {
    cacheClusterId:         cluster.CacheClusterId,
    cacheNodeType:          cluster.CacheNodeType,
    engine:                 cluster.Engine,
    engineVersion:          cluster.EngineVersion,
    cacheClusterStatus:     cluster.CacheClusterStatus,
    numCacheNodes:          cluster.NumCacheNodes,
    preferredMaintenanceWindow: cluster.PreferredMaintenanceWindow,
    snapshotRetentionLimit: cluster.SnapshotRetentionLimit,
    atRestEncryptionEnabled: cluster.AtRestEncryptionEnabled,
    transitEncryptionEnabled: cluster.TransitEncryptionEnabled,
    authTokenEnabled:       cluster.AuthTokenEnabled,
    replicationGroupId:     cluster.ReplicationGroupId,
  };
}

async function fetchElastiCacheReplicationGroup(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new ElastiCacheClient({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeReplicationGroupsCommand({ ReplicationGroupId: id }));
  const rg = resp.ReplicationGroups?.[0];
  if (!rg) return null;
  return {
    replicationGroupId:        rg.ReplicationGroupId,
    description:               rg.Description,
    status:                    rg.Status,
    cacheNodeType:             rg.CacheNodeType,
    automaticFailover:         rg.AutomaticFailover,
    multiAZ:                   rg.MultiAZ,
    snapshotRetentionLimit:    rg.SnapshotRetentionLimit,
    atRestEncryptionEnabled:   rg.AtRestEncryptionEnabled,
    transitEncryptionEnabled:  rg.TransitEncryptionEnabled,
    authTokenEnabled:          rg.AuthTokenEnabled,
    clusterEnabled:            rg.ClusterEnabled,
  };
}

async function fetchSqsQueue(ctx: AwsFetchContext, queueUrl: string): Promise<Record<string, unknown> | null> {
  const client = new SQSClient({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new GetQueueAttributesCommand({
    QueueUrl: queueUrl,
    AttributeNames: ['All'],
  }));
  const attrs = resp.Attributes ?? {};
  return {
    queueUrl,
    visibilityTimeout:              attrs.VisibilityTimeout,
    messageRetentionPeriod:         attrs.MessageRetentionPeriod,
    maximumMessageSize:             attrs.MaximumMessageSize,
    delaySeconds:                   attrs.DelaySeconds,
    receiveMessageWaitTimeSeconds:  attrs.ReceiveMessageWaitTimeSeconds,
    sqsManagedSseEnabled:           attrs.SqsManagedSseEnabled,
    kmsMasterKeyId:                 attrs.KmsMasterKeyId,
    policy:                         attrs.Policy ? (() => { try { return JSON.parse(attrs.Policy!); } catch { return attrs.Policy; } })() : undefined,
    redrivePolicy:                  attrs.RedrivePolicy ? (() => { try { return JSON.parse(attrs.RedrivePolicy!); } catch { return attrs.RedrivePolicy; } })() : undefined,
    fifoQueue:                      attrs.FifoQueue,
    contentBasedDeduplication:      attrs.ContentBasedDeduplication,
  };
}

async function fetchSnsTopic(ctx: AwsFetchContext, topicArn: string): Promise<Record<string, unknown> | null> {
  const client = new SNSClient({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new GetTopicAttributesCommand({ TopicArn: topicArn }));
  const attrs = resp.Attributes ?? {};
  return {
    topicArn,
    displayName:        attrs.DisplayName,
    subscriptionsConfirmed: attrs.SubscriptionsConfirmed,
    kmsMasterKeyId:     attrs.KmsMasterKeyId,
    fifoTopic:          attrs.FifoTopic,
    contentBasedDeduplication: attrs.ContentBasedDeduplication,
    policy:             attrs.Policy ? (() => { try { return JSON.parse(attrs.Policy!); } catch { return attrs.Policy; } })() : undefined,
    deliveryPolicy:     attrs.DeliveryPolicy ? (() => { try { return JSON.parse(attrs.DeliveryPolicy!); } catch { return attrs.DeliveryPolicy; } })() : undefined,
  };
}

async function fetchRedshiftCluster(ctx: AwsFetchContext, id: string): Promise<Record<string, unknown> | null> {
  const client = new RedshiftClient({ region: ctx.region, credentials: ctx.credentials });
  const resp = await client.send(new DescribeClustersCommand({ ClusterIdentifier: id }));
  const cluster = resp.Clusters?.[0];
  if (!cluster) return null;
  return {
    clusterIdentifier:        cluster.ClusterIdentifier,
    nodeType:                 cluster.NodeType,
    clusterStatus:            cluster.ClusterStatus,
    masterUsername:           cluster.MasterUsername,
    dbName:                   cluster.DBName,
    numberOfNodes:            cluster.NumberOfNodes,
    encrypted:                cluster.Encrypted,
    kmsKeyId:                 cluster.KmsKeyId,
    publiclyAccessible:       cluster.PubliclyAccessible,
    enhancedVpcRouting:       cluster.EnhancedVpcRouting,
    allowVersionUpgrade:      cluster.AllowVersionUpgrade,
    automatedSnapshotRetentionPeriod: cluster.AutomatedSnapshotRetentionPeriod,
    preferredMaintenanceWindow: cluster.PreferredMaintenanceWindow,
    clusterParameterGroups:   cluster.ClusterParameterGroups,
    vpcSecurityGroups:        cluster.VpcSecurityGroups,
    tags:                     cluster.Tags,
  };
}
