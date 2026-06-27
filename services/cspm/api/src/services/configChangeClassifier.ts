/**
 * Config Change Classifier
 * Classifies raw CloudTrail / Azure Activity Log / GCP Audit Log events into
 * normalized ConfigChange records: category, riskScore, severity, summary, actor, resource.
 */

export type ChangeCategory = 'IAM' | 'NETWORK' | 'STORAGE' | 'COMPUTE' | 'DATABASE' | 'ENCRYPTION' | 'LOGGING' | 'OTHER';
export type CloudProvider  = 'AWS' | 'AZURE' | 'GCP';
export type ChangeAction   = 'CREATED' | 'MODIFIED' | 'DELETED';

// ─── Azure noise filter ───────────────────────────────────────────────────────
// Namespaces that produce /action events which are NOT config changes:
// health notifications, diagnostics alerts, policy evaluations, advisor recs etc.
const AZURE_NOISE_NAMESPACES = [
  'microsoft.resourcehealth',
  'microsoft.advisor',
  'microsoft.security/assessments',
  'microsoft.policyinsights',
  'microsoft.insights/autoscalesettings/providers/microsoft.insights/diagnosticSettings',
  'microsoft.alertsmanagement',
  'microsoft.maintenance',
  'microsoft.support',
  'microsoft.billing',
  'microsoft.consumption',
  'microsoft.costmanagement',
];

export function isAzureNoiseEvent(operationName: string): boolean {
  const lower = (operationName ?? '').toLowerCase();
  return AZURE_NOISE_NAMESPACES.some(ns => lower.startsWith(ns));
}

export interface ClassifiedChange {
  changeAction:  ChangeAction;
  category:      ChangeCategory;
  riskScore:     number;           // 0–100
  severity:      'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  summary:       string;
  actor:         string | null;
  actorType:     string | null;
  sourceIp:      string | null;
  resourceType:  string | null;
  resourceId:    string | null;
  resourceName:  string | null;
  previousValue: Record<string, unknown> | null;
  newValue:      Record<string, unknown> | null;
}

// ─── Scoring helpers ──────────────────────────────────────────────────────────

function severityFromScore(score: number): ClassifiedChange['severity'] {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

function cap(n: number): number { return Math.min(100, Math.max(0, n)); }

// ─── AWS CloudTrail classifier ────────────────────────────────────────────────

const AWS_SCORES: Record<string, number> = {
  // IAM — highest risk
  AttachUserPolicy: 90, AttachRolePolicy: 90, AttachGroupPolicy: 90,
  PutUserPolicy: 90, PutRolePolicy: 90, PutGroupPolicy: 90,
  CreateAccessKey: 85, UpdateAssumeRolePolicy: 85,
  CreateLoginProfile: 80, UpdateLoginProfile: 75,
  AddUserToGroup: 70, CreateUser: 65, CreateRole: 65,
  DeleteUser: 65, DeleteRole: 65,
  DeleteAccountPasswordPolicy: 80, UpdateAccountPasswordPolicy: 55,
  // NETWORK
  AuthorizeSecurityGroupIngress: 65, AuthorizeSecurityGroupEgress: 55,
  RevokeSecurityGroupIngress: 40, RevokeSecurityGroupEgress: 35,
  CreateSecurityGroup: 40, DeleteSecurityGroup: 45,
  CreateRoute: 55, ReplaceRoute: 55, DeleteRoute: 45,
  ModifyVpcAttribute: 45, CreateInternetGateway: 50, AttachInternetGateway: 55,
  CreateNetworkAcl: 45, CreateNetworkAclEntry: 55, DeleteNetworkAclEntry: 40,
  // STORAGE
  PutBucketAcl: 80, PutBucketPolicy: 80,
  PutBucketPublicAccessBlock: 75, DeleteBucketPolicy: 70,
  DeleteBucket: 60, CreateBucket: 25,
  // COMPUTE
  RunInstances: 25, TerminateInstances: 50,
  ModifyInstanceAttribute: 45, CreateImage: 30,
  UpdateFunctionConfiguration: 45, DeleteFunction: 55,
  CreateLaunchTemplate: 35, ModifyLaunchTemplate: 45,
  // DATABASE
  CreateDBInstance: 30, ModifyDBInstance: 50, DeleteDBInstance: 70,
  CreateDBSnapshot: 35, RestoreDBInstanceFromDBSnapshot: 45,
  CreateCluster: 30, DeleteCluster: 70, ModifyDBCluster: 50,
  // ENCRYPTION
  CreateKey: 35, ScheduleKeyDeletion: 85, DisableKey: 85,
  PutKeyPolicy: 75, DisableKeyRotation: 70, EnableKeyRotation: 20,
  DeleteAlias: 60, CreateAlias: 20,
  // LOGGING — anti-forensics
  StopLogging: 95, DeleteTrail: 95, UpdateTrail: 55,
  CreateTrail: 20, PutEventSelectors: 55,
  DeleteFlowLogs: 85, CreateFlowLogs: 20,
};

const AWS_CATEGORIES: Record<string, ChangeCategory> = {
  AttachUserPolicy: 'IAM', AttachRolePolicy: 'IAM', AttachGroupPolicy: 'IAM',
  PutUserPolicy: 'IAM', PutRolePolicy: 'IAM', PutGroupPolicy: 'IAM',
  CreateAccessKey: 'IAM', UpdateAssumeRolePolicy: 'IAM',
  CreateLoginProfile: 'IAM', UpdateLoginProfile: 'IAM',
  AddUserToGroup: 'IAM', CreateUser: 'IAM', CreateRole: 'IAM',
  DeleteUser: 'IAM', DeleteRole: 'IAM', DeleteGroup: 'IAM',
  DeleteAccountPasswordPolicy: 'IAM', UpdateAccountPasswordPolicy: 'IAM',
  DetachUserPolicy: 'IAM', DetachRolePolicy: 'IAM', DetachGroupPolicy: 'IAM',
  AuthorizeSecurityGroupIngress: 'NETWORK', AuthorizeSecurityGroupEgress: 'NETWORK',
  RevokeSecurityGroupIngress: 'NETWORK', RevokeSecurityGroupEgress: 'NETWORK',
  CreateSecurityGroup: 'NETWORK', DeleteSecurityGroup: 'NETWORK',
  CreateRoute: 'NETWORK', ReplaceRoute: 'NETWORK', DeleteRoute: 'NETWORK',
  ModifyVpcAttribute: 'NETWORK', CreateInternetGateway: 'NETWORK',
  AttachInternetGateway: 'NETWORK', CreateNetworkAcl: 'NETWORK',
  CreateNetworkAclEntry: 'NETWORK', DeleteNetworkAclEntry: 'NETWORK',
  PutBucketAcl: 'STORAGE', PutBucketPolicy: 'STORAGE',
  PutBucketPublicAccessBlock: 'STORAGE', DeleteBucketPolicy: 'STORAGE',
  DeleteBucket: 'STORAGE', CreateBucket: 'STORAGE',
  PutBucketVersioning: 'STORAGE', PutBucketLogging: 'STORAGE',
  RunInstances: 'COMPUTE', TerminateInstances: 'COMPUTE',
  ModifyInstanceAttribute: 'COMPUTE', CreateImage: 'COMPUTE',
  UpdateFunctionConfiguration: 'COMPUTE', DeleteFunction: 'COMPUTE',
  CreateLaunchTemplate: 'COMPUTE', ModifyLaunchTemplate: 'COMPUTE',
  CreateDBInstance: 'DATABASE', ModifyDBInstance: 'DATABASE', DeleteDBInstance: 'DATABASE',
  CreateDBSnapshot: 'DATABASE', RestoreDBInstanceFromDBSnapshot: 'DATABASE',
  CreateCluster: 'DATABASE', DeleteCluster: 'DATABASE', ModifyDBCluster: 'DATABASE',
  CreateKey: 'ENCRYPTION', ScheduleKeyDeletion: 'ENCRYPTION',
  DisableKey: 'ENCRYPTION', PutKeyPolicy: 'ENCRYPTION',
  DisableKeyRotation: 'ENCRYPTION', EnableKeyRotation: 'ENCRYPTION',
  DeleteAlias: 'ENCRYPTION', CreateAlias: 'ENCRYPTION',
  StopLogging: 'LOGGING', DeleteTrail: 'LOGGING', UpdateTrail: 'LOGGING',
  CreateTrail: 'LOGGING', PutEventSelectors: 'LOGGING',
  DeleteFlowLogs: 'LOGGING', CreateFlowLogs: 'LOGGING',
};

function awsChangeAction(name: string): ChangeAction {
  if (
    name.startsWith('Create')   || name.startsWith('Run')    ||
    name.startsWith('Launch')   || name.startsWith('Add')    ||
    name.startsWith('Register') || name.startsWith('Attach') ||
    name.startsWith('Enable')   || name.startsWith('Start')  ||
    name.startsWith('Authorize')
  ) return 'CREATED';
  if (
    name.startsWith('Delete')    || name.startsWith('Terminate') ||
    name.startsWith('Remove')    || name.startsWith('Deregister') ||
    name.startsWith('Detach')    || name.startsWith('Revoke')    ||
    name.startsWith('Stop')      || name.startsWith('Disable')   ||
    name.startsWith('Schedule')
  ) return 'DELETED';
  return 'MODIFIED';
}

function awsVerbFromEvent(name: string): string {
  if (name.startsWith('Create'))  return 'created';
  if (name.startsWith('Delete'))  return 'deleted';
  if (name.startsWith('Update') || name.startsWith('Modify')) return 'modified';
  if (name.startsWith('Attach'))  return 'attached';
  if (name.startsWith('Detach'))  return 'detached';
  if (name.startsWith('Put'))     return 'updated';
  if (name.startsWith('Authorize')) return 'added ingress rule to';
  if (name.startsWith('Revoke'))  return 'removed rule from';
  if (name.startsWith('Run'))     return 'launched';
  if (name.startsWith('Terminate')) return 'terminated';
  if (name.startsWith('Stop'))    return 'stopped';
  if (name.startsWith('Disable')) return 'disabled';
  if (name.startsWith('Enable'))  return 'enabled';
  if (name.startsWith('Schedule')) return 'scheduled';
  return 'modified';
}

function awsSummary(eventName: string, params: Record<string, unknown>, actor: string | null, resources: { type?: string | null; name?: string | null }[]): string {
  const p     = params || {};
  const who   = actor || 'Unknown';
  const verb  = awsVerbFromEvent(eventName);

  const resource = (resources[0]?.name || p.bucketName || p.groupId || p.userName ||
    p.roleName || p.functionName || p.dbInstanceIdentifier ||
    p.trailName || p.keyId || p.instanceId || '') as string;

  // Special-case summaries
  switch (eventName) {
    case 'AuthorizeSecurityGroupIngress': {
      const rules = (p.ipPermissions as Record<string, unknown>[] | undefined) || [];
      const rule  = rules[0] || {};
      const from  = rule.fromPort ?? rule.FromPort ?? '?';
      const to    = rule.toPort   ?? rule.ToPort   ?? '?';
      const cidr  = (rule.ipRanges as Record<string, unknown>[] | undefined)?.[0]?.cidrIp ?? '?';
      return `${who} opened port ${from}–${to} on ${resource || 'security group'} from ${cidr}`;
    }
    case 'PutBucketPolicy':
    case 'PutBucketAcl':
      return `${who} updated S3 ${eventName.includes('Acl') ? 'ACL' : 'bucket policy'} on ${resource}`;
    case 'PutBucketPublicAccessBlock':
      return `${who} changed public access block settings on S3 bucket ${resource}`;
    case 'AttachUserPolicy':
      return `${who} attached policy ${(p.policyArn as string)?.split('/').pop() ?? p.policyArn ?? ''} to IAM user ${p.userName ?? ''}`;
    case 'AttachRolePolicy':
      return `${who} attached policy ${(p.policyArn as string)?.split('/').pop() ?? ''} to IAM role ${p.roleName ?? ''}`;
    case 'CreateAccessKey':
      return `${who} created access key for IAM user ${p.userName ?? ''}`;
    case 'CreateLoginProfile':
    case 'UpdateLoginProfile':
      return `${who} ${verb} console login for IAM user ${p.userName ?? ''}`;
    case 'StopLogging':
      return `${who} DISABLED CloudTrail logging on trail ${p.name ?? resource}`;
    case 'DeleteTrail':
      return `${who} DELETED CloudTrail trail ${p.name ?? resource}`;
    case 'DeleteFlowLogs':
      return `${who} deleted VPC Flow Logs`;
    case 'ScheduleKeyDeletion':
      return `${who} scheduled KMS key deletion: ${resource || p.keyId} (${p.pendingWindowInDays ?? 7} days)`;
    case 'DisableKey':
      return `${who} disabled KMS key ${resource || p.keyId}`;
    case 'UpdateAssumeRolePolicy':
      return `${who} updated trust policy on IAM role ${p.roleName ?? resource}`;
    default:
      return `${who} ${verb} ${resource || eventName.replace(/([A-Z])/g, ' $1').trim()}`;
  }
}

function awsModifier(eventName: string, params: Record<string, unknown>): number {
  let bonus = 0;
  const p = params || {};

  // Open to internet
  const ipPerms = p.ipPermissions as Record<string, unknown>[] | undefined;
  if (ipPerms?.length) {
    for (const rule of ipPerms) {
      const ranges = rule.ipRanges as Record<string, unknown>[] | undefined;
      const cidr6  = rule.ipv6Ranges as Record<string, unknown>[] | undefined;
      if (ranges?.some((r) => r.cidrIp === '0.0.0.0/0'))  bonus += 20;
      if (cidr6?.some((r)  => r.cidrIpv6 === '::/0'))      bonus += 20;
      const from = Number(rule.fromPort ?? rule.FromPort ?? -1);
      const to   = Number(rule.toPort   ?? rule.ToPort   ?? -1);
      if ((from <= 22 && to >= 22) || (from <= 3389 && to >= 3389)) bonus += 15;
    }
  }
  // Public S3
  if (eventName === 'PutBucketPublicAccessBlock') {
    const cfg = p.PublicAccessBlockConfiguration as Record<string, unknown> | undefined;
    if (cfg?.BlockPublicAcls === false || cfg?.BlockPublicPolicy === false) bonus += 20;
  }
  return bonus;
}

export function classifyAwsEvent(event: {
  eventName: string | null;
  requestParameters: Record<string, unknown> | null;
  responseElements: Record<string, unknown> | null;
  userIdentity: Record<string, unknown> | null;
  sourceIPAddress: string | null;
  awsRegion: string;
  resources: { type?: string | null; name?: string | null }[];
}): ClassifiedChange {
  const name   = event.eventName ?? 'UnknownEvent';
  const params = event.requestParameters ?? {};
  const resp   = event.responseElements ?? {};
  const uid    = event.userIdentity ?? {};

  const sessionCtx = uid.sessionContext as Record<string, unknown> | undefined;
  const sessionIss = sessionCtx?.sessionIssuer as Record<string, unknown> | undefined;
  const actor     = (uid.userName ?? sessionIss?.userName ?? uid.arn ?? null) as string | null;
  const actorType = (uid.type ?? null) as string | null;

  const baseScore    = AWS_SCORES[name] ?? 20;
  const modifier     = awsModifier(name, params);
  const riskScore    = cap(baseScore + modifier);
  const severity     = severityFromScore(riskScore);
  const category     = AWS_CATEGORIES[name] ?? 'OTHER';
  const changeAction = awsChangeAction(name);

  const summary = awsSummary(name, params, actor, event.resources);

  const resourceType = event.resources[0]?.type ?? null;
  const resourceId   = event.resources[0]?.name ?? null;
  const resourceName = resourceId ? (resourceId.split('/').pop() ?? resourceId) : null;

  // newValue = what they sent; previousValue = what was deleted/before (best effort)
  const newValue: Record<string, unknown> = Object.keys(params).length ? params : {};
  const previousValue: Record<string, unknown> | null =
    name.startsWith('Delete') || name.startsWith('Terminate') || name.startsWith('Remove')
      ? { resourceId, resourceType, resourceName }
      : null;

  // Merge in key response data
  if (Object.keys(resp).length) newValue._response = resp;

  return {
    changeAction,
    category, riskScore, severity, summary,
    actor, actorType, sourceIp: event.sourceIPAddress,
    resourceType, resourceId, resourceName,
    previousValue, newValue,
  };
}

// ─── Azure Activity Log classifier ───────────────────────────────────────────

const AZURE_CATEGORIES: { pattern: string; category: ChangeCategory }[] = [
  { pattern: 'microsoft.authorization/roleassignment',         category: 'IAM' },
  { pattern: 'microsoft.authorization/policyassignment',       category: 'IAM' },
  { pattern: 'microsoft.authorization/roledefinition',         category: 'IAM' },
  { pattern: 'microsoft.aad',                                  category: 'IAM' },
  { pattern: 'microsoft.network/networksecuritygroups',        category: 'NETWORK' },
  { pattern: 'microsoft.network/virtualnetworks',              category: 'NETWORK' },
  { pattern: 'microsoft.network/publicipaddresses',            category: 'NETWORK' },
  { pattern: 'microsoft.network/firewallpolicies',             category: 'NETWORK' },
  { pattern: 'microsoft.network/applicationgateways',          category: 'NETWORK' },
  { pattern: 'microsoft.storage',                              category: 'STORAGE' },
  { pattern: 'microsoft.compute/virtualmachines',              category: 'COMPUTE' },
  { pattern: 'microsoft.compute/vmss',                         category: 'COMPUTE' },
  { pattern: 'microsoft.web/sites',                            category: 'COMPUTE' },
  { pattern: 'microsoft.containerservice',                     category: 'COMPUTE' },
  { pattern: 'microsoft.sql',                                  category: 'DATABASE' },
  { pattern: 'microsoft.dbforpostgresql',                      category: 'DATABASE' },
  { pattern: 'microsoft.dbformysql',                           category: 'DATABASE' },
  { pattern: 'microsoft.documentdb',                           category: 'DATABASE' },
  { pattern: 'microsoft.keyvault',                             category: 'ENCRYPTION' },
  { pattern: 'microsoft.insights/diagnosticsettings',          category: 'LOGGING' },
  { pattern: 'microsoft.insights/activitylogalerts',           category: 'LOGGING' },
  { pattern: 'microsoft.operationalinsights',                  category: 'LOGGING' },
];

function azureCategory(operationName: string): ChangeCategory {
  const lower = (operationName ?? '').toLowerCase();
  for (const { pattern, category } of AZURE_CATEGORIES) {
    if (lower.includes(pattern)) return category;
  }
  return 'OTHER';
}

const AZURE_RISK: { pattern: string; score: number }[] = [
  { pattern: 'microsoft.authorization/roleassignment',   score: 80 },
  { pattern: 'microsoft.authorization/roledefinition',   score: 75 },
  { pattern: 'microsoft.authorization/policyassignment', score: 65 },
  { pattern: 'networksecuritygroups',                    score: 65 },
  { pattern: 'firewallpolicies',                         score: 70 },
  { pattern: 'microsoft.storage/storageaccounts/write',  score: 50 },
  { pattern: 'blobservices/containers',                  score: 60 },
  { pattern: 'microsoft.keyvault/vaults/keys',           score: 70 },
  { pattern: 'microsoft.keyvault/vaults/write',          score: 55 },
  { pattern: 'diagnosticsettings',                       score: 55 },
  { pattern: 'microsoft.compute/virtualmachines/write',  score: 40 },
  { pattern: 'microsoft.sql/servers/write',              score: 45 },
  { pattern: 'microsoft.sql/servers/delete',             score: 70 },
  { pattern: 'delete',                                   score: 55 }, // fallback for any delete
];

function azureRiskScore(operationName: string): number {
  const lower = operationName.toLowerCase();
  for (const { pattern, score } of AZURE_RISK) {
    if (lower.includes(pattern)) return score;
  }
  return lower.includes('write') ? 35 : lower.includes('delete') ? 55 : 20;
}

function azureResourceShortName(resourceId: string | null): string {
  if (!resourceId) return '';
  const parts = resourceId.split('/').filter(Boolean);
  return parts.slice(-2).join('/');
}

export function classifyAzureEvent(event: {
  eventDataId:       string;
  operationName:     string | null;
  caller:            string | null;
  resourceGroupName: string | null;
  resourceId:        string | null;
  level:             string | null;
  status:            string | null;
  properties:        Record<string, unknown> | null;
  description:       string | null;
}): ClassifiedChange {
  const op       = event.operationName ?? 'UnknownOperation';
  const opLower  = op.toLowerCase();
  const category = azureCategory(op);
  const riskScore = cap(azureRiskScore(op));
  const severity  = severityFromScore(riskScore);

  const resourceShort = azureResourceShortName(event.resourceId);
  const resourceType  = op.split('/').slice(0, 2).join('/') || null;
  const resourceId    = event.resourceId;
  const resourceName  = event.resourceId?.split('/').pop() ?? null;

  // Derive changeAction: /delete → DELETED, /write → CREATED or MODIFIED based on status
  let changeAction: ChangeAction;
  if (opLower.endsWith('/delete')) {
    changeAction = 'DELETED';
  } else if (opLower.endsWith('/write')) {
    // Azure doesn't always tell us if it's new; use status/properties hints
    const statusCode = (event.properties?.statusCode as string | undefined)?.toLowerCase();
    const httpStatus = Number((event.properties?.httpRequest as Record<string, unknown> | undefined)?.method);
    const isNew = statusCode === 'created' || httpStatus === 201 ||
                  (event.status?.toLowerCase() === 'succeeded' && statusCode === 'created');
    changeAction = isNew ? 'CREATED' : 'MODIFIED';
  } else {
    changeAction = 'MODIFIED';
  }

  const who  = event.caller ?? 'Unknown';
  const verb = changeAction === 'DELETED' ? 'deleted' :
               changeAction === 'CREATED' ? 'created' : 'modified';
  const summary = `${who} ${verb} ${resourceShort || op}`;

  const newValue = event.properties ? { ...event.properties } : {};

  return {
    changeAction,
    category, riskScore, severity, summary,
    actor: event.caller, actorType: null, sourceIp: null,
    resourceType, resourceId, resourceName,
    previousValue: changeAction === 'DELETED' ? { resourceId, resourceName } : null,
    newValue: Object.keys(newValue).length ? newValue : null,
  };
}

// ─── GCP Audit Log classifier ─────────────────────────────────────────────────

const GCP_CATEGORIES: { pattern: string; category: ChangeCategory }[] = [
  { pattern: 'setiampolicy',                   category: 'IAM' },
  { pattern: 'iam.serviceaccountkeys.create',  category: 'IAM' },
  { pattern: 'iam.serviceaccounts.',           category: 'IAM' },
  { pattern: 'compute.firewalls.',             category: 'NETWORK' },
  { pattern: 'compute.networks.',              category: 'NETWORK' },
  { pattern: 'compute.routes.',                category: 'NETWORK' },
  { pattern: 'storage.buckets.',               category: 'STORAGE' },
  { pattern: 'compute.instances.',             category: 'COMPUTE' },
  { pattern: 'run.services.',                  category: 'COMPUTE' },
  { pattern: 'sqladmin.',                      category: 'DATABASE' },
  { pattern: 'bigtable.',                      category: 'DATABASE' },
  { pattern: 'cloudkms.',                      category: 'ENCRYPTION' },
  { pattern: 'logging.sinks.',                 category: 'LOGGING' },
  { pattern: 'logging.exclusions.',            category: 'LOGGING' },
];

function gcpCategory(method: string): ChangeCategory {
  const lower = method.toLowerCase();
  for (const { pattern, category } of GCP_CATEGORIES) {
    if (lower.includes(pattern)) return category;
  }
  return 'OTHER';
}

const GCP_RISK: { pattern: string; score: number }[] = [
  { pattern: 'setiampolicy',                   score: 85 },
  { pattern: 'iam.serviceaccountkeys.create',  score: 80 },
  { pattern: 'compute.firewalls.insert',       score: 65 },
  { pattern: 'compute.firewalls.patch',        score: 60 },
  { pattern: 'compute.firewalls.delete',       score: 50 },
  { pattern: 'storage.buckets.setiampolicy',   score: 80 },
  { pattern: 'storage.buckets.update',         score: 55 },
  { pattern: 'logging.sinks.delete',           score: 80 },
  { pattern: 'logging.sinks.update',           score: 55 },
  { pattern: 'cloudkms.cryptokeys.destroy',    score: 85 },
  { pattern: 'cloudkms.cryptokeys.create',     score: 35 },
  { pattern: 'sqladmin.instances.delete',      score: 70 },
  { pattern: 'sqladmin.instances.insert',      score: 30 },
];

function gcpRiskScore(method: string): number {
  const lower = method.toLowerCase();
  for (const { pattern, score } of GCP_RISK) {
    if (lower.includes(pattern)) return score;
  }
  if (lower.includes('delete')) return 55;
  if (lower.includes('create') || lower.includes('insert')) return 30;
  if (lower.includes('update') || lower.includes('patch')) return 40;
  return 20;
}

export function classifyGcpEvent(payload: Record<string, unknown>): ClassifiedChange {
  const method    = (payload.methodName as string) ?? 'UnknownMethod';
  const principal = (payload.authenticationInfo as Record<string, unknown>)?.principalEmail as string | null ?? null;
  const resource  = (payload.resourceName as string) ?? null;
  const request   = (payload.request as Record<string, unknown>) ?? null;

  const category  = gcpCategory(method);
  const riskScore = cap(gcpRiskScore(method));
  const severity  = severityFromScore(riskScore);

  const resourceName = resource?.split('/').pop() ?? null;
  const resourceType = method.split('.').slice(0, 2).join('.') || null;

  const summary = `${principal ?? 'Unknown'} called ${method} on ${resourceName || resource || 'resource'}`;

  const methodLower = method.toLowerCase();
  const isDelete = methodLower.includes('delete') || methodLower.includes('destroy');
  const isCreate = methodLower.includes('create') || methodLower.includes('insert');
  const changeAction: ChangeAction = isDelete ? 'DELETED' : isCreate ? 'CREATED' : 'MODIFIED';

  return {
    changeAction,
    category, riskScore, severity, summary,
    actor: principal, actorType: 'ServiceAccount', sourceIp: null,
    resourceType, resourceId: resource, resourceName,
    previousValue: isDelete && resource ? { resourceId: resource, resourceName } : null,
    newValue: request ? { ...request } : null,
  };
}
