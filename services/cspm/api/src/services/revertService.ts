/**
 * Config Revert Service
 *
 * Given a DriftResult with baselineConfig, attempts to push the baseline state
 * back to the cloud resource.
 *
 * Strategy per provider:
 *   AWS   — resource-type-specific SDK calls for safe resources (S3, CloudTrail,
 *            KMS, IAM trust policy); generates remediation script for complex types.
 *   Azure — generic ARM PUT with the baseline config body (declarative API).
 *   GCP   — setIamPolicy for IAM resources; remediation script for others.
 *
 * Every revert is logged to DriftResult with status → RESOLVED and a revertedAt
 * timestamp so the audit trail is complete.
 *
 * "canAutoRevert" in the plan tells the UI whether the system can execute
 * the revert automatically (true) or the operator must apply the script manually.
 */

import { prisma }                      from '../config/database';
import { logger }                      from '../config/logger';
import * as credentialService          from './credentialService';
import { decryptAzureCredentials }     from './azureCredentialService';
import { decryptGcpCredentials }       from './gcpCredentialService';
import AzureClient                     from '../../../src/azure/client';
import GcpClient                       from '../../../src/gcp/client';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { S3Client, PutBucketPolicyCommand, PutPublicAccessBlockCommand } from '@aws-sdk/client-s3';
import { IAMClient, UpdateAssumeRolePolicyCommand } from '@aws-sdk/client-iam';
import { CloudTrailClient, StartLoggingCommand, UpdateTrailCommand } from '@aws-sdk/client-cloudtrail';
import { KMSClient, EnableKeyCommand, PutKeyPolicyCommand } from '@aws-sdk/client-kms';

// ─── Plan types ───────────────────────────────────────────────────────────────

export interface RevertPlan {
  canAutoRevert:   boolean;
  riskLevel:       'LOW' | 'MEDIUM' | 'HIGH';
  description:     string;
  steps:           string[];                // human-readable steps
  remediationScript?: string;              // CLI commands if canAutoRevert=false
  warnings:        string[];
}

// ─── AWS credential helper ────────────────────────────────────────────────────

async function getAwsCredentials(targetId: string, region: string) {
  const cred = await prisma.awsCredential.findUnique({ where: { accountId: targetId } });
  if (!cred) throw new Error('No AWS credentials found');
  const dec = credentialService.decryptCredentials(cred);
  if (!dec.accessKeyId || !dec.secretAccessKey) throw new Error('Missing AWS credentials');

  let credentials = {
    accessKeyId:     dec.accessKeyId,
    secretAccessKey: dec.secretAccessKey,
    sessionToken:    undefined as string | undefined,
  };

  if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
    const sts = new STSClient({ region, credentials });
    const assumed = await sts.send(new AssumeRoleCommand({
      RoleArn: cred.roleArn, RoleSessionName: 'revert-action', DurationSeconds: 900,
      ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
    }));
    if (!assumed.Credentials) throw new Error('STS AssumeRole failed');
    credentials = {
      accessKeyId:     assumed.Credentials.AccessKeyId!,
      secretAccessKey: assumed.Credentials.SecretAccessKey!,
      sessionToken:    assumed.Credentials.SessionToken,
    };
  }
  return { credentials, region };
}

// ─── Revert plan generator ────────────────────────────────────────────────────

export async function generateRevertPlan(
  baselineId: string,
  driftId: string,
): Promise<RevertPlan> {
  const drift = await prisma.driftResult.findFirst({
    where: { id: driftId, baselineId },
  });
  if (!drift) throw new Error('Drift result not found');
  if (!drift.baselineConfig) {
    return {
      canAutoRevert: false,
      riskLevel: 'MEDIUM',
      description: 'No baseline config snapshot available — cannot generate revert plan.',
      steps: ['Manually inspect the resource and restore configuration per your change management process.'],
      warnings: ['Baseline config was not captured for this resource type.'],
    };
  }

  const baseline = await prisma.configBaseline.findUnique({
    where:  { id: baselineId },
    select: { provider: true, targetId: true },
  });
  if (!baseline) throw new Error('Baseline not found');

  const { provider } = baseline;
  const type  = (drift.resourceType ?? '').toLowerCase();
  const bCfg  = drift.baselineConfig as Record<string, unknown>;

  if (provider === 'AWS') {
    return planAwsRevert(drift.driftType, type, drift.resourceName ?? drift.nativeId, bCfg);
  } else if (provider === 'AZURE') {
    return planAzureRevert(drift.driftType, type, drift.resourceName ?? drift.nativeId, bCfg, drift.nativeId);
  } else {
    return planGcpRevert(drift.driftType, type, drift.resourceName ?? drift.nativeId, bCfg);
  }
}

function planAwsRevert(driftType: string, type: string, resourceName: string, bCfg: Record<string, unknown>, _driftedFields?: string[]): RevertPlan {
  const isDelete = driftType === 'DELETED';

  if (isDelete) {
    return {
      canAutoRevert: false,
      riskLevel: 'HIGH',
      description: `Resource "${resourceName}" was deleted. Automatic recreation is not supported — restoration requires manual intervention.`,
      steps: [
        'Review the baseline config snapshot to understand the original resource configuration.',
        'Recreate the resource using your IaC tool (Terraform/CloudFormation) or the AWS Console.',
        'Apply the configuration from the baseline snapshot.',
        'Mark the drift as RESOLVED once the resource is restored.',
      ],
      remediationScript: `# Baseline config for ${resourceName}:\n${JSON.stringify(bCfg, null, 2)}`,
      warnings: ['Recreating deleted resources may have downstream dependencies. Proceed carefully.'],
    };
  }

  // S3 bucket policy / public access
  if (type.includes('s3') || type.includes('bucket')) {
    const steps: string[] = [];
    const warnings: string[] = [];
    if (bCfg.Policy || bCfg.policy) steps.push(`Restore S3 bucket policy on "${resourceName}"`);
    if (bCfg.PublicAccessBlockConfiguration) steps.push(`Restore public access block settings on "${resourceName}"`);
    if (steps.length === 0) steps.push('Restore S3 configuration from baseline snapshot');
    return {
      canAutoRevert: true, riskLevel: 'MEDIUM',
      description: `Restore S3 bucket "${resourceName}" policy and access settings to baseline state.`,
      steps, warnings,
    };
  }

  // CloudTrail
  if (type.includes('cloudtrail') || type.includes('trail')) {
    return {
      canAutoRevert: true, riskLevel: 'HIGH',
      description: `Re-enable CloudTrail logging on trail "${resourceName}".`,
      steps: [`Start logging on trail "${resourceName}"`, 'Restore trail configuration from baseline'],
      warnings: ['Stopping/deleting CloudTrail is a high-risk security event. Verify root cause before reverting.'],
    };
  }

  // KMS
  if (type.includes('kms') || type.includes('key')) {
    return {
      canAutoRevert: true, riskLevel: 'HIGH',
      description: `Re-enable KMS key "${resourceName}" and restore key policy from baseline.`,
      steps: [`Enable KMS key "${resourceName}"`, 'Restore key policy from baseline snapshot'],
      warnings: ['Restoring KMS key policy may affect encryption-dependent services. Test in non-prod first.'],
    };
  }

  // IAM role trust policy
  if (type.includes('iam') && type.includes('role')) {
    return {
      canAutoRevert: true, riskLevel: 'HIGH',
      description: `Restore IAM role trust policy for "${resourceName}" to baseline state.`,
      steps: [`Update assume-role-policy-document on role "${resourceName}"`],
      warnings: [
        'Changing IAM trust policies affects cross-account access. Verify the change is intentional.',
        'An overly permissive trust policy may be the security incident, not the revert.',
      ],
    };
  }

  // Security groups — too complex for auto-revert
  if (type.includes('securitygroup') || type.includes('security-group') || type.includes('network-security')) {
    return {
      canAutoRevert: false, riskLevel: 'HIGH',
      description: `Security group "${resourceName}" requires manual revert — rule comparison is complex.`,
      steps: [
        'Review the baseline config to identify the exact ingress/egress rules to restore.',
        'Use the AWS Console or CLI to authorize/revoke rules to match the baseline.',
        'Verify connectivity after applying changes.',
      ],
      remediationScript: generateSecurityGroupScript(resourceName, bCfg),
      warnings: [
        'Auto-revert of security groups is disabled to prevent unintended network disruption.',
        'Verify which rules are legitimate additions vs. unauthorized changes.',
      ],
    };
  }

  // Generic fallback
  return {
    canAutoRevert: false, riskLevel: 'MEDIUM',
    description: `Modified configuration for "${resourceName}" requires manual restoration.`,
    steps: [
      'Compare the baseline config snapshot with the current resource state.',
      'Apply the required changes via the AWS Console, CLI, or IaC tool.',
    ],
    remediationScript: `# Baseline config for ${resourceName}:\n${JSON.stringify(bCfg, null, 2)}`,
    warnings: ['Automatic revert is not implemented for this resource type.'],
  };
}

function planAzureRevert(driftType: string, type: string, resourceName: string, bCfg: Record<string, unknown>, nativeId: string): RevertPlan {
  if (driftType === 'DELETED') {
    return {
      canAutoRevert: false, riskLevel: 'HIGH',
      description: `Azure resource "${resourceName}" was deleted. Automatic recreation requires ARM template deployment.`,
      steps: [
        'Export the baseline config below as an ARM template.',
        'Deploy via az deployment group create or Azure Portal.',
      ],
      remediationScript: `# Baseline config:\n${JSON.stringify(bCfg, null, 2)}\n\n# ARM PUT command:\naz rest --method PUT --url "${nativeId}?api-version=2023-01-01" --body '${JSON.stringify(bCfg)}'`,
      warnings: ['Recreating deleted resources may have dependencies.'],
    };
  }
  return {
    canAutoRevert: true, riskLevel: 'MEDIUM',
    description: `Restore Azure resource "${resourceName}" to baseline state via ARM PUT.`,
    steps: [
      `Issue ARM PUT to ${nativeId}`,
      'Apply baseline configState as the resource body',
    ],
    warnings: [
      'ARM PUT is a full replacement — properties not in baseline may be removed.',
      'Verify the baseline config is complete before approving.',
    ],
  };
}

function planGcpRevert(driftType: string, type: string, resourceName: string, bCfg: Record<string, unknown>): RevertPlan {
  if (type.includes('iam') || type.includes('policy')) {
    return {
      canAutoRevert: true, riskLevel: 'HIGH',
      description: `Restore GCP IAM policy for "${resourceName}" to baseline state.`,
      steps: [`Call setIamPolicy on "${resourceName}" with baseline policy bindings`],
      warnings: ['Removing IAM bindings may revoke access for active service accounts. Verify before approving.'],
    };
  }
  return {
    canAutoRevert: false, riskLevel: 'MEDIUM',
    description: `GCP resource "${resourceName}" requires manual revert via gcloud CLI.`,
    steps: ['Apply the baseline config using the appropriate gcloud command for this resource type.'],
    remediationScript: `# Baseline config for ${resourceName}:\n${JSON.stringify(bCfg, null, 2)}`,
    warnings: ['Automatic revert is not implemented for this GCP resource type.'],
  };
}

function generateSecurityGroupScript(sgName: string, bCfg: Record<string, unknown>): string {
  const ipPerms = (bCfg.ipPermissions ?? bCfg.IpPermissions ?? []) as Record<string, unknown>[];
  const lines = [`# Restore security group "${sgName}" to baseline ingress rules`];
  for (const rule of ipPerms) {
    const from = rule.fromPort ?? rule.FromPort ?? 0;
    const to   = rule.toPort   ?? rule.ToPort   ?? 65535;
    const proto = rule.ipProtocol ?? rule.IpProtocol ?? 'tcp';
    const ranges = (rule.ipRanges ?? rule.IpRanges ?? []) as Record<string, unknown>[];
    for (const r of ranges) {
      lines.push(`aws ec2 authorize-security-group-ingress --group-name "${sgName}" --protocol ${proto} --port ${from}-${to} --cidr ${r.cidrIp ?? r.CidrIp ?? '0.0.0.0/0'}`);
    }
  }
  if (lines.length === 1) lines.push(`# Baseline config:\n${JSON.stringify(bCfg, null, 2)}`);
  return lines.join('\n');
}

// ─── Execute revert ───────────────────────────────────────────────────────────

export async function executeRevert(
  baselineId: string,
  driftId:    string,
  executedBy: string,
): Promise<{ success: boolean; message: string }> {
  const drift = await prisma.driftResult.findFirst({
    where: { id: driftId, baselineId },
  });
  if (!drift) throw new Error('Drift result not found');
  if (!drift.baselineConfig) throw new Error('No baseline config captured for this drift — cannot auto-revert');

  const baseline = await prisma.configBaseline.findUnique({ where: { id: baselineId } });
  if (!baseline) throw new Error('Baseline not found');

  const { provider, targetId } = baseline;
  const type  = (drift.resourceType ?? '').toLowerCase();
  const bCfg  = drift.baselineConfig as Record<string, unknown>;
  const cred  = await prisma.awsCredential.findUnique({ where: { accountId: targetId } });
  const region = cred?.defaultRegion ?? 'us-east-1';

  let result: { success: boolean; message: string };

  try {
    if (provider === 'AWS') {
      result = await executeAwsRevert(targetId, region, type, drift.nativeId, drift.resourceName ?? drift.nativeId, bCfg);
    } else if (provider === 'AZURE') {
      result = await executeAzureRevert(targetId, drift.nativeId, bCfg);
    } else {
      result = await executeGcpRevert(targetId, drift.nativeId, type, bCfg);
    }

    if (result.success) {
      await prisma.driftResult.update({
        where: { id: driftId },
        data:  { status: 'RESOLVED', resolvedAt: new Date() },
      });
      logger.info(`[revert] ${provider} "${drift.resourceName}" reverted by ${executedBy}: ${result.message}`);
    }
  } catch (err) {
    result = { success: false, message: (err as Error).message };
    logger.error(`[revert] Failed to revert ${drift.resourceName}: ${result.message}`);
  }

  return result;
}

// ─── AWS revert executors ─────────────────────────────────────────────────────

async function executeAwsRevert(
  targetId: string, region: string, type: string,
  nativeId: string, resourceName: string, bCfg: Record<string, unknown>,
): Promise<{ success: boolean; message: string }> {
  const { credentials } = await getAwsCredentials(targetId, region);

  // S3 policy / public access block
  if (type.includes('s3') || type.includes('bucket')) {
    const bucketName = resourceName.split(':').pop() ?? resourceName;
    const s3 = new S3Client({ region, credentials });
    const tasks: Promise<unknown>[] = [];

    const policy = bCfg.Policy ?? bCfg.policy;
    if (policy) {
      tasks.push(s3.send(new PutBucketPolicyCommand({
        Bucket: bucketName,
        Policy: typeof policy === 'string' ? policy : JSON.stringify(policy),
      })));
    }
    const pab = bCfg.PublicAccessBlockConfiguration as Record<string, boolean> | undefined;
    if (pab) {
      tasks.push(s3.send(new PutPublicAccessBlockCommand({
        Bucket: bucketName,
        PublicAccessBlockConfiguration: {
          BlockPublicAcls:       pab.BlockPublicAcls,
          IgnorePublicAcls:      pab.IgnorePublicAcls,
          BlockPublicPolicy:     pab.BlockPublicPolicy,
          RestrictPublicBuckets: pab.RestrictPublicBuckets,
        },
      })));
    }
    if (tasks.length === 0) throw new Error('No S3 policy or public-access-block config in baseline snapshot');
    await Promise.all(tasks);
    return { success: true, message: `S3 bucket "${bucketName}" policy/access settings restored` };
  }

  // CloudTrail — re-enable logging
  if (type.includes('cloudtrail') || type.includes('trail')) {
    const ct = new CloudTrailClient({ region, credentials });
    await ct.send(new StartLoggingCommand({ Name: nativeId }));
    return { success: true, message: `CloudTrail "${resourceName}" logging re-enabled` };
  }

  // KMS — enable key and restore key policy
  if (type.includes('kms') || type.includes('key')) {
    const kms = new KMSClient({ region, credentials });
    const tasks: Promise<unknown>[] = [kms.send(new EnableKeyCommand({ KeyId: nativeId }))];
    const keyPolicy = bCfg.KeyPolicy ?? bCfg.Policy;
    if (keyPolicy) {
      tasks.push(kms.send(new PutKeyPolicyCommand({
        KeyId:      nativeId,
        PolicyName: 'default',
        Policy:     typeof keyPolicy === 'string' ? keyPolicy : JSON.stringify(keyPolicy),
      })));
    }
    await Promise.all(tasks);
    return { success: true, message: `KMS key "${resourceName}" enabled and policy restored` };
  }

  // IAM role trust policy
  if (type.includes('iam') && type.includes('role')) {
    const trustDoc = bCfg.assumeRolePolicyDocument ?? bCfg.AssumeRolePolicyDocument;
    if (!trustDoc) throw new Error('No assumeRolePolicyDocument in baseline snapshot');
    const iam = new IAMClient({ region, credentials });
    await iam.send(new UpdateAssumeRolePolicyCommand({
      RoleName:       resourceName,
      PolicyDocument: typeof trustDoc === 'string' ? trustDoc : JSON.stringify(trustDoc),
    }));
    return { success: true, message: `IAM role "${resourceName}" trust policy restored` };
  }

  throw new Error(`Auto-revert not supported for resource type "${type}". Use the remediation script.`);
}

// ─── Azure revert executor ────────────────────────────────────────────────────

async function executeAzureRevert(
  targetId: string, resourceId: string, bCfg: Record<string, unknown>,
): Promise<{ success: boolean; message: string }> {
  const sub  = await prisma.azureSubscription.findUnique({ where: { id: targetId } });
  if (!sub) throw new Error('Azure subscription not found');
  const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId: targetId } });
  if (!cred) throw new Error('No Azure credentials');
  const dec  = decryptAzureCredentials(cred);

  const azure = new AzureClient({
    subscriptionId: sub.subscriptionId,
    tenantId:       dec.tenantId,
    clientId:       dec.clientId,
    clientSecret:   dec.clientSecret,
    authMethod:     cred.authMethod as 'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY',
  });

  // Get a token for the ARM REST call
  const tokenResult = await azure.credential.getToken('https://management.azure.com/.default');
  if (!tokenResult) throw new Error('Failed to obtain Azure access token');
  const token = tokenResult.token;
  const apiVersion = '2023-01-01';
  const url = `https://management.azure.com${resourceId}?api-version=${apiVersion}`;

  const resp = await fetch(url, {
    method:  'PUT',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify(bCfg),
    signal:  AbortSignal.timeout(30_000),
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`ARM PUT failed (${resp.status}): ${body.slice(0, 200)}`);
  }

  return { success: true, message: `Azure resource "${resourceId.split('/').pop()}" restored via ARM PUT` };
}

// ─── GCP revert executor ──────────────────────────────────────────────────────

async function executeGcpRevert(
  targetId: string, resourceId: string, type: string, bCfg: Record<string, unknown>,
): Promise<{ success: boolean; message: string }> {
  if (!type.includes('iam') && !type.includes('policy')) {
    throw new Error(`Auto-revert not supported for GCP resource type "${type}". Use the remediation script.`);
  }

  const project = await prisma.gcpProject.findUnique({ where: { id: targetId } });
  if (!project) throw new Error('GCP project not found');
  const cred = await prisma.gcpCredential.findUnique({ where: { projectId: targetId } });
  if (!cred) throw new Error('No GCP credentials');
  const dec = decryptGcpCredentials(cred);

  const gcpClient = new GcpClient({
    projectId:   project.projectId,
    credentials: dec.serviceAccountKey ? JSON.parse(dec.serviceAccountKey) as Record<string, unknown> : undefined,
    authMethod:  cred.authMethod as 'SERVICE_ACCOUNT_KEY' | 'WORKLOAD_IDENTITY',
  });

  const resourceManager = gcpClient.cloudresourcemanager();
  await resourceManager.projects.setIamPolicy({
    resource: `projects/${project.projectId}`,
    requestBody: { policy: bCfg },
  });

  return { success: true, message: `GCP IAM policy for project "${project.projectId}" restored` };
}
