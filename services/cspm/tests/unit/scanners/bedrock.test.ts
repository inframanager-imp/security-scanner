import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';

import {
  BedrockClient,
  GetModelInvocationLoggingConfigurationCommand,
  ListGuardrailsCommand,
  GetGuardrailCommand,
} from '@aws-sdk/client-bedrock';
import {
  BedrockAgentClient,
  ListAgentsCommand,
  GetAgentCommand,
  ListPromptsCommand,
} from '@aws-sdk/client-bedrock-agent';
import {
  IAMClient,
  ListUsersCommand,
  ListServiceSpecificCredentialsCommand,
  ListAttachedUserPoliciesCommand,
  ListUserPoliciesCommand,
  ListAttachedRolePoliciesCommand,
  ListRolePoliciesCommand,
  ListEntitiesForPolicyCommand,
  GetRoleCommand,
} from '@aws-sdk/client-iam';
import { S3Client, GetBucketEncryptionCommand } from '@aws-sdk/client-s3';
import { CloudWatchLogsClient, DescribeLogGroupsCommand } from '@aws-sdk/client-cloudwatch-logs';
import {
  EC2Client,
  DescribeVpcsCommand,
  DescribeVpcEndpointsCommand,
  DescribeNetworkInterfacesCommand,
} from '@aws-sdk/client-ec2';

import BedrockScanner from '../../../src/scanners/bedrock';
import type { ScanningResult } from '../../../src/utils/types';

const bedrockMock = mockClient(BedrockClient);
const bedrockAgentMock = mockClient(BedrockAgentClient);
const iamMock = mockClient(IAMClient);
const s3Mock = mockClient(S3Client);
const logsMock = mockClient(CloudWatchLogsClient);
const ec2Mock = mockClient(EC2Client);

// Minimal AWSClient-shaped stub: BedrockScanner only calls getClientConfig()
// in its constructor to build its own SDK v3 clients.
const fakeAwsClient: any = {
  getClientConfig: () => ({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
};

function findByCheckId(findings: ScanningResult[], checkId: string): ScanningResult[] {
  return findings.filter((f) => f.checkId === checkId);
}

// Defaults so scan() doesn't throw/hang on unmocked calls: every command used
// by the scanner gets a benign empty-ish response unless a test overrides it.
function setBenignDefaults(): void {
  bedrockMock.on(GetModelInvocationLoggingConfigurationCommand).resolves({ loggingConfig: undefined } as any);
  bedrockMock.on(ListGuardrailsCommand).resolves({ guardrails: [] } as any);
  bedrockAgentMock.on(ListAgentsCommand).resolves({ agentSummaries: [] } as any);
  bedrockAgentMock.on(ListPromptsCommand).resolves({ promptSummaries: [] } as any);
  iamMock.on(ListUsersCommand).resolves({ Users: [] } as any);
  iamMock.on(ListEntitiesForPolicyCommand).resolves({ PolicyRoles: [] } as any);
  ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [] } as any);
  ec2Mock.on(DescribeVpcEndpointsCommand).resolves({ VpcEndpoints: [] } as any);
  ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({ NetworkInterfaces: [] } as any);
}

describe('BedrockScanner', () => {
  beforeEach(() => {
    bedrockMock.reset();
    bedrockAgentMock.reset();
    iamMock.reset();
    s3Mock.reset();
    logsMock.reset();
    ec2Mock.reset();
    setBenignDefaults();
  });

  describe('model invocation logging', () => {
    it('emits bedrock_model_invocation_logging_enabled when logging is not configured', async () => {
      bedrockMock.on(GetModelInvocationLoggingConfigurationCommand).resolves({ loggingConfig: undefined } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_model_invocation_logging_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].service).toBe('Bedrock');
      expect(matches[0].evidence).toMatchObject({ region: 'us-east-1', loggingEnabled: false });
    });

    it('does not emit the logging-enabled finding, but flags unencrypted destinations when logging is configured without encryption', async () => {
      // GetBucketEncryption rejecting with this specific AWS error name is a real
      // "not encrypted" signal, not a transient failure — but BaseScanner's retry()
      // can't tell the difference and retries it 3x with backoff. Fake timers keep
      // the test fast without changing the retry/backoff behavior under test.
      jest.useFakeTimers({ advanceTimers: true });
      bedrockMock.on(GetModelInvocationLoggingConfigurationCommand).resolves({
        loggingConfig: {
          s3Config: { bucketName: 'my-bedrock-logs' },
          cloudWatchConfig: { logGroupName: '/bedrock/logs' },
        },
      } as any);
      s3Mock.on(GetBucketEncryptionCommand).rejects(
        Object.assign(new Error('not found'), { name: 'ServerSideEncryptionConfigurationNotFoundError' })
      );
      logsMock.on(DescribeLogGroupsCommand).resolves({
        logGroups: [{ logGroupName: '/bedrock/logs', kmsKeyId: undefined }],
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'bedrock_model_invocation_logging_enabled')).toHaveLength(0);
      const encryptionFindings = findByCheckId(findings, 'bedrock_model_invocation_logs_encryption_enabled');
      expect(encryptionFindings).toHaveLength(1);
      expect(encryptionFindings[0].evidence).toMatchObject({
        s3Bucket: 'my-bedrock-logs',
        s3Encrypted: false,
        cloudwatchLogGroup: '/bedrock/logs',
        cloudwatchEncrypted: false,
      });
      jest.useRealTimers();
    });

    it('emits no encryption finding when both destinations are encrypted', async () => {
      bedrockMock.on(GetModelInvocationLoggingConfigurationCommand).resolves({
        loggingConfig: {
          s3Config: { bucketName: 'my-bedrock-logs' },
          cloudWatchConfig: { logGroupName: '/bedrock/logs' },
        },
      } as any);
      s3Mock.on(GetBucketEncryptionCommand).resolves({
        ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms' } }] },
      } as any);
      logsMock.on(DescribeLogGroupsCommand).resolves({
        logGroups: [{ logGroupName: '/bedrock/logs', kmsKeyId: 'arn:aws:kms:us-east-1:123:key/abc' }],
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'bedrock_model_invocation_logs_encryption_enabled')).toHaveLength(0);
    });
  });

  describe('guardrails', () => {
    it('emits bedrock_guardrails_configured when no guardrails exist', async () => {
      bedrockMock.on(ListGuardrailsCommand).resolves({ guardrails: [] } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_guardrails_configured');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ region: 'us-east-1', guardrailCount: 0 });
    });

    it('flags guardrails missing sensitive-information filter and weak prompt-attack filter strength', async () => {
      bedrockMock.on(ListGuardrailsCommand).resolves({
        guardrails: [{ id: 'gr-1', name: 'my-guardrail', arn: 'arn:aws:bedrock:us-east-1:123:guardrail/gr-1' }],
      } as any);
      bedrockMock.on(GetGuardrailCommand).resolves({
        sensitiveInformationPolicy: undefined,
        contentPolicy: { filters: [{ type: 'PROMPT_ATTACK', inputStrength: 'LOW' }] },
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'bedrock_guardrails_configured')).toHaveLength(0);

      const sensitiveFindings = findByCheckId(findings, 'bedrock_guardrail_sensitive_information_filter_enabled');
      expect(sensitiveFindings).toHaveLength(1);
      expect(sensitiveFindings[0].evidence).toMatchObject({ guardrail: 'my-guardrail', guardrailId: 'gr-1' });

      const promptAttackFindings = findByCheckId(findings, 'bedrock_guardrail_prompt_attack_filter_enabled');
      expect(promptAttackFindings).toHaveLength(1);
      expect(promptAttackFindings[0].evidence).toMatchObject({ promptAttackFilterStrength: 'LOW' });
    });

    it('emits no guardrail findings when sensitive-info filter present and prompt-attack strength is HIGH', async () => {
      bedrockMock.on(ListGuardrailsCommand).resolves({
        guardrails: [{ id: 'gr-2', name: 'good-guardrail', arn: 'arn:aws:bedrock:us-east-1:123:guardrail/gr-2' }],
      } as any);
      bedrockMock.on(GetGuardrailCommand).resolves({
        sensitiveInformationPolicy: { piiEntities: [] },
        contentPolicy: { filters: [{ type: 'PROMPT_ATTACK', inputStrength: 'HIGH' }] },
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'bedrock_guardrail_sensitive_information_filter_enabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'bedrock_guardrail_prompt_attack_filter_enabled')).toHaveLength(0);
    });

    it('paginates through ListGuardrails using nextToken and evaluates every page', async () => {
      bedrockMock
        .on(ListGuardrailsCommand)
        .resolvesOnce({ guardrails: [{ id: 'gr-a', name: 'guardrail-a' }], nextToken: 'page2' } as any)
        .resolvesOnce({ guardrails: [{ id: 'gr-b', name: 'guardrail-b' }] } as any);
      bedrockMock.on(GetGuardrailCommand).resolves({
        sensitiveInformationPolicy: undefined,
        contentPolicy: { filters: [] },
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const sensitiveFindings = findByCheckId(findings, 'bedrock_guardrail_sensitive_information_filter_enabled');
      const evaluatedGuardrails = sensitiveFindings.map((f: any) => f.evidence.guardrailId).sort();
      expect(evaluatedGuardrails).toEqual(['gr-a', 'gr-b']);
      expect(bedrockMock.commandCalls(ListGuardrailsCommand)).toHaveLength(2);
    });
  });

  describe('agents', () => {
    it('flags agents with no guardrail configured', async () => {
      bedrockAgentMock.on(ListAgentsCommand).resolves({
        agentSummaries: [{ agentId: 'agent-1', agentName: 'my-agent', guardrailConfiguration: undefined }],
      } as any);
      bedrockAgentMock.on(GetAgentCommand).resolves({
        agent: { agentResourceRoleArn: undefined },
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_agent_guardrail_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ agent: 'my-agent', agentId: 'agent-1', guardrail: null });
    });

    it('does not flag an agent that has a guardrail configured', async () => {
      bedrockAgentMock.on(ListAgentsCommand).resolves({
        agentSummaries: [{
          agentId: 'agent-2',
          agentName: 'guarded-agent',
          guardrailConfiguration: { guardrailIdentifier: 'gr-1' },
        }],
      } as any);
      bedrockAgentMock.on(GetAgentCommand).resolves({
        agent: { agentResourceRoleArn: undefined },
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'bedrock_agent_guardrail_enabled')).toHaveLength(0);
    });

    it('flags bedrock_agent_role_least_privilege when the execution role cannot be resolved in IAM', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      bedrockAgentMock.on(ListAgentsCommand).resolves({
        agentSummaries: [{ agentId: 'agent-3', agentName: 'orphan-role-agent', guardrailConfiguration: { guardrailIdentifier: 'gr-1' } }],
      } as any);
      bedrockAgentMock.on(GetAgentCommand).resolves({
        agent: { agentResourceRoleArn: 'arn:aws:iam::123:role/missing-role' },
      } as any);
      iamMock.on(GetRoleCommand).rejects(new Error('NoSuchEntity'));

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_agent_role_least_privilege');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ agent: 'orphan-role-agent', roleResolved: false });
      jest.useRealTimers();
    });
  });

  describe('VPC endpoints', () => {
    it('skips the VPC endpoint check entirely when Bedrock has no activity in the region', async () => {
      // No logging, no guardrails, no agents => bedrockActive is false
      bedrockMock.on(GetModelInvocationLoggingConfigurationCommand).resolves({ loggingConfig: undefined } as any);
      bedrockMock.on(ListGuardrailsCommand).resolves({ guardrails: [] } as any);
      bedrockAgentMock.on(ListAgentsCommand).resolves({ agentSummaries: [] } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      await scanner.scan();

      expect(ec2Mock.commandCalls(DescribeVpcsCommand)).toHaveLength(0);
    });

    it('flags an in-use VPC missing Bedrock VPC endpoints when Bedrock is active', async () => {
      bedrockMock.on(ListGuardrailsCommand).resolves({
        guardrails: [{ id: 'gr-1', name: 'g1', arn: 'arn:x' }],
      } as any);
      bedrockMock.on(GetGuardrailCommand).resolves({
        sensitiveInformationPolicy: { piiEntities: [] },
        contentPolicy: { filters: [{ type: 'PROMPT_ATTACK', inputStrength: 'HIGH' }] },
      } as any);
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-1' }] } as any);
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [{ VpcId: 'vpc-1' }],
      } as any);
      ec2Mock.on(DescribeVpcEndpointsCommand).resolves({ VpcEndpoints: [] } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_vpc_endpoints_configured');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence.vpcId).toBe('vpc-1');
      expect(matches[0].evidence.missingEndpointServices).toEqual(
        expect.arrayContaining(['bedrock', 'bedrock-runtime'])
      );
    });
  });

  describe('Bedrock API keys', () => {
    it('flags a long-term API key configured to never expire as CRITICAL', async () => {
      iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'svc-user' }] } as any);
      const farFuture = new Date(Date.now() + 20000 * 24 * 60 * 60 * 1000).toISOString();
      iamMock.on(ListServiceSpecificCredentialsCommand).resolves({
        ServiceSpecificCredentials: [{
          ServiceSpecificCredentialId: 'cred-1',
          ServiceName: 'bedrock.amazonaws.com',
          ExpirationDate: farFuture,
        }],
      } as any);
      iamMock.on(ListAttachedUserPoliciesCommand).resolves({ AttachedPolicies: [] } as any);
      iamMock.on(ListUserPoliciesCommand).resolves({ PolicyNames: [] } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_api_key_no_long_term_credentials');
      expect(matches).toHaveLength(1);
      expect(matches[0].severity).toBe('CRITICAL');
      expect(matches[0].evidence).toMatchObject({ user: 'svc-user', apiKeyId: 'cred-1', neverExpires: true });
    });

    it('flags administrative-privilege API keys via AdministratorAccess attached policy', async () => {
      iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'admin-user' }] } as any);
      const soonExpiry = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString();
      iamMock.on(ListServiceSpecificCredentialsCommand).resolves({
        ServiceSpecificCredentials: [{
          ServiceSpecificCredentialId: 'cred-2',
          ServiceName: 'bedrock.amazonaws.com',
          ExpirationDate: soonExpiry,
        }],
      } as any);
      iamMock.on(ListAttachedUserPoliciesCommand).resolves({
        AttachedPolicies: [{ PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess', PolicyName: 'AdministratorAccess' }],
      } as any);
      iamMock.on(ListUserPoliciesCommand).resolves({ PolicyNames: [] } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_api_key_no_administrative_privileges');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({
        user: 'admin-user',
        apiKeyId: 'cred-2',
        violation: expect.stringContaining('administrative privileges'),
      });
    });

    it('emits no findings for a user without Bedrock service-specific credentials', async () => {
      iamMock.on(ListUsersCommand).resolves({ Users: [{ UserName: 'no-creds-user' }] } as any);
      iamMock.on(ListServiceSpecificCredentialsCommand).resolves({ ServiceSpecificCredentials: [] } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'bedrock_api_key_no_long_term_credentials')).toHaveLength(0);
      expect(findByCheckId(findings, 'bedrock_api_key_no_administrative_privileges')).toHaveLength(0);
    });
  });

  describe('full-access policy roles', () => {
    it('flags a non-service role with AmazonBedrockFullAccess attached', async () => {
      iamMock.on(ListEntitiesForPolicyCommand).resolves({
        PolicyRoles: [{ RoleName: 'my-role' }],
      } as any);
      iamMock.on(GetRoleCommand).resolves({
        Role: {
          RoleName: 'my-role',
          Arn: 'arn:aws:iam::123:role/my-role',
          AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify({
            Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: 'arn:aws:iam::123:root' } }],
          })),
        },
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_full_access_policy_attached');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ role: 'my-role', policyArn: 'arn:aws:iam::aws:policy/AmazonBedrockFullAccess' });
    });

    it('excludes AWS-service-assumable roles from the full-access-policy finding', async () => {
      iamMock.on(ListEntitiesForPolicyCommand).resolves({
        PolicyRoles: [{ RoleName: 'service-role' }],
      } as any);
      iamMock.on(GetRoleCommand).resolves({
        Role: {
          RoleName: 'service-role',
          Arn: 'arn:aws:iam::123:role/service-role',
          AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify({
            Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { Service: 'bedrock.amazonaws.com' } }],
          })),
        },
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'bedrock_full_access_policy_attached')).toHaveLength(0);
    });

    it('paginates through ListEntitiesForPolicy using Marker and evaluates roles from every page', async () => {
      iamMock
        .on(ListEntitiesForPolicyCommand)
        .resolvesOnce({ PolicyRoles: [{ RoleName: 'role-a' }], IsTruncated: true, Marker: 'm2' } as any)
        .resolvesOnce({ PolicyRoles: [{ RoleName: 'role-b' }], IsTruncated: false } as any);
      iamMock.on(GetRoleCommand).resolves({
        Role: {
          RoleName: 'role-x',
          Arn: 'arn:aws:iam::123:role/role-x',
          AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify({
            Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: '*' } }],
          })),
        },
      } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(iamMock.commandCalls(ListEntitiesForPolicyCommand)).toHaveLength(2);
      const matches = findByCheckId(findings, 'bedrock_full_access_policy_attached');
      const roleNames = matches.map((f: any) => f.evidence.role).sort();
      expect(roleNames).toEqual(['role-a', 'role-b']);
    });
  });

  describe('no-resources / empty account', () => {
    it('emits only the region-level "no X configured" findings when the account has no Bedrock resources at all', async () => {
      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId).sort();
      expect(checkIds).toEqual([
        'bedrock_guardrails_configured',
        'bedrock_model_invocation_logging_enabled',
        'bedrock_prompt_management_exists',
      ]);
      expect(ec2Mock.commandCalls(DescribeVpcsCommand)).toHaveLength(0);
    });
  });

  describe('error handling', () => {
    it('does not throw and returns gracefully when ListGuardrails fails on every retry', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      bedrockMock.on(ListGuardrailsCommand).rejects(new Error('AccessDenied'));

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      // Prowler-parity behavior: a failed list means the region is NOT reported
      // as having zero guardrails (avoids false PASS).
      expect(findByCheckId(findings, 'bedrock_guardrails_configured')).toHaveLength(0);
      // Rest of the scan still completes and returns other region-level findings.
      expect(findByCheckId(findings, 'bedrock_model_invocation_logging_enabled')).toHaveLength(1);
      jest.useRealTimers();
    });

    it('does not throw when listing IAM users for API key checks fails entirely', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      iamMock.on(ListUsersCommand).rejects(new Error('ThrottlingException'));

      const scanner = new BedrockScanner(fakeAwsClient);
      await expect(scanner.scan()).resolves.toEqual(expect.any(Array));
      jest.useRealTimers();
    });

    it('continues scanning other users when one user errors out while listing service-specific credentials', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      iamMock.on(ListUsersCommand).resolves({
        Users: [{ UserName: 'broken-user' }, { UserName: 'fine-user' }],
      } as any);
      iamMock
        .on(ListServiceSpecificCredentialsCommand, { UserName: 'broken-user', ServiceName: 'bedrock.amazonaws.com' } as any)
        .rejects(new Error('AccessDenied'));
      iamMock
        .on(ListServiceSpecificCredentialsCommand, { UserName: 'fine-user', ServiceName: 'bedrock.amazonaws.com' } as any)
        .resolves({
          ServiceSpecificCredentials: [{
            ServiceSpecificCredentialId: 'cred-fine',
            ServiceName: 'bedrock.amazonaws.com',
            ExpirationDate: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
          }],
        } as any);
      iamMock.on(ListAttachedUserPoliciesCommand).resolves({ AttachedPolicies: [] } as any);
      iamMock.on(ListUserPoliciesCommand).resolves({ PolicyNames: [] } as any);

      const scanner = new BedrockScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'bedrock_api_key_no_long_term_credentials');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ user: 'fine-user', apiKeyId: 'cred-fine' });
      jest.useRealTimers();
    });
  });
});
