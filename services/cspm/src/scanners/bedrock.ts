// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  BedrockClient,
  GetModelInvocationLoggingConfigurationCommand,
  ListGuardrailsCommand,
  GetGuardrailCommand,
} from '@aws-sdk/client-bedrock';
import {
  BedrockAgentClient,
  ListAgentsCommand,
  ListPromptsCommand,
  GetPromptCommand,
} from '@aws-sdk/client-bedrock-agent';
import {
  IAMClient,
  ListUsersCommand,
  ListServiceSpecificCredentialsCommand,
  ListAttachedUserPoliciesCommand,
  ListUserPoliciesCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  GetUserPolicyCommand,
  ListEntitiesForPolicyCommand,
  GetRoleCommand,
} from '@aws-sdk/client-iam';
import { S3Client, GetBucketEncryptionCommand } from '@aws-sdk/client-s3';
import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
} from '@aws-sdk/client-cloudwatch-logs';
import {
  EC2Client,
  DescribeVpcsCommand,
  DescribeVpcEndpointsCommand,
  DescribeNetworkInterfacesCommand,
} from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const BEDROCK_SERVICE_PRINCIPAL = 'bedrock.amazonaws.com';
const BEDROCK_FULL_ACCESS_POLICY_ARN = 'arn:aws:iam::aws:policy/AmazonBedrockFullAccess';
const ADMINISTRATOR_ACCESS_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess';
// Days above which a long-term Bedrock API key is considered effectively non-expiring (Prowler threshold).
const NEVER_EXPIRES_THRESHOLD_DAYS = 10000;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

const BEDROCK_ENDPOINT_SERVICES: Record<string, string> = {
  'bedrock': 'Bedrock control plane',
  'bedrock-runtime': 'Bedrock runtime',
  'bedrock-agent': 'Bedrock agent control plane',
  'bedrock-agent-runtime': 'Bedrock agent runtime',
  'bedrock-mantle': 'Bedrock Mantle (OpenAI-compatible API)',
};

export class BedrockScanner extends BaseScanner {
  private bedrock: BedrockClient;
  private bedrockAgent: BedrockAgentClient;
  private iam: IAMClient;
  private s3: S3Client;
  private logs: CloudWatchLogsClient;
  private ec2: EC2Client;
  private region: string;

  constructor(client: AWSClient) {
    super(client, 'Bedrock');
    const config = client.getClientConfig();
    this.bedrock = new BedrockClient(config);
    this.bedrockAgent = new BedrockAgentClient(config);
    this.iam = new IAMClient(config);
    this.s3 = new S3Client(config);
    this.logs = new CloudWatchLogsClient(config);
    this.ec2 = new EC2Client(config);
    this.region = config.region;
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Bedrock security scan...');

      const loggingEnabled = await this.checkModelInvocationLogging(findings);
      const guardrailCount = await this.checkGuardrails(findings);
      const agentCount = await this.checkAgents(findings);
      await this.checkPrompts(findings);

      // bedrock_vpc_endpoints_configured only applies to regions with Bedrock activity
      const bedrockActive = loggingEnabled || guardrailCount > 0 || agentCount > 0;
      if (bedrockActive) {
        await this.checkVpcEndpoints(findings);
      }

      await this.checkBedrockApiKeys(findings);
      await this.checkFullAccessPolicyRoles(findings);

      logger.info(`Bedrock scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Bedrock scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  // bedrock_model_invocation_logging_enabled / bedrock_model_invocation_logs_encryption_enabled
  private async checkModelInvocationLogging(findings: ScanningResult[]): Promise<boolean> {
    let loggingEnabled = false;
    try {
      const result: any = await retry(async () => {
        return await this.bedrock.send(new GetModelInvocationLoggingConfigurationCommand({}));
      });
      const loggingConfig: any = result?.loggingConfig;

      if (!loggingConfig) {
        findings.push(this.emit(
          'bedrock_model_invocation_logging_enabled',
          { region: this.region, loggingEnabled: false },
          {
            message: `Bedrock model invocation logging is disabled in region ${this.region}`,
          }
        ));
        return false;
      }

      loggingEnabled = true;
      const s3Bucket: string | undefined = loggingConfig.s3Config?.bucketName;
      const cloudwatchLogGroup: string | undefined = loggingConfig.cloudWatchConfig?.logGroupName;

      const s3Encrypted = await this.isLogBucketEncrypted(s3Bucket);
      const cloudwatchEncrypted = await this.isLogGroupKmsEncrypted(cloudwatchLogGroup);

      if (!s3Encrypted || !cloudwatchEncrypted) {
        const unencrypted: string[] = [];
        if (!s3Encrypted) unencrypted.push(`S3 bucket "${s3Bucket}"`);
        if (!cloudwatchEncrypted) unencrypted.push(`CloudWatch Log Group "${cloudwatchLogGroup}"`);
        findings.push(this.emit(
          'bedrock_model_invocation_logs_encryption_enabled',
          {
            region: this.region,
            s3Bucket: s3Bucket ?? null,
            s3Encrypted,
            cloudwatchLogGroup: cloudwatchLogGroup ?? null,
            cloudwatchEncrypted,
          },
          {
            message: `Bedrock model invocation logs are not encrypted in ${unencrypted.join(' and ')}`,
          }
        ));
      }
    } catch (error) {
      logger.debug('Failed to check Bedrock model invocation logging', { error: (error as Error).message });
    }
    return loggingEnabled;
  }

  private async isLogBucketEncrypted(bucketName?: string): Promise<boolean> {
    if (!bucketName) return true;
    try {
      const result: any = await retry(async () => {
        return await this.s3.send(new GetBucketEncryptionCommand({ Bucket: bucketName }));
      });
      const rules: any[] = result?.ServerSideEncryptionConfiguration?.Rules ?? [];
      return rules.length > 0;
    } catch (error) {
      const err = error as any;
      if (err?.name === 'ServerSideEncryptionConfigurationNotFoundError') {
        return false;
      }
      // Bucket not accessible (cross-account, denied, etc.) — give benefit of the doubt like Prowler
      // does when the bucket is outside its collected inventory.
      logger.debug(`Unable to determine encryption of Bedrock log bucket ${bucketName}`, { error: err?.message });
      return true;
    }
  }

  private async isLogGroupKmsEncrypted(logGroupName?: string): Promise<boolean> {
    if (!logGroupName) return true;
    try {
      const result: any = await retry(async () => {
        return await this.logs.send(new DescribeLogGroupsCommand({ logGroupNamePrefix: logGroupName }));
      });
      const logGroups: any[] = result?.logGroups ?? [];
      const logGroup = logGroups.find((lg: any) => lg?.logGroupName === logGroupName);
      if (!logGroup) return true;
      return Boolean(logGroup.kmsKeyId);
    } catch (error) {
      logger.debug(`Unable to determine encryption of Bedrock log group ${logGroupName}`, { error: (error as Error).message });
      return true;
    }
  }

  // bedrock_guardrails_configured / bedrock_guardrail_prompt_attack_filter_enabled /
  // bedrock_guardrail_sensitive_information_filter_enabled
  private async checkGuardrails(findings: ScanningResult[]): Promise<number> {
    let guardrails: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.bedrock.send(new ListGuardrailsCommand({ nextToken }));
        });
        guardrails.push(...(result?.guardrails ?? []));
        nextToken = result?.nextToken;
      } while (nextToken);
    } catch (error) {
      // Mirrors Prowler's guardrails_scanned_regions: if listing failed, do not
      // report the region as having no guardrails.
      logger.debug('Failed to list Bedrock guardrails', { error: (error as Error).message });
      return 0;
    }

    if (guardrails.length === 0) {
      findings.push(this.emit(
        'bedrock_guardrails_configured',
        { region: this.region, guardrailCount: 0 },
        {
          message: `Bedrock has no guardrails configured in region ${this.region}`,
        }
      ));
      return 0;
    }

    for (const guardrail of guardrails) {
      const guardrailId: string = guardrail?.id ?? '';
      const guardrailName: string = guardrail?.name ?? guardrailId;
      try {
        const detail: any = await retry(async () => {
          return await this.bedrock.send(new GetGuardrailCommand({ guardrailIdentifier: guardrailId }));
        });

        // Sensitive information filter must be present
        const hasSensitiveInformationFilter = detail?.sensitiveInformationPolicy !== undefined
          && detail?.sensitiveInformationPolicy !== null;
        if (!hasSensitiveInformationFilter) {
          findings.push(this.emit(
            'bedrock_guardrail_sensitive_information_filter_enabled',
            { guardrail: guardrailName, guardrailId, arn: guardrail?.arn, sensitiveInformationFilter: false },
            {
              message: `Bedrock guardrail "${guardrailName}" is not configured to block or mask sensitive information`,
            }
          ));
        }

        // Prompt attack filter must exist with HIGH input strength
        const contentFilters: any[] = detail?.contentPolicy?.filters ?? [];
        const promptAttackFilter = contentFilters.find((f: any) => f?.type === 'PROMPT_ATTACK');
        const promptAttackStrength: string | undefined = promptAttackFilter?.inputStrength;
        if (!promptAttackStrength || promptAttackStrength === 'NONE') {
          findings.push(this.emit(
            'bedrock_guardrail_prompt_attack_filter_enabled',
            { guardrail: guardrailName, guardrailId, arn: guardrail?.arn, promptAttackFilterStrength: promptAttackStrength ?? null },
            {
              message: `Bedrock guardrail "${guardrailName}" is not configured to block prompt attacks`,
            }
          ));
        } else if (promptAttackStrength !== 'HIGH') {
          findings.push(this.emit(
            'bedrock_guardrail_prompt_attack_filter_enabled',
            { guardrail: guardrailName, guardrailId, arn: guardrail?.arn, promptAttackFilterStrength: promptAttackStrength },
            {
              message: `Bedrock guardrail "${guardrailName}" blocks prompt attacks with filter strength ${promptAttackStrength}, not HIGH`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to scan Bedrock guardrail ${guardrailName}`, { error: (error as Error).message });
      }
    }

    return guardrails.length;
  }

  // bedrock_agent_guardrail_enabled
  private async checkAgents(findings: ScanningResult[]): Promise<number> {
    let agents: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.bedrockAgent.send(new ListAgentsCommand({ nextToken }));
        });
        agents.push(...(result?.agentSummaries ?? []));
        nextToken = result?.nextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list Bedrock agents', { error: (error as Error).message });
      return 0;
    }

    for (const agent of agents) {
      const agentName: string = agent?.agentName ?? agent?.agentId ?? '';
      const guardrailId: string | undefined = agent?.guardrailConfiguration?.guardrailIdentifier;
      if (!guardrailId) {
        findings.push(this.emit(
          'bedrock_agent_guardrail_enabled',
          { agent: agentName, agentId: agent?.agentId, guardrail: null },
          {
            message: `Bedrock agent "${agentName}" is not using any guardrail to protect agent sessions`,
          }
        ));
      }
    }

    return agents.length;
  }

  // bedrock_prompt_encrypted_with_cmk
  private async checkPrompts(findings: ScanningResult[]): Promise<void> {
    let prompts: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.bedrockAgent.send(new ListPromptsCommand({ nextToken }));
        });
        prompts.push(...(result?.promptSummaries ?? []));
        nextToken = result?.nextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list Bedrock prompts', { error: (error as Error).message });
      return;
    }

    for (const prompt of prompts) {
      const promptName: string = prompt?.name ?? prompt?.id ?? '';
      try {
        const detail: any = await retry(async () => {
          return await this.bedrockAgent.send(new GetPromptCommand({ promptIdentifier: prompt?.id }));
        });
        if (!detail?.customerEncryptionKeyArn) {
          findings.push(this.emit(
            'bedrock_prompt_encrypted_with_cmk',
            { prompt: promptName, promptId: prompt?.id, arn: prompt?.arn, customerEncryptionKeyArn: null },
            {
              message: `Bedrock prompt "${promptName}" is not encrypted with a customer-managed KMS key`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to scan Bedrock prompt ${promptName}`, { error: (error as Error).message });
      }
    }
  }

  // bedrock_vpc_endpoints_configured
  private async checkVpcEndpoints(findings: ScanningResult[]): Promise<void> {
    try {
      const vpcs: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.ec2.send(new DescribeVpcsCommand({ NextToken: nextToken }));
        });
        vpcs.push(...(result?.Vpcs ?? []));
        nextToken = result?.NextToken;
      } while (nextToken);
      if (vpcs.length === 0) return;

      const endpoints: any[] = [];
      nextToken = undefined;
      do {
        const result: any = await retry(async () => {
          return await this.ec2.send(new DescribeVpcEndpointsCommand({ NextToken: nextToken }));
        });
        endpoints.push(...(result?.VpcEndpoints ?? []));
        nextToken = result?.NextToken;
      } while (nextToken);

      // A VPC is "in use" when it has network interfaces (mirrors Prowler's vpc.in_use)
      const inUseVpcIds = new Set<string>();
      nextToken = undefined;
      do {
        const result: any = await retry(async () => {
          return await this.ec2.send(new DescribeNetworkInterfacesCommand({ NextToken: nextToken }));
        });
        for (const eni of result?.NetworkInterfaces ?? []) {
          if (eni?.VpcId) inUseVpcIds.add(eni.VpcId);
        }
        nextToken = result?.NextToken;
      } while (nextToken);

      const serviceSuffixes = Object.keys(BEDROCK_ENDPOINT_SERVICES);
      for (const vpc of vpcs) {
        const vpcId: string = vpc?.VpcId ?? '';
        if (!vpcId || !inUseVpcIds.has(vpcId)) continue;

        const foundServices = new Set<string>();
        for (const endpoint of endpoints) {
          if (endpoint?.VpcId !== vpcId) continue;
          if (String(endpoint?.State ?? '').toLowerCase() !== 'available') continue;
          const serviceName = String(endpoint?.ServiceName ?? '');
          for (const suffix of serviceSuffixes) {
            if (serviceName.endsWith(`.${suffix}`)) foundServices.add(suffix);
          }
        }

        const missing = serviceSuffixes.filter((s) => !foundServices.has(s));
        if (missing.length > 0) {
          const missingLabels = missing.map((s) => BEDROCK_ENDPOINT_SERVICES[s]);
          findings.push(this.emit(
            'bedrock_vpc_endpoints_configured',
            { vpcId, region: this.region, missingEndpointServices: missing },
            {
              message: `VPC ${vpcId} does not have VPC endpoints for the following Bedrock services: ${missingLabels.join(', ')}`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Failed to check Bedrock VPC endpoints', { error: (error as Error).message });
    }
  }

  // bedrock_api_key_no_long_term_credentials / bedrock_api_key_no_administrative_privileges
  private async checkBedrockApiKeys(findings: ScanningResult[]): Promise<void> {
    try {
      const users: any[] = [];
      let marker: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.iam.send(new ListUsersCommand({ Marker: marker }));
        });
        users.push(...(result?.Users ?? []));
        marker = result?.IsTruncated ? result?.Marker : undefined;
      } while (marker);

      for (const user of users) {
        const userName: string = user?.UserName ?? '';
        try {
          const result: any = await retry(async () => {
            return await this.iam.send(new ListServiceSpecificCredentialsCommand({
              UserName: userName,
              ServiceName: BEDROCK_SERVICE_PRINCIPAL,
            } as any));
          });
          const credentials: any[] = (result?.ServiceSpecificCredentials ?? [])
            .filter((c: any) => c?.ServiceName === BEDROCK_SERVICE_PRINCIPAL);
          if (credentials.length === 0) continue;

          // bedrock_api_key_no_long_term_credentials
          const now = Date.now();
          for (const credential of credentials) {
            const credentialId: string = credential?.ServiceSpecificCredentialId ?? '';
            const expiration: any = credential?.ExpirationDate;
            const expirationMs = expiration ? new Date(expiration).getTime() : NaN;
            if (!expiration || isNaN(expirationMs)) continue; // mirrors Prowler: skip keys without expiration data
            if (expirationMs <= now) continue; // expired keys can no longer authenticate (PASS)

            const daysUntilExpiration = Math.floor((expirationMs - now) / MS_PER_DAY);
            if (daysUntilExpiration > NEVER_EXPIRES_THRESHOLD_DAYS) {
              findings.push(this.emit(
                'bedrock_api_key_no_long_term_credentials',
                { user: userName, apiKeyId: credentialId, expirationDate: expiration, neverExpires: true },
                {
                  message: `Bedrock long-term API key ${credentialId} of user "${userName}" is configured to never expire; use short-term Bedrock API keys (valid up to 12 hours) instead`,
                  severity: 'CRITICAL',
                }
              ));
            } else {
              findings.push(this.emit(
                'bedrock_api_key_no_long_term_credentials',
                { user: userName, apiKeyId: credentialId, expirationDate: expiration, daysUntilExpiration },
                {
                  message: `Bedrock long-term API key ${credentialId} of user "${userName}" is active and will expire in ${daysUntilExpiration} days; use short-term Bedrock API keys (valid up to 12 hours) instead`,
                }
              ));
            }
          }

          // bedrock_api_key_no_administrative_privileges (evaluated once per user, reported per key)
          const violation = await this.findUserPrivilegeViolation(userName, user?.Arn ?? '');
          if (violation) {
            for (const credential of credentials) {
              const credentialId: string = credential?.ServiceSpecificCredentialId ?? '';
              findings.push(this.emit(
                'bedrock_api_key_no_administrative_privileges',
                { user: userName, apiKeyId: credentialId, violation },
                {
                  message: `Bedrock API key ${credentialId} of user "${userName}" has ${violation}`,
                }
              ));
            }
          }
        } catch (error) {
          logger.debug(`Failed to scan Bedrock API keys for user ${userName}`, { error: (error as Error).message });
        }
      }
    } catch (error) {
      logger.debug('Failed to list IAM users for Bedrock API key checks', { error: (error as Error).message });
    }
  }

  /**
   * Returns a description of the first excessive-privilege grant found on the
   * user's attached or inline policies, or null when none is found.
   * Ported from Prowler's check_admin_access / check_full_service_access
   * (simplified: wildcard-based detection, no action expansion or privilege
   * escalation combination tables).
   */
  private async findUserPrivilegeViolation(userName: string, userArn: string): Promise<string | null> {
    // Attached managed policies
    let marker: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.iam.send(new ListAttachedUserPoliciesCommand({ UserName: userName, Marker: marker }));
      });
      for (const attached of result?.AttachedPolicies ?? []) {
        const policyArn: string = attached?.PolicyArn ?? '';
        const policyName: string = attached?.PolicyName ?? policyArn;
        if (policyArn === ADMINISTRATOR_ACCESS_POLICY_ARN) {
          return `administrative privileges through attached policy ${policyName}`;
        }
        if (policyArn === BEDROCK_FULL_ACCESS_POLICY_ARN) {
          return `full Bedrock service access through attached policy ${policyName}`;
        }
        try {
          const policy: any = await retry(async () => {
            return await this.iam.send(new GetPolicyCommand({ PolicyArn: policyArn }));
          });
          const versionId: string | undefined = policy?.Policy?.DefaultVersionId;
          if (!versionId) continue;
          const version: any = await retry(async () => {
            return await this.iam.send(new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: versionId }));
          });
          const document = this.parsePolicyDocument(version?.PolicyVersion?.Document);
          if (!document) continue;
          if (this.policyGrantsAdminAccess(document)) {
            return `administrative privileges through attached policy ${policyName}`;
          }
          if (this.policyGrantsFullBedrockAccess(document)) {
            return `full Bedrock service access through attached policy ${policyName}`;
          }
        } catch (error) {
          logger.debug(`Failed to evaluate attached policy ${policyArn} for user ${userName}`, { error: (error as Error).message });
        }
      }
      marker = result?.IsTruncated ? result?.Marker : undefined;
    } while (marker);

    // Inline policies
    marker = undefined;
    do {
      const result: any = await retry(async () => {
        return await this.iam.send(new ListUserPoliciesCommand({ UserName: userName, Marker: marker }));
      });
      for (const inlineName of result?.PolicyNames ?? []) {
        try {
          const inline: any = await retry(async () => {
            return await this.iam.send(new GetUserPolicyCommand({ UserName: userName, PolicyName: inlineName }));
          });
          const document = this.parsePolicyDocument(inline?.PolicyDocument);
          if (!document) continue;
          if (this.policyGrantsAdminAccess(document)) {
            return `administrative privileges through inline policy ${inlineName}`;
          }
          if (this.policyGrantsFullBedrockAccess(document)) {
            return `full Bedrock service access through inline policy ${inlineName}`;
          }
        } catch (error) {
          logger.debug(`Failed to evaluate inline policy ${inlineName} for user ${userName}`, { error: (error as Error).message });
        }
      }
      marker = result?.IsTruncated ? result?.Marker : undefined;
    } while (marker);

    return null;
  }

  // bedrock_full_access_policy_attached
  private async checkFullAccessPolicyRoles(findings: ScanningResult[]): Promise<void> {
    try {
      const roleNames: string[] = [];
      let marker: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.iam.send(new ListEntitiesForPolicyCommand({
            PolicyArn: BEDROCK_FULL_ACCESS_POLICY_ARN,
            EntityFilter: 'Role',
            Marker: marker,
          }));
        });
        for (const policyRole of result?.PolicyRoles ?? []) {
          if (policyRole?.RoleName) roleNames.push(policyRole.RoleName);
        }
        marker = result?.IsTruncated ? result?.Marker : undefined;
      } while (marker);

      for (const roleName of roleNames) {
        try {
          const result: any = await retry(async () => {
            return await this.iam.send(new GetRoleCommand({ RoleName: roleName }));
          });
          const role: any = result?.Role;
          // Prowler excludes service roles (assumable only by AWS service principals)
          if (role && this.isServiceRole(role)) continue;
          findings.push(this.emit(
            'bedrock_full_access_policy_attached',
            { role: roleName, roleArn: role?.Arn, policyArn: BEDROCK_FULL_ACCESS_POLICY_ARN },
            {
              message: `IAM role "${roleName}" has the AmazonBedrockFullAccess managed policy attached`,
            }
          ));
        } catch (error) {
          logger.debug(`Failed to evaluate role ${roleName} for AmazonBedrockFullAccess`, { error: (error as Error).message });
        }
      }
    } catch (error) {
      logger.debug('Failed to list roles with AmazonBedrockFullAccess attached', { error: (error as Error).message });
    }
  }

  private parsePolicyDocument(document?: string): any {
    if (!document) return null;
    try {
      return JSON.parse(decodeURIComponent(document));
    } catch {
      try {
        return JSON.parse(document);
      } catch {
        return null;
      }
    }
  }

  private asArray(value: any): any[] {
    if (value === undefined || value === null) return [];
    return Array.isArray(value) ? value : [value];
  }

  /** Statement grants admin when Effect=Allow with Action "*" (or a NotAction carve-out) on Resource "*". */
  private policyGrantsAdminAccess(document: any): boolean {
    for (const statement of this.asArray(document?.Statement)) {
      if (statement?.Effect !== 'Allow') continue;
      const resources = this.asArray(statement?.Resource).map(String);
      if (!resources.includes('*')) continue;
      const actions = this.asArray(statement?.Action).map(String);
      if (actions.includes('*') || actions.includes('*:*') || statement?.NotAction !== undefined) {
        return true;
      }
    }
    return false;
  }

  /** Statement grants full Bedrock access when Effect=Allow with Action "bedrock:*" (or "*") on Resource "*". */
  private policyGrantsFullBedrockAccess(document: any): boolean {
    for (const statement of this.asArray(document?.Statement)) {
      if (statement?.Effect !== 'Allow') continue;
      const resources = this.asArray(statement?.Resource).map(String);
      if (!resources.includes('*')) continue;
      const actions = this.asArray(statement?.Action).map((a: any) => String(a).toLowerCase());
      if (actions.includes('*') || actions.includes('bedrock:*')) {
        return true;
      }
    }
    return false;
  }

  /** A role is a service role when every assume-role statement allows only AWS service principals (mirrors Prowler's is_service_role). */
  private isServiceRole(role: any): boolean {
    const document = this.parsePolicyDocument(role?.AssumeRolePolicyDocument);
    const statements = this.asArray(document?.Statement);
    if (statements.length === 0) return false;
    for (const statement of statements) {
      if (statement?.Effect !== 'Allow') return false;
      const actions = this.asArray(statement?.Action).map(String);
      if (!actions.some((a) => a === 'sts:AssumeRole' || a === 'sts:*' || a === '*')) return false;
      const principal = statement?.Principal ?? {};
      const principalKeys = Object.keys(principal);
      if (principalKeys.length !== 1 || principalKeys[0] !== 'Service') return false;
    }
    return true;
  }
}

export default BedrockScanner;
