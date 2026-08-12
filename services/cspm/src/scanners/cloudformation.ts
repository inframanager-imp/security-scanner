// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  CloudFormationClient,
  DescribeStacksCommand,
} from '@aws-sdk/client-cloudformation';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const RECOMMENDED_CDK_BOOTSTRAP_VERSION = 21;

// Lightweight secret heuristics for stack output values (Prowler uses a full
// secret scanner; we match well-known credential formats and secret-like keys).
const SECRET_KEY_PATTERN = /(password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|credential)/i;
const SECRET_VALUE_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: 'AWS Access Key ID', pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
  { label: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
];

export class CloudFormationScanner extends BaseScanner {
  private cloudformation: CloudFormationClient;

  constructor(client: AWSClient) {
    super(client, 'CloudFormation');
    this.cloudformation = new CloudFormationClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting CloudFormation security scan...');

      const stacks = await this.describeAllStacks();
      for (const stack of stacks) {
        const stackName: string = stack.StackName ?? '';
        logger.debug(`Scanning CloudFormation stack: ${stackName}`);
        try {
          findings.push(...this.checkStackOutputSecrets(stack));
          findings.push(...this.checkCdkToolkitBootstrapVersion(stack));
          findings.push(...await this.checkTerminationProtection(stack));
        } catch (error) {
          logger.debug(`Failed to scan CloudFormation stack ${stackName}`, { error: (error as Error).message });
        }
      }

      logger.info(`CloudFormation scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('CloudFormation scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeAllStacks(): Promise<any[]> {
    const stacks: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.cloudformation.send(new DescribeStacksCommand({ NextToken: nextToken }));
      });
      stacks.push(...(result.Stacks ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return stacks;
  }

  // cloudformation_stack_outputs_find_secrets
  private checkStackOutputSecrets(stack: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const stackName: string = stack.StackName ?? '';
    const outputs: any[] = stack.Outputs ?? [];
    if (outputs.length === 0) return findings;

    const secretsFound: string[] = [];
    for (const output of outputs) {
      const key: string = output.OutputKey ?? '';
      const value: string = output.OutputValue ?? '';
      if (SECRET_KEY_PATTERN.test(key) && value) {
        secretsFound.push(`Secret Keyword in Output ${key}`);
        continue;
      }
      for (const { label, pattern } of SECRET_VALUE_PATTERNS) {
        if (pattern.test(value)) {
          secretsFound.push(`${label} in Output ${key}`);
          break;
        }
      }
    }

    if (secretsFound.length > 0) {
      findings.push(this.emit(
        'cloudformation_stack_outputs_find_secrets',
        { stack: stackName, stackId: stack.StackId, secretsFound },
        {
          message: `Potential secret found in CloudFormation stack "${stackName}" Outputs -> ${secretsFound.join(', ')}`,
          remediation: `Remove secrets from the Outputs of stack "${stackName}"; store them in Secrets Manager or SSM Parameter Store and rotate any exposed credentials`,
        }
      ));
    }
    return findings;
  }

  // cloudformation_stack_cdktoolkit_bootstrap_version
  private checkCdkToolkitBootstrapVersion(stack: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    if (stack.StackName !== 'CDKToolkit') return findings;

    let bootstrapVersion: number | undefined;
    for (const output of stack.Outputs ?? []) {
      if (output.OutputKey === 'BootstrapVersion') {
        const parsed = parseInt(output.OutputValue, 10);
        if (!isNaN(parsed)) bootstrapVersion = parsed;
        break;
      }
    }

    if (bootstrapVersion !== undefined && bootstrapVersion < RECOMMENDED_CDK_BOOTSTRAP_VERSION) {
      findings.push(this.emit(
        'cloudformation_stack_cdktoolkit_bootstrap_version',
        { stack: 'CDKToolkit', bootstrapVersion, recommendedVersion: RECOMMENDED_CDK_BOOTSTRAP_VERSION },
        {
          message: `CloudFormation stack CDKToolkit has a Bootstrap version ${bootstrapVersion}, which is less than the recommended version ${RECOMMENDED_CDK_BOOTSTRAP_VERSION}`,
          remediation: `Re-bootstrap the environment with a modern CDK version (cdk bootstrap) so BootstrapVersion is at least ${RECOMMENDED_CDK_BOOTSTRAP_VERSION}`,
        }
      ));
    }
    return findings;
  }

  // cloudformation_stacks_termination_protection_enabled
  private async checkTerminationProtection(stack: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const stackName: string = stack.StackName ?? '';

    // EnableTerminationProtection and RootId are only reliably returned when
    // describing the stack by name (mirrors Prowler's per-stack describe).
    let terminationProtection = false;
    let rootId = '';
    try {
      const detail = await retry(async () => {
        return await this.cloudformation.send(new DescribeStacksCommand({ StackName: stackName }));
      });
      const detailStack: any = detail.Stacks?.[0];
      if (!detailStack) return findings;
      terminationProtection = detailStack.EnableTerminationProtection === true;
      rootId = detailStack.RootId ?? '';
    } catch (error) {
      logger.debug(`Failed to describe CloudFormation stack ${stackName}`, { error: (error as Error).message });
      return findings;
    }

    // Nested stacks inherit protection from the root stack, skip them (as in Prowler)
    if (rootId) return findings;

    if (!terminationProtection) {
      findings.push(this.emit(
        'cloudformation_stacks_termination_protection_enabled',
        { stack: stackName, stackId: stack.StackId, enableTerminationProtection: false },
        {
          message: `CloudFormation stack "${stackName}" has termination protection disabled`,
          remediation: `Enable termination protection on stack "${stackName}" (aws cloudformation update-termination-protection --enable-termination-protection --stack-name ${stackName})`,
        }
      ));
    }
    return findings;
  }
}

export default CloudFormationScanner;
