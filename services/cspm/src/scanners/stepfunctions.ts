// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  SFNClient,
  ListStateMachinesCommand,
  DescribeStateMachineCommand,
} from '@aws-sdk/client-sfn';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Value-based patterns approximating Prowler's detect-secrets engine for ASL definitions
const AWS_ACCESS_KEY_ID_PATTERN = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/;
// "SomethingPassword": "literalvalue" style JSON pairs with a sensitive key name
const SENSITIVE_JSON_PAIR_PATTERN =
  /"([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|credential|private[_-]?key|access[_-]?key|secret[_-]?key)[A-Za-z0-9_.\-]*)"\s*:\s*"([^"]+)"/gi;

// Dynamic/indirect values in Amazon States Language are not hardcoded secrets:
// JsonPath references ($...), intrinsic functions (States.*), JSONata ({% %}), ARNs, substitutions
function isDynamicOrSafeValue(value: string): boolean {
  return (
    value.startsWith('$') ||
    value.startsWith('arn:') ||
    value.startsWith('{%') ||
    value.startsWith('${') ||
    value.startsWith('States.') ||
    value.length < 8
  );
}

export class StepFunctionsScanner extends BaseScanner {
  private sfn: SFNClient;

  constructor(client: AWSClient) {
    super(client, 'StepFunctions');
    this.sfn = new SFNClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting StepFunctions security scan...');

      const stateMachines = await this.listStateMachines();
      for (const stateMachine of stateMachines) {
        const name: string = stateMachine.name ?? 'unknown';
        logger.debug(`Scanning Step Functions state machine: ${name}`);
        try {
          findings.push(...await this.validateStateMachine(stateMachine));
        } catch (error) {
          logger.debug(`Failed to scan Step Functions state machine ${name}`, { error: (error as Error).message });
        }
      }

      logger.info(`StepFunctions scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('StepFunctions scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listStateMachines(): Promise<any[]> {
    const stateMachines: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.sfn.send(new ListStateMachinesCommand({ nextToken }));
      });
      stateMachines.push(...(result.stateMachines ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return stateMachines;
  }

  private async validateStateMachine(stateMachine: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const arn: string = stateMachine.stateMachineArn ?? '';
    if (!arn) return findings;
    const name: string = stateMachine.name ?? arn.split(':').pop() ?? 'unknown';

    const described = await retry(async () => {
      return await this.sfn.send(new DescribeStateMachineCommand({ stateMachineArn: arn }));
    });

    // stepfunctions_statemachine_logging_enabled: loggingConfiguration level must be above OFF
    const loggingConfiguration: any = described.loggingConfiguration;
    if (!loggingConfiguration || loggingConfiguration.level === 'OFF' || !loggingConfiguration.level) {
      findings.push(this.emit(
        'stepfunctions_statemachine_logging_enabled',
        { stateMachine: name, arn, loggingLevel: loggingConfiguration?.level ?? null },
        {
          message: `Step Functions state machine "${name}" does not have logging enabled`,
          remediation: `Configure logging on state machine "${name}" with level ALL or ERROR and a CloudWatch Logs destination`,
        }
      ));
    }

    // stepfunctions_statemachine_encrypted_with_cmk: encryption type must be CUSTOMER_MANAGED_KMS_KEY
    const encryptionConfiguration: any = described.encryptionConfiguration;
    if (!encryptionConfiguration || encryptionConfiguration.type !== 'CUSTOMER_MANAGED_KMS_KEY') {
      findings.push(this.emit(
        'stepfunctions_statemachine_encrypted_with_cmk',
        {
          stateMachine: name,
          arn,
          encryptionType: encryptionConfiguration?.type ?? null,
          kmsKeyId: encryptionConfiguration?.kmsKeyId ?? null,
        },
        {
          message: `Step Functions state machine "${name}" is not encrypted at rest with a customer-managed KMS key`,
          remediation: `Configure state machine "${name}" to use a customer-managed KMS key for encryption at rest`,
        }
      ));
    }

    // stepfunctions_statemachine_no_secrets_in_definition: no hardcoded secrets in the ASL definition
    const definition: string = described.definition ?? '';
    if (definition) {
      const secretHits: string[] = [];

      if (AWS_ACCESS_KEY_ID_PATTERN.test(definition)) {
        secretHits.push('AWS access key ID');
      }

      SENSITIVE_JSON_PAIR_PATTERN.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = SENSITIVE_JSON_PAIR_PATTERN.exec(definition)) !== null) {
        const keyName = match[1];
        const value = match[2];
        // ASL dynamic-value convention: keys ending with ".$" take JsonPath values
        if (keyName.endsWith('.$')) continue;
        if (isDynamicOrSafeValue(value)) continue;
        secretHits.push(`sensitive key "${keyName}" with a literal value`);
      }

      if (secretHits.length > 0) {
        findings.push(this.emit(
          'stepfunctions_statemachine_no_secrets_in_definition',
          { stateMachine: name, arn, secretHits },
          {
            message: `Potential ${secretHits.length > 1 ? 'secrets' : 'secret'} found in Step Functions state machine "${name}" definition -> ${secretHits.join(', ')}`,
            remediation: `Remove hardcoded credentials from the definition of state machine "${name}"; store them in AWS Secrets Manager or SSM Parameter Store and resolve them at runtime`,
          }
        ));
      }
    }

    return findings;
  }
}

export default StepFunctionsScanner;
