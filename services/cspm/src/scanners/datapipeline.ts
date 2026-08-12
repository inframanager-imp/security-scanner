// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DataPipelineClient,
  ListPipelinesCommand,
  GetPipelineDefinitionCommand,
} from '@aws-sdk/client-data-pipeline';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Lightweight secret heuristics (Prowler uses a full secret scanner; we match
// secret-like field names and well-known credential formats in values).
const SECRET_KEYWORD_PATTERN =
  /(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|credential)/i;
const SECRET_VALUE_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: 'AWS Access Key ID', pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
  { label: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
  {
    label: 'Secret Assignment',
    pattern: /(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[=:]\s*['"]?[^\s'"]{6,}/i,
  },
];

// Data Pipeline expression values like "#{myDatabasePassword}" reference
// parameters or runtime fields and are not hardcoded secrets.
function isExpressionValue(value: string): boolean {
  return /^#\{[^}]*\}$/.test(value.trim());
}

export class DataPipelineScanner extends BaseScanner {
  private datapipeline: DataPipelineClient;

  constructor(client: AWSClient) {
    super(client, 'DataPipeline');
    this.datapipeline = new DataPipelineClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting DataPipeline security scan...');

      const pipelines = await this.listPipelines();
      logger.info(`DataPipeline: scanning ${pipelines.length} pipeline(s)`);

      for (const pipeline of pipelines) {
        const pipelineId: string = pipeline.id ?? '';
        if (!pipelineId) continue;
        try {
          findings.push(...await this.checkPipelineDefinitionSecrets(pipeline));
        } catch (error) {
          logger.debug(`Failed to scan Data Pipeline ${pipelineId}`, { error: (error as Error).message });
        }
      }

      logger.info(`DataPipeline scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('DataPipeline scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listPipelines(): Promise<any[]> {
    const pipelines: any[] = [];
    let marker: string | undefined;
    let hasMoreResults = true;
    while (hasMoreResults) {
      const result: any = await retry(async () => {
        return await this.datapipeline.send(new ListPipelinesCommand({ marker }));
      });
      pipelines.push(...(result.pipelineIdList ?? []));
      marker = result.marker;
      hasMoreResults = Boolean(result.hasMoreResults) && Boolean(marker);
    }
    return pipelines;
  }

  // datapipeline_pipeline_no_secrets_in_definition: no hardcoded secrets in the
  // pipeline objects, parameter objects or parameter values of the definition.
  private async checkPipelineDefinitionSecrets(pipeline: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const pipelineId: string = pipeline.id;
    const pipelineName: string = pipeline.name ?? pipelineId;

    const definition: any = await retry(async () => {
      return await this.datapipeline.send(new GetPipelineDefinitionCommand({ pipelineId }));
    });

    const secretsFound: string[] = [];

    for (const pipelineObject of definition.pipelineObjects ?? []) {
      const objectName: string = pipelineObject.name ?? pipelineObject.id ?? 'unknown';
      for (const field of pipelineObject.fields ?? []) {
        const fieldKey: string = field.key ?? '';
        // refValue points at another pipeline object; only its text is scanned,
        // it is never treated as a literal secret value for the key heuristic.
        const isReference = field.stringValue === undefined && field.refValue !== undefined;
        secretsFound.push(...this.findSecretsInDefinitionEntry(
          `object ${objectName} field ${fieldKey}`,
          fieldKey,
          field.stringValue ?? field.refValue,
          isReference
        ));
      }
    }

    for (const parameterObject of definition.parameterObjects ?? []) {
      const parameterName: string = parameterObject.id ?? 'unknown';
      for (const attribute of parameterObject.attributes ?? []) {
        const attributeKey: string = attribute.key ?? '';
        secretsFound.push(...this.findSecretsInDefinitionEntry(
          `parameter object ${parameterName} attribute ${attributeKey}`,
          attributeKey,
          attribute.stringValue,
          false
        ));
      }
    }

    for (const parameterValue of definition.parameterValues ?? []) {
      const parameterId: string = parameterValue.id ?? 'unknown';
      secretsFound.push(...this.findSecretsInDefinitionEntry(
        `parameter value ${parameterId}`,
        parameterId,
        parameterValue.stringValue,
        false
      ));
    }

    const uniqueSecrets = [...new Set(secretsFound)];
    if (uniqueSecrets.length > 0) {
      findings.push(this.emit(
        'datapipeline_pipeline_no_secrets_in_definition',
        { pipeline: pipelineName, pipelineId, secretsFound: uniqueSecrets },
        {
          message: `Potential ${uniqueSecrets.length > 1 ? 'secrets' : 'secret'} found in Data Pipeline "${pipelineName}" definition -> ${uniqueSecrets.join(', ')}`,
          remediation: `Remove hardcoded credentials from the definition of Data Pipeline "${pipelineName}"; store them in AWS Secrets Manager or SSM Parameter Store, retrieve them at runtime and rotate any exposed credentials`,
        }
      ));
    }

    return findings;
  }

  private findSecretsInDefinitionEntry(
    context: string,
    key: string,
    value: string | undefined,
    isReference: boolean
  ): string[] {
    const hits: string[] = [];
    if (!value) return hits;

    if (!isReference && !isExpressionValue(value) && value.length >= 6 && SECRET_KEYWORD_PATTERN.test(key)) {
      hits.push(`Secret Keyword in ${context}`);
    }
    for (const { label, pattern } of SECRET_VALUE_PATTERNS) {
      if (pattern.test(value)) hits.push(`${label} in ${context}`);
    }
    return hits;
  }
}

export default DataPipelineScanner;
