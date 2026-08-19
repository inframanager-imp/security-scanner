// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  SageMakerClient,
  ListNotebookInstancesCommand,
  DescribeNotebookInstanceCommand,
  DescribeNotebookInstanceLifecycleConfigCommand,
  ListModelsCommand,
  DescribeModelCommand,
  ListTrainingJobsCommand,
  DescribeTrainingJobCommand,
  ListDomainsCommand,
  DescribeDomainCommand,
  ListEndpointConfigsCommand,
  DescribeEndpointConfigCommand,
} from '@aws-sdk/client-sagemaker';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/**
 * Lightweight secret detection for lifecycle scripts. Prowler uses the
 * detect-secrets library; this is a conservative regex port covering the most
 * common credential patterns.
 */
const SECRET_PATTERNS: { type: string; regex: RegExp }[] = [
  { type: 'AWS Access Key ID', regex: /\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/ },
  { type: 'AWS Secret Access Key', regex: /aws_?secret_?access_?key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}\b/i },
  { type: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY/ },
  { type: 'Hardcoded Password', regex: /\b(password|passwd|pwd)\b\s*[=:]\s*['"][^'"]{4,}['"]/i },
  { type: 'Hardcoded Secret or Token', regex: /\b(secret|token|api[_-]?key|auth[_-]?key|access[_-]?token)\b\s*[=:]\s*['"][^'"]{8,}['"]/i },
  { type: 'Credentials in URL', regex: /[a-z][a-z0-9+.-]*:\/\/[^/\s:@'"]+:[^/\s:@'"]+@[^\s'"]+/i },
];

export class SageMakerScanner extends BaseScanner {
  private sagemaker: SageMakerClient;

  constructor(client: AWSClient) {
    super(client, 'SageMaker');
    this.sagemaker = new SageMakerClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting SageMaker security scan...');

      await this.checkNotebookInstances(findings);
      await this.checkModels(findings);
      await this.checkTrainingJobs(findings);
      await this.checkDomains(findings);
      await this.checkEndpointConfigs(findings);

      logger.info(`SageMaker scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('SageMaker scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  // sagemaker_notebook_instance_encryption_enabled / _root_access_disabled /
  // _vpc_settings_configured / _without_direct_internet_access_configured / _no_secrets
  private async checkNotebookInstances(findings: ScanningResult[]): Promise<void> {
    let notebookInstances: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.sagemaker.send(new ListNotebookInstancesCommand({ NextToken: nextToken, MaxResults: 100 }));
        });
        notebookInstances.push(...(result?.NotebookInstances ?? []));
        nextToken = result?.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list SageMaker notebook instances', { error: (error as Error).message });
      return;
    }

    for (const instance of notebookInstances) {
      const name: string = instance?.NotebookInstanceName ?? '';
      const arn: string = instance?.NotebookInstanceArn ?? '';
      try {
        const detail: any = await retry(async () => {
          return await this.sagemaker.send(new DescribeNotebookInstanceCommand({ NotebookInstanceName: name }));
        });

        // sagemaker_notebook_instance_encryption_enabled
        if (!detail?.KmsKeyId) {
          findings.push(this.emit(
            'sagemaker_notebook_instance_encryption_enabled',
            { notebookInstance: name, arn, kmsKeyId: null },
            {
              message: `SageMaker notebook instance "${name}" does not have KMS encryption enabled for its storage volume`,
            }
          ));
        }

        // sagemaker_notebook_instance_root_access_disabled
        if (detail?.RootAccess === 'Enabled') {
          findings.push(this.emit(
            'sagemaker_notebook_instance_root_access_disabled',
            { notebookInstance: name, arn, rootAccess: 'Enabled' },
            {
              message: `SageMaker notebook instance "${name}" has root access enabled`,
            }
          ));
        }

        // sagemaker_notebook_instance_vpc_settings_configured
        if (!detail?.SubnetId) {
          findings.push(this.emit(
            'sagemaker_notebook_instance_vpc_settings_configured',
            { notebookInstance: name, arn, subnetId: null },
            {
              message: `SageMaker notebook instance "${name}" is not deployed in a VPC subnet`,
            }
          ));
        }

        // sagemaker_notebook_instance_without_direct_internet_access_configured
        // (Prowler's service layer gates this on RootAccess by mistake; ported to the intended field.)
        if (detail?.DirectInternetAccess === 'Enabled') {
          findings.push(this.emit(
            'sagemaker_notebook_instance_without_direct_internet_access_configured',
            { notebookInstance: name, arn, directInternetAccess: 'Enabled' },
            {
              message: `SageMaker notebook instance "${name}" has direct internet access enabled`,
            }
          ));
        }

        // sagemaker_notebook_instance_no_secrets
        const lifecycleConfigName: string | undefined = detail?.NotebookInstanceLifecycleConfigName;
        if (lifecycleConfigName) {
          await this.checkLifecycleConfigSecrets(findings, name, arn, lifecycleConfigName);
        }
      } catch (error) {
        logger.debug(`Failed to scan SageMaker notebook instance ${name}`, { error: (error as Error).message });
      }
    }
  }

  private async checkLifecycleConfigSecrets(
    findings: ScanningResult[],
    instanceName: string,
    instanceArn: string,
    lifecycleConfigName: string
  ): Promise<void> {
    try {
      const lifecycleConfig: any = await retry(async () => {
        return await this.sagemaker.send(new DescribeNotebookInstanceLifecycleConfigCommand({
          NotebookInstanceLifecycleConfigName: lifecycleConfigName,
        }));
      });

      const secretHits: string[] = [];
      for (const hookName of ['OnCreate', 'OnStart']) {
        const scripts: any[] = lifecycleConfig?.[hookName] ?? [];
        for (let scriptIndex = 0; scriptIndex < scripts.length; scriptIndex++) {
          const contentB64: string | undefined = scripts[scriptIndex]?.Content;
          if (!contentB64) continue;
          let script: string;
          try {
            script = Buffer.from(contentB64, 'base64').toString('utf-8');
          } catch {
            continue;
          }
          const lines = script.split('\n');
          for (let lineNumber = 0; lineNumber < lines.length; lineNumber++) {
            for (const pattern of SECRET_PATTERNS) {
              if (pattern.regex.test(lines[lineNumber])) {
                secretHits.push(`${hookName}[${scriptIndex}]: ${pattern.type} on line ${lineNumber + 1}`);
              }
            }
          }
        }
      }

      if (secretHits.length > 0) {
        findings.push(this.emit(
          'sagemaker_notebook_instance_no_secrets',
          { notebookInstance: instanceName, arn: instanceArn, lifecycleConfig: lifecycleConfigName, secrets: secretHits },
          {
            message: `Potential ${secretHits.length > 1 ? 'secrets' : 'secret'} found in SageMaker notebook instance "${instanceName}" lifecycle configuration -> ${secretHits.join('; ')}`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to scan lifecycle config ${lifecycleConfigName} of notebook instance ${instanceName}`, { error: (error as Error).message });
    }
  }

  // sagemaker_models_network_isolation_enabled / sagemaker_models_vpc_settings_configured
  private async checkModels(findings: ScanningResult[]): Promise<void> {
    let models: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.sagemaker.send(new ListModelsCommand({ NextToken: nextToken, MaxResults: 100 }));
        });
        models.push(...(result?.Models ?? []));
        nextToken = result?.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list SageMaker models', { error: (error as Error).message });
      return;
    }

    for (const model of models) {
      const name: string = model?.ModelName ?? '';
      const arn: string = model?.ModelArn ?? '';
      try {
        const detail: any = await retry(async () => {
          return await this.sagemaker.send(new DescribeModelCommand({ ModelName: name }));
        });

        if (!detail?.EnableNetworkIsolation) {
          findings.push(this.emit(
            'sagemaker_models_network_isolation_enabled',
            { model: name, arn, networkIsolation: false },
            {
              message: `SageMaker model "${name}" has network isolation disabled`,
            }
          ));
        }

        const subnets: any[] = detail?.VpcConfig?.Subnets ?? [];
        if (subnets.length === 0) {
          findings.push(this.emit(
            'sagemaker_models_vpc_settings_configured',
            { model: name, arn, vpcConfigSubnets: [] },
            {
              message: `SageMaker model "${name}" does not have VPC settings configured`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to scan SageMaker model ${name}`, { error: (error as Error).message });
      }
    }
  }

  // sagemaker_training_jobs_intercontainer_encryption_enabled / _network_isolation_enabled /
  // _volume_and_output_encryption_enabled / _vpc_settings_configured
  private async checkTrainingJobs(findings: ScanningResult[]): Promise<void> {
    let trainingJobs: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.sagemaker.send(new ListTrainingJobsCommand({ NextToken: nextToken, MaxResults: 100 }));
        });
        trainingJobs.push(...(result?.TrainingJobSummaries ?? []));
        nextToken = result?.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list SageMaker training jobs', { error: (error as Error).message });
      return;
    }

    for (const job of trainingJobs) {
      const name: string = job?.TrainingJobName ?? '';
      const arn: string = job?.TrainingJobArn ?? '';
      try {
        const detail: any = await retry(async () => {
          return await this.sagemaker.send(new DescribeTrainingJobCommand({ TrainingJobName: name }));
        });

        if (!detail?.EnableInterContainerTrafficEncryption) {
          findings.push(this.emit(
            'sagemaker_training_jobs_intercontainer_encryption_enabled',
            { trainingJob: name, arn, interContainerTrafficEncryption: false },
            {
              message: `SageMaker training job "${name}" has inter-container traffic encryption disabled`,
            }
          ));
        }

        if (!detail?.EnableNetworkIsolation) {
          findings.push(this.emit(
            'sagemaker_training_jobs_network_isolation_enabled',
            { trainingJob: name, arn, networkIsolation: false },
            {
              message: `SageMaker training job "${name}" has network isolation disabled`,
            }
          ));
        }

        if (!detail?.ResourceConfig?.VolumeKmsKeyId) {
          findings.push(this.emit(
            'sagemaker_training_jobs_volume_and_output_encryption_enabled',
            { trainingJob: name, arn, volumeKmsKeyId: null },
            {
              message: `SageMaker training job "${name}" does not have KMS encryption enabled for its ML storage volume`,
            }
          ));
        }

        const subnets: any[] = detail?.VpcConfig?.Subnets ?? [];
        if (subnets.length === 0) {
          findings.push(this.emit(
            'sagemaker_training_jobs_vpc_settings_configured',
            { trainingJob: name, arn, vpcConfigSubnets: [] },
            {
              message: `SageMaker training job "${name}" does not have VPC settings configured`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to scan SageMaker training job ${name}`, { error: (error as Error).message });
      }
    }
  }

  // sagemaker_domain_sso_configured
  private async checkDomains(findings: ScanningResult[]): Promise<void> {
    let domains: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.sagemaker.send(new ListDomainsCommand({ NextToken: nextToken, MaxResults: 100 }));
        });
        domains.push(...(result?.Domains ?? []));
        nextToken = result?.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list SageMaker domains', { error: (error as Error).message });
      return;
    }

    for (const domain of domains) {
      const domainId: string = domain?.DomainId ?? '';
      const name: string = domain?.DomainName ?? domainId;
      const arn: string = domain?.DomainArn ?? '';
      try {
        const detail: any = await retry(async () => {
          return await this.sagemaker.send(new DescribeDomainCommand({ DomainId: domainId }));
        });

        const authMode: string | undefined = detail?.AuthMode;
        if (authMode === 'SSO') {
          const associated = Boolean(
            detail?.SingleSignOnManagedApplicationInstanceId || detail?.SingleSignOnApplicationArn
          );
          if (!associated) {
            findings.push(this.emit(
              'sagemaker_domain_sso_configured',
              { domain: name, domainId, arn, authMode, identityCenterAssociated: false },
              {
                message: `SageMaker domain "${name}" is configured with SSO authentication but is not associated with an IAM Identity Center instance`,
              }
            ));
          }
        } else {
          findings.push(this.emit(
            'sagemaker_domain_sso_configured',
            { domain: name, domainId, arn, authMode: authMode ?? 'unknown' },
            {
              message: `SageMaker domain "${name}" is not configured with SSO authentication; current mode is ${authMode ?? 'unknown'}`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to scan SageMaker domain ${name}`, { error: (error as Error).message });
      }
    }
  }

  // sagemaker_endpoint_config_prod_variant_instances
  private async checkEndpointConfigs(findings: ScanningResult[]): Promise<void> {
    let endpointConfigs: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.sagemaker.send(new ListEndpointConfigsCommand({ NextToken: nextToken, MaxResults: 100 }));
        });
        endpointConfigs.push(...(result?.EndpointConfigs ?? []));
        nextToken = result?.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list SageMaker endpoint configs', { error: (error as Error).message });
      return;
    }

    for (const endpointConfig of endpointConfigs) {
      const name: string = endpointConfig?.EndpointConfigName ?? '';
      const arn: string = endpointConfig?.EndpointConfigArn ?? '';
      try {
        const detail: any = await retry(async () => {
          return await this.sagemaker.send(new DescribeEndpointConfigCommand({ EndpointConfigName: name }));
        });

        const nonCompliantVariants: string[] = [];
        for (const variant of detail?.ProductionVariants ?? []) {
          const initialInstanceCount: number = variant?.InitialInstanceCount ?? 0;
          if (initialInstanceCount <= 1) {
            nonCompliantVariants.push(variant?.VariantName ?? '');
          }
        }

        if (nonCompliantVariants.length > 0) {
          findings.push(this.emit(
            'sagemaker_endpoint_config_prod_variant_instances',
            { endpointConfig: name, arn, nonCompliantVariants },
            {
              message: `SageMaker endpoint config "${name}" has production variant(s) ${nonCompliantVariants.join(', ')} with fewer than two initial instances`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to scan SageMaker endpoint config ${name}`, { error: (error as Error).message });
      }
    }
  }
}

export default SageMakerScanner;
