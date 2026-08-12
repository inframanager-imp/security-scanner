// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  GlueClient,
  GetConnectionsCommand,
  GetJobsCommand,
  GetSecurityConfigurationsCommand,
  GetDataCatalogEncryptionSettingsCommand,
  GetResourcePolicyCommand,
  SearchTablesCommand,
  GetMLTransformsCommand,
  GetDevEndpointsCommand,
} from '@aws-sdk/client-glue';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Heuristic port of Prowler's secrets scan over Glue job DefaultArguments:
// flag secret-looking argument names with inline values, and AWS key IDs in values.
const SECRET_ARG_NAME = /(password|passwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credential)/i;
const AWS_ACCESS_KEY_PATTERN = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/;

function isSecretReference(value: string): boolean {
  // Values that reference Secrets Manager / SSM rather than embedding the secret
  return /^arn:aws/i.test(value) || /\{\{\s*resolve:/i.test(value) || /secretsmanager|parameter[-_ ]?store|ssm:/i.test(value);
}

// glue_development_endpoints_* checks are a table-driven family: same evaluation
// against the endpoint's security configuration, differing only in which
// encryption mode is inspected.
const DEV_ENDPOINT_ENCRYPTION_CHECKS: {
  checkId: string;
  label: string;
  getMode: (encryption: any) => string;
}[] = [
  {
    checkId: 'glue_development_endpoints_s3_encryption_enabled',
    label: 'S3 encryption',
    getMode: encryption => encryption?.S3Encryption?.[0]?.S3EncryptionMode || 'DISABLED',
  },
  {
    checkId: 'glue_development_endpoints_cloudwatch_logs_encryption_enabled',
    label: 'CloudWatch Logs encryption',
    getMode: encryption => encryption?.CloudWatchEncryption?.CloudWatchEncryptionMode || 'DISABLED',
  },
  {
    checkId: 'glue_development_endpoints_job_bookmark_encryption_enabled',
    label: 'job bookmark encryption',
    getMode: encryption => encryption?.JobBookmarksEncryption?.JobBookmarksEncryptionMode || 'DISABLED',
  },
];

export class GlueScanner extends BaseScanner {
  private glue: GlueClient;

  constructor(client: AWSClient) {
    super(client, 'Glue');
    this.glue = new GlueClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Glue security scan...');

      const securityConfigs = await this.getSecurityConfigMap();

      const jobs = await this.getJobs();
      for (const job of jobs) {
        findings.push(...this.validateJob(job, securityConfigs));
      }

      const connections = await this.getConnections();
      for (const conn of connections) {
        findings.push(...this.validateConnection(conn));
      }

      const devEndpoints = await this.getDevEndpoints();
      for (const endpoint of devEndpoints) {
        findings.push(...this.validateDevEndpoint(endpoint, securityConfigs));
      }

      findings.push(...await this.checkDataCatalog());
      findings.push(...await this.checkMLTransforms());

      logger.info(`Glue scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Glue scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async getJobs(): Promise<any[]> {
    try {
      return await retry(async () => {
        logger.debug('Fetching Glue jobs...');
        const jobs: any[] = [];
        let nextToken: string | undefined;
        do {
          const result: any = await this.glue.send(new GetJobsCommand({ NextToken: nextToken }));
          jobs.push(...(result.Jobs || []));
          nextToken = result.NextToken;
        } while (nextToken);
        return jobs;
      });
    } catch (error) {
      logger.debug('Failed to fetch Glue jobs', { error: (error as Error).message });
      return [];
    }
  }

  private async getSecurityConfigMap(): Promise<Map<string, any>> {
    const configs = new Map<string, any>();
    try {
      await retry(async () => {
        logger.debug('Fetching Glue security configurations...');
        let nextToken: string | undefined;
        do {
          const result: any = await this.glue.send(
            new GetSecurityConfigurationsCommand({ NextToken: nextToken })
          );
          for (const config of result.SecurityConfigurations || []) {
            if (config.Name) configs.set(config.Name, config);
          }
          nextToken = result.NextToken;
        } while (nextToken);
      });
    } catch (error) {
      logger.debug('Failed to fetch Glue security configurations', { error: (error as Error).message });
    }
    return configs;
  }

  private async getConnections(): Promise<any[]> {
    try {
      return await retry(async () => {
        logger.debug('Fetching Glue connections...');
        const connections: any[] = [];
        let nextToken: string | undefined;
        do {
          const result: any = await this.glue.send(new GetConnectionsCommand({ NextToken: nextToken }));
          connections.push(...(result.ConnectionList || []));
          nextToken = result.NextToken;
        } while (nextToken);
        return connections;
      });
    } catch (error) {
      logger.debug('Failed to fetch Glue connections', { error: (error as Error).message });
      return [];
    }
  }

  private validateJob(job: any, securityConfigs: Map<string, any>): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const jobName = job.Name || 'Unknown';
    const args: Record<string, string> = job.DefaultArguments || {};
    const secConfig = job.SecurityConfiguration ? securityConfigs.get(job.SecurityConfiguration) : undefined;
    const encryption = secConfig?.EncryptionConfiguration;

    // glue_etl_jobs_amazon_s3_encryption_enabled
    if (secConfig) {
      const s3Mode = encryption?.S3Encryption?.[0]?.S3EncryptionMode || 'DISABLED';
      if (s3Mode === 'DISABLED') {
        findings.push(this.emit(
          'glue_etl_jobs_amazon_s3_encryption_enabled',
          { job: jobName, securityConfiguration: job.SecurityConfiguration, s3EncryptionMode: s3Mode },
          { message: `Glue job "${jobName}" security configuration has S3 encryption disabled` }
        ));
      }
    } else if (args['--encryption-type'] !== 'sse-s3') {
      findings.push(this.emit(
        'glue_etl_jobs_amazon_s3_encryption_enabled',
        { job: jobName, securityConfiguration: job.SecurityConfiguration || null },
        { message: `Glue job "${jobName}" has no security configuration and no S3 encryption argument, so job outputs to S3 are not encrypted` }
      ));
    }

    // glue_etl_jobs_cloudwatch_logs_encryption_enabled
    const cwMode = secConfig
      ? (encryption?.CloudWatchEncryption?.CloudWatchEncryptionMode || 'DISABLED')
      : 'DISABLED';
    if (cwMode === 'DISABLED') {
      findings.push(this.emit(
        'glue_etl_jobs_cloudwatch_logs_encryption_enabled',
        { job: jobName, securityConfiguration: job.SecurityConfiguration || null, cloudWatchEncryptionMode: cwMode },
        { message: `Glue job "${jobName}" does not have CloudWatch Logs encryption enabled` }
      ));
    }

    // glue_etl_jobs_job_bookmark_encryption_enabled
    const jbMode = secConfig
      ? (encryption?.JobBookmarksEncryption?.JobBookmarksEncryptionMode || 'DISABLED')
      : 'DISABLED';
    if (jbMode === 'DISABLED') {
      findings.push(this.emit(
        'glue_etl_jobs_job_bookmark_encryption_enabled',
        { job: jobName, securityConfiguration: job.SecurityConfiguration || null, jobBookmarksEncryptionMode: jbMode },
        { message: `Glue job "${jobName}" does not have job bookmark encryption enabled` }
      ));
    }

    // glue_etl_jobs_logging_enabled
    if (args['--enable-continuous-cloudwatch-log'] !== 'true') {
      findings.push(this.emit(
        'glue_etl_jobs_logging_enabled',
        { job: jobName, continuousLogging: args['--enable-continuous-cloudwatch-log'] || 'false' },
        { message: `Glue job "${jobName}" does not have continuous CloudWatch logging enabled` }
      ));
    }

    // glue_etl_jobs_no_secrets_in_arguments
    const suspectArguments: string[] = [];
    for (const [argName, argValue] of Object.entries(args)) {
      if (typeof argValue !== 'string' || !argValue) continue;
      if (SECRET_ARG_NAME.test(argName) && !isSecretReference(argValue)) {
        suspectArguments.push(argName);
      } else if (AWS_ACCESS_KEY_PATTERN.test(argValue)) {
        suspectArguments.push(argName);
      }
    }
    if (suspectArguments.length > 0) {
      findings.push(this.emit(
        'glue_etl_jobs_no_secrets_in_arguments',
        { job: jobName, suspectArguments },
        { message: `Glue job "${jobName}" appears to have secrets in its default arguments: ${suspectArguments.join(', ')}` }
      ));
    }

    return findings;
  }

  private validateConnection(conn: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const connName = conn.Name || 'Unknown';

    // glue_database_connections_ssl_enabled
    if (conn.ConnectionProperties?.JDBC_ENFORCE_SSL !== 'true') {
      findings.push(this.emit(
        'glue_database_connections_ssl_enabled',
        { connection: connName, connectionType: conn.ConnectionType, jdbcEnforceSsl: conn.ConnectionProperties?.JDBC_ENFORCE_SSL || 'false' },
        { message: `Glue connection "${connName}" does not enforce SSL (JDBC_ENFORCE_SSL is not true)` }
      ));
    }

    // glue_catalog_connection_no_secrets — heuristic port of Prowler's
    // detect-secrets scan over ConnectionProperties.
    const properties: Record<string, any> = conn.ConnectionProperties || {};
    const suspectProperties: string[] = [];
    for (const [propName, propValue] of Object.entries(properties)) {
      if (typeof propValue !== 'string' || !propValue) continue;
      // ENCRYPTED_* values are KMS-encrypted by the catalog; SECRET_ID references Secrets Manager
      if (propName.startsWith('ENCRYPTED_') || propName === 'SECRET_ID') continue;
      if (isSecretReference(propValue)) continue;
      if (SECRET_ARG_NAME.test(propName) || AWS_ACCESS_KEY_PATTERN.test(propValue)) {
        suspectProperties.push(propName);
      }
    }
    if (suspectProperties.length > 0) {
      findings.push(this.emit(
        'glue_catalog_connection_no_secrets',
        { connection: connName, connectionType: conn.ConnectionType, suspectProperties },
        { message: `Potential secrets found in Glue connection "${connName}" properties: ${suspectProperties.join(', ')}` }
      ));
    }

    return findings;
  }

  private async getDevEndpoints(): Promise<any[]> {
    try {
      return await retry(async () => {
        logger.debug('Fetching Glue development endpoints...');
        const endpoints: any[] = [];
        let nextToken: string | undefined;
        do {
          const result: any = await this.glue.send(new GetDevEndpointsCommand({ NextToken: nextToken }));
          endpoints.push(...(result.DevEndpoints || []));
          nextToken = result.NextToken;
        } while (nextToken);
        return endpoints;
      });
    } catch (error) {
      // Dev endpoints are not supported in every region ("Operation is not supported")
      logger.debug('Failed to fetch Glue development endpoints', { error: (error as Error).message });
      return [];
    }
  }

  // glue_development_endpoints_{s3,cloudwatch_logs,job_bookmark}_encryption_enabled
  private validateDevEndpoint(endpoint: any, securityConfigs: Map<string, any>): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const endpointName = endpoint.EndpointName || 'Unknown';
    const securityConfigName: string | undefined = endpoint.SecurityConfiguration;
    const secConfig = securityConfigName ? securityConfigs.get(securityConfigName) : undefined;
    const encryption = secConfig?.EncryptionConfiguration;

    for (const check of DEV_ENDPOINT_ENCRYPTION_CHECKS) {
      if (!secConfig) {
        findings.push(this.emit(
          check.checkId,
          { devEndpoint: endpointName, securityConfiguration: securityConfigName || null },
          { message: `Glue development endpoint "${endpointName}" does not have a security configuration, so ${check.label} is disabled` }
        ));
        continue;
      }
      const mode = check.getMode(encryption);
      if (mode === 'DISABLED') {
        findings.push(this.emit(
          check.checkId,
          { devEndpoint: endpointName, securityConfiguration: securityConfigName, encryptionMode: mode },
          { message: `Glue development endpoint "${endpointName}" does not have ${check.label} enabled` }
        ));
      }
    }

    return findings;
  }

  private async checkDataCatalog(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // Prowler only evaluates catalog encryption settings when Glue tables exist in the region
    let hasTables = false;
    try {
      const result: any = await retry(async () => {
        return await this.glue.send(new SearchTablesCommand({ MaxResults: 10 }));
      });
      hasTables = (result.TableList || []).length > 0;
    } catch (error) {
      logger.debug('Failed to search Glue tables', { error: (error as Error).message });
    }

    if (hasTables) {
      try {
        const result: any = await retry(async () => {
          return await this.glue.send(new GetDataCatalogEncryptionSettingsCommand({}));
        });
        const settings = result.DataCatalogEncryptionSettings || {};

        // glue_data_catalogs_metadata_encryption_enabled
        const catalogMode = settings.EncryptionAtRest?.CatalogEncryptionMode || 'DISABLED';
        if (!catalogMode.startsWith('SSE-KMS')) {
          findings.push(this.emit(
            'glue_data_catalogs_metadata_encryption_enabled',
            { catalogEncryptionMode: catalogMode },
            { message: 'Glue Data Catalog settings have metadata encryption disabled' }
          ));
        }

        // glue_data_catalogs_connection_passwords_encryption_enabled
        const passwordEncrypted = settings.ConnectionPasswordEncryption?.ReturnConnectionPasswordEncrypted === true;
        if (!passwordEncrypted) {
          findings.push(this.emit(
            'glue_data_catalogs_connection_passwords_encryption_enabled',
            { returnConnectionPasswordEncrypted: passwordEncrypted },
            { message: 'Glue Data Catalog connection passwords are not encrypted with a KMS key' }
          ));
        }
      } catch (error) {
        logger.debug('Failed to get Glue Data Catalog encryption settings', { error: (error as Error).message });
      }
    }

    // glue_data_catalogs_not_publicly_accessible (skipped when no resource policy exists)
    try {
      const result: any = await retry(async () => {
        return await this.glue.send(new GetResourcePolicyCommand({}));
      });
      if (result.PolicyInJson) {
        const policy = JSON.parse(result.PolicyInJson);
        if (this.isPolicyPublic(policy)) {
          findings.push(this.emit(
            'glue_data_catalogs_not_publicly_accessible',
            { policy },
            { message: 'Glue Data Catalog resource policy allows public access (wildcard principal without restrictive conditions)' }
          ));
        }
      }
    } catch (error) {
      const msg = (error as Error).message;
      // EntityNotFoundException means no resource policy is set — nothing to evaluate
      if (!msg.includes('EntityNotFound')) {
        logger.debug('Failed to get Glue Data Catalog resource policy', { error: msg });
      }
    }

    return findings;
  }

  private isPolicyPublic(policy: any): boolean {
    const statements = Array.isArray(policy?.Statement) ? policy.Statement : [policy?.Statement].filter(Boolean);
    for (const stmt of statements) {
      if (stmt.Effect !== 'Allow') continue;
      const principal = stmt.Principal;
      const awsPrincipals = principal?.AWS
        ? (Array.isArray(principal.AWS) ? principal.AWS : [principal.AWS])
        : [];
      const isWildcard =
        principal === '*' ||
        awsPrincipals.includes('*') ||
        principal?.CanonicalUser === '*';
      if (isWildcard && !stmt.Condition) {
        return true;
      }
    }
    return false;
  }

  private async checkMLTransforms(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const transforms = await retry(async () => {
        const collected: any[] = [];
        let nextToken: string | undefined;
        do {
          const result: any = await this.glue.send(new GetMLTransformsCommand({ NextToken: nextToken }));
          collected.push(...(result.Transforms || []));
          nextToken = result.NextToken;
        } while (nextToken);
        return collected;
      });

      for (const transform of transforms) {
        const transformName = transform.Name || transform.TransformId || 'Unknown';
        const mode = transform.TransformEncryption?.MlUserDataEncryption?.MlUserDataEncryptionMode || 'DISABLED';
        if (mode === 'DISABLED') {
          findings.push(this.emit(
            'glue_ml_transform_encrypted_at_rest',
            { transform: transformName, transformId: transform.TransformId, userDataEncryptionMode: mode },
            { message: `Glue ML Transform "${transformName}" is not encrypted at rest` }
          ));
        }
      }
    } catch (error) {
      logger.debug('Failed to fetch Glue ML transforms', { error: (error as Error).message });
    }

    return findings;
  }
}

export default GlueScanner;
