// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  AppSyncClient,
  ListGraphqlApisCommand,
} from '@aws-sdk/client-appsync';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class AppSyncScanner extends BaseScanner {
  private appsync: AppSyncClient;

  constructor(client: AWSClient) {
    super(client, 'AppSync');
    this.appsync = new AppSyncClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting AppSync security scan...');

      const apis = await this.listGraphqlApis();
      for (const api of apis) {
        const apiName: string = api.name ?? api.apiId ?? 'unknown';
        logger.debug(`Scanning AppSync API: ${apiName}`);
        try {
          findings.push(...this.validateApi(api));
        } catch (error) {
          logger.debug(`Failed to scan AppSync API ${apiName}`, { error: (error as Error).message });
        }
      }

      logger.info(`AppSync scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('AppSync scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listGraphqlApis(): Promise<any[]> {
    const apis: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.appsync.send(new ListGraphqlApisCommand({ nextToken }));
      });
      apis.push(...(result.graphqlApis ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return apis;
  }

  private validateApi(api: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const apiName: string = api.name ?? api.apiId ?? 'unknown';
    const apiType: string = api.apiType ?? 'GRAPHQL';
    const fieldLogLevel: string = api.logConfig?.fieldLogLevel ?? '';
    const authenticationType: string = api.authenticationType ?? 'API_KEY';

    // appsync_field_level_logging_enabled: field log level must be ALL or ERROR
    if (fieldLogLevel !== 'ALL' && fieldLogLevel !== 'ERROR') {
      findings.push(this.emit(
        'appsync_field_level_logging_enabled',
        { apiId: api.apiId, apiName, arn: api.arn, fieldLogLevel: fieldLogLevel || null },
        {
          message: `AppSync API "${apiName}" does not have field log level enabled`,
          remediation: `Enable logging on AppSync API "${apiName}" with field resolver log level ERROR or ALL and a CloudWatch Logs role`,
        }
      ));
    }

    // appsync_graphql_api_no_api_key_authentication: GraphQL APIs must not default to API_KEY auth
    if (apiType === 'GRAPHQL' && authenticationType === 'API_KEY') {
      findings.push(this.emit(
        'appsync_graphql_api_no_api_key_authentication',
        { apiId: api.apiId, apiName, arn: api.arn, authenticationType },
        {
          message: `AppSync GraphQL API "${apiName}" is using an API KEY for authentication`,
          remediation: `Change the default authorization mode of AppSync API "${apiName}" to AWS_IAM, Cognito User Pools, OIDC, or a Lambda authorizer`,
        }
      ));
    }

    return findings;
  }
}

export default AppSyncScanner;
