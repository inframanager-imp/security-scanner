// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ApiGatewayV2Client,
  GetApisCommand,
  GetAuthorizersCommand,
  GetStagesCommand,
} from '@aws-sdk/client-apigatewayv2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class APIGatewayV2Scanner extends BaseScanner {
  private apigatewayv2: ApiGatewayV2Client;

  constructor(client: AWSClient) {
    super(client, 'APIGatewayV2');
    this.apigatewayv2 = new ApiGatewayV2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting APIGatewayV2 security scan...');

      const apis = await this.getApis();
      for (const api of apis) {
        const apiName: string = api.Name ?? api.ApiId ?? 'unknown';
        logger.debug(`Scanning API Gateway V2 API: ${apiName}`);
        try {
          findings.push(...await this.validateApi(api));
        } catch (error) {
          logger.debug(`Failed to scan API Gateway V2 API ${apiName}`, { error: (error as Error).message });
        }
      }

      logger.info(`APIGatewayV2 scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('APIGatewayV2 scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async getApis(): Promise<any[]> {
    const apis: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.apigatewayv2.send(new GetApisCommand({ NextToken: nextToken }));
      });
      apis.push(...(result.Items ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return apis;
  }

  private async getAuthorizers(apiId: string): Promise<any[]> {
    const authorizers: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.apigatewayv2.send(new GetAuthorizersCommand({ ApiId: apiId, NextToken: nextToken }));
      });
      authorizers.push(...(result.Items ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return authorizers;
  }

  private async getStages(apiId: string): Promise<any[]> {
    const stages: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.apigatewayv2.send(new GetStagesCommand({ ApiId: apiId, NextToken: nextToken }));
      });
      stages.push(...(result.Items ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return stages;
  }

  private async validateApi(api: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const apiId: string = api.ApiId ?? '';
    const apiName: string = api.Name ?? apiId;
    if (!apiId) return findings;

    // apigatewayv2_api_authorizers_enabled: API must have at least one authorizer
    let hasAuthorizer = false;
    try {
      const authorizers = await this.getAuthorizers(apiId);
      hasAuthorizer = authorizers.length > 0;
    } catch (error) {
      // Mirror Prowler: an error fetching authorizers leaves the API treated as having none
      logger.debug(`Failed to get authorizers for API Gateway V2 API ${apiName}`, { error: (error as Error).message });
    }
    if (!hasAuthorizer) {
      findings.push(this.emit(
        'apigatewayv2_api_authorizers_enabled',
        { apiId, apiName, protocolType: api.ProtocolType ?? null, authorizer: false },
        {
          message: `API Gateway V2 "${apiName}" (ID ${apiId}) does not have an authorizer configured`,
          remediation: `Create a JWT/Cognito or Lambda authorizer for API "${apiName}" and attach it to its routes`,
        }
      ));
    }

    // apigatewayv2_api_access_logging_enabled: each stage must have AccessLogSettings
    try {
      const stages = await this.getStages(apiId);
      for (const stage of stages) {
        const stageName: string = stage.StageName ?? 'unknown';
        const logging = !!stage.AccessLogSettings;
        if (!logging) {
          findings.push(this.emit(
            'apigatewayv2_api_access_logging_enabled',
            { apiId, apiName, stage: stageName, accessLogSettings: false },
            {
              message: `API Gateway V2 "${apiName}" (ID ${apiId}) in stage ${stageName} has access logging disabled`,
              remediation: `Enable access logging on stage "${stageName}" of API "${apiName}" with a CloudWatch Logs destination and structured log format`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug(`Failed to get stages for API Gateway V2 API ${apiName}`, { error: (error as Error).message });
    }

    return findings;
  }
}

export default APIGatewayV2Scanner;
