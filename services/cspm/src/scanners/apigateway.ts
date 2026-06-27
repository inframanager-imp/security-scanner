import {
  GetRestApisCommand,
  GetStagesCommand,
  GetResourcesCommand,
  type RestApi,
  type Resource,
  type Stage,
} from '@aws-sdk/client-api-gateway';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class APIGatewayScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'APIGateway');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting API Gateway security scan...');

    const apis = await this.listAPIs();
    logger.info(`API Gateway: scanning ${apis.length} REST API(s)`);

    for (const api of apis) {
      findings.push(...(await this.scanAPI(api)));
    }

    logger.info(`API Gateway scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listAPIs(): Promise<RestApi[]> {
    const apis: RestApi[] = [];
    let position: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.apigateway.send(new GetRestApisCommand({ position, limit: 500 }))
        );
        apis.push(...(result.items ?? []));
        position = result.position;
      } while (position);
    } catch { /* no permission */ }
    return apis;
  }

  private async scanAPI(api: RestApi): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const apiName = api.name ?? 'Unknown';
    const apiId   = api.id   ?? '';

    let stages: Stage[] = [];
    try {
      const result = await retry(() =>
        this.client.apigateway.send(new GetStagesCommand({ restApiId: apiId }))
      );
      stages = result.item ?? [];
    } catch { return findings; }

    // Unauthenticated methods exposed at the API level (independent of stages)
    findings.push(...(await this.checkUnauthenticatedMethods(api, apiId, apiName)));

    for (const stage of stages) {
      const stageName = stage.stageName ?? 'Unknown';
      const stageId   = `${apiId}::${stageName}`;

      // 1. No access logging
      if (!stage.accessLogSettings?.destinationArn) {
        findings.push(this.createFinding(
          'API Gateway Stage Access Logging Disabled',
          `API Gateway REST API "${apiName}" stage "${stageName}" does not have access logging enabled. ` +
          `Without logs, API abuse and unauthorized access cannot be detected or audited.`,
          'HIGH',
          { resourceId: stageId, apiName, apiId, stageName },
          `Enable access logging for stage "${stageName}" by setting a CloudWatch Logs or Kinesis ARN as the logging destination in API Gateway stage settings.`,
          ['apigateway', 'logging'],
        ));
      }

      // 2. Execution logging disabled
      const loggingLevel = stage.methodSettings?.['*/*']?.loggingLevel ?? 'OFF';
      if (loggingLevel === 'OFF') {
        findings.push(this.createFinding(
          'API Gateway Stage Execution Logging Disabled',
          `API "${apiName}" stage "${stageName}" has execution logging set to OFF. ` +
          `Request/response details are not captured for troubleshooting or security analysis.`,
          'MEDIUM',
          { resourceId: `${stageId}::exec-logging`, apiName, apiId, stageName },
          `Enable execution logging in API Gateway console under Stages > "${stageName}" > Logs/Tracing. Set level to ERROR or INFO.`,
          ['apigateway', 'logging'],
        ));
      }

      // 3. No WAF WebACL
      if (!stage.webAclArn) {
        findings.push(this.createFinding(
          'API Gateway Stage Not Protected By WAF',
          `API Gateway stage "${apiName}/${stageName}" has no WAF WebACL associated. ` +
          `The API is exposed to web attacks (SQLi, XSS, bot traffic) without WAF protection.`,
          'HIGH',
          { resourceId: `${stageId}::waf`, apiName, apiId, stageName },
          `Associate a WAF WebACL with this API stage in the AWS WAF console or via: ` +
          `aws wafv2 associate-web-acl --web-acl-arn <acl-arn> --resource-arn arn:aws:apigateway:<region>::/restapis/${apiId}/stages/${stageName}`,
          ['apigateway', 'waf'],
        ));
      }

      // 4. Cache encryption disabled (if caching is enabled)
      if (stage.cacheClusterEnabled && !stage.cacheClusterSize) {
        // cache enabled but check encryption
        const cacheEncrypted = stage.methodSettings?.['*/*']?.cacheDataEncrypted;
        if (cacheEncrypted === false) {
          findings.push(this.createFinding(
            'API Gateway Stage Cache Not Encrypted',
            `API Gateway stage "${apiName}/${stageName}" has caching enabled but cache data is not encrypted. ` +
            `Sensitive API responses cached in plaintext can be exposed.`,
            'MEDIUM',
            { resourceId: `${stageId}::cache`, apiName, apiId, stageName },
            `Enable cache encryption in API Gateway stage method settings.`,
            ['apigateway', 'encryption'],
          ));
        }
      }

      // 5. No throttling configured
      const throttleRate  = stage.methodSettings?.['*/*']?.throttlingRateLimit;
      const throttleBurst = stage.methodSettings?.['*/*']?.throttlingBurstLimit;
      if (!throttleRate && !throttleBurst) {
        findings.push(this.createFinding(
          'API Gateway Stage No Throttling Configured',
          `API Gateway stage "${apiName}/${stageName}" has no throttling configured. ` +
          `Without throttling, the API is vulnerable to abuse, DDoS, and unexpected cost spikes.`,
          'MEDIUM',
          { resourceId: `${stageId}::throttle`, apiName, apiId, stageName },
          `Configure throttling limits in API Gateway stage settings to limit requests per second.`,
          ['apigateway', 'throttling'],
        ));
      }
    }

    return findings;
  }

  private async checkUnauthenticatedMethods(
    _api: RestApi,
    apiId: string,
    apiName: string,
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const resources: Resource[] = [];
    let position: string | undefined;

    try {
      do {
        const result = await retry(() =>
          this.client.apigateway.send(new GetResourcesCommand({
            restApiId: apiId,
            position,
            limit: 500,
            embed: ['methods'],
          }))
        );
        resources.push(...(result.items ?? []));
        position = result.position;
      } while (position);
    } catch { return findings; }

    const openMethods: { path: string; method: string }[] = [];
    for (const res of resources) {
      const path = res.path ?? '';
      for (const [methodName, methodCfg] of Object.entries(res.resourceMethods ?? {})) {
        const authType = (methodCfg as any)?.authorizationType ?? 'NONE';
        const apiKeyRequired = (methodCfg as any)?.apiKeyRequired === true;
        if (authType === 'NONE' && !apiKeyRequired && methodName !== 'OPTIONS') {
          openMethods.push({ path, method: methodName });
        }
      }
    }

    if (openMethods.length > 0) {
      const sample = openMethods.slice(0, 5).map(m => `${m.method} ${m.path}`).join(', ');
      findings.push(this.createFinding(
        'API Gateway Method Has No Authorization',
        `API "${apiName}" has ${openMethods.length} method(s) with authorizationType=NONE and no API key required: ${sample}${openMethods.length > 5 ? '...' : ''}. ` +
        `These endpoints are publicly invokable without authentication.`,
        'HIGH',
        { resourceId: `${apiId}::unauth-methods`, apiName, apiId, methodCount: openMethods.length, sample: openMethods.slice(0, 10) },
        `Add IAM, Cognito, or Lambda authorizer to these methods, or require an API key. Configure in API Gateway console under Resources > Method Request.`,
        ['apigateway', 'authentication', 'public-access'],
      ));
    }
    return findings;
  }
}

export default APIGatewayScanner;
