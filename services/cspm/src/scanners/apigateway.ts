// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  GetRestApisCommand,
  GetStagesCommand,
  GetResourcesCommand,
  GetDomainNamesCommand,
  GetAuthorizersCommand,
  type RestApi,
  type Resource,
  type Stage,
  type DomainName,
} from '@aws-sdk/client-api-gateway';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Conservative secret patterns (Prowler uses detect-secrets library; this is a regex port)
const SECRET_PATTERNS: { type: string; regex: RegExp }[] = [
  { type: 'AWS Access Key ID', regex: /\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/ },
  { type: 'AWS Secret Access Key', regex: /aws_?secret_?access_?key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}\b/i },
  { type: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY/ },
  { type: 'Hardcoded Password', regex: /\b(password|passwd|pwd)\b\s*[=:]\s*['"][^'"]{4,}['"]/i },
  { type: 'Hardcoded Secret or Token', regex: /\b(secret|token|api[_-]?key|auth[_-]?key|access[_-]?token)\b\s*[=:]\s*['"][^'"]{8,}['"]/i },
  { type: 'Credentials in URL', regex: /[a-z][a-z0-9+.-]*:\/\/[^/\s:@'"]+:[^/\s:@'"]+@[^\s'"]+/i },
];

// PQ-ready security policies (Prowler defaults + AWS-published options)
const PQC_APIGATEWAY_POLICIES = [
  'SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09',
  'SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09',
  'SecurityPolicy_TLS13_1_2_PQ_2025_09',
];

export class APIGatewayScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'APIGateway');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting API Gateway security scan...');

    const apis = await this.listAPIs();
    logger.info(`API Gateway: scanning ${apis.length} REST API(s)`);

    const domainNames = await this.listDomainNames();
    logger.info(`API Gateway: scanning ${domainNames.length} custom domain name(s)`);

    // 1. Custom domain name PQ-TLS check
    findings.push(...(await this.checkDomainNamesPQC(domainNames)));

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

  private async listDomainNames(): Promise<DomainName[]> {
    const domains: DomainName[] = [];
    let position: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.apigateway.send(new GetDomainNamesCommand({ position, limit: 500 }))
        );
        domains.push(...(result.items ?? []));
        position = result.position;
      } while (position);
    } catch { /* no permission */ }
    return domains;
  }

  private async checkDomainNamesPQC(domainNames: DomainName[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    for (const domain of domainNames) {
      const domainName = domain.domainName ?? 'Unknown';
      const policy = domain.securityPolicy ?? '';
      if (!PQC_APIGATEWAY_POLICIES.includes(policy)) {
        findings.push(this.emit(
          'apigateway_domain_name_pqc_tls_enabled',
          { resourceId: domainName, domainName, securityPolicy: policy || null },
          {
            message: `API Gateway custom domain "${domainName}" uses TLS policy "${policy}" instead of a post-quantum policy. ` +
              `Traffic captured today can be decrypted once quantum computers exist (harvest-now, decrypt-later attack).`,
            remediation: `Update the security policy to one of: ${PQC_APIGATEWAY_POLICIES.join(', ')} via the console or ` +
              `aws apigateway update-domain-name --domain-name ${domainName} --patch-operations op=replace,path=/securityPolicy,value=SecurityPolicy_TLS13_1_2_PQ_2025_09`,
          }
        ));
      }
    }
    return findings;
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

    // Check endpoint type and authorizers (once per API)
    findings.push(...(await this.checkEndpointType(api, apiId, apiName)));
    findings.push(...(await this.checkAuthorizers(api, apiId, apiName)));
    findings.push(...(await this.checkUnauthenticatedMethods(api, apiId, apiName)));

    for (const stage of stages) {
      const stageName = stage.stageName ?? 'Unknown';
      const stageId   = `${apiId}::${stageName}`;

      // Stage-level checks
      // 1. Client certificate
      if (!stage.clientCertificateId) {
        findings.push(this.emit(
          'apigateway_restapi_client_certificate_enabled',
          { resourceId: stageId, apiName, apiId, stageName },
          {
            message: `API Gateway REST API "${apiName}" stage "${stageName}" does not have a client certificate configured. ` +
              `Without mutual TLS, the backend cannot verify requests originate from API Gateway.`,
            remediation: `Create a client certificate and attach it to the stage: ` +
              `aws apigateway create-client-certificate && ` +
              `aws apigateway update-stage --rest-api-id ${apiId} --stage-name ${stageName} --patch-operations op=replace,path=/clientCertificateId,value=<cert-id>`,
          }
        ));
      }

      // 2. Secrets in stage variables
      findings.push(...(await this.checkStageVariablesForSecrets(apiName, apiId, stageName, stage.variables ?? {})));

      // 3. X-Ray tracing
      if (!stage.tracingEnabled) {
        findings.push(this.emit(
          'apigateway_restapi_tracing_enabled',
          { resourceId: `${stageId}::tracing`, apiName, apiId, stageName },
          {
            message: `API Gateway REST API "${apiName}" stage "${stageName}" does not have X-Ray tracing enabled. ` +
              `Without traces, end-to-end visibility of latency, errors and integration failures is lost.`,
            remediation: `Enable X-Ray tracing: aws apigateway update-stage --rest-api-id ${apiId} --stage-name ${stageName} ` +
              `--patch-operations op=replace,path=/tracingEnabled,value=true`,
          }
        ));
      }
    }

    return findings;
  }

  private async checkEndpointType(api: RestApi, apiId: string, apiName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const endpointType = api.endpointConfiguration?.types?.[0] ?? 'EDGE';
    const isPrivate = endpointType === 'PRIVATE';

    if (!isPrivate) {
      findings.push(this.emit(
        'apigateway_restapi_public',
        { resourceId: apiId, apiName, apiId, endpointType },
        {
          message: `API Gateway REST API "${apiName}" has endpoint type "${endpointType}" (public/internet-accessible). ` +
            `Public endpoints increase attack surface; private endpoints (via VPC endpoints) reduce exposure.`,
          remediation: `Change to PRIVATE endpoint type: aws apigateway update-rest-api --rest-api-id ${apiId} ` +
            `--patch-operations op=replace,path=/endpointConfiguration/types/0,value=PRIVATE (or use resource policies to restrict access)`,
        }
      ));
    }
    return findings;
  }

  private async checkAuthorizers(api: RestApi, apiId: string, apiName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const endpointType = api.endpointConfiguration?.types?.[0] ?? 'EDGE';
    const isPublic = endpointType !== 'PRIVATE';

    if (!isPublic) return findings; // Only check public APIs

    let hasAuthorizer = false;
    try {
      const result: any = await retry(() =>
        this.client.apigateway.send(new GetAuthorizersCommand({ restApiId: apiId }))
      );
      hasAuthorizer = (result.items ?? []).length > 0;
    } catch (error) {
      logger.debug(`Failed to check authorizers for API ${apiId}`, { error: (error as Error).message });
    }

    if (!hasAuthorizer) {
      findings.push(this.emit(
        'apigateway_restapi_public_with_authorizer',
        { resourceId: apiId, apiName, apiId, hasAuthorizer: false },
        {
          message: `API Gateway REST API "${apiName}" is internet-accessible but has no authorizer configured. ` +
            `Without authentication, anonymous callers can invoke methods and access/modify backend data.`,
          remediation: `Attach an authorizer (Lambda, Cognito, or API key) to the API or its methods: ` +
            `aws apigateway create-authorizer --rest-api-id ${apiId} --name <authorizer-name> --type TOKEN --authorizer-uri <lambda-uri>`,
        }
      ));
    }
    return findings;
  }

  private async checkStageVariablesForSecrets(apiName: string, apiId: string, stageName: string, variables: Record<string, string>): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const secretHits: string[] = [];
    const variableNames = Object.keys(variables);

    for (let varIndex = 0; varIndex < variableNames.length; varIndex++) {
      const varName = variableNames[varIndex];
      const varValue = variables[varName];
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.regex.test(varValue)) {
          secretHits.push(`${pattern.type} in variable "${varName}"`);
        }
      }
    }

    if (secretHits.length > 0) {
      findings.push(this.emit(
        'apigateway_restapi_no_secrets_in_stage_variables',
        { resourceId: `${apiId}::${stageName}`, apiName, apiId, stageName, secretTypes: secretHits },
        {
          message: `API Gateway REST API "${apiName}" stage "${stageName}" contains potential ${secretHits.length > 1 ? 'secrets' : 'secret'} in stage variables: ${secretHits.join(', ')}. ` +
            `Hardcoded credentials can be viewed by anyone with read access to the API configuration.`,
          remediation: `Remove secrets from stage variables and store them in AWS Secrets Manager or Parameter Store. Reference them via Lambda authorizers or integration request mapping templates.`,
        }
      ));
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
      findings.push(this.emit(
        'apigateway_restapi_public_with_authorizer',
        { resourceId: `${apiId}::unauth-methods`, apiName, apiId, methodCount: openMethods.length, sample: openMethods.slice(0, 10) },
        {
          message: `API "${apiName}" has ${openMethods.length} method(s) with authorizationType=NONE and no API key required: ${sample}${openMethods.length > 5 ? '...' : ''}. ` +
            `These endpoints are publicly invokable without authentication.`,
        }
      ));
    }
    return findings;
  }
}

export default APIGatewayScanner;
