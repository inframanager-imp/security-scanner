// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  AmplifyClient,
  ListAppsCommand,
  ListBranchesCommand,
} from '@aws-sdk/client-amplify';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Name-based heuristic consistent with other scanners in this codebase
// (Prowler uses a detect-secrets engine; we approximate with sensitive-name matching).
const SENSITIVE_KEY_PATTERN =
  /password|passwd|pwd|secret|api[_-]?key|apikey|token|credential|cred|private[_-]?key|access[_-]?key|secret[_-]?key|auth/i;

// Values that reference a secure store or are substituted at deploy time are not hardcoded secrets
const SAFE_VALUE_PREFIXES = ['arn:', '${', 'ssm:', 'secretsmanager:'];

// buildSpec lines like "MY_API_KEY: abc123..." or "PASSWORD=..." with a literal value
const BUILDSPEC_SECRET_LINE =
  /(password|passwd|pwd|secret|api[_-]?key|apikey|token|credential|private[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*['"]?([^\s'"$]{8,})/i;

function isHardcodedSecretValue(value: string | undefined): boolean {
  if (!value) return false;
  return !SAFE_VALUE_PREFIXES.some((prefix) => value.startsWith(prefix));
}

export class AmplifyScanner extends BaseScanner {
  private amplify: AmplifyClient;

  constructor(client: AWSClient) {
    super(client, 'Amplify');
    this.amplify = new AmplifyClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Amplify security scan...');

      const apps = await this.listApps();
      for (const app of apps) {
        const appName: string = app.name ?? app.appId ?? 'unknown';
        logger.debug(`Scanning Amplify app: ${appName}`);
        try {
          findings.push(...await this.validateApp(app));
        } catch (error) {
          logger.debug(`Failed to scan Amplify app ${appName}`, { error: (error as Error).message });
        }
      }

      logger.info(`Amplify scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Amplify scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listApps(): Promise<any[]> {
    const apps: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.amplify.send(new ListAppsCommand({ nextToken }));
      });
      apps.push(...(result.apps ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return apps;
  }

  private async listBranches(appId: string): Promise<any[]> {
    const branches: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.amplify.send(new ListBranchesCommand({ appId, nextToken }));
      });
      branches.push(...(result.branches ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return branches;
  }

  private async validateApp(app: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const appName: string = app.name ?? app.appId ?? 'unknown';

    // amplify_app_no_secrets_in_environment: no hardcoded secrets in env vars or build settings
    const suspiciousContexts: string[] = [];

    // App environment variables
    const appEnvVars: Record<string, string> = app.environmentVariables ?? {};
    for (const [varName, varValue] of Object.entries(appEnvVars)) {
      if (SENSITIVE_KEY_PATTERN.test(varName) && isHardcodedSecretValue(varValue)) {
        suspiciousContexts.push(`app environment variable '${varName}'`);
      }
    }

    // App buildSpec lines
    const buildSpec: string = app.buildSpec ?? '';
    if (buildSpec) {
      const lines = buildSpec.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(BUILDSPEC_SECRET_LINE);
        if (match && isHardcodedSecretValue(match[2])) {
          suspiciousContexts.push(`app buildSpec line ${i + 1}`);
        }
      }
    }

    // Branch environment variables
    if (app.appId) {
      let branches: any[] = [];
      try {
        branches = await this.listBranches(app.appId);
      } catch (error) {
        logger.debug(`Failed to list branches for Amplify app ${appName}`, { error: (error as Error).message });
      }
      for (const branch of branches) {
        const branchName: string = branch.branchName ?? 'unknown';
        const branchEnvVars: Record<string, string> = branch.environmentVariables ?? {};
        for (const [varName, varValue] of Object.entries(branchEnvVars)) {
          if (SENSITIVE_KEY_PATTERN.test(varName) && isHardcodedSecretValue(varValue)) {
            suspiciousContexts.push(`branch '${branchName}' environment variable '${varName}'`);
          }
        }
      }
    }

    if (suspiciousContexts.length > 0) {
      findings.push(this.emit(
        'amplify_app_no_secrets_in_environment',
        {
          appId: app.appId,
          appName,
          arn: app.appArn,
          suspiciousContexts,
        },
        {
          message: `Potential ${suspiciousContexts.length > 1 ? 'secrets' : 'secret'} found in Amplify app "${appName}" environment variables or build settings -> ${suspiciousContexts.join(', ')}`,
          remediation: `Move the flagged values in Amplify app "${appName}" to AWS Secrets Manager or SSM Parameter Store and reference them securely during the build`,
        }
      ));
    }

    return findings;
  }
}

export default AmplifyScanner;
