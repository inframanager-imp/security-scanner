import {
  ListFunctionsCommand,
  GetFunctionCommand,
  GetPolicyCommand,
  ListAliasesCommand,
  GetFunctionConcurrencyCommand,
  FunctionConfiguration,
} from '@aws-sdk/client-lambda';
import AdmZip from 'adm-zip';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// EOL runtimes — no longer receive security patches
const EOL_RUNTIMES = new Set([
  'nodejs4.3',
  'nodejs6.10',
  'nodejs8.10',
  'nodejs10.x',
  'python2.7',
  'python3.6',
  'ruby2.5',
  'java8',
  'dotnet5.0',
  'dotnetcore1.0',
  'dotnetcore2.0',
  'dotnetcore2.1',
]);

// Deprecated runtimes — still running but approaching EOL
const DEPRECATED_RUNTIMES = new Set([
  'nodejs12.x',
  'nodejs14.x',
  'nodejs16.x',
  'python3.7',
  'python3.8',
  'ruby2.7',
  'java8.al2',
  'dotnet6',
  'dotnetcore3.1',
  'go1.x',
]);

const SENSITIVE_KEY_PATTERN =
  /password|passwd|pwd|secret|api_key|apikey|token|credential|cred|private_key|auth|access_key|secret_key/i;

const SAFE_VALUE_PREFIXES = ['arn:', '${', 'ssm:', 'secretsmanager:'];

const SENSITIVE_FUNCTION_NAME_PATTERN =
  /db|database|rds|aurora|redis|cache|private|internal|secure|payment|billing|auth/i;

const MAX_PACKAGES_TO_CHECK = 50;
const MAX_ZIP_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB

async function queryOSV(
  packageName: string,
  version: string,
  ecosystem: string
): Promise<any[]> {
  try {
    const resp = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        version,
        package: { name: packageName, ecosystem },
      }),
    });
    if (!resp.ok) return [];
    const data = (await resp.json()) as { vulns?: any[] };
    return data.vulns ?? [];
  } catch {
    return [];
  }
}

function stripVersionPrefix(version: string): string {
  return version.replace(/^[~^>=~=]+/, '').trim();
}

function isSkippableVersion(version: string): boolean {
  if (!version) return true;
  if (version === 'latest') return true;
  if (version.startsWith('git+')) return true;
  // ^ without numeric prefix (e.g. just "^" or "^abc")
  if (/^\^[^0-9]/.test(version)) return true;
  if (version.includes('*')) return true;
  return false;
}

function mapOSVSeverity(vuln: any): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  // Check database_specific severity
  const dbSeverity = vuln.database_specific?.severity as string | undefined;
  if (dbSeverity === 'CRITICAL') return 'CRITICAL';
  if (dbSeverity === 'HIGH') return 'HIGH';
  if (dbSeverity === 'MEDIUM') return 'MEDIUM';
  if (dbSeverity === 'LOW') return 'LOW';

  // Check CVSS scores from severity array
  if (Array.isArray(vuln.severity)) {
    let maxScore = 0;
    for (const s of vuln.severity) {
      if (s.type === 'CVSS_V3' || s.type === 'CVSS_V2') {
        // CVSS score is in s.score as a string like "CVSS:3.1/AV:N/..."
        // Try to extract base score from database_specific or affected
        const scoreMatch = String(s.score ?? '').match(/(\d+\.\d+)$/);
        if (scoreMatch) {
          const score = parseFloat(scoreMatch[1]);
          if (score > maxScore) maxScore = score;
        }
      }
    }
    if (maxScore >= 9.0) return 'CRITICAL';
    if (maxScore >= 7.0) return 'HIGH';
    if (maxScore >= 4.0) return 'MEDIUM';
    if (maxScore > 0) return 'LOW';
  }

  return 'MEDIUM';
}

export class LambdaScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'Lambda');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      logger.info('Starting Lambda security scan...');
      const functions = await this.listAllFunctions();
      logger.info(`Found ${functions.length} Lambda functions to scan`);

      for (const fn of functions) {
        const fnName = fn.FunctionName ?? 'Unknown';
        logger.debug(`Scanning Lambda function: ${fnName}`);

        findings.push(...this.checkRuntime(fn));
        findings.push(...this.checkEnvironmentVariables(fn));
        findings.push(...this.checkFunctionConfig(fn));

        try {
          findings.push(...(await this.checkFunctionPolicy(fn)));
        } catch (err) {
          logger.debug(`Policy check failed for ${fnName}`, {
            error: (err as Error).message,
          });
        }

        try {
          findings.push(...(await this.checkDependencyVulnerabilities(fn)));
        } catch (err) {
          logger.debug(`Dependency check failed for ${fnName}`, {
            error: (err as Error).message,
          });
        }

        try {
          findings.push(...(await this.checkConcurrencyLimit(fn)));
        } catch (err) {
          logger.debug(`Concurrency check failed for ${fnName}`, {
            error: (err as Error).message,
          });
        }

        try {
          findings.push(...(await this.checkAliasesPointToLatest(fn)));
        } catch (err) {
          logger.debug(`Alias check failed for ${fnName}`, {
            error: (err as Error).message,
          });
        }
      }

      logger.info(`Lambda scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Lambda scan failed', { error: (error as Error).message });
    }
    return findings;
  }

  private async listAllFunctions(): Promise<FunctionConfiguration[]> {
    const allFunctions: FunctionConfiguration[] = [];
    let marker: string | undefined;

    do {
      const result = await retry(async () => {
        return await this.client.lambda.send(
          new ListFunctionsCommand({ Marker: marker })
        );
      });

      if (result.Functions) {
        allFunctions.push(...result.Functions);
      }

      marker = result.NextMarker;
    } while (marker);

    return allFunctions;
  }

  private checkRuntime(fn: FunctionConfiguration): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const runtime = fn.Runtime;
    const fnName = fn.FunctionName ?? 'Unknown';

    if (!runtime) {
      // Custom runtime (provided.*) — skip
      return findings;
    }

    if (EOL_RUNTIMES.has(runtime)) {
      findings.push(
        this.createFinding(
          'Lambda EOL Runtime',
          `Function "${fnName}" uses runtime "${runtime}" which is end-of-life and no longer receives security patches.`,
          'CRITICAL',
          { functionName: fnName, runtime, arn: fn.FunctionArn },
          `Upgrade function "${fnName}" to a supported runtime immediately. EOL runtimes have known unpatched vulnerabilities.`,
          ['lambda', 'runtime', 'eol', 'cis']
        )
      );
    } else if (DEPRECATED_RUNTIMES.has(runtime)) {
      findings.push(
        this.createFinding(
          'Lambda Deprecated Runtime',
          `Function "${fnName}" uses runtime "${runtime}" which is deprecated and will reach end-of-life soon.`,
          'HIGH',
          { functionName: fnName, runtime, arn: fn.FunctionArn },
          `Upgrade function "${fnName}" to a current runtime (e.g. nodejs20.x, python3.12, java21, dotnet8).`,
          ['lambda', 'runtime', 'deprecated']
        )
      );
    }

    return findings;
  }

  private checkEnvironmentVariables(fn: FunctionConfiguration): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';
    const variables = fn.Environment?.Variables;

    if (!variables) {
      return findings;
    }

    const suspiciousKeys: string[] = [];

    for (const [keyName, value] of Object.entries(variables)) {
      if (!SENSITIVE_KEY_PATTERN.test(keyName)) continue;
      if (!value) continue;

      const isSafeRef = SAFE_VALUE_PREFIXES.some((prefix) =>
        value.startsWith(prefix)
      );
      if (isSafeRef) continue;

      suspiciousKeys.push(keyName);
    }

    if (suspiciousKeys.length > 0) {
      // Aggregate all suspicious keys into one finding
      const firstKey = suspiciousKeys[0];
      findings.push(
        this.createFinding(
          'Lambda Sensitive Environment Variable',
          `Function "${fnName}" has environment variable "${firstKey}" that may contain a hardcoded secret. Hardcoded credentials are a critical security risk.`,
          'HIGH',
          {
            functionName: fnName,
            variableName: firstKey,
            variableNames: suspiciousKeys,
            arn: fn.FunctionArn,
          },
          `Move the value of "${firstKey}" to AWS Secrets Manager or SSM Parameter Store and reference it at runtime.`,
          [
            'lambda',
            'secrets',
            'environment-variables',
            'hardcoded-credentials',
          ]
        )
      );
    }

    return findings;
  }

  private async checkFunctionPolicy(
    fn: FunctionConfiguration
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    let policyJson: string | undefined;
    try {
      const result = await retry(async () => {
        return await this.client.lambda.send(
          new GetPolicyCommand({ FunctionName: fn.FunctionArn! })
        );
      });
      policyJson = result.Policy;
    } catch (err) {
      const errName = (err as any)?.name ?? '';
      const errMsg = (err as Error).message ?? '';
      // No policy means the function is private — that's fine
      if (
        errName === 'ResourceNotFoundException' ||
        errName === 'GetPolicyException' ||
        errMsg.includes('ResourceNotFoundException') ||
        errMsg.includes('No policy is associated')
      ) {
        return findings;
      }
      throw err;
    }

    if (!policyJson) {
      return findings;
    }

    let policy: any;
    try {
      policy = JSON.parse(policyJson);
    } catch {
      logger.warn(`Could not parse policy JSON for function ${fnName}`);
      return findings;
    }

    const statements: any[] = policy.Statement ?? [];
    for (const stmt of statements) {
      if (stmt.Effect !== 'Allow') continue;

      const principal = stmt.Principal;
      const isPublic =
        principal === '*' ||
        principal?.AWS === '*' ||
        (Array.isArray(principal?.AWS) && principal.AWS.includes('*'));

      if (isPublic) {
        findings.push(
          this.createFinding(
            'Lambda Public Function',
            `Function "${fnName}" has a resource-based policy that allows public invocation from any principal ("*").`,
            'HIGH',
            {
              functionName: fnName,
              arn: fn.FunctionArn,
              statement: stmt,
            },
            `Remove or restrict the resource-based policy on "${fnName}" to only allow specific AWS accounts, services, or principals.`,
            ['lambda', 'public-access', 'policy']
          )
        );
      }
    }

    return findings;
  }

  private checkFunctionConfig(fn: FunctionConfiguration): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    // a) No dead-letter queue
    if (!fn.DeadLetterConfig?.TargetArn) {
      findings.push(
        this.createFinding(
          'Lambda No Dead Letter Queue',
          `Function "${fnName}" has no dead-letter queue (DLQ) configured. Failed async invocations will be silently dropped.`,
          'LOW',
          { functionName: fnName, arn: fn.FunctionArn },
          `Configure an SQS queue or SNS topic as the dead-letter queue for "${fnName}" to capture and reprocess failed invocations.`,
          ['lambda', 'reliability', 'dlq']
        )
      );
    }

    // b) No VPC — only flag if function name suggests sensitive data
    if (
      !fn.VpcConfig?.VpcId &&
      SENSITIVE_FUNCTION_NAME_PATTERN.test(fn.FunctionName ?? '')
    ) {
      findings.push(
        this.createFinding(
          'Lambda Sensitive Function Not in VPC',
          `Function "${fnName}" appears to handle sensitive operations but is not configured to run inside a VPC.`,
          'MEDIUM',
          { functionName: fnName, arn: fn.FunctionArn },
          `Configure VPC settings for "${fnName}" to restrict network access to private subnets.`,
          ['lambda', 'vpc', 'network-isolation']
        )
      );
    }

    // c) No code signing
    if (!(fn as Record<string, unknown>).CodeSigningConfigArn) {
      findings.push(
        this.createFinding(
          'Lambda No Code Signing',
          `Function "${fnName}" does not have code signing configured. Unsigned code can be deployed without verification.`,
          'LOW',
          { functionName: fnName, arn: fn.FunctionArn },
          `Enable code signing for "${fnName}" using AWS Signer to ensure only trusted code is deployed.`,
          ['lambda', 'code-signing', 'integrity']
        )
      );
    }

    return findings;
  }

  private async checkDependencyVulnerabilities(
    fn: FunctionConfiguration
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';
    const runtime = fn.Runtime ?? '';

    // Only handle Node.js and Python runtimes
    const isNode = runtime.startsWith('nodejs');
    const isPython = runtime.startsWith('python');
    if (!isNode && !isPython) {
      return findings;
    }

    // a) Download deployment package URL
    let fnDetail: any;
    try {
      fnDetail = await retry(async () => {
        return await this.client.lambda.send(
          new GetFunctionCommand({ FunctionName: fn.FunctionArn! })
        );
      });
    } catch (err) {
      logger.debug(`Could not get function detail for ${fnName}`, {
        error: (err as Error).message,
      });
      return findings;
    }

    const downloadUrl = fnDetail.Code?.Location;
    if (!downloadUrl) return [];

    // b) Download the zip
    let buffer: Buffer;
    try {
      const response = await fetch(downloadUrl);
      if (!response.ok) {
        logger.debug(
          `Failed to download zip for ${fnName}: HTTP ${response.status}`
        );
        return findings;
      }
      buffer = Buffer.from(await response.arrayBuffer());
    } catch (err) {
      logger.debug(`Zip download failed for ${fnName}`, {
        error: (err as Error).message,
      });
      return findings;
    }

    // Check zip size limit
    if (buffer.byteLength > MAX_ZIP_SIZE_BYTES) {
      findings.push(
        this.createFinding(
          'Lambda Package Too Large for Analysis',
          `Function "${fnName}" deployment package exceeds 50 MB and was skipped for dependency vulnerability analysis.`,
          'INFO',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            sizeBytes: buffer.byteLength,
          },
          `Consider breaking the function into smaller deployment packages or using Lambda layers to reduce package size.`,
          ['lambda', 'package-size']
        )
      );
      return findings;
    }

    // c) Parse dependencies based on runtime
    let packages: Array<{ name: string; version: string }> = [];
    let ecosystem: string;

    try {
      const zip = new AdmZip(buffer);
      const entries = zip.getEntries();

      if (isNode) {
        ecosystem = 'npm';
        // Find root-level package.json (not inside node_modules)
        const pkgEntry = entries.find((e) => {
          const name = e.entryName;
          return (
            (name === 'package.json' || name.endsWith('/package.json')) &&
            !name.includes('node_modules/')
          );
        });

        if (!pkgEntry) {
          return findings;
        }

        let pkgJson: any;
        try {
          pkgJson = JSON.parse(pkgEntry.getData().toString('utf-8'));
        } catch {
          logger.debug(`Could not parse package.json for ${fnName}`);
          return findings;
        }

        const deps: Record<string, string> = {
          ...(pkgJson.dependencies ?? {}),
          ...(pkgJson.devDependencies ?? {}),
        };

        for (const [name, version] of Object.entries(deps)) {
          packages.push({ name, version: String(version) });
        }
      } else if (isPython) {
        ecosystem = 'PyPI';
        // Find root-level requirements.txt
        const reqEntry = entries.find(
          (e) =>
            e.entryName === 'requirements.txt' ||
            e.entryName.endsWith('/requirements.txt')
        );

        if (!reqEntry) {
          return findings;
        }

        const lines = reqEntry.getData().toString('utf-8').split('\n');
        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line || line.startsWith('#')) continue;

          // Strip inline comments
          const commentIdx = line.indexOf('#');
          const cleanLine = commentIdx >= 0 ? line.slice(0, commentIdx).trim() : line;
          if (!cleanLine) continue;

          // Parse package==version, package>=version, package~=version
          const eqMatch = cleanLine.match(/^([A-Za-z0-9_\-\.]+)\s*[=~><!]+\s*([^\s,;]+)/);
          if (eqMatch) {
            packages.push({ name: eqMatch[1], version: eqMatch[2] });
          } else {
            // Package with no version specified — skip
            const nameOnly = cleanLine.match(/^([A-Za-z0-9_\-\.]+)$/);
            if (nameOnly) {
              // No version, can't query OSV reliably
              continue;
            }
          }
        }
      } else {
        return findings;
      }
    } catch (err) {
      logger.debug(`Failed to parse zip for ${fnName}`, {
        error: (err as Error).message,
      });
      return findings;
    }

    if (packages.length === 0) {
      return findings;
    }

    // Cap to 50 packages
    if (packages.length > MAX_PACKAGES_TO_CHECK) {
      packages = packages.slice(0, MAX_PACKAGES_TO_CHECK);
    }

    // d) Query OSV for each package
    for (const pkg of packages) {
      const rawVersion = pkg.version;

      if (isSkippableVersion(rawVersion)) {
        continue;
      }

      const version = stripVersionPrefix(rawVersion);
      if (!version) continue;

      const vulns = await queryOSV(pkg.name, version, ecosystem!);

      for (const vuln of vulns) {
        const vulnId: string = vuln.id ?? 'UNKNOWN';
        const severity = mapOSVSeverity(vuln);

        findings.push(
          this.createFinding(
            'Lambda Vulnerable Dependency',
            `Function "${fnName}" uses ${pkg.name}@${version} which has known vulnerability ${vulnId}: ${vuln.summary ?? 'See advisory for details'}.`,
            severity,
            {
              // resourceId is checked first by the dedup fingerprint — unique per (function, CVE)
              // so multiple CVEs in the same function each get their own DB record.
              resourceId: `${fnName}::${vulnId}`,
              lambdaFunction: fnName,   // renamed from functionName to avoid fingerprint collision
              arn: fn.FunctionArn,
              package: pkg.name,
              version,
              vulnId,
              summary: vuln.summary,
              runtime: fn.Runtime,
            },
            `Update ${pkg.name} to a patched version. See: https://osv.dev/vulnerability/${vulnId}`,
            ['lambda', 'vulnerable-dependency', 'cve', ecosystem!.toLowerCase()]
          )
        );
      }

      // Be respectful to the OSV API
      await new Promise((r) => setTimeout(r, 100));
    }

    return findings;
  }

  private async checkConcurrencyLimit(
    fn: FunctionConfiguration
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    // Only flag for functions whose name hints at sensitive/expensive work
    if (!SENSITIVE_FUNCTION_NAME_PATTERN.test(fnName)) {
      return findings;
    }

    let reserved: number | undefined;
    try {
      const result = await retry(async () => {
        return await this.client.lambda.send(
          new GetFunctionConcurrencyCommand({ FunctionName: fn.FunctionArn! })
        );
      });
      reserved = result.ReservedConcurrentExecutions;
    } catch (err) {
      logger.debug(`GetFunctionConcurrency failed for ${fnName}`, {
        error: (err as Error).message,
      });
      return findings;
    }

    if (reserved === undefined) {
      findings.push(
        this.createFinding(
          'Lambda Sensitive Function Has No Reserved Concurrency',
          `Function "${fnName}" appears to perform sensitive or expensive operations but has no reserved concurrency. A burst of invocations can exhaust the account concurrency pool and cause downstream throttling or cost spikes.`,
          'LOW',
          { functionName: fnName, arn: fn.FunctionArn },
          `Set a reserved concurrency limit for "${fnName}" to bound its blast radius: aws lambda put-function-concurrency --function-name ${fnName} --reserved-concurrent-executions <N>.`,
          ['lambda', 'concurrency', 'reliability']
        )
      );
    }
    return findings;
  }

  private async checkAliasesPointToLatest(
    fn: FunctionConfiguration
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    let aliases: any[] = [];
    try {
      const result = await retry(async () => {
        return await this.client.lambda.send(
          new ListAliasesCommand({ FunctionName: fn.FunctionArn! })
        );
      });
      aliases = result.Aliases ?? [];
    } catch (err) {
      logger.debug(`ListAliases failed for ${fnName}`, {
        error: (err as Error).message,
      });
      return findings;
    }

    const pointingToLatest = aliases.filter(a => a.FunctionVersion === '$LATEST');
    if (pointingToLatest.length > 0) {
      const aliasNames = pointingToLatest.map(a => a.Name).join(', ');
      findings.push(
        this.createFinding(
          'Lambda Alias Points to $LATEST',
          `Function "${fnName}" has ${pointingToLatest.length} alias(es) pointing to $LATEST: ${aliasNames}. Aliases should point to a numbered version so deployments are immutable and rollback is possible.`,
          'LOW',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            aliases: pointingToLatest.map(a => a.Name),
          },
          `Publish a numbered version and update each alias to point at it: aws lambda update-alias --function-name ${fnName} --name <alias> --function-version <N>.`,
          ['lambda', 'alias', 'release-management']
        )
      );
    }
    return findings;
  }
}

export default LambdaScanner;
