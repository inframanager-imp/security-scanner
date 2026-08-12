// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ListFunctionsCommand,
  GetFunctionCommand,
  GetPolicyCommand,
  ListAliasesCommand,
  GetFunctionConcurrencyCommand,
  GetFunctionUrlConfigCommand,
  FunctionConfiguration,
} from '@aws-sdk/client-lambda';
import { DescribeSubnetsCommand } from '@aws-sdk/client-ec2';
import {
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
} from '@aws-sdk/client-cloudtrail';
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

// awslambda_function_vpc_multi_az (Prowler default: lambda_min_azs = 2)
const LAMBDA_MIN_AZS = 2;

// Bounds for the in-code secrets scan (awslambda_function_no_secrets_in_code).
// Prowler extracts the whole package and runs its detect-secrets scanner over
// every file; this port scans a bounded number of text files per function.
const MAX_CODE_FILES_SCANNED = 200;
const MAX_CODE_FILE_BYTES = 512 * 1024; // per file
const MAX_CODE_TOTAL_BYTES = 10 * 1024 * 1024; // per function
const MAX_CODE_SECRET_MATCHES = 25; // evidence cap per function

// File extensions that cannot meaningfully contain scannable text secrets
const BINARY_FILE_EXTENSIONS = new Set([
  '.jar', '.class', '.so', '.dll', '.dylib', '.exe', '.bin', '.pyc', '.pyo',
  '.zip', '.gz', '.tar', '.tgz', '.bz2', '.xz', '.7z',
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pdf', '.wasm', '.node', '.o', '.a', '.lib', '.obj',
  '.mp3', '.mp4', '.avi', '.mov', '.wav',
]);

/**
 * Lightweight secret detection for function code. Prowler runs its
 * detect-secrets scanner over the extracted package; this is a conservative
 * regex port of the most common credential patterns (same approach as the
 * SageMaker scanner).
 */
const SECRET_PATTERNS: { type: string; regex: RegExp }[] = [
  { type: 'AWS Access Key ID', regex: /\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/ },
  { type: 'AWS Secret Access Key', regex: /aws_?secret_?access_?key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}\b/i },
  { type: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY/ },
  { type: 'Hardcoded Password', regex: /\b(password|passwd|pwd)\b\s*[=:]\s*['"][^'"]{4,}['"]/i },
  { type: 'Hardcoded Secret or Token', regex: /\b(secret|token|api[_-]?key|auth[_-]?key|access[_-]?token)\b\s*[=:]\s*['"][^'"]{8,}['"]/i },
  { type: 'Credentials in URL', regex: /[a-z][a-z0-9+.-]*:\/\/[^/\s:@'"]+:[^/\s:@'"]+@[^\s'"]+/i },
];

/** Result of downloading a function's deployment package, shared across checks. */
type FunctionCodeZip =
  | { status: 'ok'; buffer: Buffer }
  | { status: 'too-large'; sizeBytes: number }
  | { status: 'unavailable' };

/** Account-wide CloudTrail coverage of Lambda Invoke data events. */
interface LambdaTrailCoverage {
  /** false when trails could not be listed — the check is skipped, not failed */
  available: boolean;
  allFunctionsCovered: boolean;
  coveredArns: Set<string>;
  coveringTrail: string | null;
}

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

      // Shared state fetched once for the per-function checks below
      const trailCoverage = await this.getLambdaTrailCoverage();
      const subnetAzMap = functions.some((f) => f.VpcConfig?.VpcId)
        ? await this.getSubnetAzMap()
        : new Map<string, string>();
      let accountId: string | null = null;
      try {
        accountId = await this.client.getAccountId();
      } catch (err) {
        logger.debug('Could not resolve account ID; skipping cross-account layer check', {
          error: (err as Error).message,
        });
      }

      for (const fn of functions) {
        const fnName = fn.FunctionName ?? 'Unknown';
        logger.debug(`Scanning Lambda function: ${fnName}`);

        findings.push(...this.checkRuntime(fn));
        findings.push(...this.checkEnvironmentVariables(fn));
        findings.push(...this.checkFunctionConfig(fn));
        findings.push(...this.checkEnvVarsCmkEncryption(fn));
        findings.push(...this.checkVpcMultiAz(fn, subnetAzMap));
        findings.push(...this.checkCloudTrailInvokeLogging(fn, trailCoverage));
        if (accountId) {
          findings.push(...this.checkCrossAccountLayers(fn, accountId));
        }

        try {
          findings.push(...(await this.checkFunctionPolicy(fn)));
        } catch (err) {
          logger.debug(`Policy check failed for ${fnName}`, {
            error: (err as Error).message,
          });
        }

        try {
          findings.push(...(await this.checkFunctionUrl(fn)));
        } catch (err) {
          logger.debug(`Function URL check failed for ${fnName}`, {
            error: (err as Error).message,
          });
        }

        // The deployment package is downloaded once and shared by the
        // dependency vulnerability check and the in-code secrets check.
        let codeZip: FunctionCodeZip = { status: 'unavailable' };
        try {
          codeZip = await this.downloadFunctionCode(fn);
        } catch (err) {
          logger.debug(`Code download failed for ${fnName}`, {
            error: (err as Error).message,
          });
        }

        try {
          findings.push(...(await this.checkDependencyVulnerabilities(fn, codeZip)));
        } catch (err) {
          logger.debug(`Dependency check failed for ${fnName}`, {
            error: (err as Error).message,
          });
        }

        try {
          findings.push(...this.checkCodeSecrets(fn, codeZip));
        } catch (err) {
          logger.debug(`Code secrets check failed for ${fnName}`, {
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
        this.emit(
          'awslambda_function_using_supported_runtimes',
          { functionName: fnName, runtime, arn: fn.FunctionArn },
          {
            message: `Function "${fnName}" uses runtime "${runtime}" which is end-of-life and no longer receives security patches.`,
            remediation: `Upgrade function "${fnName}" to a supported runtime immediately. EOL runtimes have known unpatched vulnerabilities.`,
          }
        )
      );
    } else if (DEPRECATED_RUNTIMES.has(runtime)) {
      findings.push(
        this.emit(
          'lambda_function_deprecated_runtime',
          { functionName: fnName, runtime, arn: fn.FunctionArn },
          {
            message: `Function "${fnName}" uses runtime "${runtime}" which is deprecated and will reach end-of-life soon.`,
            remediation: `Upgrade function "${fnName}" to a current runtime (e.g. nodejs20.x, python3.12, java21, dotnet8).`,
          }
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
        this.emit(
          'awslambda_function_no_secrets_in_variables',
          {
            functionName: fnName,
            variableName: firstKey,
            variableNames: suspiciousKeys,
            arn: fn.FunctionArn,
          },
          {
            message: `Function "${fnName}" has environment variable "${firstKey}" that may contain a hardcoded secret. Hardcoded credentials are a critical security risk.`,
            remediation: `Move the value of "${firstKey}" to AWS Secrets Manager or SSM Parameter Store and reference it at runtime.`,
          }
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
          this.emit(
            'awslambda_function_not_publicly_accessible',
            {
              functionName: fnName,
              arn: fn.FunctionArn,
              statement: stmt,
            },
            {
              message: `Function "${fnName}" has a resource-based policy that allows public invocation from any principal ("*").`,
              remediation: `Remove or restrict the resource-based policy on "${fnName}" to only allow specific AWS accounts, services, or principals.`,
            }
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
        this.emit(
          'awslambda_function_no_dead_letter_queue',
          { functionName: fnName, arn: fn.FunctionArn },
          {
            message: `Function "${fnName}" has no dead-letter queue (DLQ) configured. Failed async invocations will be silently dropped.`,
            remediation: `Configure an SQS queue or SNS topic as the dead-letter queue for "${fnName}" to capture and reprocess failed invocations.`,
          }
        )
      );
    }

    // b) No VPC — only flag if function name suggests sensitive data
    if (
      !fn.VpcConfig?.VpcId &&
      SENSITIVE_FUNCTION_NAME_PATTERN.test(fn.FunctionName ?? '')
    ) {
      findings.push(
        this.emit(
          'awslambda_function_inside_vpc',
          { functionName: fnName, arn: fn.FunctionArn },
          {
            message: `Function "${fnName}" appears to handle sensitive operations but is not configured to run inside a VPC.`,
            remediation: `Configure VPC settings for "${fnName}" to restrict network access to private subnets.`,
          }
        )
      );
    }

    // c) No code signing
    if (!(fn as Record<string, unknown>).CodeSigningConfigArn) {
      findings.push(
        this.emit(
          'lambda_function_code_signing_enabled',
          { functionName: fnName, arn: fn.FunctionArn },
          {
            message: `Function "${fnName}" does not have code signing configured. Unsigned code can be deployed without verification.`,
            remediation: `Enable code signing for "${fnName}" using AWS Signer to ensure only trusted code is deployed.`,
          }
        )
      );
    }

    return findings;
  }

  private async checkDependencyVulnerabilities(
    fn: FunctionConfiguration,
    codeZip: FunctionCodeZip
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

    if (codeZip.status === 'too-large') {
      findings.push(
        this.emit(
          'lambda_function_package_too_large',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            sizeBytes: codeZip.sizeBytes,
          },
          {
            message: `Function "${fnName}" deployment package exceeds 50 MB and was skipped for dependency vulnerability analysis.`,
          }
        )
      );
      return findings;
    }
    if (codeZip.status !== 'ok') {
      return findings;
    }
    const buffer = codeZip.buffer;

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
          this.emit(
            'lambda_function_vulnerable_dependency',
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
            {
              message: `Function "${fnName}" uses ${pkg.name}@${version} which has known vulnerability ${vulnId}: ${vuln.summary ?? 'See advisory for details'}.`,
              remediation: `Update ${pkg.name} to a patched version. See: https://osv.dev/vulnerability/${vulnId}`,
              severity,
              tags: [ecosystem!.toLowerCase()],
            }
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
        this.emit(
          'lambda_function_no_reserved_concurrency',
          { functionName: fnName, arn: fn.FunctionArn },
          {
            message: `Function "${fnName}" appears to perform sensitive or expensive operations but has no reserved concurrency. A burst of invocations can exhaust the account concurrency pool and cause downstream throttling or cost spikes.`,
            remediation: `Set a reserved concurrency limit for "${fnName}" to bound its blast radius: aws lambda put-function-concurrency --function-name ${fnName} --reserved-concurrent-executions <N>.`,
          }
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
        this.emit(
          'lambda_function_alias_points_to_latest',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            aliases: pointingToLatest.map(a => a.Name),
          },
          {
            message: `Function "${fnName}" has ${pointingToLatest.length} alias(es) pointing to $LATEST: ${aliasNames}. Aliases should point to a numbered version so deployments are immutable and rollback is possible.`,
            remediation: `Publish a numbered version and update each alias to point at it: aws lambda update-alias --function-name ${fnName} --name <alias> --function-version <N>.`,
          }
        )
      );
    }
    return findings;
  }

  /**
   * Download the function's deployment package once so the dependency and
   * in-code secrets checks can share it. Image-based functions (no
   * Code.Location) resolve to 'unavailable'.
   */
  private async downloadFunctionCode(
    fn: FunctionConfiguration
  ): Promise<FunctionCodeZip> {
    const fnName = fn.FunctionName ?? 'Unknown';

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
      return { status: 'unavailable' };
    }

    const downloadUrl = fnDetail.Code?.Location;
    if (!downloadUrl) return { status: 'unavailable' };

    try {
      const response = await fetch(downloadUrl);
      if (!response.ok) {
        logger.debug(
          `Failed to download zip for ${fnName}: HTTP ${response.status}`
        );
        return { status: 'unavailable' };
      }
      const buffer = Buffer.from(await response.arrayBuffer());
      if (buffer.byteLength > MAX_ZIP_SIZE_BYTES) {
        return { status: 'too-large', sizeBytes: buffer.byteLength };
      }
      return { status: 'ok', buffer };
    } catch (err) {
      logger.debug(`Zip download failed for ${fnName}`, {
        error: (err as Error).message,
      });
      return { status: 'unavailable' };
    }
  }

  // awslambda_function_no_secrets_in_code: scan the deployment package's text
  // files for credential patterns. Bounded port of Prowler's detect-secrets
  // scan over the extracted package; only file names, secret types and line
  // numbers are reported — never the matched values.
  private checkCodeSecrets(
    fn: FunctionConfiguration,
    codeZip: FunctionCodeZip
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    if (codeZip.status !== 'ok') {
      if (codeZip.status === 'too-large') {
        logger.debug(
          `Skipping code secrets scan for ${fnName}: package exceeds ${MAX_ZIP_SIZE_BYTES} bytes`
        );
      }
      return findings;
    }

    const hits: { file: string; type: string; line: number }[] = [];
    let filesScanned = 0;
    let bytesScanned = 0;
    try {
      const zip = new AdmZip(codeZip.buffer);
      for (const entry of zip.getEntries()) {
        if (hits.length >= MAX_CODE_SECRET_MATCHES) break;
        if (filesScanned >= MAX_CODE_FILES_SCANNED) break;
        if (bytesScanned >= MAX_CODE_TOTAL_BYTES) break;
        if (entry.isDirectory) continue;

        const entryName = entry.entryName;
        const dotIndex = entryName.lastIndexOf('.');
        const ext = dotIndex >= 0 ? entryName.slice(dotIndex).toLowerCase() : '';
        if (BINARY_FILE_EXTENSIONS.has(ext)) continue;
        if (entry.header.size > MAX_CODE_FILE_BYTES) continue;

        let content: string;
        try {
          content = entry.getData().toString('latin1');
        } catch {
          continue;
        }
        filesScanned++;
        bytesScanned += content.length;

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          for (const pattern of SECRET_PATTERNS) {
            if (pattern.regex.test(lines[i])) {
              hits.push({ file: entryName, type: pattern.type, line: i + 1 });
            }
          }
          if (hits.length >= MAX_CODE_SECRET_MATCHES) break;
        }
      }
    } catch (err) {
      logger.debug(`Failed to scan code for secrets in ${fnName}`, {
        error: (err as Error).message,
      });
      return findings;
    }

    if (hits.length > 0) {
      const detail = hits
        .slice(0, 10)
        .map((h) => `${h.file}: ${h.type} on line ${h.line}`)
        .join('; ');
      findings.push(
        this.emit(
          'awslambda_function_no_secrets_in_code',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            filesScanned,
            secretTypes: [...new Set(hits.map((h) => h.type))],
            matches: hits,
          },
          {
            message: `Function "${fnName}" deployment package contains potential hardcoded secrets: ${detail}.`,
            remediation: `Remove the hardcoded values from the "${fnName}" code, rotate the exposed credentials, and load secrets at runtime from AWS Secrets Manager or SSM Parameter Store.`,
          }
        )
      );
    }

    return findings;
  }

  // awslambda_function_env_vars_not_encrypted_with_cmk: functions with
  // environment variables must encrypt them with a customer-managed KMS key.
  private checkEnvVarsCmkEncryption(fn: FunctionConfiguration): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    const variableCount = Object.keys(fn.Environment?.Variables ?? {}).length;
    if (variableCount === 0) return findings;

    if (!fn.KMSKeyArn) {
      findings.push(
        this.emit(
          'awslambda_function_env_vars_not_encrypted_with_cmk',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            environmentVariableCount: variableCount,
            kmsKeyArn: null,
          },
          {
            message: `Function "${fnName}" has ${variableCount} environment variable(s) encrypted with the default AWS-managed key instead of a customer-managed KMS key.`,
            remediation: `Associate a customer-managed KMS key with "${fnName}": aws lambda update-function-configuration --function-name ${fnName} --kms-key-arn <cmk-arn>.`,
          }
        )
      );
    }

    return findings;
  }

  // awslambda_function_using_cross_account_layers: every attached layer must be
  // published by the audited account (supply-chain risk otherwise).
  private checkCrossAccountLayers(
    fn: FunctionConfiguration,
    accountId: string
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    const crossAccountLayers: string[] = [];
    for (const layer of fn.Layers ?? []) {
      const layerArn: string = (layer as any).Arn ?? '';
      // Layer ARN: arn:aws:lambda:region:account-id:layer:name:version
      const parts = layerArn.split(':');
      const layerAccount = parts.length >= 5 ? parts[4] : '';
      if (layerAccount && layerAccount !== accountId) {
        crossAccountLayers.push(layerArn);
      }
    }

    if (crossAccountLayers.length > 0) {
      findings.push(
        this.emit(
          'awslambda_function_using_cross_account_layers',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            crossAccountLayers,
          },
          {
            message: `Function "${fnName}" uses ${crossAccountLayers.length} layer(s) published by another AWS account: ${crossAccountLayers.join(', ')}. A compromised external layer executes attacker code with this function's IAM role.`,
            remediation: `Republish the layer content in account ${accountId} and update "${fnName}" to reference the account-owned layer ARN via update-function-configuration --layers.`,
          }
        )
      );
    }

    return findings;
  }

  // awslambda_function_url_public / awslambda_function_url_cors_policy:
  // functions with a function URL must require IAM auth and must not allow
  // wildcard CORS origins.
  private async checkFunctionUrl(
    fn: FunctionConfiguration
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    let urlConfig: any;
    try {
      urlConfig = await retry(async () => {
        try {
          return await this.client.lambda.send(
            new GetFunctionUrlConfigCommand({ FunctionName: fn.FunctionArn! })
          );
        } catch (err) {
          // No function URL configured — nothing to check
          if ((err as any)?.name === 'ResourceNotFoundException') return null;
          throw err;
        }
      });
    } catch (err) {
      logger.debug(`GetFunctionUrlConfig failed for ${fnName}`, {
        error: (err as Error).message,
      });
      return findings;
    }
    if (!urlConfig) return findings;

    if (urlConfig.AuthType !== 'AWS_IAM') {
      findings.push(
        this.emit(
          'awslambda_function_url_public',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            functionUrl: urlConfig.FunctionUrl,
            authType: urlConfig.AuthType ?? 'NONE',
          },
          {
            message: `Function "${fnName}" has a function URL with auth type "${urlConfig.AuthType ?? 'NONE'}" that allows unauthenticated public invocation.`,
            remediation: `Require IAM authentication on the function URL: aws lambda update-function-url-config --function-name ${fnName} --auth-type AWS_IAM.`,
          }
        )
      );
    }

    const allowOrigins: string[] = urlConfig.Cors?.AllowOrigins ?? [];
    if (allowOrigins.includes('*')) {
      findings.push(
        this.emit(
          'awslambda_function_url_cors_policy',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            functionUrl: urlConfig.FunctionUrl,
            allowOrigins,
          },
          {
            message: `Function "${fnName}" function URL CORS policy allows any origin ("*"), letting any website invoke it from a browser and read responses.`,
            remediation: `Restrict the URL's allowed origins to trusted domains: aws lambda update-function-url-config --function-name ${fnName} --cors AllowOrigins=https://<trusted-domain>.`,
          }
        )
      );
    }

    return findings;
  }

  // awslambda_function_vpc_multi_az: VPC-attached functions must have subnets
  // spanning at least LAMBDA_MIN_AZS Availability Zones. Functions not in a VPC
  // fail here too (as in Prowler) unless awslambda_function_inside_vpc already
  // flagged them (sensitive name pattern), to avoid duplicate reports.
  private checkVpcMultiAz(
    fn: FunctionConfiguration,
    subnetAzMap: Map<string, string> | null
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const fnName = fn.FunctionName ?? 'Unknown';

    const vpcId = fn.VpcConfig?.VpcId;
    if (!vpcId) {
      if (SENSITIVE_FUNCTION_NAME_PATTERN.test(fnName)) return findings;
      findings.push(
        this.emit(
          'awslambda_function_vpc_multi_az',
          { functionName: fnName, arn: fn.FunctionArn, vpcId: null, availabilityZones: [] },
          {
            message: `Function "${fnName}" is not attached to a VPC, so it cannot span multiple Availability Zones.`,
            remediation: `Attach "${fnName}" to a VPC with subnets in at least ${LAMBDA_MIN_AZS} different Availability Zones via update-function-configuration --vpc-config.`,
          }
        )
      );
      return findings;
    }

    // Subnet->AZ lookup unavailable: skip rather than emit false positives
    if (!subnetAzMap) return findings;

    const azs = new Set<string>();
    for (const subnetId of fn.VpcConfig?.SubnetIds ?? []) {
      const az = subnetAzMap.get(subnetId);
      if (az) azs.add(az);
    }

    if (azs.size < LAMBDA_MIN_AZS) {
      findings.push(
        this.emit(
          'awslambda_function_vpc_multi_az',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            vpcId,
            availabilityZones: [...azs],
          },
          {
            message: `Function "${fnName}" is attached to VPC ${vpcId} with subnets in only ${azs.size} Availability Zone(s) (${[...azs].join(', ') || 'none resolved'}); at least ${LAMBDA_MIN_AZS} are required for fault tolerance.`,
            remediation: `Add subnets from at least ${LAMBDA_MIN_AZS} different Availability Zones to "${fnName}": aws lambda update-function-configuration --function-name ${fnName} --vpc-config SubnetIds=<subnet-az1>,<subnet-az2>,SecurityGroupIds=<sg>.`,
          }
        )
      );
    }

    return findings;
  }

  /** Map every subnet in the region to its Availability Zone (null on failure). */
  private async getSubnetAzMap(): Promise<Map<string, string> | null> {
    try {
      const map = new Map<string, string>();
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.client.ec2.send(
            new DescribeSubnetsCommand({ NextToken: nextToken })
          );
        });
        for (const subnet of result.Subnets ?? []) {
          if (subnet.SubnetId && subnet.AvailabilityZone) {
            map.set(subnet.SubnetId, subnet.AvailabilityZone);
          }
        }
        nextToken = result.NextToken;
      } while (nextToken);
      return map;
    } catch (err) {
      logger.debug('Failed to describe subnets for Lambda multi-AZ check', {
        error: (err as Error).message,
      });
      return null;
    }
  }

  /**
   * Determine which Lambda functions have their Invoke calls recorded as
   * CloudTrail data events, from classic event selectors (DataResources of
   * type AWS::Lambda::Function) and advanced event selectors (resources.type).
   */
  private async getLambdaTrailCoverage(): Promise<LambdaTrailCoverage> {
    const coverage: LambdaTrailCoverage = {
      available: false,
      allFunctionsCovered: false,
      coveredArns: new Set<string>(),
      coveringTrail: null,
    };

    let trails: any[] = [];
    try {
      const result: any = await retry(async () => {
        return await this.client.cloudtrail.send(
          new DescribeTrailsCommand({ includeShadowTrails: true })
        );
      });
      trails = result.trailList ?? [];
    } catch (err) {
      logger.debug('Failed to describe CloudTrail trails for Lambda Invoke logging check', {
        error: (err as Error).message,
      });
      return coverage;
    }
    coverage.available = true;

    for (const trail of trails) {
      const trailName: string = trail.Name ?? trail.TrailARN ?? 'Unknown';
      let selectors: any;
      try {
        selectors = await retry(async () => {
          return await this.client.cloudtrail.send(
            new GetEventSelectorsCommand({ TrailName: trail.TrailARN ?? trail.Name })
          );
        });
      } catch (err) {
        logger.debug(`Failed to get event selectors for trail ${trailName}`, {
          error: (err as Error).message,
        });
        continue;
      }

      // Classic event selectors
      for (const selector of selectors.EventSelectors ?? []) {
        for (const dataResource of selector.DataResources ?? []) {
          if (dataResource.Type !== 'AWS::Lambda::Function') continue;
          for (const value of dataResource.Values ?? []) {
            // "arn:<partition>:lambda" is CloudTrail's log-all-functions value
            if (/^arn:[^:]+:lambda$/.test(value)) {
              coverage.allFunctionsCovered = true;
              coverage.coveringTrail = coverage.coveringTrail ?? trailName;
            } else {
              coverage.coveredArns.add(value);
            }
          }
        }
      }

      // Advanced event selectors
      for (const advanced of selectors.AdvancedEventSelectors ?? []) {
        for (const fieldSelector of advanced.FieldSelectors ?? []) {
          if (
            fieldSelector.Field === 'resources.type' &&
            (fieldSelector.Equals ?? []).includes('AWS::Lambda::Function')
          ) {
            coverage.allFunctionsCovered = true;
            coverage.coveringTrail = coverage.coveringTrail ?? trailName;
          }
        }
      }

      if (coverage.allFunctionsCovered) break;
    }

    return coverage;
  }

  // awslambda_function_invoke_api_operations_cloudtrail_logging_enabled
  private checkCloudTrailInvokeLogging(
    fn: FunctionConfiguration,
    coverage: LambdaTrailCoverage
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];
    // Trails could not be enumerated: skip instead of emitting false positives
    if (!coverage.available) return findings;

    const fnName = fn.FunctionName ?? 'Unknown';
    const recorded =
      coverage.allFunctionsCovered ||
      coverage.coveredArns.has(fn.FunctionArn ?? '');

    if (!recorded) {
      findings.push(
        this.emit(
          'awslambda_function_invoke_api_operations_cloudtrail_logging_enabled',
          {
            functionName: fnName,
            arn: fn.FunctionArn,
            lambdaDataEventsTrail: coverage.coveringTrail,
          },
          {
            message: `Function "${fnName}" Invoke API calls are not recorded by any CloudTrail trail, so there is no per-invocation audit trail.`,
            remediation: `Add a Lambda data event selector covering "${fnName}" (or all functions) to a trail: aws cloudtrail put-event-selectors --trail-name <trail> --advanced-event-selectors '[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Data"]},{"Field":"resources.type","Equals":["AWS::Lambda::Function"]}]}]'.`,
          }
        )
      );
    }

    return findings;
  }
}

export default LambdaScanner;
