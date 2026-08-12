// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  CodeBuildClient,
  ListProjectsCommand,
  BatchGetProjectsCommand,
  ListBuildsForProjectCommand,
  BatchGetBuildsCommand,
  ListReportGroupsCommand,
  BatchGetReportGroupsCommand,
} from '@aws-sdk/client-codebuild';
import { GetRoleCommand } from '@aws-sdk/client-iam';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const INACTIVE_DAYS_THRESHOLD = 90;
const HIGH_RISK_WEBHOOK_FILTER_TYPES = ['ACTOR_ACCOUNT_ID', 'HEAD_REF', 'BASE_REF'];

// Approved GitHub organizations for codebuild_project_uses_allowed_github_organizations.
// Mirrors Prowler's codebuild_github_allowed_organizations audit config, whose default
// is empty: every GitHub-sourced project whose service role trusts CodeBuild fails
// until the approved organizations are listed here.
const ALLOWED_GITHUB_ORGANIZATIONS: string[] = [];

// Bitbucket URLs with embedded credentials (mirrors Prowler's regexes)
const BITBUCKET_TOKEN_PATTERN = /^https:\/\/x-token-auth:[^@]+@bitbucket\.org\/.+\.git/;
const BITBUCKET_USER_PASS_PATTERN = /^https:\/\/[^:]+:[^@]+@bitbucket\.org\/.+\.git/;

// Secret-like environment variable names (Prowler uses a full secret scanner;
// we flag PLAINTEXT variables whose names or values look like credentials).
const SECRET_ENV_NAME_PATTERN = /(password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|credential)/i;
const SECRET_VALUE_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: 'AWS Access Key ID', pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
  { label: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
];

function isPatternAnchored(pattern: string): boolean {
  if (!pattern) return true;
  for (const alt of pattern.split('|')) {
    const trimmed = alt.trim();
    if (trimmed && !(trimmed.startsWith('^') && trimmed.endsWith('$'))) {
      return false;
    }
  }
  return true;
}

export class CodeBuildScanner extends BaseScanner {
  private codebuild: CodeBuildClient;

  constructor(client: AWSClient) {
    super(client, 'CodeBuild');
    this.codebuild = new CodeBuildClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting CodeBuild security scan...');

      const projectNames = await this.listProjects();
      const projects = await this.batchGetProjects(projectNames);
      const lastBuildEndTimes = await this.getLastBuildEndTimes(projectNames);

      for (const project of projects) {
        const projectName: string = project.name ?? '';
        logger.debug(`Scanning CodeBuild project: ${projectName}`);
        try {
          findings.push(...this.validateProject(project, lastBuildEndTimes));
        } catch (error) {
          logger.debug(`Failed to scan CodeBuild project ${projectName}`, { error: (error as Error).message });
        }
        try {
          findings.push(...await this.validateGithubOrganization(project));
        } catch (error) {
          logger.debug(`Failed to check GitHub organization for CodeBuild project ${projectName}`, { error: (error as Error).message });
        }
      }

      try {
        findings.push(...await this.validateReportGroups());
      } catch (error) {
        logger.debug('Failed to scan CodeBuild report groups', { error: (error as Error).message });
      }

      logger.info(`CodeBuild scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('CodeBuild scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listProjects(): Promise<string[]> {
    const names: string[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.codebuild.send(new ListProjectsCommand({ nextToken }));
      });
      names.push(...(result.projects ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return names;
  }

  private async batchGetProjects(names: string[]): Promise<any[]> {
    const projects: any[] = [];
    for (let i = 0; i < names.length; i += 100) {
      const batch = names.slice(i, i + 100);
      const result = await retry(async () => {
        return await this.codebuild.send(new BatchGetProjectsCommand({ names: batch }));
      });
      projects.push(...(result.projects ?? []));
    }
    return projects;
  }

  private async getLastBuildEndTimes(projectNames: string[]): Promise<Map<string, Date | null>> {
    // projectName -> endTime of most recent build; null when never built
    const endTimes = new Map<string, Date | null>();
    const buildIdToProject = new Map<string, string>();

    for (const projectName of projectNames) {
      try {
        const result = await retry(async () => {
          return await this.codebuild.send(new ListBuildsForProjectCommand({ projectName }));
        });
        const ids = result.ids ?? [];
        if (ids.length > 0) {
          buildIdToProject.set(ids[0], projectName);
        } else {
          endTimes.set(projectName, null);
        }
      } catch (error) {
        logger.debug(`Failed to list builds for CodeBuild project ${projectName}`, { error: (error as Error).message });
      }
    }

    const buildIds = [...buildIdToProject.keys()];
    for (let i = 0; i < buildIds.length; i += 100) {
      const batch = buildIds.slice(i, i + 100);
      try {
        const result = await retry(async () => {
          return await this.codebuild.send(new BatchGetBuildsCommand({ ids: batch }));
        });
        for (const build of result.builds ?? []) {
          const projectName = build.id ? buildIdToProject.get(build.id) : undefined;
          if (projectName) {
            endTimes.set(projectName, build.endTime ? new Date(build.endTime) : null);
          }
        }
      } catch (error) {
        logger.debug('Failed to batch get CodeBuild builds', { error: (error as Error).message });
      }
    }

    return endTimes;
  }

  private validateProject(project: any, lastBuildEndTimes: Map<string, Date | null>): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const projectName: string = project.name ?? '';

    // codebuild_project_logging_enabled
    const cwLogsEnabled = project.logsConfig?.cloudWatchLogs?.status === 'ENABLED';
    const s3LogsEnabled = project.logsConfig?.s3Logs?.status === 'ENABLED';
    if (!cwLogsEnabled && !s3LogsEnabled) {
      findings.push(this.emit(
        'codebuild_project_logging_enabled',
        { project: projectName, cloudWatchLogs: false, s3Logs: false },
        {
          message: `CodeBuild project "${projectName}" does not have logging enabled`,
          remediation: `Enable CloudWatch Logs or S3 logging on CodeBuild project "${projectName}"`,
        }
      ));
    }

    // codebuild_project_s3_logs_encrypted (only projects that write logs to S3)
    if (s3LogsEnabled && project.logsConfig?.s3Logs?.encryptionDisabled === true) {
      findings.push(this.emit(
        'codebuild_project_s3_logs_encrypted',
        { project: projectName, s3LogsLocation: project.logsConfig?.s3Logs?.location ?? '', encryptionDisabled: true },
        {
          message: `CodeBuild project "${projectName}" does not have encrypted S3 logs stored in ${project.logsConfig?.s3Logs?.location ?? 'its S3 log location'}`,
        }
      ));
    }

    // codebuild_project_no_secrets_in_variables
    const secretsFound: string[] = [];
    for (const envVar of project.environment?.environmentVariables ?? []) {
      if (envVar.type !== 'PLAINTEXT') continue;
      const name: string = envVar.name ?? '';
      const value: string = envVar.value ?? '';
      if (value && SECRET_ENV_NAME_PATTERN.test(name)) {
        secretsFound.push(`Secret Keyword in variable ${name}`);
        continue;
      }
      for (const { label, pattern } of SECRET_VALUE_PATTERNS) {
        if (pattern.test(value)) {
          secretsFound.push(`${label} in variable ${name}`);
          break;
        }
      }
    }
    if (secretsFound.length > 0) {
      findings.push(this.emit(
        'codebuild_project_no_secrets_in_variables',
        { project: projectName, secretsFound },
        {
          message: `CodeBuild project "${projectName}" has sensitive environment plaintext credentials in variables: ${secretsFound.join(', ')}`,
          remediation: `Move the flagged variables of project "${projectName}" to Secrets Manager or SSM Parameter Store references and rotate any exposed credentials`,
        }
      ));
    }

    // codebuild_project_not_publicly_accessible
    if (project.projectVisibility !== 'PRIVATE') {
      findings.push(this.emit(
        'codebuild_project_not_publicly_accessible',
        { project: projectName, projectVisibility: project.projectVisibility ?? 'UNKNOWN' },
        {
          message: `CodeBuild project "${projectName}" is public`,
          remediation: `Set the visibility of CodeBuild project "${projectName}" to PRIVATE`,
        }
      ));
    }

    // codebuild_project_older_90_days
    const lastEndTime = lastBuildEndTimes.get(projectName);
    if (lastEndTime === null) {
      findings.push(this.emit(
        'codebuild_project_older_90_days',
        { project: projectName, lastInvokedTime: null },
        {
          message: `CodeBuild project "${projectName}" has never been built`,
        }
      ));
    } else if (lastEndTime instanceof Date) {
      const daysSince = (Date.now() - lastEndTime.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSince > INACTIVE_DAYS_THRESHOLD) {
        findings.push(this.emit(
          'codebuild_project_older_90_days',
          { project: projectName, lastInvokedTime: lastEndTime.toISOString(), daysSinceLastBuild: Math.floor(daysSince) },
          {
            message: `CodeBuild project "${projectName}" has not been invoked in the last ${INACTIVE_DAYS_THRESHOLD} days`,
          }
        ));
      }
    }

    // codebuild_project_source_repo_url_no_sensitive_credentials
    const credentialUrls: string[] = [];
    const sources: any[] = [];
    if (project.source && project.source.type !== 'NO_SOURCE') sources.push(project.source);
    sources.push(...(project.secondarySources ?? []));
    for (const source of sources) {
      if (source.type !== 'BITBUCKET') continue;
      const location: string = source.location ?? '';
      if (BITBUCKET_TOKEN_PATTERN.test(location)) {
        credentialUrls.push(`Token in ${source.type} URL`);
      } else if (BITBUCKET_USER_PASS_PATTERN.test(location)) {
        credentialUrls.push(`Basic Auth Credentials in ${source.type} URL`);
      }
    }
    if (credentialUrls.length > 0) {
      findings.push(this.emit(
        'codebuild_project_source_repo_url_no_sensitive_credentials',
        { project: projectName, credentialUrls },
        {
          message: `CodeBuild project "${projectName}" has sensitive credentials in source repository URLs: ${credentialUrls.join(', ')}`,
          remediation: `Remove embedded credentials from the source URLs of project "${projectName}", use OAuth/CodeStar Connections instead, and rotate the exposed tokens`,
        }
      ));
    }

    // codebuild_project_user_controlled_buildspec
    const buildspec: string = project.source?.buildspec ?? '';
    if (buildspec && /\.ya?ml$/.test(buildspec)) {
      findings.push(this.emit(
        'codebuild_project_user_controlled_buildspec',
        { project: projectName, buildspec },
        {
          message: `CodeBuild project "${projectName}" uses a user controlled buildspec (${buildspec})`,
        }
      ));
    }

    // codebuild_project_webhook_filters_use_anchored_patterns
    const unanchoredFilters: string[] = [];
    for (const filterGroup of project.webhook?.filterGroups ?? []) {
      for (const filter of filterGroup ?? []) {
        const filterType: string = filter.type ?? '';
        if (HIGH_RISK_WEBHOOK_FILTER_TYPES.includes(filterType) && !isPatternAnchored(filter.pattern ?? '')) {
          unanchoredFilters.push(`${filterType}: '${filter.pattern}'`);
        }
      }
    }
    if (unanchoredFilters.length > 0) {
      let filtersStr = unanchoredFilters.slice(0, 3).join(', ');
      if (unanchoredFilters.length > 3) {
        filtersStr += ` and ${unanchoredFilters.length - 3} more`;
      }
      findings.push(this.emit(
        'codebuild_project_webhook_filters_use_anchored_patterns',
        { project: projectName, unanchoredFilters },
        {
          message: `CodeBuild project "${projectName}" has webhook filters with unanchored patterns that could allow bypass attacks: ${filtersStr}`,
          remediation: `Anchor the webhook filter patterns of project "${projectName}" with ^ and $ (e.g. ^value1$|^value2$) so only exact matches trigger builds`,
        }
      ));
    }

    return findings;
  }

  /**
   * codebuild_project_uses_allowed_github_organizations: GitHub-sourced projects
   * whose service role trusts CodeBuild hand AWS credentials to builds triggered
   * from the repository, so the repository organization must be on the allowlist.
   * Projects whose organization cannot be derived from the source URL produce no
   * finding (mirrors Prowler).
   */
  private async validateGithubOrganization(project: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const projectName: string = project.name ?? '';
    const sourceType: string = project.source?.type ?? '';
    if (sourceType !== 'GITHUB' && sourceType !== 'GITHUB_ENTERPRISE') return findings;

    const location: string = project.source?.location ?? '';
    const orgName = this.extractGithubOrganization(location);
    if (!orgName) return findings;

    if (!(await this.roleTrustsCodeBuild(project.serviceRole ?? ''))) return findings;

    if (!ALLOWED_GITHUB_ORGANIZATIONS.includes(orgName)) {
      findings.push(this.emit(
        'codebuild_project_uses_allowed_github_organizations',
        {
          project: projectName,
          sourceType,
          location,
          gitHubOrganization: orgName,
          allowedOrganizations: ALLOWED_GITHUB_ORGANIZATIONS,
        },
        {
          message: `CodeBuild project "${projectName}" uses GitHub organization "${orgName}", which is not in the allowed organizations list`,
          remediation: `Point project "${projectName}" at a repository under an approved GitHub organization, or add "${orgName}" to the allowed organizations list after review`,
        }
      ));
    }

    return findings;
  }

  private extractGithubOrganization(repoUrl: string): string | null {
    try {
      const url = new URL(repoUrl);
      const segments = url.pathname.split('/').filter(Boolean);
      return segments.length >= 2 ? segments[0] : null;
    } catch {
      return null;
    }
  }

  private async roleTrustsCodeBuild(roleArn: string): Promise<boolean> {
    if (!roleArn) return false;
    const roleName = roleArn.split('/').pop() ?? '';
    if (!roleName) return false;
    try {
      const result: any = await retry(async () => {
        return await this.client.iam.send(new GetRoleCommand({ RoleName: roleName }));
      });
      const rawDocument: string = result?.Role?.AssumeRolePolicyDocument ?? '';
      if (!rawDocument) return false;
      let document: any;
      try {
        document = JSON.parse(decodeURIComponent(rawDocument));
      } catch {
        try {
          document = JSON.parse(rawDocument);
        } catch {
          return false;
        }
      }
      const rawStatements = document?.Statement;
      const statements: any[] = Array.isArray(rawStatements) ? rawStatements : rawStatements ? [rawStatements] : [];
      for (const statement of statements) {
        if (statement?.Effect !== 'Allow') continue;
        const service = statement?.Principal?.Service;
        const services: string[] = Array.isArray(service) ? service : service ? [service] : [];
        if (services.includes('codebuild.amazonaws.com')) return true;
      }
      return false;
    } catch (error) {
      logger.debug(`Failed to get trust policy for CodeBuild service role ${roleName}`, { error: (error as Error).message });
      return false;
    }
  }

  // codebuild_report_group_export_encrypted
  private async validateReportGroups(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const reportGroupArns: string[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.codebuild.send(new ListReportGroupsCommand({ nextToken }));
      });
      reportGroupArns.push(...(result.reportGroups ?? []));
      nextToken = result.nextToken;
    } while (nextToken);

    for (let i = 0; i < reportGroupArns.length; i += 100) {
      const batch = reportGroupArns.slice(i, i + 100);
      const result = await retry(async () => {
        return await this.codebuild.send(new BatchGetReportGroupsCommand({ reportGroupArns: batch }));
      });
      for (const reportGroup of result.reportGroups ?? []) {
        const name: string = reportGroup.name ?? (reportGroup.arn ?? '').split('/').pop() ?? '';
        const exportConfig: any = reportGroup.exportConfig;
        if (!exportConfig || exportConfig.exportConfigType !== 'S3') continue;
        const s3Destination: any = exportConfig.s3Destination ?? {};
        const encrypted = !(s3Destination.encryptionDisabled ?? true);
        if (!encrypted) {
          const bucketLocation = s3Destination.bucket ? `s3://${s3Destination.bucket}/${s3Destination.path ?? ''}` : '';
          findings.push(this.emit(
            'codebuild_report_group_export_encrypted',
            { reportGroup: name, arn: reportGroup.arn, bucketLocation, encryptionDisabled: s3Destination.encryptionDisabled ?? null },
            {
              message: `CodeBuild report group "${name}" exports are not encrypted${bucketLocation ? ` at ${bucketLocation}` : ''}`,
              remediation: `Enable KMS encryption on the S3 export of report group "${name}"`,
            }
          ));
        }
      }
    }

    return findings;
  }
}

export default CodeBuildScanner;
