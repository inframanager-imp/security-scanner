import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  CodeBuildClient,
  ListProjectsCommand,
  BatchGetProjectsCommand,
  ListBuildsForProjectCommand,
  BatchGetBuildsCommand,
  ListReportGroupsCommand,
  BatchGetReportGroupsCommand,
} from '@aws-sdk/client-codebuild';
import { IAMClient, GetRoleCommand } from '@aws-sdk/client-iam';
import CodeBuildScanner from '../../../src/scanners/codebuild';

const codebuildMock = mockClient(CodeBuildClient);
const iamMock = mockClient(IAMClient);

/**
 * CodeBuildScanner builds its own CodeBuildClient via `client.getClientConfig()`,
 * but reaches IAM through `this.client.iam` directly (see roleTrustsCodeBuild).
 */
function makeMockAWSClient() {
  return {
    iam: new IAMClient({ region: 'us-east-1' }),
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
  } as any;
}

function findByCheckId(findings: any[], checkId: string) {
  return findings.filter((f) => f.checkId === checkId);
}

/** Minimal well-formed project that should produce zero findings by default. */
const CLEAN_PROJECT = {
  name: 'clean-project',
  projectVisibility: 'PRIVATE',
  logsConfig: {
    cloudWatchLogs: { status: 'ENABLED' },
    s3Logs: { status: 'DISABLED' },
  },
  environment: {
    environmentVariables: [],
  },
  source: { type: 'CODECOMMIT', location: 'https://git-codecommit.us-east-1.amazonaws.com/v1/repos/repo' },
};

/** Stub project listing/batch-get plumbing for a single given project, with a recent build. */
function stubProject(project: any, opts: { hasBuild?: boolean; buildEndTime?: Date } = {}) {
  const hasBuild = opts.hasBuild ?? true;
  codebuildMock.on(ListProjectsCommand).resolves({ projects: [project.name] } as any);
  codebuildMock.on(BatchGetProjectsCommand).resolves({ projects: [project] } as any);
  if (hasBuild) {
    codebuildMock.on(ListBuildsForProjectCommand).resolves({ ids: [`${project.name}:build1`] } as any);
    codebuildMock.on(BatchGetBuildsCommand).resolves({
      builds: [{ id: `${project.name}:build1`, endTime: opts.buildEndTime ?? new Date() }],
    } as any);
  } else {
    codebuildMock.on(ListBuildsForProjectCommand).resolves({ ids: [] } as any);
  }
  codebuildMock.on(ListReportGroupsCommand).resolves({ reportGroups: [] } as any);
}

describe('CodeBuildScanner', () => {
  beforeEach(() => {
    codebuildMock.reset();
    iamMock.reset();
  });

  describe('scan() — no projects', () => {
    it('returns an empty array when the account has no CodeBuild projects', async () => {
      codebuildMock.on(ListProjectsCommand).resolves({ projects: [] } as any);
      codebuildMock.on(BatchGetProjectsCommand).resolves({ projects: [] } as any);
      codebuildMock.on(ListReportGroupsCommand).resolves({ reportGroups: [] } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });

  describe('scan() — happy path on a fully compliant project', () => {
    it('emits no project-level findings for a private project with logging enabled, no secrets, and a recent build', async () => {
      stubProject(CLEAN_PROJECT);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId);
      expect(checkIds).not.toContain('codebuild_project_logging_enabled');
      expect(checkIds).not.toContain('codebuild_project_not_publicly_accessible');
      expect(checkIds).not.toContain('codebuild_project_no_secrets_in_variables');
      expect(checkIds).not.toContain('codebuild_project_older_90_days');
      expect(checkIds).not.toContain('codebuild_project_source_repo_url_no_sensitive_credentials');
    });
  });

  describe('scan() — codebuild_project_logging_enabled', () => {
    it('emits a finding when neither CloudWatch nor S3 logging is enabled', async () => {
      const project = {
        ...CLEAN_PROJECT,
        logsConfig: { cloudWatchLogs: { status: 'DISABLED' }, s3Logs: { status: 'DISABLED' } },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_logging_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].service).toBe('CodeBuild');
      expect(matches[0].evidence).toMatchObject({ project: 'clean-project', cloudWatchLogs: false, s3Logs: false });
    });
  });

  describe('scan() — codebuild_project_s3_logs_encrypted', () => {
    it('emits a finding when S3 logs are enabled but encryption is disabled', async () => {
      const project = {
        ...CLEAN_PROJECT,
        logsConfig: {
          cloudWatchLogs: { status: 'DISABLED' },
          s3Logs: { status: 'ENABLED', encryptionDisabled: true, location: 'my-log-bucket/logs' },
        },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_s3_logs_encrypted');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({
        project: 'clean-project',
        s3LogsLocation: 'my-log-bucket/logs',
        encryptionDisabled: true,
      });
      // S3 logging is enabled so the "no logging at all" check must not also fire
      expect(findByCheckId(findings, 'codebuild_project_logging_enabled')).toHaveLength(0);
    });
  });

  describe('scan() — codebuild_project_no_secrets_in_variables', () => {
    it('flags a plaintext env var whose name looks like a credential', async () => {
      const project = {
        ...CLEAN_PROJECT,
        environment: {
          environmentVariables: [
            { name: 'DB_PASSWORD', value: 'hunter2', type: 'PLAINTEXT' },
          ],
        },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_no_secrets_in_variables');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence.secretsFound[0]).toContain('DB_PASSWORD');
    });

    it('flags a plaintext env var whose value looks like an AWS access key', async () => {
      const project = {
        ...CLEAN_PROJECT,
        environment: {
          environmentVariables: [
            { name: 'SOME_VAR', value: 'AKIAXXXXXXXXXXXXXXXX', type: 'PLAINTEXT' },
          ],
        },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_no_secrets_in_variables');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence.secretsFound[0]).toContain('AWS Access Key ID');
    });

    it('does not flag PARAMETER_STORE or SECRETS_MANAGER typed variables even with sensitive-looking names', async () => {
      const project = {
        ...CLEAN_PROJECT,
        environment: {
          environmentVariables: [
            { name: 'DB_PASSWORD', value: '/my/param/path', type: 'PARAMETER_STORE' },
          ],
        },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'codebuild_project_no_secrets_in_variables')).toHaveLength(0);
    });
  });

  describe('scan() — codebuild_project_not_publicly_accessible', () => {
    it('emits a finding when a project is not PRIVATE', async () => {
      const project = { ...CLEAN_PROJECT, projectVisibility: 'PUBLIC_READ' };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_not_publicly_accessible');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ project: 'clean-project', projectVisibility: 'PUBLIC_READ' });
    });
  });

  describe('scan() — codebuild_project_older_90_days', () => {
    it('emits a finding with lastInvokedTime null when the project has never been built', async () => {
      stubProject(CLEAN_PROJECT, { hasBuild: false });

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_older_90_days');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ project: 'clean-project', lastInvokedTime: null });
    });

    it('emits a finding when the last build finished more than 90 days ago', async () => {
      const oldDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000);
      stubProject(CLEAN_PROJECT, { buildEndTime: oldDate });

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_older_90_days');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence.daysSinceLastBuild).toBeGreaterThanOrEqual(120);
    });

    it('does not emit a finding when the last build finished recently', async () => {
      stubProject(CLEAN_PROJECT, { buildEndTime: new Date() });

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'codebuild_project_older_90_days')).toHaveLength(0);
    });
  });

  describe('scan() — codebuild_project_source_repo_url_no_sensitive_credentials', () => {
    it('flags a Bitbucket source URL containing an embedded token', async () => {
      const project = {
        ...CLEAN_PROJECT,
        source: { type: 'BITBUCKET', location: 'https://x-token-auth:abc123@bitbucket.org/org/repo.git' },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_source_repo_url_no_sensitive_credentials');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence.credentialUrls[0]).toContain('Token');
    });
  });

  describe('scan() — codebuild_project_user_controlled_buildspec', () => {
    it('emits a finding when the source buildspec points at a YAML file', async () => {
      const project = {
        ...CLEAN_PROJECT,
        source: { ...CLEAN_PROJECT.source, buildspec: 'custom/buildspec.yml' },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_user_controlled_buildspec');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ project: 'clean-project', buildspec: 'custom/buildspec.yml' });
    });
  });

  describe('scan() — codebuild_project_webhook_filters_use_anchored_patterns', () => {
    it('emits a finding when a high-risk webhook filter uses an unanchored pattern', async () => {
      const project = {
        ...CLEAN_PROJECT,
        webhook: {
          filterGroups: [
            [{ type: 'HEAD_REF', pattern: 'feature/.*' }],
          ],
        },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_webhook_filters_use_anchored_patterns');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence.unanchoredFilters[0]).toContain('HEAD_REF');
    });

    it('does not emit a finding when the high-risk webhook filter pattern is anchored', async () => {
      const project = {
        ...CLEAN_PROJECT,
        webhook: {
          filterGroups: [
            [{ type: 'HEAD_REF', pattern: '^refs/heads/main$' }],
          ],
        },
      };
      stubProject(project);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'codebuild_project_webhook_filters_use_anchored_patterns')).toHaveLength(0);
    });
  });

  describe('scan() — codebuild_project_uses_allowed_github_organizations', () => {
    it('emits a finding for a GitHub-sourced project whose service role trusts CodeBuild and whose org is not allowlisted', async () => {
      const project = {
        ...CLEAN_PROJECT,
        source: { type: 'GITHUB', location: 'https://github.com/some-org/some-repo.git' },
        serviceRole: 'arn:aws:iam::123456789012:role/codebuild-service-role',
      };
      stubProject(project);
      iamMock.on(GetRoleCommand).resolves({
        Role: {
          RoleName: 'codebuild-service-role',
          AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify({
            Statement: [{ Effect: 'Allow', Principal: { Service: 'codebuild.amazonaws.com' } }],
          })),
        },
      } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_project_uses_allowed_github_organizations');
      expect(matches).toHaveLength(1);
      expect(matches[0].service).toBe('CodeBuild');
      expect(matches[0].evidence).toMatchObject({
        project: 'clean-project',
        gitHubOrganization: 'some-org',
      });
    });

    it('does not emit a finding when the service role trust policy does not trust CodeBuild', async () => {
      const project = {
        ...CLEAN_PROJECT,
        source: { type: 'GITHUB', location: 'https://github.com/some-org/some-repo.git' },
        serviceRole: 'arn:aws:iam::123456789012:role/other-role',
      };
      stubProject(project);
      iamMock.on(GetRoleCommand).resolves({
        Role: {
          RoleName: 'other-role',
          AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify({
            Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' } }],
          })),
        },
      } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'codebuild_project_uses_allowed_github_organizations')).toHaveLength(0);
    });

    it('does not emit a finding for non-GitHub sourced projects', async () => {
      stubProject(CLEAN_PROJECT); // source.type === 'CODECOMMIT'

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'codebuild_project_uses_allowed_github_organizations')).toHaveLength(0);
      expect(iamMock.calls()).toHaveLength(0);
    });
  });

  describe('scan() — codebuild_report_group_export_encrypted', () => {
    it('emits a finding when a report group exports to S3 with encryption disabled', async () => {
      stubProject(CLEAN_PROJECT);
      codebuildMock.on(ListReportGroupsCommand).resolves({
        reportGroups: ['arn:aws:codebuild:us-east-1:123456789012:report-group/my-reports'],
      } as any);
      codebuildMock.on(BatchGetReportGroupsCommand).resolves({
        reportGroups: [
          {
            name: 'my-reports',
            arn: 'arn:aws:codebuild:us-east-1:123456789012:report-group/my-reports',
            exportConfig: {
              exportConfigType: 'S3',
              s3Destination: { bucket: 'report-bucket', path: 'reports', encryptionDisabled: true },
            },
          },
        ],
      } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'codebuild_report_group_export_encrypted');
      expect(matches).toHaveLength(1);
      expect(matches[0].service).toBe('CodeBuild');
      expect(matches[0].evidence).toMatchObject({
        reportGroup: 'my-reports',
        bucketLocation: 's3://report-bucket/reports',
      });
    });

    it('does not emit a finding when the report group export is encrypted', async () => {
      stubProject(CLEAN_PROJECT);
      codebuildMock.on(ListReportGroupsCommand).resolves({
        reportGroups: ['arn:aws:codebuild:us-east-1:123456789012:report-group/my-reports'],
      } as any);
      codebuildMock.on(BatchGetReportGroupsCommand).resolves({
        reportGroups: [
          {
            name: 'my-reports',
            arn: 'arn:aws:codebuild:us-east-1:123456789012:report-group/my-reports',
            exportConfig: {
              exportConfigType: 'S3',
              s3Destination: { bucket: 'report-bucket', path: 'reports', encryptionDisabled: false },
            },
          },
        ],
      } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'codebuild_report_group_export_encrypted')).toHaveLength(0);
    });

    it('does not emit a finding for report groups that do not export to S3', async () => {
      stubProject(CLEAN_PROJECT);
      codebuildMock.on(ListReportGroupsCommand).resolves({
        reportGroups: ['arn:aws:codebuild:us-east-1:123456789012:report-group/no-export'],
      } as any);
      codebuildMock.on(BatchGetReportGroupsCommand).resolves({
        reportGroups: [
          { name: 'no-export', arn: 'arn:aws:codebuild:us-east-1:123456789012:report-group/no-export', exportConfig: undefined },
        ],
      } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'codebuild_report_group_export_encrypted')).toHaveLength(0);
    });
  });

  describe('scan() — pagination', () => {
    it('follows the nextToken cursor across two pages of ListProjects and scans projects from both', async () => {
      const projectA = { ...CLEAN_PROJECT, name: 'project-a' };
      const projectB = { ...CLEAN_PROJECT, name: 'project-b', projectVisibility: 'PUBLIC_READ' };

      codebuildMock
        .on(ListProjectsCommand)
        .resolvesOnce({ projects: ['project-a'], nextToken: 'page2' } as any)
        .resolvesOnce({ projects: ['project-b'] } as any);
      codebuildMock.on(BatchGetProjectsCommand).resolves({ projects: [projectA, projectB] } as any);
      codebuildMock.on(ListBuildsForProjectCommand).resolves({ ids: [] } as any);
      codebuildMock.on(ListReportGroupsCommand).resolves({ reportGroups: [] } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(codebuildMock.commandCalls(ListProjectsCommand)).toHaveLength(2);
      const projects = findings.map((f) => f.evidence.project);
      expect(projects).toContain('project-a');
      expect(projects).toContain('project-b');
      expect(findByCheckId(findings, 'codebuild_project_not_publicly_accessible')[0].evidence).toMatchObject({
        project: 'project-b',
      });
    });

    it('follows the nextToken cursor across two pages of ListReportGroups', async () => {
      stubProject(CLEAN_PROJECT);
      codebuildMock
        .on(ListReportGroupsCommand)
        .resolvesOnce({ reportGroups: ['arn:aws:codebuild:us-east-1:123:report-group/rg-a'], nextToken: 'p2' } as any)
        .resolvesOnce({ reportGroups: ['arn:aws:codebuild:us-east-1:123:report-group/rg-b'] } as any);
      codebuildMock.on(BatchGetReportGroupsCommand).resolves({
        reportGroups: [
          {
            name: 'rg-a',
            arn: 'arn:aws:codebuild:us-east-1:123:report-group/rg-a',
            exportConfig: { exportConfigType: 'S3', s3Destination: { bucket: 'b', encryptionDisabled: true } },
          },
          {
            name: 'rg-b',
            arn: 'arn:aws:codebuild:us-east-1:123:report-group/rg-b',
            exportConfig: { exportConfigType: 'S3', s3Destination: { bucket: 'b', encryptionDisabled: true } },
          },
        ],
      } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(codebuildMock.commandCalls(ListReportGroupsCommand)).toHaveLength(2);
      const matches = findByCheckId(findings, 'codebuild_report_group_export_encrypted');
      expect(matches.map((m) => m.evidence.reportGroup).sort()).toEqual(['rg-a', 'rg-b']);
    });
  });

  describe('scan() — error handling', () => {
    it('does not throw and returns an empty array when ListProjects fails outright', async () => {
      codebuildMock.on(ListProjectsCommand).rejects(new Error('AccessDenied'));

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      await expect(scanner.scan()).resolves.toEqual([]);
    }, 15000);

    it('continues scanning other projects when ListBuildsForProject fails for one of them', async () => {
      const projectA = { ...CLEAN_PROJECT, name: 'project-a', projectVisibility: 'PUBLIC_READ' };
      codebuildMock.on(ListProjectsCommand).resolves({ projects: ['project-a'] } as any);
      codebuildMock.on(BatchGetProjectsCommand).resolves({ projects: [projectA] } as any);
      codebuildMock.on(ListBuildsForProjectCommand).rejects(new Error('Throttling'));
      codebuildMock.on(ListReportGroupsCommand).resolves({ reportGroups: [] } as any);

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      // Build-time lookup failed (per-project try/catch in getLastBuildEndTimes),
      // but the other project-level checks still ran and produced findings.
      expect(findByCheckId(findings, 'codebuild_project_not_publicly_accessible')).toHaveLength(1);
    }, 15000);

    it('returns gracefully when IAM GetRole fails while checking the GitHub organization trust policy', async () => {
      const project = {
        ...CLEAN_PROJECT,
        source: { type: 'GITHUB', location: 'https://github.com/some-org/some-repo.git' },
        serviceRole: 'arn:aws:iam::123456789012:role/codebuild-service-role',
      };
      stubProject(project);
      iamMock.on(GetRoleCommand).rejects(new Error('NoSuchEntity'));

      const scanner = new CodeBuildScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'codebuild_project_uses_allowed_github_organizations')).toHaveLength(0);
    }, 15000);
  });
});
