// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  CodePipelineClient,
  ListPipelinesCommand,
  GetPipelineCommand,
} from '@aws-sdk/client-codepipeline';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const HTTP_TIMEOUT_MS = 10000;

export class CodePipelineScanner extends BaseScanner {
  private codepipeline: CodePipelineClient;

  constructor(client: AWSClient) {
    super(client, 'CodePipeline');
    this.codepipeline = new CodePipelineClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting CodePipeline security scan...');

      const pipelineNames = await this.listPipelines();
      for (const pipelineName of pipelineNames) {
        logger.debug(`Scanning CodePipeline pipeline: ${pipelineName}`);
        try {
          findings.push(...await this.validatePipeline(pipelineName));
        } catch (error) {
          logger.debug(`Failed to scan CodePipeline pipeline ${pipelineName}`, { error: (error as Error).message });
        }
      }

      logger.info(`CodePipeline scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('CodePipeline scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listPipelines(): Promise<string[]> {
    const names: string[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.codepipeline.send(new ListPipelinesCommand({ nextToken }));
      });
      for (const pipeline of result.pipelines ?? []) {
        if (pipeline.name) names.push(pipeline.name);
      }
      nextToken = result.nextToken;
    } while (nextToken);
    return names;
  }

  // codepipeline_project_repo_private
  private async validatePipeline(pipelineName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const result = await retry(async () => {
      return await this.codepipeline.send(new GetPipelineCommand({ name: pipelineName }));
    });
    const sourceAction: any = result.pipeline?.stages?.[0]?.actions?.[0];
    if (!sourceAction) return findings;

    const provider: string = sourceAction.actionTypeId?.provider ?? '';
    const repositoryId: string = sourceAction.configuration?.FullRepositoryId ?? '';
    if (provider !== 'CodeStarSourceConnection' || !repositoryId) return findings;

    const githubUrl = `https://github.com/${repositoryId}`;
    const gitlabUrl = `https://gitlab.com/${repositoryId}`;

    const isPublicGithub = await this.isPublicRepo(githubUrl);
    const isPublicGitlab = isPublicGithub ? false : await this.isPublicRepo(gitlabUrl);

    if (isPublicGithub || isPublicGitlab) {
      const publicUrl = isPublicGithub ? githubUrl : gitlabUrl;
      findings.push(this.emit(
        'codepipeline_project_repo_private',
        { pipeline: pipelineName, repositoryId, publicUrl },
        {
          message: `CodePipeline pipeline "${pipelineName}" source repository is public: ${publicUrl}`,
          remediation: `Make the source repository ${repositoryId} of pipeline "${pipelineName}" private and connect it through AWS CodeStar Connections`,
        }
      ));
    }

    return findings;
  }

  /**
   * Anonymously probes a repository URL; a reachable page whose final URL is not
   * a sign-in redirect indicates the repository is public (mirrors Prowler).
   * Any error or non-success status is treated as private/inaccessible.
   */
  private async isPublicRepo(repoUrl: string): Promise<boolean> {
    let url = repoUrl;
    if (url.endsWith('.git')) {
      url = url.slice(0, -4);
    }
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
      try {
        const response = await fetch(url, {
          method: 'HEAD',
          redirect: 'follow',
          signal: controller.signal,
        });
        return response.ok && !response.url.endsWith('sign_in');
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return false;
    }
  }
}

export default CodePipelineScanner;
