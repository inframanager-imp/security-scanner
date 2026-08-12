// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  CodeartifactClient,
  ListDomainsCommand,
  ListRepositoriesCommand,
  ListPackagesCommand,
} from '@aws-sdk/client-codeartifact';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class CodeArtifactScanner extends BaseScanner {
  private codeartifact: CodeartifactClient;

  constructor(client: AWSClient) {
    super(client, 'CodeArtifact');
    this.codeartifact = new CodeartifactClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting CodeArtifact security scan...');

      const domains = await this.listDomains();
      logger.info(`CodeArtifact: scanning ${domains.length} domain(s)`);

      // codeartifact_packages_external_public_publishing_disabled: internal
      // packages that also allow upstream (public) resolution are exposed to
      // dependency-confusion attacks.
      for (const domain of domains) {
        try {
          const repositories = await this.listRepositories(domain.name);
          for (const repo of repositories) {
            try {
              const packages = await this.listPackages(domain.name, repo.name);
              for (const pkg of packages) {
                const restrictions = pkg.originConfiguration?.restrictions;
                if (restrictions?.publish === 'ALLOW' && restrictions?.upstream === 'ALLOW') {
                  findings.push(this.emit(
                    'codeartifact_packages_external_public_publishing_disabled',
                    {
                      domain: domain.name,
                      repository: repo.name,
                      package: pkg.package,
                      format: pkg.format,
                      restrictions,
                    },
                    {
                      message: `CodeArtifact package "${pkg.package}" (${pkg.format}) in ${domain.name}/${repo.name} allows both internal publishing and upstream resolution, exposing it to dependency confusion`,
                      remediation: `Set the origin configuration of "${pkg.package}" to block upstream resolution for internally published packages (upstream=BLOCK)`,
                    }
                  ));
                }
              }
            } catch (error) {
              logger.debug(`Failed to list packages in ${domain.name}/${repo.name}`, { error: (error as Error).message });
            }
          }
        } catch (error) {
          logger.debug(`Failed to scan CodeArtifact domain ${domain.name}`, { error: (error as Error).message });
        }
      }

      logger.info(`CodeArtifact scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('CodeArtifact scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listDomains(): Promise<any[]> {
    const domains: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.codeartifact.send(new ListDomainsCommand({ nextToken }));
      });
      domains.push(...(result.domains ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return domains;
  }

  private async listRepositories(domain: string): Promise<any[]> {
    const repositories: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.codeartifact.send(new ListRepositoriesCommand({ nextToken }));
      });
      repositories.push(...(result.repositories ?? []).filter((r: any) => r.domainName === domain));
      nextToken = result.nextToken;
    } while (nextToken);
    return repositories;
  }

  private async listPackages(domain: string, repository: string): Promise<any[]> {
    const packages: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.codeartifact.send(new ListPackagesCommand({
          domain,
          repository,
          nextToken,
        }));
      });
      packages.push(...(result.packages ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return packages;
  }
}

export default CodeArtifactScanner;
