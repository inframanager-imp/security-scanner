// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  CodeCommitClient,
  ListRepositoriesCommand,
  GetRepositoryCommand,
  GetBranchCommand,
  GetFolderCommand,
  GetBlobCommand,
} from '@aws-sdk/client-codecommit';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Bounded port of Prowler's codecommit_repository_no_secrets: Prowler walks the
// entire tree at the tip of the default branch and downloads every blob, which
// is unbounded for large repositories. We walk the same tree but cap the number
// of folders and files visited per repository and the blob size scanned, so the
// scan stays practical; the caps are recorded in the finding evidence.
const MAX_FOLDERS_PER_REPOSITORY = 100;
const MAX_FILES_PER_REPOSITORY = 200;
const MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1 MB (CodeCommit GetBlob refuses > 6 MB anyway)
const MAX_SECRETS_IN_MESSAGE = 10;

// Lightweight secret heuristics (Prowler uses a full secret scanner; we match
// well-known credential formats and secret-like assignments in file content).
const SECRET_CONTENT_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: 'AWS Access Key ID', pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
  { label: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
  {
    label: 'Secret Assignment',
    pattern: /(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[=:]\s*['"]?[^\s'"]{6,}/i,
  },
];

// Machine-generated files that produce noise, mirroring Prowler's
// secrets_ignore_files default intent (lockfiles, dependency manifests).
const IGNORED_FILE_NAMES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'npm-shrinkwrap.json',
  'poetry.lock',
  'pipfile.lock',
  'cargo.lock',
  'gemfile.lock',
  'composer.lock',
  'go.sum',
]);

// Binary or asset extensions that cannot contain scannable text secrets.
const IGNORED_FILE_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'webp', 'svg',
  'pdf', 'zip', 'gz', 'tgz', 'tar', 'bz2', 'xz', '7z', 'rar', 'jar', 'war',
  'exe', 'dll', 'so', 'dylib', 'bin', 'class', 'pyc', 'o', 'a', 'lib',
  'woff', 'woff2', 'ttf', 'eot', 'otf',
  'mp3', 'mp4', 'avi', 'mov', 'webm', 'wav', 'flac',
  'min.js', 'min.css', 'map',
]);

function isIgnoredFile(filePath: string): boolean {
  const baseName = (filePath.split('/').pop() ?? '').toLowerCase();
  if (IGNORED_FILE_NAMES.has(baseName)) return true;
  if (baseName.endsWith('.min.js') || baseName.endsWith('.min.css')) return true;
  const extension = baseName.includes('.') ? baseName.split('.').pop() ?? '' : '';
  return IGNORED_FILE_EXTENSIONS.has(extension);
}

function findSecretsInText(text: string): string[] {
  const matches: string[] = [];
  for (const { label, pattern } of SECRET_CONTENT_PATTERNS) {
    if (pattern.test(text)) matches.push(label);
  }
  return matches;
}

export class CodeCommitScanner extends BaseScanner {
  private codecommit: CodeCommitClient;

  constructor(client: AWSClient) {
    super(client, 'CodeCommit');
    this.codecommit = new CodeCommitClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting CodeCommit security scan...');

      const repositories = await this.listRepositories();
      logger.info(`CodeCommit: scanning ${repositories.length} repository(ies)`);

      for (const repository of repositories) {
        const name: string = repository.repositoryName ?? '';
        if (!name) continue;
        try {
          findings.push(...await this.checkRepositorySecrets(name));
        } catch (error) {
          logger.debug(`Failed to scan CodeCommit repository ${name}`, { error: (error as Error).message });
        }
      }

      logger.info(`CodeCommit scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('CodeCommit scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listRepositories(): Promise<any[]> {
    const repositories: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.codecommit.send(new ListRepositoriesCommand({ nextToken }));
      });
      repositories.push(...(result.repositories ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return repositories;
  }

  // codecommit_repository_no_secrets: no hardcoded secrets in the files at the
  // tip of the default branch (repositories without a default branch have no
  // content to scan and pass, as in Prowler).
  private async checkRepositorySecrets(repositoryName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const repositoryResult: any = await retry(async () => {
      return await this.codecommit.send(new GetRepositoryCommand({ repositoryName }));
    });
    const defaultBranch: string = repositoryResult.repositoryMetadata?.defaultBranch ?? '';
    if (!defaultBranch) return findings;

    let commitId = '';
    try {
      const branchResult: any = await retry(async () => {
        return await this.codecommit.send(new GetBranchCommand({ repositoryName, branchName: defaultBranch }));
      });
      commitId = branchResult.branch?.commitId ?? '';
    } catch (error) {
      logger.debug(`Unable to resolve default branch ${defaultBranch} of CodeCommit repository ${repositoryName}`, { error: (error as Error).message });
    }
    if (!commitId) return findings;

    const secretsFound: string[] = [];
    const foldersToProcess: string[] = ['/'];
    let foldersProcessed = 0;
    let filesScanned = 0;
    let truncated = false;

    while (foldersToProcess.length > 0 && filesScanned < MAX_FILES_PER_REPOSITORY) {
      if (foldersProcessed >= MAX_FOLDERS_PER_REPOSITORY) {
        truncated = true;
        break;
      }
      const folderPath = foldersToProcess.pop()!;
      foldersProcessed++;

      let folder: any;
      try {
        folder = await retry(async () => {
          return await this.codecommit.send(new GetFolderCommand({
            repositoryName,
            commitSpecifier: commitId,
            folderPath,
          }));
        });
      } catch (error) {
        logger.debug(`Unable to read folder ${folderPath} of CodeCommit repository ${repositoryName}`, { error: (error as Error).message });
        continue;
      }

      for (const subFolder of folder.subFolders ?? []) {
        if (subFolder.absolutePath) foldersToProcess.push(subFolder.absolutePath);
      }

      for (const file of folder.files ?? []) {
        if (filesScanned >= MAX_FILES_PER_REPOSITORY) {
          truncated = true;
          break;
        }
        const filePath: string = file.absolutePath ?? file.relativePath ?? '';
        if (!filePath || !file.blobId) continue;
        if (isIgnoredFile(filePath)) continue;
        filesScanned++;

        try {
          const blob: any = await retry(async () => {
            return await this.codecommit.send(new GetBlobCommand({ repositoryName, blobId: file.blobId }));
          });
          const content: any = blob.content;
          if (!content || content.length === 0 || content.length > MAX_FILE_SIZE_BYTES) continue;
          const buffer = Buffer.from(content);
          if (buffer.includes(0)) continue; // binary content
          for (const label of findSecretsInText(buffer.toString('utf-8'))) {
            secretsFound.push(`${label} in ${filePath}`);
          }
        } catch (error) {
          logger.debug(`Unable to retrieve file ${filePath} of CodeCommit repository ${repositoryName}`, { error: (error as Error).message });
        }
      }
    }
    if (foldersToProcess.length > 0) truncated = true;

    if (secretsFound.length > 0) {
      const displayed = secretsFound.slice(0, MAX_SECRETS_IN_MESSAGE);
      const extra = secretsFound.length - displayed.length;
      const secretsSummary = extra > 0 ? `${displayed.join(', ')} and ${extra} more` : displayed.join(', ');
      findings.push(this.emit(
        'codecommit_repository_no_secrets',
        {
          repository: repositoryName,
          defaultBranch,
          commitId,
          filesScanned,
          truncatedScan: truncated,
          secretsFound,
        },
        {
          message: `Potential ${secretsFound.length > 1 ? 'secrets' : 'secret'} found in CodeCommit repository "${repositoryName}" branch ${defaultBranch} (commit ${commitId}) -> ${secretsSummary}`,
          remediation: `Remove the flagged credentials from repository "${repositoryName}" and rotate them immediately (they remain in commit history); reference secrets from AWS Secrets Manager or SSM Parameter Store instead`,
        }
      ));
    }

    return findings;
  }
}

export default CodeCommitScanner;
