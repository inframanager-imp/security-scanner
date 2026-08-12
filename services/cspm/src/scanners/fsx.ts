// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  FSxClient,
  DescribeFileSystemsCommand,
} from '@aws-sdk/client-fsx';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class FSxScanner extends BaseScanner {
  private fsx: FSxClient;

  constructor(client: AWSClient) {
    super(client, 'FSx');
    this.fsx = new FSxClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting FSx security scan...');

      const fileSystems = await this.describeFileSystems();
      for (const fileSystem of fileSystems) {
        const fsId: string = fileSystem.FileSystemId ?? '';
        logger.debug(`Scanning FSx file system: ${fsId}`);
        try {
          findings.push(...this.validateFileSystem(fileSystem, fsId));
        } catch (error) {
          logger.debug(`Failed to scan FSx file system ${fsId}`, { error: (error as Error).message });
        }
      }

      logger.info(`FSx scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('FSx scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeFileSystems(): Promise<any[]> {
    const fileSystems: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.fsx.send(new DescribeFileSystemsCommand({ NextToken: nextToken }));
      });
      fileSystems.push(...(result.FileSystems ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return fileSystems;
  }

  private validateFileSystem(fileSystem: any, fsId: string): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const type: string = fileSystem.FileSystemType ?? '';

    // Copy-tags settings only exist for LUSTRE, WINDOWS and OPENZFS file systems
    let copyTagsToBackups: boolean | null = null;
    let copyTagsToVolumes: boolean | null = null;
    if (type === 'LUSTRE') {
      copyTagsToBackups = fileSystem.LustreConfiguration?.CopyTagsToBackups ?? false;
    } else if (type === 'WINDOWS') {
      copyTagsToBackups = fileSystem.WindowsConfiguration?.CopyTagsToBackups ?? false;
    } else if (type === 'OPENZFS') {
      copyTagsToBackups = fileSystem.OpenZFSConfiguration?.CopyTagsToBackups ?? false;
      copyTagsToVolumes = fileSystem.OpenZFSConfiguration?.CopyTagsToVolumes ?? false;
    }

    // fsx_file_system_copy_tags_to_backups_enabled
    if (copyTagsToBackups === false) {
      findings.push(this.emit(
        'fsx_file_system_copy_tags_to_backups_enabled',
        { fileSystemId: fsId, fileSystemType: type, copyTagsToBackups: false },
        {
          message: `FSx file system "${fsId}" does not have copy tags to backups enabled`,
        }
      ));
    }

    // fsx_file_system_copy_tags_to_volumes_enabled (OpenZFS only)
    if (copyTagsToVolumes === false) {
      findings.push(this.emit(
        'fsx_file_system_copy_tags_to_volumes_enabled',
        { fileSystemId: fsId, fileSystemType: type, copyTagsToVolumes: false },
        {
          message: `FSx file system "${fsId}" does not have copy tags to volumes enabled`,
        }
      ));
    }

    // fsx_windows_file_system_multi_az_enabled
    if (type === 'WINDOWS') {
      const subnetIds: string[] = fileSystem.SubnetIds ?? [];
      if (subnetIds.length <= 1) {
        findings.push(this.emit(
          'fsx_windows_file_system_multi_az_enabled',
          { fileSystemId: fsId, fileSystemType: type, subnetIds },
          {
            message: `FSx Windows file system "${fsId}" is not configured for Multi-AZ deployment`,
          }
        ));
      }
    }

    return findings;
  }
}

export default FSxScanner;
