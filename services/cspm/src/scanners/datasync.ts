// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DataSyncClient,
  ListTasksCommand,
  DescribeTaskCommand,
} from '@aws-sdk/client-datasync';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class DataSyncScanner extends BaseScanner {
  private datasync: DataSyncClient;

  constructor(client: AWSClient) {
    super(client, 'DataSync');
    this.datasync = new DataSyncClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting DataSync security scan...');

      const tasks = await this.listTasks();
      for (const task of tasks) {
        const taskArn: string = task.TaskArn ?? '';
        if (!taskArn) continue;
        const taskName: string = task.Name ?? taskArn.split('/').pop() ?? taskArn;
        logger.debug(`Scanning DataSync task: ${taskName}`);
        try {
          const detail = await retry(async () => {
            return await this.datasync.send(new DescribeTaskCommand({ TaskArn: taskArn }));
          });

          // datasync_task_logging_enabled: CloudWatch log group must be configured
          if (!detail.CloudWatchLogGroupArn) {
            findings.push(this.emit(
              'datasync_task_logging_enabled',
              { taskArn, taskName, status: detail.Status ?? null, cloudWatchLogGroupArn: null },
              {
                message: `DataSync task "${taskName}" does not have logging enabled`,
                remediation: `Configure a CloudWatch Logs log group for DataSync task "${taskName}" (aws datasync update-task --task-arn ${taskArn} --cloud-watch-log-group-arn <log-group-arn>)`,
              }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to scan DataSync task ${taskName}`, { error: (error as Error).message });
        }
      }

      logger.info(`DataSync scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('DataSync scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listTasks(): Promise<any[]> {
    const tasks: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.datasync.send(new ListTasksCommand({ NextToken: nextToken }));
      });
      tasks.push(...(result.Tasks ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return tasks;
  }
}

export default DataSyncScanner;
