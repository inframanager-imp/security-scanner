// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  TransferClient,
  ListServersCommand,
  DescribeServerCommand,
} from '@aws-sdk/client-transfer';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Security policies that enable post-quantum hybrid (ML-KEM) SSH key exchange
const PQC_TRANSFER_POLICIES = [
  'TransferSecurityPolicy-2025-03',
  'TransferSecurityPolicy-FIPS-2025-03',
  'TransferSecurityPolicy-AS2Restricted-2025-07',
];

export class TransferScanner extends BaseScanner {
  private transfer: TransferClient;

  constructor(client: AWSClient) {
    super(client, 'Transfer');
    this.transfer = new TransferClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Transfer security scan...');

      const serverIds = await this.listServers();
      for (const serverId of serverIds) {
        logger.debug(`Scanning Transfer server: ${serverId}`);
        try {
          findings.push(...await this.validateServer(serverId));
        } catch (error) {
          logger.debug(`Failed to scan Transfer server ${serverId}`, { error: (error as Error).message });
        }
      }

      logger.info(`Transfer scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Transfer scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listServers(): Promise<string[]> {
    const serverIds: string[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.transfer.send(new ListServersCommand({ NextToken: nextToken }));
      });
      for (const server of result.Servers ?? []) {
        if (server.ServerId) {
          serverIds.push(server.ServerId);
        }
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return serverIds;
  }

  private async validateServer(serverId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const result = await retry(async () => {
      return await this.transfer.send(new DescribeServerCommand({ ServerId: serverId }));
    });
    const server: any = result.Server ?? {};
    const protocols: string[] = server.Protocols ?? [];
    const securityPolicyName: string = server.SecurityPolicyName ?? '';

    // transfer_server_in_transit_encryption_enabled: plain FTP means unencrypted transfers
    if (protocols.includes('FTP')) {
      findings.push(this.emit(
        'transfer_server_in_transit_encryption_enabled',
        { serverId, serverArn: server.Arn, protocols },
        {
          message: `Transfer server "${serverId}" does not have encryption in transit enabled (FTP protocol is allowed)`,
          remediation: `Remove FTP from the protocol list of server "${serverId}" and use SFTP, FTPS or AS2 instead`,
        }
      ));
    }

    // transfer_server_pqc_ssh_kex_enabled: security policy must enable post-quantum hybrid SSH KEX
    if (!PQC_TRANSFER_POLICIES.includes(securityPolicyName)) {
      findings.push(this.emit(
        'transfer_server_pqc_ssh_kex_enabled',
        { serverId, serverArn: server.Arn, securityPolicyName: securityPolicyName || null },
        {
          message: `Transfer server "${serverId}" uses security policy "${securityPolicyName || '<none>'}", which does not enable post-quantum hybrid SSH key exchange`,
        }
      ));
    }

    return findings;
  }
}

export default TransferScanner;
