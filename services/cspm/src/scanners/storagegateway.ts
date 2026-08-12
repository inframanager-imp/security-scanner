// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  StorageGatewayClient,
  ListFileSharesCommand,
  ListGatewaysCommand,
  DescribeNFSFileSharesCommand,
  DescribeSMBFileSharesCommand,
} from '@aws-sdk/client-storage-gateway';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class StorageGatewayScanner extends BaseScanner {
  private storagegateway: StorageGatewayClient;

  constructor(client: AWSClient) {
    super(client, 'StorageGateway');
    this.storagegateway = new StorageGatewayClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting StorageGateway security scan...');

      try {
        findings.push(...await this.checkFileShares());
      } catch (error) {
        logger.debug('Failed to scan StorageGateway file shares', { error: (error as Error).message });
      }

      try {
        findings.push(...await this.checkGateways());
      } catch (error) {
        logger.debug('Failed to scan StorageGateway gateways', { error: (error as Error).message });
      }

      logger.info(`StorageGateway scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('StorageGateway scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  // storagegateway_fileshare_encryption_enabled
  private async checkFileShares(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const fileShares: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.storagegateway.send(new ListFileSharesCommand({ Marker: marker }));
      });
      fileShares.push(...(result.FileShareInfoList ?? []));
      marker = result.NextMarker;
    } while (marker);

    for (const fileShare of fileShares) {
      const shareId: string = fileShare.FileShareId ?? '';
      const shareArn: string | undefined = fileShare.FileShareARN;
      const fsType: string = fileShare.FileShareType ?? '';
      if (!shareArn) continue;

      try {
        let kmsEncrypted = false;
        let kmsKey: string | undefined;
        if (fsType === 'NFS') {
          const result = await retry(async () => {
            return await this.storagegateway.send(new DescribeNFSFileSharesCommand({ FileShareARNList: [shareArn] }));
          });
          const info: any = (result.NFSFileShareInfoList ?? [])[0] ?? {};
          kmsEncrypted = info.KMSEncrypted ?? false;
          kmsKey = info.KMSKey;
        } else if (fsType === 'SMB') {
          const result = await retry(async () => {
            return await this.storagegateway.send(new DescribeSMBFileSharesCommand({ FileShareARNList: [shareArn] }));
          });
          const info: any = (result.SMBFileShareInfoList ?? [])[0] ?? {};
          kmsEncrypted = info.KMSEncrypted ?? false;
          kmsKey = info.KMSKey;
        } else {
          continue;
        }

        if (!kmsEncrypted) {
          findings.push(this.emit(
            'storagegateway_fileshare_encryption_enabled',
            { fileShareId: shareId, fileShareArn: shareArn, fileShareType: fsType, kmsEncrypted: false, kmsKey: kmsKey ?? null },
            {
              message: `StorageGateway file share "${shareId}" (${fsType}) is not encrypted with a KMS CMK`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to scan StorageGateway file share ${shareId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  // storagegateway_gateway_fault_tolerant
  private async checkGateways(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const gateways: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.storagegateway.send(new ListGatewaysCommand({ Marker: marker }));
      });
      gateways.push(...(result.Gateways ?? []));
      marker = result.Marker;
    } while (marker);

    for (const gateway of gateways) {
      const name: string = gateway.GatewayName ?? gateway.GatewayId ?? '';
      const environment: string = gateway.HostEnvironment ?? '';
      if (environment === 'EC2') {
        findings.push(this.emit(
          'storagegateway_gateway_fault_tolerant',
          { gatewayId: gateway.GatewayId, gatewayName: name, gatewayType: gateway.GatewayType, hostEnvironment: environment },
          {
            message: `StorageGateway gateway "${name}" may not be fault tolerant as it is hosted on EC2`,
          }
        ));
      }
    }

    return findings;
  }
}

export default StorageGatewayScanner;
