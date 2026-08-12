// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DirectConnectClient,
  DescribeConnectionsCommand,
  DescribeVirtualInterfacesCommand,
} from '@aws-sdk/client-direct-connect';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

interface GatewayVifGroup {
  vifIds: string[];
  connectionIds: string[];
}

export class DirectConnectScanner extends BaseScanner {
  private directconnect: DirectConnectClient;

  constructor(client: AWSClient) {
    super(client, 'DirectConnect');
    this.directconnect = new DirectConnectClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting DirectConnect security scan...');

      try {
        findings.push(...await this.checkConnectionRedundancy());
      } catch (error) {
        logger.debug('Failed to check Direct Connect connection redundancy', { error: (error as Error).message });
      }

      try {
        findings.push(...await this.checkVirtualInterfaceRedundancy());
      } catch (error) {
        logger.debug('Failed to check Direct Connect virtual interface redundancy', { error: (error as Error).message });
      }

      logger.info(`DirectConnect scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('DirectConnect scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  // directconnect_connection_redundancy: multiple connections across at least two locations
  private async checkConnectionRedundancy(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const result = await retry(async () => {
      return await this.directconnect.send(new DescribeConnectionsCommand({}));
    });
    const connections: any[] = result.connections ?? [];
    if (connections.length === 0) return findings;

    const connectionIds = connections.map((c: any) => c.connectionId);
    const locations = [...new Set(connections.map((c: any) => c.location))];

    if (connections.length === 1) {
      findings.push(this.emit(
        'directconnect_connection_redundancy',
        { connections: connectionIds, connectionCount: 1, locations },
        {
          message: 'There is only one Direct Connect connection in this region',
          remediation: 'Create an additional Direct Connect connection in a different Direct Connect location to achieve connection and location redundancy',
        }
      ));
    } else if (locations.length === 1) {
      findings.push(this.emit(
        'directconnect_connection_redundancy',
        { connections: connectionIds, connectionCount: connections.length, locations },
        {
          message: `There is only one location ${locations[0]} used by all the Direct Connect connections`,
          remediation: 'Create an additional Direct Connect connection in a different Direct Connect location so that connections span at least two locations',
        }
      ));
    }

    return findings;
  }

  // directconnect_virtual_interface_redundancy: each virtual private gateway and
  // Direct Connect gateway should have 2+ VIFs on more than one DX connection
  private async checkVirtualInterfaceRedundancy(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const result = await retry(async () => {
      return await this.directconnect.send(new DescribeVirtualInterfacesCommand({}));
    });
    const vifs: any[] = result.virtualInterfaces ?? [];

    const vgws = new Map<string, GatewayVifGroup>();
    const dxgws = new Map<string, GatewayVifGroup>();

    for (const vif of vifs) {
      const vifId: string = vif.virtualInterfaceId ?? '';
      const connectionId: string = vif.connectionId ?? '';
      const vgwId: string = vif.virtualGatewayId ?? '';
      const dxgwId: string = vif.directConnectGatewayId ?? '';

      if (vgwId) {
        const group = vgws.get(vgwId) ?? { vifIds: [], connectionIds: [] };
        group.vifIds.push(vifId);
        group.connectionIds.push(connectionId);
        vgws.set(vgwId, group);
      }
      if (dxgwId) {
        const group = dxgws.get(dxgwId) ?? { vifIds: [], connectionIds: [] };
        group.vifIds.push(vifId);
        group.connectionIds.push(connectionId);
        dxgws.set(dxgwId, group);
      }
    }

    for (const [vgwId, group] of vgws) {
      findings.push(...this.evaluateGateway('virtual private gateway', vgwId, group));
    }
    for (const [dxgwId, group] of dxgws) {
      findings.push(...this.evaluateGateway('Direct Connect gateway', dxgwId, group));
    }

    return findings;
  }

  private evaluateGateway(gatewayType: string, gatewayId: string, group: GatewayVifGroup): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const distinctConnections = [...new Set(group.connectionIds.filter((c) => c))];

    if (group.vifIds.length < 2) {
      findings.push(this.emit(
        'directconnect_virtual_interface_redundancy',
        { gatewayType, gatewayId, vifs: group.vifIds, connections: distinctConnections },
        {
          message: `${gatewayType.charAt(0).toUpperCase() + gatewayType.slice(1)} ${gatewayId} only has one VIF`,
          remediation: `Create a second virtual interface on a different Direct Connect connection and attach it to ${gatewayType} ${gatewayId}`,
        }
      ));
    } else if (distinctConnections.length < 2) {
      findings.push(this.emit(
        'directconnect_virtual_interface_redundancy',
        { gatewayType, gatewayId, vifs: group.vifIds, connections: distinctConnections },
        {
          message: `${gatewayType.charAt(0).toUpperCase() + gatewayType.slice(1)} ${gatewayId} has more than 1 VIFs, but all the VIFs are on the same DX Connection`,
          remediation: `Create an additional virtual interface for ${gatewayType} ${gatewayId} on a different Direct Connect connection so its VIFs span multiple connections`,
        }
      ));
    }

    return findings;
  }
}

export default DirectConnectScanner;
