// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  WorkSpacesClient,
  DescribeWorkspacesCommand,
} from '@aws-sdk/client-workspaces';
import {
  EC2Client,
  DescribeSubnetsCommand,
  DescribeRouteTablesCommand,
} from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

interface VpcAnalysis {
  vpcId: string;
  publicSubnets: number;
  privateSubnets: number;
  natGateway: boolean;
  /** subnetId -> whether the subnet routes 0.0.0.0/0 to an internet gateway */
  subnetIsPublic: Map<string, boolean>;
}

export class WorkSpacesScanner extends BaseScanner {
  private workspaces: WorkSpacesClient;
  private ec2: EC2Client;
  private subnetVpcCache: Map<string, string | null> = new Map();
  private vpcAnalysisCache: Map<string, VpcAnalysis> = new Map();

  constructor(client: AWSClient) {
    super(client, 'WorkSpaces');
    this.workspaces = new WorkSpacesClient(client.getClientConfig());
    this.ec2 = new EC2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting WorkSpaces security scan...');

      const workspaces = await this.describeWorkspaces();
      for (const workspace of workspaces) {
        const workspaceId: string = workspace?.WorkspaceId ?? '';
        if (!workspaceId) continue;
        logger.debug(`Scanning WorkSpace: ${workspaceId}`);
        try {
          findings.push(...this.validateVolumeEncryption(workspace));
          const vpcFinding = await this.validateVpcTopology(workspace);
          if (vpcFinding) findings.push(vpcFinding);
        } catch (error) {
          logger.debug(`Failed to scan WorkSpace ${workspaceId}`, { error: (error as Error).message });
        }
      }

      logger.info(`WorkSpaces scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('WorkSpaces scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeWorkspaces(): Promise<any[]> {
    const workspaces: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.workspaces.send(new DescribeWorkspacesCommand({ NextToken: nextToken }));
      });
      workspaces.push(...(result.Workspaces ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return workspaces;
  }

  // workspaces_volume_encryption_enabled: both root and user volumes must be encrypted
  private validateVolumeEncryption(workspace: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const workspaceId: string = workspace.WorkspaceId;
    const userEncrypted = workspace.UserVolumeEncryptionEnabled === true;
    const rootEncrypted = workspace.RootVolumeEncryptionEnabled === true;

    if (!userEncrypted || !rootEncrypted) {
      const unencrypted =
        !userEncrypted && !rootEncrypted ? 'root and user volumes' : (!rootEncrypted ? 'root volume' : 'user volume');
      findings.push(this.emit(
        'workspaces_volume_encryption_enabled',
        {
          workspaceId,
          rootVolumeEncryptionEnabled: rootEncrypted,
          userVolumeEncryptionEnabled: userEncrypted,
        },
        {
          message: `WorkSpaces workspace "${workspaceId}" has unencrypted ${unencrypted}`,
          remediation: `Rebuild workspace "${workspaceId}" with root and user volume encryption enabled (encryption can only be set at creation time)`,
        }
      ));
    }
    return findings;
  }

  // workspaces_vpc_2private_1public_subnets_nat: the WorkSpace must live in a private subnet of a
  // VPC with >= 1 public subnet and >= 2 private subnets where a private subnet routes via a NAT gateway
  private async validateVpcTopology(workspace: any): Promise<ScanningResult | null> {
    const workspaceId: string = workspace.WorkspaceId;
    const subnetId: string | undefined = workspace.SubnetId;

    let analysis: VpcAnalysis | null = null;
    let isInPrivateSubnet = false;

    if (subnetId) {
      try {
        const vpcId = await this.getSubnetVpcId(subnetId);
        if (vpcId) {
          analysis = await this.analyzeVpc(vpcId);
          isInPrivateSubnet = analysis.subnetIsPublic.get(subnetId) === false;
        }
      } catch (error) {
        // Cannot determine the topology; skip the check rather than raise a false positive
        logger.debug(`Failed to analyze VPC topology for WorkSpace ${workspaceId}`, { error: (error as Error).message });
        return null;
      }
    }

    const publicSubnets = analysis?.publicSubnets ?? 0;
    const privateSubnets = analysis?.privateSubnets ?? 0;
    const natGateway = analysis?.natGateway ?? false;

    if (publicSubnets < 1 || privateSubnets < 2 || !natGateway || !isInPrivateSubnet) {
      return this.emit(
        'workspaces_vpc_2private_1public_subnets_nat',
        {
          workspaceId,
          subnetId: subnetId ?? null,
          vpcId: analysis?.vpcId ?? null,
          isInPrivateSubnet,
          publicSubnets,
          privateSubnets,
          natGateway,
        },
        {
          message: `WorkSpace "${workspaceId}" is not in a private subnet, or its VPC does not have 1 public subnet and 2 private subnets with a NAT Gateway attached`,
        }
      );
    }
    return null;
  }

  private async getSubnetVpcId(subnetId: string): Promise<string | null> {
    if (this.subnetVpcCache.has(subnetId)) {
      return this.subnetVpcCache.get(subnetId) ?? null;
    }
    const result: any = await retry(async () => {
      return await this.ec2.send(new DescribeSubnetsCommand({ SubnetIds: [subnetId] }));
    });
    const vpcId: string | null = result.Subnets?.[0]?.VpcId ?? null;
    this.subnetVpcCache.set(subnetId, vpcId);
    return vpcId;
  }

  private async analyzeVpc(vpcId: string): Promise<VpcAnalysis> {
    const cached = this.vpcAnalysisCache.get(vpcId);
    if (cached) return cached;

    // All subnets of the VPC
    const subnets: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.ec2.send(new DescribeSubnetsCommand({
          Filters: [{ Name: 'vpc-id', Values: [vpcId] }],
          NextToken: nextToken,
        }));
      });
      subnets.push(...(result.Subnets ?? []));
      nextToken = result.NextToken;
    } while (nextToken);

    // All route tables of the VPC, mapped to subnets (explicit association, else main route table)
    const routeTables: any[] = [];
    nextToken = undefined;
    do {
      const result: any = await retry(async () => {
        return await this.ec2.send(new DescribeRouteTablesCommand({
          Filters: [{ Name: 'vpc-id', Values: [vpcId] }],
          NextToken: nextToken,
        }));
      });
      routeTables.push(...(result.RouteTables ?? []));
      nextToken = result.NextToken;
    } while (nextToken);

    const routeTableBySubnet = new Map<string, any>();
    let mainRouteTable: any = null;
    for (const routeTable of routeTables) {
      for (const association of routeTable.Associations ?? []) {
        if (association.SubnetId) {
          routeTableBySubnet.set(association.SubnetId, routeTable);
        }
        if (association.Main) {
          mainRouteTable = routeTable;
        }
      }
    }

    const analysis: VpcAnalysis = {
      vpcId,
      publicSubnets: 0,
      privateSubnets: 0,
      natGateway: false,
      subnetIsPublic: new Map<string, boolean>(),
    };

    for (const subnet of subnets) {
      const id: string = subnet.SubnetId;
      const routeTable = routeTableBySubnet.get(id) ?? mainRouteTable;
      const routes: any[] = routeTable?.Routes ?? [];
      const isPublic = routes.some(
        (route) => route.GatewayId && String(route.GatewayId).includes('igw') && route.DestinationCidrBlock === '0.0.0.0/0'
      );
      const hasNatRoute = routes.some((route) => route.NatGatewayId);
      analysis.subnetIsPublic.set(id, isPublic);
      if (isPublic) {
        analysis.publicSubnets += 1;
      } else {
        analysis.privateSubnets += 1;
        if (hasNatRoute) analysis.natGateway = true;
      }
    }

    this.vpcAnalysisCache.set(vpcId, analysis);
    return analysis;
  }
}

export default WorkSpacesScanner;
