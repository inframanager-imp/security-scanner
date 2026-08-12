// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ShieldClient,
  GetSubscriptionStateCommand,
  ListProtectionsCommand,
} from '@aws-sdk/client-shield';
import { EC2Client, DescribeAddressesCommand } from '@aws-sdk/client-ec2';
import {
  ElasticLoadBalancingClient,
  DescribeLoadBalancersCommand as DescribeClassicLoadBalancersCommand,
} from '@aws-sdk/client-elastic-load-balancing';
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand as DescribeV2LoadBalancersCommand,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import { CloudFrontClient, ListDistributionsCommand } from '@aws-sdk/client-cloudfront';
import { GlobalAcceleratorClient, ListAcceleratorsCommand } from '@aws-sdk/client-global-accelerator';
import { Route53Client, ListHostedZonesCommand } from '@aws-sdk/client-route-53';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/**
 * Shield Advanced protection coverage. Shield is a global service (us-east-1);
 * all checks are skipped unless the account has an active Shield Advanced
 * subscription, mirroring Prowler's behaviour.
 */
export class ShieldScanner extends BaseScanner {
  private shield: ShieldClient;

  constructor(client: AWSClient) {
    super(client, 'Shield');
    this.shield = new ShieldClient({ ...client.getClientConfig(), region: 'us-east-1' });
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Shield Advanced security scan...');

      const state: any = await retry(async () => {
        return await this.shield.send(new GetSubscriptionStateCommand({}));
      });
      if (state.SubscriptionState !== 'ACTIVE') {
        logger.info('Shield Advanced subscription not active — skipping protection coverage checks');
        return findings;
      }

      const protectedArns = await this.listProtectedResourceArns();

      await Promise.all([
        this.checkElasticIps(findings, protectedArns),
        this.checkClassicLoadBalancers(findings, protectedArns),
        this.checkV2LoadBalancers(findings, protectedArns),
        this.checkCloudFrontDistributions(findings, protectedArns),
        this.checkGlobalAccelerators(findings, protectedArns),
        this.checkRoute53HostedZones(findings, protectedArns),
      ]);

      logger.info(`Shield scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Shield scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listProtectedResourceArns(): Promise<Set<string>> {
    const arns = new Set<string>();
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.shield.send(new ListProtectionsCommand({ NextToken: nextToken }));
      });
      for (const protection of result.Protections ?? []) {
        if (protection.ResourceArn) arns.add(protection.ResourceArn);
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return arns;
  }

  // shield_advanced_protection_in_associated_elastic_ips
  private async checkElasticIps(findings: ScanningResult[], protectedArns: Set<string>): Promise<void> {
    try {
      const ec2 = new EC2Client(this.client.getClientConfig());
      const region = this.client.getClientConfig().region as string;
      const accountId = await this.client.getAccountId();
      const result: any = await retry(async () => ec2.send(new DescribeAddressesCommand({})));
      for (const address of result.Addresses ?? []) {
        if (!address.AllocationId || !address.AssociationId) continue;
        const arn = `arn:aws:ec2:${region}:${accountId}:eip-allocation/${address.AllocationId}`;
        if (!protectedArns.has(arn)) {
          findings.push(this.emit(
            'shield_advanced_protection_in_associated_elastic_ips',
            { allocationId: address.AllocationId, publicIp: address.PublicIp, arn },
            {
              message: `Elastic IP ${address.PublicIp} (${address.AllocationId}) is associated but not protected by Shield Advanced`,
              remediation: `Add Shield Advanced protection for Elastic IP allocation ${address.AllocationId}`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Shield EIP coverage check failed', { error: (error as Error).message });
    }
  }

  // shield_advanced_protection_in_classic_load_balancers
  private async checkClassicLoadBalancers(findings: ScanningResult[], protectedArns: Set<string>): Promise<void> {
    try {
      const elb = new ElasticLoadBalancingClient(this.client.getClientConfig());
      const region = this.client.getClientConfig().region as string;
      const accountId = await this.client.getAccountId();
      const result: any = await retry(async () => elb.send(new DescribeClassicLoadBalancersCommand({})));
      for (const lb of result.LoadBalancerDescriptions ?? []) {
        const arn = `arn:aws:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
        if (!protectedArns.has(arn)) {
          findings.push(this.emit(
            'shield_advanced_protection_in_classic_load_balancers',
            { loadBalancer: lb.LoadBalancerName, arn },
            {
              message: `Classic Load Balancer "${lb.LoadBalancerName}" is not protected by Shield Advanced`,
              remediation: `Add Shield Advanced protection for Classic Load Balancer "${lb.LoadBalancerName}"`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Shield CLB coverage check failed', { error: (error as Error).message });
    }
  }

  // shield_advanced_protection_in_internet_facing_load_balancers
  private async checkV2LoadBalancers(findings: ScanningResult[], protectedArns: Set<string>): Promise<void> {
    try {
      const elbv2 = new ElasticLoadBalancingV2Client(this.client.getClientConfig());
      const result: any = await retry(async () => elbv2.send(new DescribeV2LoadBalancersCommand({})));
      for (const lb of result.LoadBalancers ?? []) {
        if (lb.Scheme !== 'internet-facing' || lb.Type !== 'application') continue;
        if (!protectedArns.has(lb.LoadBalancerArn)) {
          findings.push(this.emit(
            'shield_advanced_protection_in_internet_facing_load_balancers',
            { loadBalancer: lb.LoadBalancerName, arn: lb.LoadBalancerArn },
            {
              message: `Internet-facing Application Load Balancer "${lb.LoadBalancerName}" is not protected by Shield Advanced`,
              remediation: `Add Shield Advanced protection for ALB "${lb.LoadBalancerName}"`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Shield ALB coverage check failed', { error: (error as Error).message });
    }
  }

  // shield_advanced_protection_in_cloudfront_distributions
  private async checkCloudFrontDistributions(findings: ScanningResult[], protectedArns: Set<string>): Promise<void> {
    try {
      const cloudfront = new CloudFrontClient({ ...this.client.getClientConfig(), region: 'us-east-1' });
      const result: any = await retry(async () => cloudfront.send(new ListDistributionsCommand({})));
      for (const dist of result.DistributionList?.Items ?? []) {
        if (!protectedArns.has(dist.ARN)) {
          findings.push(this.emit(
            'shield_advanced_protection_in_cloudfront_distributions',
            { distributionId: dist.Id, domainName: dist.DomainName, arn: dist.ARN },
            {
              message: `CloudFront distribution ${dist.Id} (${dist.DomainName}) is not protected by Shield Advanced`,
              remediation: `Add Shield Advanced protection for CloudFront distribution ${dist.Id}`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Shield CloudFront coverage check failed', { error: (error as Error).message });
    }
  }

  // shield_advanced_protection_in_global_accelerators
  private async checkGlobalAccelerators(findings: ScanningResult[], protectedArns: Set<string>): Promise<void> {
    try {
      // Global Accelerator control plane lives in us-west-2
      const ga = new GlobalAcceleratorClient({ ...this.client.getClientConfig(), region: 'us-west-2' });
      const result: any = await retry(async () => ga.send(new ListAcceleratorsCommand({})));
      for (const accelerator of result.Accelerators ?? []) {
        if (!protectedArns.has(accelerator.AcceleratorArn)) {
          findings.push(this.emit(
            'shield_advanced_protection_in_global_accelerators',
            { accelerator: accelerator.Name, arn: accelerator.AcceleratorArn },
            {
              message: `Global Accelerator "${accelerator.Name}" is not protected by Shield Advanced`,
              remediation: `Add Shield Advanced protection for Global Accelerator "${accelerator.Name}"`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Shield Global Accelerator coverage check failed', { error: (error as Error).message });
    }
  }

  // shield_advanced_protection_in_route53_hosted_zones
  private async checkRoute53HostedZones(findings: ScanningResult[], protectedArns: Set<string>): Promise<void> {
    try {
      const route53 = new Route53Client({ ...this.client.getClientConfig(), region: 'us-east-1' });
      const result: any = await retry(async () => route53.send(new ListHostedZonesCommand({})));
      for (const zone of result.HostedZones ?? []) {
        if (zone.Config?.PrivateZone) continue;
        const zoneId = (zone.Id ?? '').replace('/hostedzone/', '');
        const arn = `arn:aws:route53:::hostedzone/${zoneId}`;
        if (!protectedArns.has(arn)) {
          findings.push(this.emit(
            'shield_advanced_protection_in_route53_hosted_zones',
            { zone: zone.Name, zoneId, arn },
            {
              message: `Public Route 53 hosted zone "${zone.Name}" is not protected by Shield Advanced`,
              remediation: `Add Shield Advanced protection for hosted zone "${zone.Name}" (${zoneId})`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Shield Route53 coverage check failed', { error: (error as Error).message });
    }
  }
}

export default ShieldScanner;
