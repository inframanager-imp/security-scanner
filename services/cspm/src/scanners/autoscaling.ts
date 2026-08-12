// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  AutoScalingClient,
  DescribeAutoScalingGroupsCommand,
  DescribeLaunchConfigurationsCommand,
} from '@aws-sdk/client-auto-scaling';
import { gunzipSync } from 'zlib';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Lightweight secret heuristics (Prowler uses a full secret scanner; we match
// well-known credential formats and secret-like assignments in user data).
const SECRET_CONTENT_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: 'AWS Access Key ID', pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
  { label: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
  {
    label: 'Secret Assignment',
    pattern: /(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[=:]\s*['"]?[^\s'"]{6,}/i,
  },
];

function findSecretsInText(text: string): string[] {
  const matches: string[] = [];
  for (const { label, pattern } of SECRET_CONTENT_PATTERNS) {
    if (pattern.test(text)) matches.push(label);
  }
  return matches;
}

export class AutoScalingScanner extends BaseScanner {
  private autoscaling: AutoScalingClient;

  constructor(client: AWSClient) {
    super(client, 'AutoScaling');
    this.autoscaling = new AutoScalingClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting AutoScaling security scan...');

      const launchConfigurations = await this.describeLaunchConfigurations();
      const groups = await this.describeAutoScalingGroups();

      // Launch-configuration-level check: secrets in User Data
      for (const lc of launchConfigurations) {
        try {
          const secretFindings = this.checkLaunchConfigurationSecrets(lc);
          findings.push(...secretFindings);
        } catch (error) {
          logger.debug(`Failed to scan launch configuration ${lc.LaunchConfigurationName}`, { error: (error as Error).message });
        }
      }

      const lcByName = new Map<string, any>();
      for (const lc of launchConfigurations) {
        if (lc.LaunchConfigurationName) lcByName.set(lc.LaunchConfigurationName, lc);
      }

      for (const group of groups) {
        try {
          findings.push(...this.validateGroup(group, lcByName));
        } catch (error) {
          logger.debug(`Failed to scan Auto Scaling group ${group.AutoScalingGroupName}`, { error: (error as Error).message });
        }
      }

      logger.info(`AutoScaling scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('AutoScaling scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeLaunchConfigurations(): Promise<any[]> {
    const configurations: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.autoscaling.send(new DescribeLaunchConfigurationsCommand({ NextToken: nextToken }));
      });
      configurations.push(...(result.LaunchConfigurations ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return configurations;
  }

  private async describeAutoScalingGroups(): Promise<any[]> {
    const groups: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.autoscaling.send(new DescribeAutoScalingGroupsCommand({ NextToken: nextToken }));
      });
      groups.push(...(result.AutoScalingGroups ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return groups;
  }

  // autoscaling_find_secrets_ec2_launch_configuration
  private checkLaunchConfigurationSecrets(lc: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const lcName: string = lc.LaunchConfigurationName ?? '';
    const userData: string = lc.UserData ?? '';
    if (!userData) return findings;

    let decoded: string;
    try {
      let buffer = Buffer.from(userData, 'base64');
      // GZIP magic number check, as in Prowler
      if (buffer.length > 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
        buffer = gunzipSync(buffer);
      }
      decoded = buffer.toString('utf-8');
    } catch (error) {
      logger.debug(`Unable to decode user data in launch configuration ${lcName}`, { error: (error as Error).message });
      return findings;
    }

    const secretsFound = findSecretsInText(decoded);
    if (secretsFound.length > 0) {
      findings.push(this.emit(
        'autoscaling_find_secrets_ec2_launch_configuration',
        { launchConfiguration: lcName, arn: lc.LaunchConfigurationARN, secretTypes: secretsFound },
        {
          message: `Potential secret found in Auto Scaling launch configuration "${lcName}" User Data (${secretsFound.join(', ')})`,
          remediation: `Remove secrets from the User Data of launch configuration "${lcName}"; fetch them at runtime from Secrets Manager or SSM Parameter Store and rotate any exposed credentials`,
        }
      ));
    }
    return findings;
  }

  private validateGroup(group: any, lcByName: Map<string, any>): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const groupName: string = group.AutoScalingGroupName ?? '';
    const loadBalancers: string[] = group.LoadBalancerNames ?? [];
    const targetGroups: string[] = group.TargetGroupARNs ?? [];
    const availabilityZones: string[] = group.AvailabilityZones ?? [];

    // Launch-configuration-dependent checks (only when the group's launch configuration was found)
    const lc = group.LaunchConfigurationName ? lcByName.get(group.LaunchConfigurationName) : undefined;
    if (lc) {
      // autoscaling_group_launch_configuration_no_public_ip
      if (lc.AssociatePublicIpAddress === true) {
        findings.push(this.emit(
          'autoscaling_group_launch_configuration_no_public_ip',
          { group: groupName, launchConfiguration: lc.LaunchConfigurationName, associatePublicIpAddress: true },
          {
            message: `Auto Scaling group "${groupName}" has an associated launch configuration assigning a public IP address`,
            remediation: `Set AssociatePublicIpAddress=false on launch configuration "${lc.LaunchConfigurationName}" and place instances of group "${groupName}" in private subnets`,
          }
        ));
      }

      // autoscaling_group_launch_configuration_requires_imdsv2
      const httpEndpoint: string = lc.MetadataOptions?.HttpEndpoint ?? '';
      const httpTokens: string = lc.MetadataOptions?.HttpTokens ?? '';
      const imdsv2Enforced = httpEndpoint === 'enabled' && httpTokens === 'required';
      const metadataDisabled = httpEndpoint === 'disabled';
      if (!imdsv2Enforced && !metadataDisabled) {
        findings.push(this.emit(
          'autoscaling_group_launch_configuration_requires_imdsv2',
          { group: groupName, launchConfiguration: lc.LaunchConfigurationName, httpEndpoint, httpTokens },
          {
            message: `Auto Scaling group "${groupName}" has IMDSv2 disabled or not required`,
            remediation: `Set HttpTokens=required in the metadata options of launch configuration "${lc.LaunchConfigurationName}", or disable the metadata endpoint if not needed`,
          }
        ));
      }
    }

    // autoscaling_group_capacity_rebalance_enabled (only load-balanced groups, as in Prowler)
    if (loadBalancers.length > 0 && targetGroups.length > 0 && !group.CapacityRebalance) {
      findings.push(this.emit(
        'autoscaling_group_capacity_rebalance_enabled',
        { group: groupName, capacityRebalance: false },
        {
          message: `Auto Scaling group "${groupName}" does not have capacity rebalance enabled`,
        }
      ));
    }

    // autoscaling_group_elb_health_check_enabled (only load-balanced groups, as in Prowler)
    const healthCheckType: string = group.HealthCheckType ?? '';
    if (loadBalancers.length > 0 && targetGroups.length > 0 && !healthCheckType.includes('ELB')) {
      findings.push(this.emit(
        'autoscaling_group_elb_health_check_enabled',
        { group: groupName, healthCheckType },
        {
          message: `Auto Scaling group "${groupName}" is associated with a load balancer but does not have ELB health checks enabled, instead it has ${healthCheckType || 'EC2'} health checks`,
          remediation: `Set the health check type to ELB on Auto Scaling group "${groupName}" so instances failing load balancer probes are replaced`,
        }
      ));
    }

    // autoscaling_group_multiple_az
    if (availabilityZones.length <= 1) {
      findings.push(this.emit(
        'autoscaling_group_multiple_az',
        { group: groupName, availabilityZones },
        {
          message: `Auto Scaling group "${groupName}" has only one Availability Zone`,
          remediation: `Add subnets in at least one more Availability Zone to Auto Scaling group "${groupName}"`,
        }
      ));
    }

    // autoscaling_group_multiple_instance_types
    const azInstanceTypes = new Map<string, Set<string>>();
    for (const instance of group.Instances ?? []) {
      const az: string | undefined = instance.AvailabilityZone;
      const instanceType: string | undefined = instance.InstanceType;
      if (!az || !instanceType) continue;
      if (!azInstanceTypes.has(az)) azInstanceTypes.set(az, new Set<string>());
      azInstanceTypes.get(az)!.add(instanceType);
    }
    const failingAzs: string[] = [];
    for (const [az, types] of azInstanceTypes) {
      if (types.size < 2) failingAzs.push(az);
    }
    if (!(failingAzs.length === 0 && azInstanceTypes.size > 1)) {
      const message = failingAzs.length > 0
        ? `Auto Scaling group "${groupName}" has only one or no instance types in Availability Zone(s): ${failingAzs.join(', ')}`
        : `Auto Scaling group "${groupName}" does not have multiple instance types in multiple Availability Zones`;
      findings.push(this.emit(
        'autoscaling_group_multiple_instance_types',
        {
          group: groupName,
          azInstanceTypes: Object.fromEntries([...azInstanceTypes].map(([az, types]) => [az, [...types]])),
          failingAzs,
        },
        { message }
      ));
    }

    // autoscaling_group_using_ec2_launch_template
    const launchTemplate = group.LaunchTemplate;
    const mixedInstancesPolicyLaunchTemplate = group.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification;
    if (!launchTemplate && !mixedInstancesPolicyLaunchTemplate) {
      findings.push(this.emit(
        'autoscaling_group_using_ec2_launch_template',
        { group: groupName, launchConfigurationName: group.LaunchConfigurationName ?? null },
        {
          message: `Auto Scaling group "${groupName}" is not using an EC2 launch template`,
          remediation: `Migrate Auto Scaling group "${groupName}" from its launch configuration to a versioned EC2 launch template`,
        }
      ));
    }

    return findings;
  }
}

export default AutoScalingScanner;
