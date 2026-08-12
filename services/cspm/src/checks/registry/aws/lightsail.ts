// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const lightsailChecks: CheckMetadata[] = [
  {
    checkId: 'lightsail_database_public',
    provider: 'aws',
    service: 'lightsail',
    title: 'Lightsail Database Publicly Accessible',
    severity: 'HIGH',
    description: 'Checks that Lightsail managed databases do not have public network reachability enabled.',
    remediation: 'Disable public mode on the database so it only accepts connections from Lightsail resources in the same region, or reach it privately via VPC peering.',
    tags: ['lightsail', 'database', 'public-access'],
  },
  {
    checkId: 'lightsail_instance_public',
    provider: 'aws',
    service: 'lightsail',
    title: 'Lightsail Instance Publicly Exposed',
    severity: 'HIGH',
    description: 'Checks that Lightsail instances with a public IP do not have firewall ports open to any IPv4 address.',
    remediation: 'Restrict instance firewall rules to specific trusted source IPs, close unused ports, or remove the public IP and access the instance through a bastion or VPN.',
    tags: ['lightsail', 'public-access', 'network'],
  },
  {
    checkId: 'lightsail_instance_automated_snapshots',
    provider: 'aws',
    service: 'lightsail',
    title: 'Lightsail Instance Automated Snapshots Disabled',
    severity: 'MEDIUM',
    description: 'Checks that Lightsail instances have the automatic snapshots add-on enabled for point-in-time recovery.',
    remediation: 'Enable the automatic snapshots add-on on the instance and verify the snapshot schedule and retention meet recovery objectives.',
    tags: ['lightsail', 'snapshots', 'resilience'],
  },
  {
    checkId: 'lightsail_static_ip_unused',
    provider: 'aws',
    service: 'lightsail',
    title: 'Lightsail Static IP Unattached',
    severity: 'LOW',
    description: 'Checks that Lightsail static IPs are attached to an instance; unattached static IPs expose account footprint information and accrue cost.',
    remediation: 'Attach the static IP to an instance or release it if it is no longer needed.',
    tags: ['lightsail', 'static-ip', 'hygiene'],
  },
];
