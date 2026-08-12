// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const directconnectChecks: CheckMetadata[] = [
  {
    checkId: 'directconnect_connection_redundancy',
    provider: 'aws',
    service: 'directconnect',
    title: 'Direct Connect Missing Connection Redundancy',
    severity: 'MEDIUM',
    description: 'Checks that Direct Connect connectivity in the region uses multiple connections spread across at least two distinct Direct Connect locations, avoiding a single point of failure.',
    remediation: 'Provision at least two Direct Connect connections in different Direct Connect locations, use dynamic active/active routing for automatic failover, ensure provider/device diversity, and size capacity so a single link loss does not overload the remaining paths.',
    tags: ['directconnect', 'redundancy', 'resilience', 'network'],
  },
  {
    checkId: 'directconnect_virtual_interface_redundancy',
    provider: 'aws',
    service: 'directconnect',
    title: 'Direct Connect Gateway Missing VIF Redundancy',
    severity: 'MEDIUM',
    description: 'Checks that each Direct Connect gateway and virtual private gateway has at least two virtual interfaces (VIFs) distributed across more than one Direct Connect connection.',
    remediation: 'Attach at least two VIFs per gateway on separate Direct Connect connections in distinct locations, prefer active/active dynamic routing, and optionally add a VPN or Transit Gateway path as backup during provider outages.',
    tags: ['directconnect', 'redundancy', 'resilience', 'network'],
  },
];
