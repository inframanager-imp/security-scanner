// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const eventbridgeChecks: CheckMetadata[] = [
  {
    checkId: 'eventbridge_bus_exposed',
    provider: 'aws',
    service: 'eventbridge',
    title: 'EventBridge Bus Publicly Accessible',
    severity: 'HIGH',
    description: 'Checks that EventBridge event bus resource policies do not grant access to all principals ("*") without restrictive conditions.',
    remediation: 'Remove public principals from the event bus resource policy or scope them with restrictive conditions; grant PutEvents only to specific accounts, organizations or services.',
    tags: ['eventbridge', 'public-access', 'resource-policy'],
  },
  {
    checkId: 'eventbridge_bus_cross_account_access',
    provider: 'aws',
    service: 'eventbridge',
    title: 'EventBridge Bus Allows Cross-Account Access',
    severity: 'HIGH',
    description: 'Checks that EventBridge event bus resource policies do not allow principals from other AWS accounts to publish or manage events on the bus.',
    remediation: 'Limit the event bus policy to principals in your own account or an explicit allow-list of trusted accounts, and add conditions such as aws:PrincipalOrgID to constrain access.',
    tags: ['eventbridge', 'cross-account', 'resource-policy'],
  },
  {
    checkId: 'eventbridge_global_endpoint_event_replication_enabled',
    provider: 'aws',
    service: 'eventbridge',
    title: 'EventBridge Global Endpoint Replication Disabled',
    severity: 'MEDIUM',
    description: 'Checks that EventBridge global endpoints have event replication enabled so events continue to be processed in the secondary region after a failover.',
    remediation: 'Enable event replication on the global endpoint so events are delivered to both the primary and secondary region event buses, avoiding event loss during failover.',
    tags: ['eventbridge', 'resilience', 'replication'],
  },
  {
    checkId: 'eventbridge_schema_registry_cross_account_access',
    provider: 'aws',
    service: 'eventbridge',
    title: 'EventBridge Schema Registry Allows Cross-Account Access',
    severity: 'HIGH',
    description: 'Checks that EventBridge schema registry resource policies do not allow access from other AWS accounts.',
    remediation: 'Scope the schema registry resource policy to your own account or explicitly trusted accounts; remove public or wildcard principals from the policy.',
    tags: ['eventbridge', 'schemas', 'cross-account', 'resource-policy'],
  },
];
