// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const appstreamChecks: CheckMetadata[] = [
  {
    checkId: 'appstream_fleet_default_internet_access_disabled',
    provider: 'aws',
    service: 'appstream',
    title: 'AppStream Fleet Default Internet Access Enabled',
    severity: 'MEDIUM',
    description: 'Checks that AppStream fleets do not have default internet access enabled, which gives streaming instances direct Internet exposure through a public IP.',
    remediation: 'Disable default internet access on the fleet and provide outbound connectivity through a NAT gateway in the fleet VPC instead.',
    tags: ['appstream', 'internet-access', 'network'],
  },
  {
    checkId: 'appstream_fleet_maximum_session_duration',
    provider: 'aws',
    service: 'appstream',
    title: 'AppStream Fleet Session Duration Too Long',
    severity: 'MEDIUM',
    description: 'Checks that the fleet maximum user session duration is less than 10 hours to bound the exposure window of hijacked or unattended sessions.',
    remediation: 'Set the fleet maximum session duration (MaxUserDurationInSeconds) below 36000 seconds (10 hours) so streaming sessions cannot run indefinitely.',
    tags: ['appstream', 'session-management'],
  },
  {
    checkId: 'appstream_fleet_session_disconnect_timeout',
    provider: 'aws',
    service: 'appstream',
    title: 'AppStream Fleet Disconnect Timeout Too Long',
    severity: 'MEDIUM',
    description: 'Checks that the fleet session disconnect timeout is 5 minutes or less so disconnected sessions are terminated promptly instead of remaining resumable.',
    remediation: 'Set the fleet disconnect timeout (DisconnectTimeoutInSeconds) to 300 seconds (5 minutes) or less.',
    tags: ['appstream', 'session-management'],
  },
  {
    checkId: 'appstream_fleet_session_idle_disconnect_timeout',
    provider: 'aws',
    service: 'appstream',
    title: 'AppStream Fleet Idle Disconnect Timeout Too Long',
    severity: 'MEDIUM',
    description: 'Checks that the fleet idle disconnect timeout is configured and set to 10 minutes or less so idle users are disconnected from their streaming session.',
    remediation: 'Set the fleet idle disconnect timeout (IdleDisconnectTimeoutInSeconds) to a value between 1 and 600 seconds (10 minutes).',
    tags: ['appstream', 'session-management'],
  },
];
