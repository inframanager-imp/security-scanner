import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeNetworkAclsCommand,
  DescribeInstancesCommand,
  DescribeRouteTablesCommand,
  DescribeAddressesCommand,
  DescribeImagesCommand,
  DescribeVolumesCommand,
  DescribeSnapshotsCommand,
  DescribeNetworkInterfacesCommand,
  DescribeLaunchTemplatesCommand,
  DescribeClientVpnEndpointsCommand,
  DescribeTransitGatewaysCommand,
  GetEbsEncryptionByDefaultCommand,
  GetImageBlockPublicAccessStateCommand,
  GetSnapshotBlockPublicAccessStateCommand,
  GetInstanceMetadataDefaultsCommand,
} from '@aws-sdk/client-ec2';
import { BackupClient, ListProtectedResourcesCommand } from '@aws-sdk/client-backup';
import { EC2Scanner } from '../../../src/scanners/ec2';
import AWSClient from '../../../src/aws/client';

const ec2Mock = mockClient(EC2Client);
const backupMock = mockClient(BackupClient);

/**
 * Wire every command the EC2Scanner touches to a benign empty-ish default so
 * scan() (which fans out into ~15 sub-checks) resolves cleanly. Individual
 * tests override specific commands to exercise specific check branches.
 */
function stubAllCommandsToEmpty() {
  ec2Mock.on(DescribeSecurityGroupsCommand).resolves({ SecurityGroups: [] });
  ec2Mock.on(DescribeNetworkAclsCommand).resolves({ NetworkAcls: [] });
  ec2Mock.on(DescribeInstancesCommand).resolves({ Reservations: [] });
  ec2Mock.on(DescribeRouteTablesCommand).resolves({ RouteTables: [] });
  ec2Mock.on(DescribeAddressesCommand).resolves({ Addresses: [] });
  ec2Mock.on(DescribeImagesCommand).resolves({ Images: [] });
  ec2Mock.on(DescribeVolumesCommand).resolves({ Volumes: [] });
  ec2Mock.on(DescribeSnapshotsCommand).resolves({ Snapshots: [] });
  ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({ NetworkInterfaces: [] });
  ec2Mock.on(DescribeLaunchTemplatesCommand).resolves({ LaunchTemplates: [] });
  ec2Mock.on(DescribeClientVpnEndpointsCommand).resolves({ ClientVpnEndpoints: [] });
  ec2Mock.on(DescribeTransitGatewaysCommand).resolves({ TransitGateways: [] });
  ec2Mock.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });
  ec2Mock.on(GetImageBlockPublicAccessStateCommand).resolves({ ImageBlockPublicAccessState: 'block-new-sharing' });
  ec2Mock.on(GetSnapshotBlockPublicAccessStateCommand).resolves({ State: 'block-all-sharing' });
  ec2Mock.on(GetInstanceMetadataDefaultsCommand).resolves({ AccountLevel: { HttpTokens: 'required' } });
  backupMock.on(ListProtectedResourcesCommand).resolves({ Results: [] });
}

function makeClient(): AWSClient {
  // Real AWSClient so this.client.ec2 is a genuine EC2Client instance that
  // aws-sdk-client-mock's prototype patch intercepts.
  return new AWSClient('us-east-1', undefined, {
    accessKeyId: 'test-access-key',
    secretAccessKey: 'test-secret-key',
  });
}

describe('EC2Scanner', () => {
  beforeEach(() => {
    ec2Mock.reset();
    backupMock.reset();
    stubAllCommandsToEmpty();
  });

  describe('scan() - security groups', () => {
    it('emits a high-risk-ports finding when a security group opens an admin port to the internet', async () => {
      ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
        SecurityGroups: [
          {
            GroupId: 'sg-12345',
            GroupName: 'web-sg',
            IpPermissions: [
              {
                IpProtocol: 'tcp',
                FromPort: 22,
                ToPort: 22,
                IpRanges: [{ CidrIp: '0.0.0.0/0' }],
              },
            ],
          },
        ],
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find(
        (f) => f.checkId === 'ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports',
      );
      expect(finding).toBeDefined();
      expect(finding!.service).toBe('EC2');
      expect(finding!.evidence).toMatchObject({ sgId: 'sg-12345', sgName: 'web-sg' });
      expect(finding!.evidence.openPorts).toEqual([{ port: '22', protocol: 'tcp' }]);
    });

    it('does not emit a high-risk-ports finding when ingress is restricted to a private CIDR', async () => {
      ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
        SecurityGroups: [
          {
            GroupId: 'sg-private',
            GroupName: 'internal-sg',
            IpPermissions: [
              {
                IpProtocol: 'tcp',
                FromPort: 22,
                ToPort: 22,
                IpRanges: [{ CidrIp: '10.0.0.0/16' }],
              },
            ],
          },
        ],
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      expect(
        findings.some((f) => f.checkId === 'ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports'),
      ).toBe(false);
    });
  });

  describe('scan() - network ACLs', () => {
    it('emits ec2_networkacl_allow_ingress_any_port when an entry allows 0.0.0.0/0', async () => {
      ec2Mock.on(DescribeNetworkAclsCommand).resolves({
        NetworkAcls: [
          {
            NetworkAclId: 'acl-9999',
            Entries: [
              { RuleNumber: 100, RuleAction: 'allow', CidrBlock: '0.0.0.0/0', Egress: false, Protocol: '-1' },
            ],
          },
        ],
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'ec2_networkacl_allow_ingress_any_port');
      expect(finding).toBeDefined();
      expect(finding!.evidence.naclId).toBe('acl-9999');
      expect(finding!.evidence.permissiveEntries).toHaveLength(1);
    });

    it('returns no NACL finding when there are no permissive entries', async () => {
      ec2Mock.on(DescribeNetworkAclsCommand).resolves({
        NetworkAcls: [
          {
            NetworkAclId: 'acl-clean',
            Entries: [
              { RuleNumber: 100, RuleAction: 'deny', CidrBlock: '0.0.0.0/0', Egress: false, Protocol: '-1' },
            ],
          },
        ],
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'ec2_networkacl_allow_ingress_any_port')).toBe(false);
    });
  });

  describe('scan() - instances', () => {
    it('flags a running instance without IMDSv2 enforced and without detailed monitoring', async () => {
      ec2Mock.on(DescribeInstancesCommand).resolves({
        Reservations: [
          {
            Instances: [
              {
                InstanceId: 'i-abc123',
                State: { Name: 'running' },
                SecurityGroups: [{ GroupId: 'sg-1' }],
                MetadataOptions: { HttpTokens: 'optional' },
                Monitoring: { State: 'disabled' },
              },
            ],
          },
        ],
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      const imdsFinding = findings.find((f) => f.checkId === 'ec2_instance_imdsv2_enabled');
      expect(imdsFinding).toBeDefined();
      expect(imdsFinding!.evidence).toMatchObject({ instanceId: 'i-abc123', httpTokens: 'optional' });

      const monitoringFinding = findings.find((f) => f.checkId === 'ec2_instance_detailed_monitoring_enabled');
      expect(monitoringFinding).toBeDefined();
      expect(monitoringFinding!.evidence).toMatchObject({ instanceId: 'i-abc123' });
    });

    it('flags an instance with a public IP and no attached security groups', async () => {
      ec2Mock.on(DescribeInstancesCommand).resolves({
        Reservations: [
          {
            Instances: [
              {
                InstanceId: 'i-nosg',
                State: { Name: 'running' },
                PublicIpAddress: '203.0.113.5',
                SecurityGroups: [],
                MetadataOptions: { HttpTokens: 'required' },
                Monitoring: { State: 'enabled' },
              },
            ],
          },
        ],
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'ec2_instance_public_ip_without_security_group');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ instanceId: 'i-nosg', publicIp: '203.0.113.5' });
    });

    it('does not flag a well-configured instance (IMDSv2 required, monitoring enabled, SG attached)', async () => {
      ec2Mock.on(DescribeInstancesCommand).resolves({
        Reservations: [
          {
            Instances: [
              {
                InstanceId: 'i-good',
                State: { Name: 'running' },
                SecurityGroups: [{ GroupId: 'sg-1' }],
                MetadataOptions: { HttpTokens: 'required' },
                Monitoring: { State: 'enabled' },
              },
            ],
          },
        ],
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'ec2_instance_imdsv2_enabled' && f.evidence.instanceId === 'i-good')).toBe(false);
      expect(findings.some((f) => f.checkId === 'ec2_instance_detailed_monitoring_enabled' && f.evidence.instanceId === 'i-good')).toBe(false);
      expect(findings.some((f) => f.checkId === 'ec2_instance_public_ip_without_security_group' && f.evidence.instanceId === 'i-good')).toBe(false);
    });

    it('paginates the any-state instance fetch across two pages and processes instances from both', async () => {
      // ec2_instance_imdsv2_enabled comes from scanInstances(), which issues a
      // single non-paginated DescribeInstances call. The NextToken pagination
      // loop lives in getAllInstancesAnyState() (feeding checkInstanceHygiene,
      // e.g. ec2_instance_profile_attached) and getAllRunningInstances(), both
      // of which also call DescribeInstances — so drive pagination off the
      // actual NextToken request parameter rather than call order, which is
      // shared across all three call sites within a single scan().
      ec2Mock.on(DescribeInstancesCommand).callsFake((input: any) => {
        if (!input.NextToken) {
          return Promise.resolve({
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: 'i-page1',
                    State: { Name: 'running' },
                    SecurityGroups: [{ GroupId: 'sg-1' }],
                  },
                ],
              },
            ],
            NextToken: 'token-page-2',
          });
        }
        return Promise.resolve({
          Reservations: [
            {
              Instances: [
                {
                  InstanceId: 'i-page2',
                  State: { Name: 'running' },
                  SecurityGroups: [{ GroupId: 'sg-1' }],
                },
              ],
            },
          ],
        });
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      const noProfileInstanceIds = findings
        .filter((f) => f.checkId === 'ec2_instance_profile_attached')
        .map((f) => f.evidence.instanceId);

      expect(noProfileInstanceIds).toEqual(expect.arrayContaining(['i-page1', 'i-page2']));
    });
  });

  describe('scan() - EBS default encryption', () => {
    it('emits ec2_ebs_default_encryption when default encryption is disabled for the region', async () => {
      ec2Mock.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: false });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'ec2_ebs_default_encryption');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ ebsEncryptionByDefault: false, region: 'us-east-1' });
    });

    it('does not emit ec2_ebs_default_encryption when default encryption is enabled', async () => {
      ec2Mock.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'ec2_ebs_default_encryption')).toBe(false);
    });
  });

  describe('scan() - empty account', () => {
    it('returns no findings for security groups, NACLs, or instances when the account has none', async () => {
      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      expect(
        findings.some((f) =>
          [
            'ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports',
            'ec2_networkacl_allow_ingress_any_port',
            'ec2_instance_imdsv2_enabled',
            'ec2_instance_public_ip_without_security_group',
            'ec2_instance_detailed_monitoring_enabled',
          ].includes(f.checkId as string),
        ),
      ).toBe(false);
    });
  });

  describe('scan() - error handling', () => {
    // retry() backs off between attempts with real setTimeout delays (1s, 2s
    // per call site). A full scan() fans out into ~15 independent check
    // groups, so a universally-rejecting mock would serialize many such
    // backoffs and blow the test timeout. Patch setTimeout to fire on the
    // next tick so the retry logic still runs for real, just without the wait.
    let setTimeoutSpy: ReturnType<typeof jest.spyOn>;

    beforeEach(() => {
      setTimeoutSpy = jest
        .spyOn(global, 'setTimeout')
        // @ts-expect-error - simplified overload for test instrumentation
        .mockImplementation((fn: () => void) => {
          fn();
          return 0 as any;
        });
    });

    afterEach(() => {
      setTimeoutSpy.mockRestore();
    });

    it('does not throw and returns gracefully when DescribeSecurityGroups rejects', async () => {
      ec2Mock.on(DescribeSecurityGroupsCommand).rejects(new Error('AccessDenied'));

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      expect(Array.isArray(findings)).toBe(true);
      expect(
        findings.some((f) => f.checkId === 'ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports'),
      ).toBe(false);
    });

    it('does not throw and still returns other findings when DescribeInstances rejects', async () => {
      ec2Mock.on(DescribeInstancesCommand).rejects(new Error('Throttling'));
      ec2Mock.on(DescribeNetworkAclsCommand).resolves({
        NetworkAcls: [
          {
            NetworkAclId: 'acl-still-works',
            Entries: [
              { RuleNumber: 100, RuleAction: 'allow', CidrBlock: '0.0.0.0/0', Egress: false, Protocol: '-1' },
            ],
          },
        ],
      });

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      // Instance-derived findings are absent, but unrelated NACL findings still surface.
      expect(findings.some((f) => f.checkId === 'ec2_instance_imdsv2_enabled')).toBe(false);
      expect(findings.some((f) => f.checkId === 'ec2_networkacl_allow_ingress_any_port')).toBe(true);
    });

    it('returns an empty array without throwing when every EC2 call rejects', async () => {
      ec2Mock.rejects(new Error('ServiceUnavailable'));
      backupMock.rejects(new Error('ServiceUnavailable'));

      const scanner = new EC2Scanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });
});
