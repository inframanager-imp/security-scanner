import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import { CloudTrailClient, LookupEventsCommand } from '@aws-sdk/client-cloudtrail';
import {
  GuardDutyClient,
  ListDetectorsCommand,
  GetDetectorCommand,
  GetAdministratorAccountCommand,
  ListMembersCommand,
  ListFindingsCommand,
  ListOrganizationAdminAccountsCommand,
  DescribeOrganizationConfigurationCommand,
} from '@aws-sdk/client-guardduty';
import ThreatDetectionScanner from '../../../src/scanners/threatdetection';

/**
 * Minimal stand-in for AWSClient. The scanner constructor only calls
 * client.getClientConfig() (to build its own GuardDutyClient), and scan
 * logic reads client.cloudtrail directly and client.getRegion(). SDK v3
 * client construction performs no network I/O, so no mocking is needed there.
 */
function makeMockAWSClient(cloudtrail: CloudTrailClient) {
  return {
    cloudtrail,
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
    getRegion: () => 'us-east-1',
  } as any;
}

/** Wraps a CloudTrailEvent's raw JSON payload the way real CloudTrail responses do. */
function ctEvent(overrides: {
  EventId?: string;
  EventName: string;
  EventTime?: Date;
  Username?: string;
  raw: any;
}) {
  return {
    EventId: overrides.EventId ?? `evt-${Math.random().toString(36).slice(2)}`,
    EventName: overrides.EventName,
    EventTime: overrides.EventTime ?? new Date('2026-08-10T00:00:00.000Z'),
    Username: overrides.Username,
    CloudTrailEvent: JSON.stringify(overrides.raw),
  };
}

describe('ThreatDetectionScanner', () => {
  let ctMock: ReturnType<typeof mockClient>;
  let gdMock: ReturnType<typeof mockClient>;
  let scanner: ThreatDetectionScanner;

  beforeEach(() => {
    ctMock = mockClient(CloudTrailClient);
    gdMock = mockClient(GuardDutyClient);
    // Default: every CloudTrail lookup and GuardDuty call returns empty/no-detector,
    // so tests only need to override the specific commands they care about.
    ctMock.on(LookupEventsCommand).resolves({ Events: [] });
    gdMock.on(ListDetectorsCommand).resolves({ DetectorIds: [] });

    scanner = new ThreatDetectionScanner(makeMockAWSClient(new CloudTrailClient({})));
    // Swap in the mocked cloudtrail client reference used internally.
    (scanner as any).client.cloudtrail = new CloudTrailClient({});
  });

  afterEach(() => {
    ctMock.restore();
    gdMock.restore();
  });

  describe('scan() — happy path', () => {
    it('emits a threatdetection_cloudtrail_logging_tampering finding for a StopLogging event', async () => {
      ctMock.on(LookupEventsCommand).callsFake((input: any) => {
        const eventName = input.LookupAttributes?.[0]?.AttributeValue;
        if (eventName === 'StopLogging') {
          return Promise.resolve({
            Events: [
              ctEvent({
                EventName: 'StopLogging',
                raw: {
                  eventName: 'StopLogging',
                  userIdentity: { type: 'IAMUser', userName: 'attacker', arn: 'arn:aws:iam::123456789012:user/attacker' },
                  sourceIPAddress: '203.0.113.5',
                  requestParameters: { name: 'my-trail' },
                },
              }),
            ],
          });
        }
        return Promise.resolve({ Events: [] });
      });

      const findings = await scanner.scan();

      const tamperFinding = findings.find((f) => f.checkId === 'threatdetection_cloudtrail_logging_tampering');
      expect(tamperFinding).toBeDefined();
      expect(tamperFinding!.service).toBe('THREAT');
      expect(tamperFinding!.severity).toBe('HIGH');
      expect(tamperFinding!.evidence.actor).toBe('arn:aws:iam::123456789012:user/attacker');
      expect(tamperFinding!.evidence.affectedResource).toBe('my-trail');
      expect(tamperFinding!.evidence.threatCategory).toBe('DefenseEvasion');
    });

    it('escalates severity to CRITICAL for a DeleteTrail event', async () => {
      ctMock.on(LookupEventsCommand).callsFake((input: any) => {
        const eventName = input.LookupAttributes?.[0]?.AttributeValue;
        if (eventName === 'DeleteTrail') {
          return Promise.resolve({
            Events: [
              ctEvent({
                EventName: 'DeleteTrail',
                raw: {
                  eventName: 'DeleteTrail',
                  userIdentity: { type: 'IAMUser', userName: 'attacker' },
                  requestParameters: { name: 'critical-trail' },
                },
              }),
            ],
          });
        }
        return Promise.resolve({ Events: [] });
      });

      const findings = await scanner.scan();
      const finding = findings.find((f) => f.checkId === 'threatdetection_cloudtrail_logging_tampering' && f.evidence.eventName === 'DeleteTrail');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('CRITICAL');
    });

    it('emits threatdetection_admin_policy_attached_to_user when AdministratorAccess is attached', async () => {
      ctMock.on(LookupEventsCommand).callsFake((input: any) => {
        const eventName = input.LookupAttributes?.[0]?.AttributeValue;
        if (eventName === 'AttachUserPolicy') {
          return Promise.resolve({
            Events: [
              ctEvent({
                EventName: 'AttachUserPolicy',
                raw: {
                  eventName: 'AttachUserPolicy',
                  userIdentity: { type: 'IAMUser', userName: 'bob' },
                  requestParameters: {
                    userName: 'victim-user',
                    policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
                  },
                },
              }),
            ],
          });
        }
        return Promise.resolve({ Events: [] });
      });

      const findings = await scanner.scan();
      const finding = findings.find((f) => f.checkId === 'threatdetection_admin_policy_attached_to_user');
      expect(finding).toBeDefined();
      expect(finding!.checkId).toBe('threatdetection_admin_policy_attached_to_user');
      expect(finding!.service).toBe('THREAT');
      expect(finding!.evidence.affectedResource).toBe('victim-user');
      expect(finding!.evidence.threatCategory).toBe('Persistence');
    });

    it('does not flag AttachUserPolicy when the policy is not AdministratorAccess', async () => {
      ctMock.on(LookupEventsCommand).callsFake((input: any) => {
        const eventName = input.LookupAttributes?.[0]?.AttributeValue;
        if (eventName === 'AttachUserPolicy') {
          return Promise.resolve({
            Events: [
              ctEvent({
                EventName: 'AttachUserPolicy',
                raw: {
                  eventName: 'AttachUserPolicy',
                  userIdentity: { type: 'IAMUser', userName: 'bob' },
                  requestParameters: {
                    userName: 'regular-user',
                    policyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess',
                  },
                },
              }),
            ],
          });
        }
        return Promise.resolve({ Events: [] });
      });

      const findings = await scanner.scan();
      const finding = findings.find((f) => f.checkId === 'threatdetection_admin_policy_attached_to_user');
      expect(finding).toBeUndefined();
    });

    it('emits guardduty_is_enabled when no GuardDuty detector exists in the region', async () => {
      gdMock.on(ListDetectorsCommand).resolves({ DetectorIds: [] });

      const findings = await scanner.scan();
      const finding = findings.find((f) => f.checkId === 'guardduty_is_enabled');
      expect(finding).toBeDefined();
      expect(finding!.evidence.region).toBe('us-east-1');
      expect(finding!.evidence.enabledInAccount).toBe(false);
    });

    it('emits guardduty posture findings (S3 protection disabled) when a detector is enabled but missing data sources', async () => {
      gdMock.on(ListDetectorsCommand).resolves({ DetectorIds: ['detector-1'] });
      gdMock.on(GetDetectorCommand).resolves({
        Status: 'ENABLED',
        DataSources: {
          S3Logs: { Status: 'DISABLED' },
          Kubernetes: { AuditLogs: { Status: 'ENABLED' } },
          MalwareProtection: { ScanEc2InstanceWithFindings: { EbsVolumes: { Status: 'ENABLED' } } },
        },
        Features: [
          { Name: 'RDS_LOGIN_EVENTS', Status: 'ENABLED' },
          { Name: 'LAMBDA_NETWORK_LOGS', Status: 'ENABLED' },
          { Name: 'EKS_RUNTIME_MONITORING', Status: 'ENABLED' },
        ],
      });
      gdMock.on(GetAdministratorAccountCommand).resolves({});
      gdMock.on(ListMembersCommand).resolves({ Members: [{ AccountId: '999999999999' }] });
      gdMock.on(ListFindingsCommand).resolves({ FindingIds: [] });
      gdMock.on(ListOrganizationAdminAccountsCommand).resolves({ AdminAccounts: [{ AdminStatus: 'ENABLED' }] });
      gdMock.on(DescribeOrganizationConfigurationCommand).resolves({ AutoEnableOrganizationMembers: 'ALL' });

      const findings = await scanner.scan();
      const s3Finding = findings.find((f) => f.checkId === 'guardduty_s3_protection_enabled');
      expect(s3Finding).toBeDefined();
      expect(s3Finding!.evidence.detectorId).toBe('detector-1');
      expect(s3Finding!.evidence.s3Protection).toBe(false);

      // Other data sources were enabled, so those checks should not fire.
      expect(findings.find((f) => f.checkId === 'guardduty_eks_audit_log_enabled')).toBeUndefined();
      expect(findings.find((f) => f.checkId === 'guardduty_ec2_malware_protection_enabled')).toBeUndefined();
      // Detector itself is enabled so guardduty_is_enabled should not fire.
      expect(findings.find((f) => f.checkId === 'guardduty_is_enabled')).toBeUndefined();
    });
  });

  describe('scan() — no resources', () => {
    it('returns an empty array when there are no CloudTrail events and GuardDuty is not configured (no detector)', async () => {
      ctMock.on(LookupEventsCommand).resolves({ Events: [] });
      gdMock.on(ListDetectorsCommand).resolves({ DetectorIds: [] });

      const findings = await scanner.scan();

      // GuardDuty "not enabled" finding is still expected (plus the related
      // delegated-admin finding, since no org admin accounts are configured
      // either) — everything CloudTrail-based should be silent.
      expect(findings.length).toBe(2);
      expect(findings.map((f) => f.checkId).sort()).toEqual([
        'guardduty_delegated_admin_enabled_all_regions',
        'guardduty_is_enabled',
      ]);
    });
  });

  describe('scan() — pagination', () => {
    it('follows NextToken across two pages of ConsoleLogin events and aggregates brute-force attempts from both pages', async () => {
      const sameIP = '198.51.100.9';
      const makeFailureEvents = (count: number, offset: number) =>
        Array.from({ length: count }, (_, i) =>
          ctEvent({
            EventName: 'ConsoleLogin',
            EventTime: new Date(Date.now() - (offset + i) * 1000),
            raw: {
              eventName: 'ConsoleLogin',
              sourceIPAddress: sameIP,
              responseElements: { ConsoleLogin: 'Failure' },
              userIdentity: { type: 'IAMUser' },
            },
          }),
        );

      ctMock.on(LookupEventsCommand).callsFake((input: any) => {
        const eventName = input.LookupAttributes?.[0]?.AttributeValue;
        if (eventName !== 'ConsoleLogin') return Promise.resolve({ Events: [] });

        if (!input.NextToken) {
          // First page: 6 failed logins + a token for the next page.
          return Promise.resolve({ Events: makeFailureEvents(6, 0), NextToken: 'page-2' });
        }
        if (input.NextToken === 'page-2') {
          // Second page: 6 more failed logins from the same IP, no further token.
          return Promise.resolve({ Events: makeFailureEvents(6, 6) });
        }
        return Promise.resolve({ Events: [] });
      });

      const findings = await scanner.scan();
      const bruteForce = findings.find((f) => f.checkId === 'threatdetection_brute_force_login_attempts');
      expect(bruteForce).toBeDefined();
      expect(bruteForce!.evidence.sourceIP).toBe(sameIP);
      // 12 total failures across both pages, well over the >=10 threshold.
      expect(bruteForce!.evidence.eventCount).toBe(12);
    });
  });

  describe('scan() — error handling', () => {
    it('does not throw and returns gracefully when CloudTrail LookupEvents rejects', async () => {
      ctMock.on(LookupEventsCommand).rejects(new Error('AccessDenied: cloudtrail:LookupEvents'));
      gdMock.on(ListDetectorsCommand).resolves({ DetectorIds: [] });

      const findings = await scanner.scan();
      // scan() resolving at all (rather than throwing/rejecting) is the main
      // assertion here — CloudTrail-based checks silently produce no findings
      // on error; GuardDuty path is independent and still reports its own findings.
      expect(
        findings.every((f) => f.checkId === 'guardduty_is_enabled' || f.checkId === 'guardduty_delegated_admin_enabled_all_regions'),
      ).toBe(true);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('does not throw and skips GuardDuty findings when ListDetectors rejects', async () => {
      ctMock.on(LookupEventsCommand).resolves({ Events: [] });
      gdMock.on(ListDetectorsCommand).rejects(new Error('AccessDenied: guardduty:ListDetectors'));

      const findings = await scanner.scan();
      expect(findings).toEqual([]);
    });
  });
});
