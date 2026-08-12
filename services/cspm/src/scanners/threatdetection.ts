/**
 * Threat Detection Scanner — GuardDuty-equivalent
 *
 * Analyzes CloudTrail management events (last 90 days via LookupEvents API)
 * to detect active threats without requiring AWS GuardDuty.
 *
 * Detection categories:
 *  - Defense Evasion  (CloudTrail disabled, Config stopped)
 *  - Unauthorized Access (root activity, MFA-less logins, brute force)
 *  - Persistence      (new admin users, access keys, policy changes)
 *  - Privilege Escalation (policy grants *)
 *  - Reconnaissance   (IAM dump, bulk Describe* calls)
 *  - Impact / Exfiltration (mass deletion, public snapshots, mass S3 get)
 *  - Crypto Mining    (high-compute instance launches)
 */

import {
  LookupEventsCommand,
  type Event as CTEvent,
} from '@aws-sdk/client-cloudtrail';
// GuardDuty posture checks derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
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
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// ─── Time windows ────────────────────────────────────────────────────────────

const WINDOW_24H = 24 * 60 * 60 * 1000;
const WINDOW_7D  =  7 * 24 * 60 * 60 * 1000;

// ─── High-compute instance types (crypto-mining indicator) ───────────────────

const HIGH_COMPUTE_TYPES = new Set([
  'p2', 'p3', 'p4', 'p5',
  'g4', 'g5', 'g6',
  'c5n', 'c6gn',
  'hpc6a', 'hpc7g',
  'inf1', 'inf2',
  'trn1',
]);

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hoursAgo(ms: number) {
  return new Date(Date.now() - ms);
}

function actorFromEvent(e: CTEvent): string {
  const ui = (e as any).CloudTrailEvent
    ? JSON.parse((e as any).CloudTrailEvent)?.userIdentity
    : null;
  if (!ui) return e.Username ?? 'Unknown';
  if (ui.type === 'Root') return 'root';
  return ui.arn ?? ui.userName ?? ui.principalId ?? 'Unknown';
}

function sourceIPFromEvent(e: CTEvent): string {
  try {
    const raw = JSON.parse((e as any).CloudTrailEvent ?? '{}');
    return raw.sourceIPAddress ?? '';
  } catch { return ''; }
}

function parseRaw(e: CTEvent): any {
  try { return JSON.parse((e as any).CloudTrailEvent ?? '{}'); } catch { return {}; }
}

/** Rate-limited LookupEvents — fetches up to maxResults events for given filter */
async function lookupEvents(
  client: AWSClient,
  params: {
    eventName?: string;
    startTime: Date;
    endTime?: Date;
    maxResults?: number;
  },
): Promise<CTEvent[]> {
  const events: CTEvent[] = [];
  let nextToken: string | undefined;
  const max = params.maxResults ?? 50;

  try {
    do {
      const result = await client.cloudtrail.send(
        new LookupEventsCommand({
          LookupAttributes: params.eventName
            ? [{ AttributeKey: 'EventName', AttributeValue: params.eventName }]
            : undefined,
          StartTime: params.startTime,
          EndTime:   params.endTime ?? new Date(),
          MaxResults: Math.min(max - events.length, 50),
          NextToken: nextToken,
        }),
      );
      events.push(...(result.Events ?? []));
      nextToken = result.NextToken;
    } while (nextToken && events.length < max);
  } catch (err) {
    logger.debug(`LookupEvents(${params.eventName}) failed`, { error: (err as Error).message });
  }

  return events;
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

export class ThreatDetectionScanner extends BaseScanner {
  private guardduty: GuardDutyClient;

  constructor(client: AWSClient) {
    super(client, 'THREAT');
    this.guardduty = new GuardDutyClient(client.getClientConfig());
  }

  /**
   * Full scan — uses predefined time windows (24h / 7d).
   * Used by the on-demand scan engine.
   */
  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting Threat Detection scan (CloudTrail-based)...');

    const checks = [
      this.detectCloudTrailTampering(),
      this.detectRootActivity(),
      this.detectConsoleLoginIssues(),
      this.detectNewAdminUsers(),
      this.detectNewAccessKeys(),
      this.detectPrivilegeEscalation(),
      this.detectIAMEnumeration(),
      this.detectInfraEnumeration(),
      this.detectMassDeletion(),
      this.detectPublicSnapshots(),
      this.detectHighComputeLaunch(),
      this.detectConfigTampering(),
      this.checkGuardDutyPosture(),
    ];

    const results = await Promise.allSettled(checks);
    for (const r of results) {
      if (r.status === 'fulfilled') findings.push(...r.value);
      else logger.debug('Threat check failed', { error: (r as any).reason?.message });
    }

    logger.info(`Threat Detection complete. ${findings.length} threat indicator(s) found.`);
    return findings;
  }

  /**
   * Incremental scan for real-time monitoring.
   * Only looks at CloudTrail events that occurred since `since`.
   * Returns findings with their source CloudTrail eventId for deduplication.
   * Runs only the event-driven checks (skips aggregation-based ones).
   */
  async scanSince(since: Date): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    const now = new Date();

    logger.debug(`Threat monitor incremental scan: ${since.toISOString()} → ${now.toISOString()}`);

    // High-value real-time event checks — each returns findings with _eventId
    const checks = [
      this.detectWindowedCloudTrailTamper(since, now),
      this.detectWindowedRootActivity(since, now),
      this.detectWindowedConsoleLogins(since, now),
      this.detectWindowedAdminUsers(since, now),
      this.detectWindowedAccessKeys(since, now),
      this.detectWindowedPrivilegeEscalation(since, now),
      this.detectWindowedPublicSnapshots(since, now),
      this.detectWindowedHighCompute(since, now),
      this.detectWindowedConfigTamper(since, now),
    ];

    const results = await Promise.allSettled(checks);
    for (const r of results) {
      if (r.status === 'fulfilled') findings.push(...r.value);
    }

    logger.debug(`Threat monitor: ${findings.length} new indicator(s) in window`);
    return findings;
  }

  // ── Windowed variants (real-time, use explicit start/end) ─────────────────

  private async detectWindowedCloudTrailTamper(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    for (const eventName of ['StopLogging', 'DeleteTrail', 'UpdateTrail']) {
      const events = await lookupEvents(this.client, { eventName, startTime: start, endTime: end });
      for (const e of events) {
        const raw    = parseRaw(e);
        const actor  = actorFromEvent(e);
        const trail  = raw.requestParameters?.name ?? raw.requestParameters?.trailARN ?? 'Unknown';
        const f: ScanningResult & { _eventId?: string } = {
          ...this.emit(
            'threatdetection_cloudtrail_logging_tampering',
            { resourceId: `threat::cloudtrail-tamper::${actor}::${e.EventTime?.getTime()}`, threatCategory: 'DefenseEvasion', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), eventName, affectedResource: trail, rawEvents: [raw] },
            {
              message: `CloudTrail "${eventName}" by ${actor} at ${e.EventTime?.toISOString()}. Trail: ${trail}.`,
              remediation: `Re-enable CloudTrail: aws cloudtrail start-logging --name ${trail}`,
              severity: eventName === 'DeleteTrail' ? 'CRITICAL' : 'HIGH',
            },
          ),
          _eventId: e.EventId ?? `${eventName}-${e.EventTime?.getTime()}`,
        };
        findings.push(f);
      }
    }
    return findings;
  }

  private async detectWindowedRootActivity(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    try {
      const result = await this.client.cloudtrail.send(new LookupEventsCommand({
        LookupAttributes: [{ AttributeKey: 'Username', AttributeValue: 'root' }],
        StartTime: start, EndTime: end, MaxResults: 20,
      }));
      for (const e of result.Events ?? []) {
        if (e.EventName === 'ConsoleLogin') continue;
        const raw = parseRaw(e);
        const f: ScanningResult & { _eventId?: string } = {
          ...this.emit(
            'threatdetection_root_account_activity',
            { resourceId: `threat::root::${e.EventTime?.getTime()}`, threatCategory: 'UnauthorizedAccess', actor: 'root', eventName: e.EventName, eventTime: e.EventTime?.toISOString(), sourceIP: sourceIPFromEvent(e), rawEvents: [raw] },
            {
              message: `Root account performed "${e.EventName}" at ${e.EventTime?.toISOString()} from IP ${sourceIPFromEvent(e)}.`,
            },
          ),
          _eventId: e.EventId ?? `root-${e.EventTime?.getTime()}`,
        };
        findings.push(f);
      }
    } catch { /* no permission */ }
    return findings;
  }

  private async detectWindowedConsoleLogins(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    const events = await lookupEvents(this.client, { eventName: 'ConsoleLogin', startTime: start, endTime: end, maxResults: 50 });
    for (const e of events) {
      const raw = parseRaw(e);
      if (raw.additionalEventData?.MFAUsed === 'No' && raw.responseElements?.ConsoleLogin === 'Success' && raw.userIdentity?.type !== 'Root') {
        const actor = actorFromEvent(e);
        findings.push({
          ...this.emit(
            'threatdetection_console_login_without_mfa',
            { resourceId: `threat::no-mfa::${actor}::${e.EventTime?.getTime()}`, threatCategory: 'UnauthorizedAccess', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), rawEvents: [raw] },
            {
              message: `"${actor}" logged in without MFA at ${e.EventTime?.toISOString()} from ${sourceIPFromEvent(e)}.`,
              remediation: `Enforce MFA on IAM user "${actor}".`,
            },
          ),
          _eventId: e.EventId ?? `mfa-${e.EventTime?.getTime()}`,
        });
      }
    }
    return findings;
  }

  private async detectWindowedAdminUsers(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    const events = await lookupEvents(this.client, { eventName: 'AttachUserPolicy', startTime: start, endTime: end });
    for (const e of events) {
      const raw = parseRaw(e);
      if (!(raw.requestParameters?.policyArn ?? '').includes('AdministratorAccess')) continue;
      const actor  = actorFromEvent(e);
      const target = raw.requestParameters?.userName ?? 'Unknown';
      findings.push({
        ...this.emit(
          'threatdetection_admin_policy_attached_to_user',
          { resourceId: `threat::admin-attach::${target}::${e.EventTime?.getTime()}`, threatCategory: 'Persistence', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), affectedResource: target, rawEvents: [raw] },
          {
            message: `AdministratorAccess attached to "${target}" by "${actor}" at ${e.EventTime?.toISOString()}.`,
            remediation: `Detach AdministratorAccess from "${target}" immediately.`,
          },
        ),
        _eventId: e.EventId ?? `admin-${e.EventTime?.getTime()}`,
      });
    }
    return findings;
  }

  private async detectWindowedAccessKeys(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    const events = await lookupEvents(this.client, { eventName: 'CreateAccessKey', startTime: start, endTime: end });
    for (const e of events) {
      const raw    = parseRaw(e);
      const actor  = actorFromEvent(e);
      const target = raw.responseElements?.accessKey?.userName ?? raw.requestParameters?.userName ?? 'Unknown';
      const keyId  = raw.responseElements?.accessKey?.accessKeyId ?? '';
      findings.push({
        ...this.emit(
          'threatdetection_new_access_key_created',
          { resourceId: `threat::new-key::${target}::${e.EventTime?.getTime()}`, threatCategory: 'Persistence', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), affectedResource: target, accessKeyId: keyId, rawEvents: [raw] },
          {
            message: `New access key ${keyId ? `(${keyId}) ` : ''}for "${target}" by "${actor}" at ${e.EventTime?.toISOString()}.`,
            remediation: `Verify this key creation was authorized. Deactivate if not: aws iam update-access-key --access-key-id ${keyId} --status Inactive`,
          },
        ),
        _eventId: e.EventId ?? `key-${e.EventTime?.getTime()}`,
      });
    }
    return findings;
  }

  private async detectWindowedPrivilegeEscalation(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    for (const eventName of ['PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy']) {
      const events = await lookupEvents(this.client, { eventName, startTime: start, endTime: end });
      for (const e of events) {
        const raw = parseRaw(e);
        const doc = decodeURIComponent(raw.requestParameters?.policyDocument ?? '{}');
        const isAdmin = doc.includes('"Action":"*"') || doc.includes('"iam:*"');
        if (!isAdmin) continue;
        const actor  = actorFromEvent(e);
        const target = raw.requestParameters?.userName ?? raw.requestParameters?.roleName ?? 'Unknown';
        findings.push({
          ...this.emit(
            'cloudtrail_threat_detection_privilege_escalation',
            { resourceId: `threat::priv-esc::${target}::${e.EventTime?.getTime()}`, threatCategory: 'PrivilegeEscalation', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), affectedResource: target, rawEvents: [raw] },
            {
              message: `Wildcard policy attached to "${target}" by "${actor}" via ${eventName} at ${e.EventTime?.toISOString()}.`,
              remediation: `Delete the inline policy from "${target}" immediately.`,
            },
          ),
          _eventId: e.EventId ?? `privesc-${e.EventTime?.getTime()}`,
        });
      }
    }
    return findings;
  }

  private async detectWindowedPublicSnapshots(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    const events = await lookupEvents(this.client, { eventName: 'ModifySnapshotAttribute', startTime: start, endTime: end });
    for (const e of events) {
      const raw = parseRaw(e);
      const isPublic = (raw.requestParameters?.createVolumePermission?.add?.items ?? []).some((i: any) => i.group === 'all');
      if (!isPublic) continue;
      const actor  = actorFromEvent(e);
      const snapId = raw.requestParameters?.snapshotId ?? 'Unknown';
      findings.push({
        ...this.emit(
          'threatdetection_ebs_snapshot_made_public',
          { resourceId: `threat::public-snapshot::${snapId}`, threatCategory: 'Exfiltration', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), affectedResource: snapId, rawEvents: [raw] },
          {
            message: `Snapshot "${snapId}" made public by "${actor}" at ${e.EventTime?.toISOString()}.`,
            remediation: `Make snapshot private: aws ec2 modify-snapshot-attribute --snapshot-id ${snapId} --attribute createVolumePermission --operation-type remove --group-names all`,
          },
        ),
        _eventId: e.EventId ?? `snapshot-${snapId}`,
      });
    }
    return findings;
  }

  private async detectWindowedHighCompute(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    const events = await lookupEvents(this.client, { eventName: 'RunInstances', startTime: start, endTime: end });
    for (const e of events) {
      const raw = parseRaw(e);
      const instanceType = raw.requestParameters?.instanceType ?? '';
      const prefix = instanceType.split('.')[0];
      if (!HIGH_COMPUTE_TYPES.has(prefix)) continue;
      const actor = actorFromEvent(e);
      findings.push({
        ...this.emit(
          'threatdetection_high_compute_instance_launch',
          { resourceId: `threat::high-compute::${actor}::${e.EventTime?.getTime()}`, threatCategory: 'Impact', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), instanceType, rawEvents: [raw] },
          {
            message: `Instance type "${instanceType}" launched by "${actor}" at ${e.EventTime?.toISOString()} from ${sourceIPFromEvent(e)}.`,
            remediation: `If unauthorized, terminate instance(s) and revoke "${actor}" credentials.`,
          },
        ),
        _eventId: e.EventId ?? `compute-${e.EventTime?.getTime()}`,
      });
    }
    return findings;
  }

  private async detectWindowedConfigTamper(
    start: Date, end: Date,
  ): Promise<Array<ScanningResult & { _eventId?: string }>> {
    const findings: Array<ScanningResult & { _eventId?: string }> = [];
    for (const eventName of ['StopConfigurationRecorder', 'DeleteConfigurationRecorder']) {
      const events = await lookupEvents(this.client, { eventName, startTime: start, endTime: end });
      for (const e of events) {
        const actor = actorFromEvent(e);
        findings.push({
          ...this.emit(
            'threatdetection_config_recorder_stopped',
            { resourceId: `threat::config-tamper::${actor}::${e.EventTime?.getTime()}`, threatCategory: 'DefenseEvasion', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), eventName, rawEvents: [parseRaw(e)] },
            {
              message: `"${eventName}" by "${actor}" at ${e.EventTime?.toISOString()}.`,
            },
          ),
          _eventId: e.EventId ?? `config-${e.EventTime?.getTime()}`,
        });
      }
    }
    return findings;
  }

  // ── 1. CloudTrail Tampering ──────────────────────────────────────────────

  private async detectCloudTrailTampering(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_7D);

    for (const eventName of ['StopLogging', 'DeleteTrail', 'UpdateTrail']) {
      const events = await lookupEvents(this.client, { eventName, startTime: start });
      for (const e of events) {
        const raw    = parseRaw(e);
        const actor  = actorFromEvent(e);
        const trailArn = raw.requestParameters?.name ?? raw.requestParameters?.trailARN ?? 'Unknown trail';
        findings.push(
          this.emit(
            'threatdetection_cloudtrail_logging_tampering',
            {
              resourceId:      `threat::cloudtrail-tamper::${actor}::${e.EventTime?.getTime()}`,
              threatCategory:  'DefenseEvasion',
              actor,
              sourceIP:        sourceIPFromEvent(e),
              eventTime:       e.EventTime?.toISOString(),
              eventName,
              affectedResource: trailArn,
              rawEvents:       [raw],
            },
            {
              message: `CloudTrail event "${eventName}" detected at ${e.EventTime?.toISOString()} by ${actor}. ` +
                `Trail: ${trailArn}. This may indicate an attacker disabling audit logging to cover their tracks.`,
              remediation: `Re-enable CloudTrail logging immediately: aws cloudtrail start-logging --name ${trailArn}. ` +
                `Investigate who performed this action and revoke access if unauthorized.`,
              severity: eventName === 'DeleteTrail' ? 'CRITICAL' : 'HIGH',
            },
          ),
        );
      }
    }
    return findings;
  }

  // ── 2. Root Account Activity ─────────────────────────────────────────────

  private async detectRootActivity(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_24H);

    // LookupEvents by username 'root'
    const events: CTEvent[] = [];
    try {
      const result = await this.client.cloudtrail.send(
        new LookupEventsCommand({
          LookupAttributes: [{ AttributeKey: 'Username', AttributeValue: 'root' }],
          StartTime: start,
          MaxResults: 50,
        }),
      );
      events.push(...(result.Events ?? []));
    } catch { return findings; }

    // Filter to actual API calls (exclude ConsoleLogin handled separately)
    const apiEvents = events.filter(
      (e) => e.EventName !== 'ConsoleLogin' && e.EventName !== 'ExitRole',
    );

    if (apiEvents.length === 0) return findings;

    const eventNames = [...new Set(apiEvents.map((e) => e.EventName ?? 'Unknown'))];
    findings.push(
      this.emit(
        'threatdetection_root_account_activity',
        {
          resourceId:      `threat::root-activity::${start.toISOString()}`,
          threatCategory:  'UnauthorizedAccess',
          actor:           'root',
          eventCount:      apiEvents.length,
          eventNames,
          eventTime:       apiEvents[0].EventTime?.toISOString(),
          rawEvents:       apiEvents.slice(0, 3).map(parseRaw),
        },
        {
          message: `${apiEvents.length} API call(s) made using the AWS root account in the last 24 hours. ` +
            `Events: ${eventNames.slice(0, 5).join(', ')}. Root account should never be used for daily operations.`,
        },
      ),
    );
    return findings;
  }

  // ── 3. Console Login Issues ──────────────────────────────────────────────

  private async detectConsoleLoginIssues(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_24H);

    const events = await lookupEvents(this.client, { eventName: 'ConsoleLogin', startTime: start, maxResults: 100 });

    // MFA-less successful logins (exclude root — covered separately)
    const noMFALogins = events.filter((e) => {
      const raw = parseRaw(e);
      return (
        raw.additionalEventData?.MFAUsed === 'No' &&
        raw.responseElements?.ConsoleLogin === 'Success' &&
        raw.userIdentity?.type !== 'Root'
      );
    });

    for (const e of noMFALogins) {
      const actor = actorFromEvent(e);
      findings.push(
        this.emit(
          'threatdetection_console_login_without_mfa',
          {
            resourceId:     `threat::no-mfa-login::${actor}::${e.EventTime?.getTime()}`,
            threatCategory: 'UnauthorizedAccess',
            actor,
            sourceIP:       sourceIPFromEvent(e),
            eventTime:      e.EventTime?.toISOString(),
            eventName:      'ConsoleLogin',
            affectedResource: actor,
            rawEvents:      [parseRaw(e)],
          },
          {
            message: `IAM user "${actor}" logged into the AWS console without MFA at ${e.EventTime?.toISOString()} ` +
              `from IP ${sourceIPFromEvent(e)}. This is a credential compromise risk.`,
          },
        ),
      );
    }

    // Brute-force detection: >10 failed logins from same IP in 24h
    const failures = events.filter((e) => {
      const raw = parseRaw(e);
      return raw.responseElements?.ConsoleLogin === 'Failure';
    });

    const byIP = new Map<string, CTEvent[]>();
    for (const e of failures) {
      const ip = sourceIPFromEvent(e);
      if (!ip) continue;
      if (!byIP.has(ip)) byIP.set(ip, []);
      byIP.get(ip)!.push(e);
    }

    for (const [ip, ipEvents] of byIP) {
      if (ipEvents.length < 10) continue;
      findings.push(
        this.emit(
          'threatdetection_brute_force_login_attempts',
          {
            resourceId:     `threat::brute-force::${ip}::${start.toISOString()}`,
            threatCategory: 'UnauthorizedAccess',
            sourceIP:       ip,
            eventCount:     ipEvents.length,
            eventTime:      ipEvents[0].EventTime?.toISOString(),
            rawEvents:      ipEvents.slice(0, 3).map(parseRaw),
          },
          {
            message: `${ipEvents.length} failed console login attempts from IP ${ip} in the last 24 hours. ` +
              `This indicates a brute-force or credential stuffing attack.`,
            remediation: `Block the source IP ${ip} at the network/WAF level. ` +
              `Enable account lockout policies. Review whether any login succeeded.`,
          },
        ),
      );
    }

    return findings;
  }

  // ── 4. New Admin Users / Persistence ────────────────────────────────────

  private async detectNewAdminUsers(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_24H);

    const [createEvents, attachEvents] = await Promise.all([
      lookupEvents(this.client, { eventName: 'CreateUser', startTime: start }),
      lookupEvents(this.client, { eventName: 'AttachUserPolicy', startTime: start }),
    ]);

    // Check for AdminAccess policy attachments
    const adminAttachments = attachEvents.filter((e) => {
      const raw = parseRaw(e);
      return (raw.requestParameters?.policyArn ?? '').includes('AdministratorAccess');
    });

    for (const e of adminAttachments) {
      const raw    = parseRaw(e);
      const actor  = actorFromEvent(e);
      const target = raw.requestParameters?.userName ?? raw.requestParameters?.userArn ?? 'Unknown';
      findings.push(
        this.emit(
          'threatdetection_admin_policy_attached_to_user',
          {
            resourceId:      `threat::admin-attach::${target}::${e.EventTime?.getTime()}`,
            threatCategory:  'Persistence',
            actor,
            sourceIP:        sourceIPFromEvent(e),
            eventTime:       e.EventTime?.toISOString(),
            eventName:       'AttachUserPolicy',
            affectedResource: target,
            rawEvents:       [raw],
          },
          {
            message: `AdministratorAccess policy attached to "${target}" by "${actor}" at ${e.EventTime?.toISOString()}. ` +
              `This grants full AWS access and may indicate persistence or privilege escalation.`,
            remediation: `Immediately detach AdministratorAccess from "${target}": ` +
              `aws iam detach-user-policy --user-name ${target} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess. ` +
              `Investigate whether this was authorized.`,
          },
        ),
      );
    }

    // New users created in last 24h
    for (const e of createEvents) {
      const raw    = parseRaw(e);
      const actor  = actorFromEvent(e);
      const newUser = raw.requestParameters?.userName ?? 'Unknown';
      findings.push(
        this.emit(
          'threatdetection_new_iam_user_created',
          {
            resourceId:      `threat::new-user::${newUser}::${e.EventTime?.getTime()}`,
            threatCategory:  'Persistence',
            actor,
            sourceIP:        sourceIPFromEvent(e),
            eventTime:       e.EventTime?.toISOString(),
            eventName:       'CreateUser',
            affectedResource: newUser,
            rawEvents:       [raw],
          },
          {
            message: `New IAM user "${newUser}" created by "${actor}" at ${e.EventTime?.toISOString()} ` +
              `from IP ${sourceIPFromEvent(e)}. Verify this was an authorized action.`,
            remediation: `Verify that user "${newUser}" was created as part of an authorized onboarding process. ` +
              `If unauthorized, delete immediately: aws iam delete-user --user-name ${newUser}.`,
          },
        ),
      );
    }

    return findings;
  }

  // ── 5. New Access Keys ───────────────────────────────────────────────────

  private async detectNewAccessKeys(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_24H);

    const events = await lookupEvents(this.client, { eventName: 'CreateAccessKey', startTime: start });

    for (const e of events) {
      const raw     = parseRaw(e);
      const actor   = actorFromEvent(e);
      const target  = raw.responseElements?.accessKey?.userName ?? raw.requestParameters?.userName ?? 'Unknown';
      const keyId   = raw.responseElements?.accessKey?.accessKeyId ?? '';
      findings.push(
        this.emit(
          'threatdetection_new_access_key_created',
          {
            resourceId:      `threat::new-key::${target}::${e.EventTime?.getTime()}`,
            threatCategory:  'Persistence',
            actor,
            sourceIP:        sourceIPFromEvent(e),
            eventTime:       e.EventTime?.toISOString(),
            eventName:       'CreateAccessKey',
            affectedResource: target,
            accessKeyId:     keyId,
            rawEvents:       [raw],
          },
          {
            message: `New access key ${keyId ? `(${keyId}) ` : ''}created for user "${target}" by "${actor}" ` +
              `at ${e.EventTime?.toISOString()} from IP ${sourceIPFromEvent(e)}.`,
            remediation: `Verify this key creation was authorized. If not, deactivate immediately: ` +
              `aws iam update-access-key --user-name ${target} --access-key-id ${keyId} --status Inactive`,
          },
        ),
      );
    }
    return findings;
  }

  // ── 6. Privilege Escalation ──────────────────────────────────────────────

  private async detectPrivilegeEscalation(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_7D);

    for (const eventName of ['PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy']) {
      const events = await lookupEvents(this.client, { eventName, startTime: start });
      for (const e of events) {
        const raw    = parseRaw(e);
        const doc    = decodeURIComponent(raw.requestParameters?.policyDocument ?? '{}');
        // Flag if policy grants iam:*, *:*, or Action: * with Resource: *
        const isAdmin =
          doc.includes('"Action":"*"') ||
          doc.includes('"Action":["*"]') ||
          doc.includes('"iam:*"') ||
          (doc.includes('"Effect":"Allow"') && doc.includes('"Resource":"*"') && doc.includes('"Action":"*"'));

        if (!isAdmin) continue;
        const actor  = actorFromEvent(e);
        const target = raw.requestParameters?.userName ?? raw.requestParameters?.roleName ?? raw.requestParameters?.groupName ?? 'Unknown';
        findings.push(
          this.emit(
            'cloudtrail_threat_detection_privilege_escalation',
            {
              resourceId:      `threat::priv-esc::${target}::${e.EventTime?.getTime()}`,
              threatCategory:  'PrivilegeEscalation',
              actor,
              sourceIP:        sourceIPFromEvent(e),
              eventTime:       e.EventTime?.toISOString(),
              eventName,
              affectedResource: target,
              rawEvents:       [raw],
            },
            {
              message: `Inline policy with wildcard permissions attached to "${target}" by "${actor}" ` +
                `via ${eventName} at ${e.EventTime?.toISOString()}. This grants unrestricted AWS access.`,
              remediation: `Delete the inline policy immediately: aws iam delete-user-policy --user-name ${target} --policy-name <PolicyName>. ` +
                `Replace with least-privilege managed policies.`,
            },
          ),
        );
      }
    }
    return findings;
  }

  // ── 7. IAM Enumeration / Reconnaissance ─────────────────────────────────

  private async detectIAMEnumeration(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_24H);

    // GetAccountAuthorizationDetails = full IAM dump — always suspicious when called by non-admin automation
    const events = await lookupEvents(this.client, {
      eventName: 'GetAccountAuthorizationDetails',
      startTime: start,
    });

    for (const e of events) {
      const actor = actorFromEvent(e);
      if (actor === 'root') continue; // root calling this is covered elsewhere
      findings.push(
        this.emit(
          'threatdetection_iam_enumeration',
          {
            resourceId:     `threat::iam-enum::${actor}::${e.EventTime?.getTime()}`,
            threatCategory: 'Reconnaissance',
            actor,
            sourceIP:       sourceIPFromEvent(e),
            eventTime:      e.EventTime?.toISOString(),
            eventName:      'GetAccountAuthorizationDetails',
            rawEvents:      [parseRaw(e)],
          },
          {
            message: `"GetAccountAuthorizationDetails" called by "${actor}" at ${e.EventTime?.toISOString()} ` +
              `from IP ${sourceIPFromEvent(e)}. This API dumps the entire IAM configuration — a common reconnaissance technique.`,
            remediation: `Review whether "${actor}" should have iam:GetAccountAuthorizationDetails permission. ` +
              `Restrict this permission to only security/audit roles.`,
          },
        ),
      );
    }
    return findings;
  }

  // ── 8. Infrastructure Enumeration ────────────────────────────────────────

  private async detectInfraEnumeration(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_24H);

    // Fetch bulk Describe* events and look for actors calling many different ones
    const describeEvents: CTEvent[] = [];
    for (const evtName of [
      'DescribeInstances', 'DescribeSecurityGroups', 'DescribeSubnets',
      'DescribeVpcs', 'ListBuckets', 'DescribeDBInstances', 'ListFunctions',
    ]) {
      const evts = await lookupEvents(this.client, { eventName: evtName, startTime: start, maxResults: 20 });
      describeEvents.push(...evts);
      await new Promise(r => setTimeout(r, 300)); // rate limit
    }

    // Group by actor
    const byActor = new Map<string, Set<string>>();
    for (const e of describeEvents) {
      const actor = actorFromEvent(e);
      if (!byActor.has(actor)) byActor.set(actor, new Set());
      byActor.get(actor)!.add(e.EventName ?? '');
    }

    for (const [actor, eventNames] of byActor) {
      if (eventNames.size < 5) continue; // only flag if called 5+ different Describe APIs
      findings.push(
        this.emit(
          'cloudtrail_threat_detection_enumeration',
          {
            resourceId:     `threat::infra-enum::${actor}::${start.toISOString()}`,
            threatCategory: 'Reconnaissance',
            actor,
            eventCount:     eventNames.size,
            eventNames:     [...eventNames],
            eventTime:      start.toISOString(),
          },
          {
            message: `"${actor}" called ${eventNames.size} different discovery APIs in the last 24 hours ` +
              `(${[...eventNames].join(', ')}). This pattern indicates automated reconnaissance of your AWS environment.`,
            remediation: `Investigate whether "${actor}" is a legitimate automation tool or compromised credential. ` +
              `Apply least-privilege — restrict discovery APIs to only needed services.`,
          },
        ),
      );
    }
    return findings;
  }

  // ── 9. Mass Deletion (Impact) ────────────────────────────────────────────

  private async detectMassDeletion(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_24H);

    // EC2 mass termination
    const terminateEvents = await lookupEvents(this.client, {
      eventName: 'TerminateInstances',
      startTime: start,
      maxResults: 50,
    });

    const byActor = new Map<string, CTEvent[]>();
    for (const e of terminateEvents) {
      const actor = actorFromEvent(e);
      if (!byActor.has(actor)) byActor.set(actor, []);
      byActor.get(actor)!.push(e);
    }

    for (const [actor, events] of byActor) {
      if (events.length < 3) continue;
      const instanceIds = events.flatMap((e) => {
        const raw = parseRaw(e);
        return (raw.requestParameters?.instancesSet?.items ?? []).map((i: any) => i.instanceId);
      }).filter(Boolean);

      findings.push(
        this.emit(
          'threatdetection_mass_ec2_termination',
          {
            resourceId:      `threat::mass-terminate::${actor}::${start.toISOString()}`,
            threatCategory:  'Impact',
            actor,
            eventCount:      events.length,
            affectedInstances: instanceIds.slice(0, 10),
            eventTime:       events[0].EventTime?.toISOString(),
            rawEvents:       events.slice(0, 2).map(parseRaw),
          },
          {
            message: `${events.length} TerminateInstances calls by "${actor}" in the last 24 hours ` +
              `affecting ${instanceIds.length} instance(s). This may indicate ransomware, sabotage, or a compromised credential.`,
            remediation: `Immediately revoke "${actor}" credentials. Restore instances from snapshots/AMIs. ` +
              `Enable EC2 termination protection on critical instances.`,
          },
        ),
      );
    }

    return findings;
  }

  // ── 10. Public Snapshots ─────────────────────────────────────────────────

  private async detectPublicSnapshots(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_7D);

    const events = await lookupEvents(this.client, {
      eventName: 'ModifySnapshotAttribute',
      startTime: start,
    });

    for (const e of events) {
      const raw  = parseRaw(e);
      const perm = raw.requestParameters?.createVolumePermission;
      const isPublic = (perm?.add?.items ?? []).some((i: any) => i.group === 'all');
      if (!isPublic) continue;

      const actor      = actorFromEvent(e);
      const snapshotId = raw.requestParameters?.snapshotId ?? 'Unknown';
      findings.push(
        this.emit(
          'threatdetection_ebs_snapshot_made_public',
          {
            resourceId:      `threat::public-snapshot::${snapshotId}`,
            threatCategory:  'Exfiltration',
            actor,
            sourceIP:        sourceIPFromEvent(e),
            eventTime:       e.EventTime?.toISOString(),
            affectedResource: snapshotId,
            rawEvents:       [raw],
          },
          {
            message: `EBS snapshot "${snapshotId}" was made publicly accessible by "${actor}" ` +
              `at ${e.EventTime?.toISOString()}. Public snapshots expose all data in the volume to any AWS account.`,
            remediation: `Immediately make the snapshot private: ` +
              `aws ec2 modify-snapshot-attribute --snapshot-id ${snapshotId} --attribute createVolumePermission --operation-type remove --group-names all`,
          },
        ),
      );
    }

    // RDS snapshots made public
    const rdsEvents = await lookupEvents(this.client, {
      eventName: 'ModifyDBSnapshotAttribute',
      startTime: start,
    });

    for (const e of rdsEvents) {
      const raw      = parseRaw(e);
      const isPublic = (raw.requestParameters?.valuesToAdd ?? []).includes('all');
      if (!isPublic) continue;
      const actor  = actorFromEvent(e);
      const snapId = raw.requestParameters?.dbSnapshotIdentifier ?? 'Unknown';
      findings.push(
        this.emit(
          'threatdetection_rds_snapshot_made_public',
          {
            resourceId:      `threat::public-rds-snapshot::${snapId}`,
            threatCategory:  'Exfiltration',
            actor,
            sourceIP:        sourceIPFromEvent(e),
            eventTime:       e.EventTime?.toISOString(),
            affectedResource: snapId,
            rawEvents:       [raw],
          },
          {
            message: `RDS snapshot "${snapId}" was made publicly restorable by "${actor}" at ${e.EventTime?.toISOString()}.`,
            remediation: `Make the snapshot private: aws rds modify-db-snapshot-attribute --db-snapshot-identifier ${snapId} ` +
              `--attribute-name restore --values-to-remove all`,
          },
        ),
      );
    }

    return findings;
  }

  // ── 11. Crypto Mining (high-compute launches) ────────────────────────────

  private async detectHighComputeLaunch(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_24H);

    const events = await lookupEvents(this.client, { eventName: 'RunInstances', startTime: start, maxResults: 50 });

    for (const e of events) {
      const raw          = parseRaw(e);
      const actor        = actorFromEvent(e);
      const instanceType = raw.requestParameters?.instanceType ?? '';
      const prefix       = instanceType.split('.')[0];
      if (!HIGH_COMPUTE_TYPES.has(prefix)) continue;

      const instanceCount = raw.requestParameters?.instancesSet?.items?.length ?? 1;
      findings.push(
        this.emit(
          'threatdetection_high_compute_instance_launch',
          {
            resourceId:      `threat::high-compute::${actor}::${e.EventTime?.getTime()}`,
            threatCategory:  'Impact',
            actor,
            sourceIP:        sourceIPFromEvent(e),
            eventTime:       e.EventTime?.toISOString(),
            instanceType,
            instanceCount,
            rawEvents:       [raw],
          },
          {
            message: `${instanceCount} instance(s) of type "${instanceType}" launched by "${actor}" ` +
              `at ${e.EventTime?.toISOString()} from IP ${sourceIPFromEvent(e)}. ` +
              `High-compute/GPU instances launched by unexpected identities often indicate crypto-mining.`,
            remediation: `If unauthorized, immediately terminate the instance(s) and revoke "${actor}" credentials. ` +
              `Enable AWS Cost Anomaly Detection to catch unexpected compute spend.`,
          },
        ),
      );
    }
    return findings;
  }

  // ── 12. Config Tampering ─────────────────────────────────────────────────

  private async detectConfigTampering(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const start = hoursAgo(WINDOW_7D);

    for (const eventName of ['StopConfigurationRecorder', 'DeleteConfigurationRecorder', 'DeleteDeliveryChannel']) {
      const events = await lookupEvents(this.client, { eventName, startTime: start });
      for (const e of events) {
        const actor = actorFromEvent(e);
        findings.push(
          this.emit(
            'threatdetection_config_recorder_stopped',
            {
              resourceId:     `threat::config-tamper::${actor}::${e.EventTime?.getTime()}`,
              threatCategory: 'DefenseEvasion',
              actor,
              sourceIP:       sourceIPFromEvent(e),
              eventTime:      e.EventTime?.toISOString(),
              eventName,
              rawEvents:      [parseRaw(e)],
            },
            {
              message: `"${eventName}" called by "${actor}" at ${e.EventTime?.toISOString()}. ` +
                `Disabling AWS Config stops configuration change tracking — a common defense evasion technique.`,
            },
          ),
        );
      }
    }
    return findings;
  }

  // ── 13. GuardDuty posture (ported from Prowler guardduty checks) ─────────
  // Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)

  private async checkGuardDutyPosture(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const region = this.client.getRegion();

    let detectorIds: string[] = [];
    try {
      detectorIds = await this.listGuardDutyDetectors();
    } catch (error) {
      logger.debug('GuardDuty ListDetectors failed', { error: (error as Error).message });
      return findings;
    }

    // guardduty_is_enabled: no detector configured at all in this region
    if (detectorIds.length === 0) {
      findings.push(
        this.emit(
          'guardduty_is_enabled',
          { resourceId: `guardduty::${region}::detector`, region, detectorId: null, enabledInAccount: false },
          { message: `GuardDuty is not enabled in region ${region} (no detector configured)` },
        ),
      );
      // guardduty_delegated_admin_enabled_all_regions also evaluates the no-detector case
      findings.push(...await this.checkGuardDutyDelegatedAdmin(region, null, false));
      return findings;
    }

    for (const detectorId of detectorIds) {
      try {
        findings.push(...await this.validateGuardDutyDetector(region, detectorId));
      } catch (error) {
        logger.debug(`Failed to scan GuardDuty detector ${detectorId}`, { error: (error as Error).message });
      }
    }
    return findings;
  }

  private async listGuardDutyDetectors(): Promise<string[]> {
    const detectorIds: string[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.guardduty.send(new ListDetectorsCommand({ NextToken: nextToken }));
      });
      detectorIds.push(...(result.DetectorIds ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return detectorIds;
  }

  private async validateGuardDutyDetector(region: string, detectorId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const resourceId = `guardduty::${region}::detector/${detectorId}`;

    const info: any = await retry(async () => {
      return await this.guardduty.send(new GetDetectorCommand({ DetectorId: detectorId }));
    });
    const status: string | undefined = info.Status;
    const enabled = status === 'ENABLED';

    // guardduty_is_enabled: detector exists but is not configured or is suspended
    if (!status) {
      findings.push(
        this.emit(
          'guardduty_is_enabled',
          { resourceId, region, detectorId, status: null },
          { message: `GuardDuty detector "${detectorId}" in region ${region} is not configured` },
        ),
      );
    } else if (!enabled) {
      findings.push(
        this.emit(
          'guardduty_is_enabled',
          { resourceId, region, detectorId, status },
          { message: `GuardDuty detector "${detectorId}" in region ${region} is configured but suspended (status: ${status})` },
        ),
      );
    }

    // Data sources / features (Prowler only evaluates these when the detector is enabled)
    if (enabled) {
      const dataSources: any = info.DataSources ?? {};
      const s3Protection = dataSources.S3Logs?.Status === 'ENABLED';
      const eksAuditLogProtection = dataSources.Kubernetes?.AuditLogs?.Status === 'ENABLED';
      const ec2MalwareProtection =
        dataSources.MalwareProtection?.ScanEc2InstanceWithFindings?.EbsVolumes?.Status === 'ENABLED';

      let rdsProtection = false;
      let lambdaProtection = false;
      let eksRuntimeMonitoring = false;
      for (const feature of info.Features ?? []) {
        if (feature?.Name === 'RDS_LOGIN_EVENTS' && feature?.Status === 'ENABLED') rdsProtection = true;
        else if (feature?.Name === 'LAMBDA_NETWORK_LOGS' && feature?.Status === 'ENABLED') lambdaProtection = true;
        else if (feature?.Name === 'EKS_RUNTIME_MONITORING' && feature?.Status === 'ENABLED') eksRuntimeMonitoring = true;
      }

      if (!s3Protection) {
        findings.push(
          this.emit(
            'guardduty_s3_protection_enabled',
            { resourceId, region, detectorId, s3Protection: false },
            { message: `GuardDuty detector "${detectorId}" does not have S3 Protection enabled` },
          ),
        );
      }
      if (!eksAuditLogProtection) {
        findings.push(
          this.emit(
            'guardduty_eks_audit_log_enabled',
            { resourceId, region, detectorId, eksAuditLogProtection: false },
            { message: `GuardDuty detector "${detectorId}" does not have EKS Audit Log Monitoring enabled` },
          ),
        );
      }
      if (!eksRuntimeMonitoring) {
        findings.push(
          this.emit(
            'guardduty_eks_runtime_monitoring_enabled',
            { resourceId, region, detectorId, eksRuntimeMonitoring: false },
            { message: `GuardDuty detector "${detectorId}" does not have EKS Runtime Monitoring enabled` },
          ),
        );
      }
      if (!ec2MalwareProtection) {
        findings.push(
          this.emit(
            'guardduty_ec2_malware_protection_enabled',
            { resourceId, region, detectorId, ec2MalwareProtection: false },
            { message: `GuardDuty detector "${detectorId}" does not have Malware Protection for EC2 enabled` },
          ),
        );
      }
      if (!rdsProtection) {
        findings.push(
          this.emit(
            'guardduty_rds_protection_enabled',
            { resourceId, region, detectorId, rdsProtection: false },
            { message: `GuardDuty detector "${detectorId}" does not have RDS Protection enabled` },
          ),
        );
      }
      if (!lambdaProtection) {
        findings.push(
          this.emit(
            'guardduty_lambda_protection_enabled',
            { resourceId, region, detectorId, lambdaProtection: false },
            { message: `GuardDuty detector "${detectorId}" does not have Lambda Protection enabled` },
          ),
        );
      }
    }

    // guardduty_centrally_managed: administrator account, or admin with member accounts
    let administratorAccount: string | undefined;
    try {
      const adminResult = await retry(async () => {
        return await this.guardduty.send(new GetAdministratorAccountCommand({ DetectorId: detectorId }));
      });
      administratorAccount = adminResult.Administrator?.AccountId;
    } catch (error) {
      logger.debug(`GuardDuty GetAdministratorAccount failed for ${detectorId}`, { error: (error as Error).message });
    }
    let memberAccountCount = 0;
    if (!administratorAccount) {
      try {
        memberAccountCount = await this.countGuardDutyMembers(detectorId);
      } catch (error) {
        logger.debug(`GuardDuty ListMembers failed for ${detectorId}`, { error: (error as Error).message });
      }
    }
    if (!administratorAccount && memberAccountCount === 0) {
      findings.push(
        this.emit(
          'guardduty_centrally_managed',
          { resourceId, region, detectorId, administratorAccount: null, memberAccounts: 0 },
          { message: `GuardDuty detector "${detectorId}" is not centrally managed (no administrator account and no member accounts)` },
        ),
      );
    }

    // guardduty_no_high_severity_findings: unarchived findings with severity 8
    try {
      const highSeverityCount = await this.countHighSeverityGuardDutyFindings(detectorId);
      if (highSeverityCount > 0) {
        findings.push(
          this.emit(
            'guardduty_no_high_severity_findings',
            { resourceId, region, detectorId, highSeverityFindingCount: highSeverityCount },
            { message: `GuardDuty detector "${detectorId}" has ${highSeverityCount} unarchived high severity finding(s)` },
          ),
        );
      }
    } catch (error) {
      logger.debug(`GuardDuty ListFindings failed for ${detectorId}`, { error: (error as Error).message });
    }

    // guardduty_delegated_admin_enabled_all_regions
    findings.push(...await this.checkGuardDutyDelegatedAdmin(region, detectorId, enabled));

    return findings;
  }

  private async countGuardDutyMembers(detectorId: string): Promise<number> {
    let count = 0;
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.guardduty.send(new ListMembersCommand({ DetectorId: detectorId, NextToken: nextToken }));
      });
      count += (result.Members ?? []).length;
      nextToken = result.NextToken;
    } while (nextToken);
    return count;
  }

  private async countHighSeverityGuardDutyFindings(detectorId: string): Promise<number> {
    let count = 0;
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.guardduty.send(new ListFindingsCommand({
          DetectorId: detectorId,
          FindingCriteria: {
            Criterion: {
              severity: { Eq: ['8'] },
              'service.archived': { Eq: ['false'] },
            },
          },
          NextToken: nextToken,
        }));
      });
      count += (result.FindingIds ?? []).length;
      nextToken = result.NextToken;
    } while (nextToken);
    return count;
  }

  private async checkGuardDutyDelegatedAdmin(
    region: string,
    detectorId: string | null,
    detectorEnabled: boolean,
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const issues: string[] = [];

    // Delegated administrator accounts (only visible from the org management or
    // delegated admin account — access errors are treated as "no admin", as in Prowler)
    let hasDelegatedAdmin = false;
    try {
      let nextToken: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.guardduty.send(new ListOrganizationAdminAccountsCommand({ NextToken: nextToken }));
        });
        for (const admin of result.AdminAccounts ?? []) {
          if (admin?.AdminStatus === 'ENABLED') hasDelegatedAdmin = true;
        }
        nextToken = result.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('GuardDuty ListOrganizationAdminAccounts failed', { error: (error as Error).message });
    }
    if (!hasDelegatedAdmin) issues.push('no delegated administrator configured');

    if (!detectorEnabled) issues.push('detector not enabled');

    // Organization auto-enable — only reported when org config data is available
    let organizationConfigAvailable = false;
    let autoEnableMembers = 'NONE';
    if (detectorId) {
      try {
        const orgConfig: any = await retry(async () => {
          return await this.guardduty.send(new DescribeOrganizationConfigurationCommand({ DetectorId: detectorId }));
        });
        autoEnableMembers = orgConfig.AutoEnableOrganizationMembers ?? 'NONE';
        organizationConfigAvailable = true;
      } catch (error) {
        logger.debug('GuardDuty DescribeOrganizationConfiguration failed', { error: (error as Error).message });
      }
    }
    if (organizationConfigAvailable && autoEnableMembers !== 'NEW' && autoEnableMembers !== 'ALL') {
      issues.push('organization auto-enable not configured');
    }

    if (issues.length > 0) {
      findings.push(
        this.emit(
          'guardduty_delegated_admin_enabled_all_regions',
          {
            resourceId: `guardduty::${region}::organization-admin`,
            region,
            detectorId,
            hasDelegatedAdmin,
            detectorEnabled,
            autoEnableMembers: organizationConfigAvailable ? autoEnableMembers : null,
            issues,
          },
          { message: `GuardDuty in region ${region} has issues: ${issues.join(', ')}` },
        ),
      );
    }
    return findings;
  }
}

export default ThreatDetectionScanner;
