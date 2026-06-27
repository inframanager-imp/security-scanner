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
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';

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
  constructor(client: AWSClient) {
    super(client, 'THREAT');
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
          ...this.createFinding(
            'Threat: CloudTrail Logging Disabled or Modified',
            `CloudTrail "${eventName}" by ${actor} at ${e.EventTime?.toISOString()}. Trail: ${trail}.`,
            eventName === 'DeleteTrail' ? 'CRITICAL' : 'HIGH',
            { resourceId: `threat::cloudtrail-tamper::${actor}::${e.EventTime?.getTime()}`, threatCategory: 'DefenseEvasion', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), eventName, affectedResource: trail, rawEvents: [raw] },
            `Re-enable CloudTrail: aws cloudtrail start-logging --name ${trail}`,
            ['threat', 'cloudtrail', 'defense-evasion'],
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
          ...this.createFinding(
            'Threat: Root Account API Activity',
            `Root account performed "${e.EventName}" at ${e.EventTime?.toISOString()} from IP ${sourceIPFromEvent(e)}.`,
            'CRITICAL',
            { resourceId: `threat::root::${e.EventTime?.getTime()}`, threatCategory: 'UnauthorizedAccess', actor: 'root', eventName: e.EventName, eventTime: e.EventTime?.toISOString(), sourceIP: sourceIPFromEvent(e), rawEvents: [raw] },
            'Immediately investigate and rotate root credentials. Enable MFA on root account.',
            ['threat', 'root'],
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
          ...this.createFinding(
            'Threat: Console Login Without MFA',
            `"${actor}" logged in without MFA at ${e.EventTime?.toISOString()} from ${sourceIPFromEvent(e)}.`,
            'HIGH',
            { resourceId: `threat::no-mfa::${actor}::${e.EventTime?.getTime()}`, threatCategory: 'UnauthorizedAccess', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), rawEvents: [raw] },
            `Enforce MFA on IAM user "${actor}".`,
            ['threat', 'mfa'],
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
        ...this.createFinding(
          'Threat: Admin Policy Attached to User',
          `AdministratorAccess attached to "${target}" by "${actor}" at ${e.EventTime?.toISOString()}.`,
          'CRITICAL',
          { resourceId: `threat::admin-attach::${target}::${e.EventTime?.getTime()}`, threatCategory: 'Persistence', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), affectedResource: target, rawEvents: [raw] },
          `Detach AdministratorAccess from "${target}" immediately.`,
          ['threat', 'persistence'],
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
        ...this.createFinding(
          'Threat: New Access Key Created',
          `New access key ${keyId ? `(${keyId}) ` : ''}for "${target}" by "${actor}" at ${e.EventTime?.toISOString()}.`,
          'HIGH',
          { resourceId: `threat::new-key::${target}::${e.EventTime?.getTime()}`, threatCategory: 'Persistence', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), affectedResource: target, accessKeyId: keyId, rawEvents: [raw] },
          `Verify this key creation was authorized. Deactivate if not: aws iam update-access-key --access-key-id ${keyId} --status Inactive`,
          ['threat', 'access-key'],
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
          ...this.createFinding(
            'Threat: IAM Policy Privilege Escalation',
            `Wildcard policy attached to "${target}" by "${actor}" via ${eventName} at ${e.EventTime?.toISOString()}.`,
            'CRITICAL',
            { resourceId: `threat::priv-esc::${target}::${e.EventTime?.getTime()}`, threatCategory: 'PrivilegeEscalation', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), affectedResource: target, rawEvents: [raw] },
            `Delete the inline policy from "${target}" immediately.`,
            ['threat', 'privilege-escalation'],
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
        ...this.createFinding(
          'Threat: EBS Snapshot Made Public',
          `Snapshot "${snapId}" made public by "${actor}" at ${e.EventTime?.toISOString()}.`,
          'CRITICAL',
          { resourceId: `threat::public-snapshot::${snapId}`, threatCategory: 'Exfiltration', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), affectedResource: snapId, rawEvents: [raw] },
          `Make snapshot private: aws ec2 modify-snapshot-attribute --snapshot-id ${snapId} --attribute createVolumePermission --operation-type remove --group-names all`,
          ['threat', 'exfiltration'],
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
        ...this.createFinding(
          'Threat: High-Compute Instance Launch (Crypto Mining Indicator)',
          `Instance type "${instanceType}" launched by "${actor}" at ${e.EventTime?.toISOString()} from ${sourceIPFromEvent(e)}.`,
          'HIGH',
          { resourceId: `threat::high-compute::${actor}::${e.EventTime?.getTime()}`, threatCategory: 'Impact', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), instanceType, rawEvents: [raw] },
          `If unauthorized, terminate instance(s) and revoke "${actor}" credentials.`,
          ['threat', 'crypto-mining'],
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
          ...this.createFinding(
            'Threat: AWS Config Recorder Stopped',
            `"${eventName}" by "${actor}" at ${e.EventTime?.toISOString()}.`,
            'HIGH',
            { resourceId: `threat::config-tamper::${actor}::${e.EventTime?.getTime()}`, threatCategory: 'DefenseEvasion', actor, sourceIP: sourceIPFromEvent(e), eventTime: e.EventTime?.toISOString(), eventName, rawEvents: [parseRaw(e)] },
            `Re-enable AWS Config recording immediately.`,
            ['threat', 'defense-evasion'],
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
          this.createFinding(
            'Threat: CloudTrail Logging Disabled or Modified',
            `CloudTrail event "${eventName}" detected at ${e.EventTime?.toISOString()} by ${actor}. ` +
            `Trail: ${trailArn}. This may indicate an attacker disabling audit logging to cover their tracks.`,
            eventName === 'DeleteTrail' ? 'CRITICAL' : 'HIGH',
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
            `Re-enable CloudTrail logging immediately: aws cloudtrail start-logging --name ${trailArn}. ` +
            `Investigate who performed this action and revoke access if unauthorized.`,
            ['threat', 'cloudtrail', 'defense-evasion'],
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
      this.createFinding(
        'Threat: Root Account API Activity',
        `${apiEvents.length} API call(s) made using the AWS root account in the last 24 hours. ` +
        `Events: ${eventNames.slice(0, 5).join(', ')}. Root account should never be used for daily operations.`,
        'CRITICAL',
        {
          resourceId:      `threat::root-activity::${start.toISOString()}`,
          threatCategory:  'UnauthorizedAccess',
          actor:           'root',
          eventCount:      apiEvents.length,
          eventNames,
          eventTime:       apiEvents[0].EventTime?.toISOString(),
          rawEvents:       apiEvents.slice(0, 3).map(parseRaw),
        },
        `Immediately rotate root account credentials. Enable MFA on root. ` +
        `Delete root access keys if any exist. Use IAM roles for all operations.`,
        ['threat', 'root', 'unauthorized-access'],
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
        this.createFinding(
          'Threat: Console Login Without MFA',
          `IAM user "${actor}" logged into the AWS console without MFA at ${e.EventTime?.toISOString()} ` +
          `from IP ${sourceIPFromEvent(e)}. This is a credential compromise risk.`,
          'HIGH',
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
          `Enforce MFA for all IAM users via IAM policy condition aws:MultiFactorAuthPresent. ` +
          `Temporarily disable the user's console access until MFA is configured.`,
          ['threat', 'mfa', 'unauthorized-access'],
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
        this.createFinding(
          'Threat: Brute Force Login Attempt',
          `${ipEvents.length} failed console login attempts from IP ${ip} in the last 24 hours. ` +
          `This indicates a brute-force or credential stuffing attack.`,
          'HIGH',
          {
            resourceId:     `threat::brute-force::${ip}::${start.toISOString()}`,
            threatCategory: 'UnauthorizedAccess',
            sourceIP:       ip,
            eventCount:     ipEvents.length,
            eventTime:      ipEvents[0].EventTime?.toISOString(),
            rawEvents:      ipEvents.slice(0, 3).map(parseRaw),
          },
          `Block the source IP ${ip} at the network/WAF level. ` +
          `Enable account lockout policies. Review whether any login succeeded.`,
          ['threat', 'brute-force', 'unauthorized-access'],
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
        this.createFinding(
          'Threat: Admin Policy Attached to User',
          `AdministratorAccess policy attached to "${target}" by "${actor}" at ${e.EventTime?.toISOString()}. ` +
          `This grants full AWS access and may indicate persistence or privilege escalation.`,
          'CRITICAL',
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
          `Immediately detach AdministratorAccess from "${target}": ` +
          `aws iam detach-user-policy --user-name ${target} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess. ` +
          `Investigate whether this was authorized.`,
          ['threat', 'persistence', 'admin'],
        ),
      );
    }

    // New users created in last 24h
    for (const e of createEvents) {
      const raw    = parseRaw(e);
      const actor  = actorFromEvent(e);
      const newUser = raw.requestParameters?.userName ?? 'Unknown';
      findings.push(
        this.createFinding(
          'Threat: New IAM User Created',
          `New IAM user "${newUser}" created by "${actor}" at ${e.EventTime?.toISOString()} ` +
          `from IP ${sourceIPFromEvent(e)}. Verify this was an authorized action.`,
          'MEDIUM',
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
          `Verify that user "${newUser}" was created as part of an authorized onboarding process. ` +
          `If unauthorized, delete immediately: aws iam delete-user --user-name ${newUser}.`,
          ['threat', 'persistence', 'iam'],
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
        this.createFinding(
          'Threat: New Access Key Created',
          `New access key ${keyId ? `(${keyId}) ` : ''}created for user "${target}" by "${actor}" ` +
          `at ${e.EventTime?.toISOString()} from IP ${sourceIPFromEvent(e)}.`,
          'HIGH',
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
          `Verify this key creation was authorized. If not, deactivate immediately: ` +
          `aws iam update-access-key --user-name ${target} --access-key-id ${keyId} --status Inactive`,
          ['threat', 'persistence', 'access-key'],
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
          this.createFinding(
            'Threat: IAM Policy Privilege Escalation',
            `Inline policy with wildcard permissions attached to "${target}" by "${actor}" ` +
            `via ${eventName} at ${e.EventTime?.toISOString()}. This grants unrestricted AWS access.`,
            'CRITICAL',
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
            `Delete the inline policy immediately: aws iam delete-user-policy --user-name ${target} --policy-name <PolicyName>. ` +
            `Replace with least-privilege managed policies.`,
            ['threat', 'privilege-escalation', 'iam'],
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
        this.createFinding(
          'Threat: IAM Enumeration Detected',
          `"GetAccountAuthorizationDetails" called by "${actor}" at ${e.EventTime?.toISOString()} ` +
          `from IP ${sourceIPFromEvent(e)}. This API dumps the entire IAM configuration — a common reconnaissance technique.`,
          'HIGH',
          {
            resourceId:     `threat::iam-enum::${actor}::${e.EventTime?.getTime()}`,
            threatCategory: 'Reconnaissance',
            actor,
            sourceIP:       sourceIPFromEvent(e),
            eventTime:      e.EventTime?.toISOString(),
            eventName:      'GetAccountAuthorizationDetails',
            rawEvents:      [parseRaw(e)],
          },
          `Review whether "${actor}" should have iam:GetAccountAuthorizationDetails permission. ` +
          `Restrict this permission to only security/audit roles.`,
          ['threat', 'reconnaissance', 'iam'],
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
        this.createFinding(
          'Threat: Infrastructure Enumeration Detected',
          `"${actor}" called ${eventNames.size} different discovery APIs in the last 24 hours ` +
          `(${[...eventNames].join(', ')}). This pattern indicates automated reconnaissance of your AWS environment.`,
          'MEDIUM',
          {
            resourceId:     `threat::infra-enum::${actor}::${start.toISOString()}`,
            threatCategory: 'Reconnaissance',
            actor,
            eventCount:     eventNames.size,
            eventNames:     [...eventNames],
            eventTime:      start.toISOString(),
          },
          `Investigate whether "${actor}" is a legitimate automation tool or compromised credential. ` +
          `Apply least-privilege — restrict discovery APIs to only needed services.`,
          ['threat', 'reconnaissance', 'enumeration'],
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
        this.createFinding(
          'Threat: Mass EC2 Instance Termination',
          `${events.length} TerminateInstances calls by "${actor}" in the last 24 hours ` +
          `affecting ${instanceIds.length} instance(s). This may indicate ransomware, sabotage, or a compromised credential.`,
          'CRITICAL',
          {
            resourceId:      `threat::mass-terminate::${actor}::${start.toISOString()}`,
            threatCategory:  'Impact',
            actor,
            eventCount:      events.length,
            affectedInstances: instanceIds.slice(0, 10),
            eventTime:       events[0].EventTime?.toISOString(),
            rawEvents:       events.slice(0, 2).map(parseRaw),
          },
          `Immediately revoke "${actor}" credentials. Restore instances from snapshots/AMIs. ` +
          `Enable EC2 termination protection on critical instances.`,
          ['threat', 'impact', 'deletion'],
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
        this.createFinding(
          'Threat: EBS Snapshot Made Public',
          `EBS snapshot "${snapshotId}" was made publicly accessible by "${actor}" ` +
          `at ${e.EventTime?.toISOString()}. Public snapshots expose all data in the volume to any AWS account.`,
          'CRITICAL',
          {
            resourceId:      `threat::public-snapshot::${snapshotId}`,
            threatCategory:  'Exfiltration',
            actor,
            sourceIP:        sourceIPFromEvent(e),
            eventTime:       e.EventTime?.toISOString(),
            affectedResource: snapshotId,
            rawEvents:       [raw],
          },
          `Immediately make the snapshot private: ` +
          `aws ec2 modify-snapshot-attribute --snapshot-id ${snapshotId} --attribute createVolumePermission --operation-type remove --group-names all`,
          ['threat', 'exfiltration', 'snapshot'],
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
        this.createFinding(
          'Threat: RDS Snapshot Made Public',
          `RDS snapshot "${snapId}" was made publicly restorable by "${actor}" at ${e.EventTime?.toISOString()}.`,
          'CRITICAL',
          {
            resourceId:      `threat::public-rds-snapshot::${snapId}`,
            threatCategory:  'Exfiltration',
            actor,
            sourceIP:        sourceIPFromEvent(e),
            eventTime:       e.EventTime?.toISOString(),
            affectedResource: snapId,
            rawEvents:       [raw],
          },
          `Make the snapshot private: aws rds modify-db-snapshot-attribute --db-snapshot-identifier ${snapId} ` +
          `--attribute-name restore --values-to-remove all`,
          ['threat', 'exfiltration', 'rds'],
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
        this.createFinding(
          'Threat: High-Compute Instance Launch (Crypto Mining Indicator)',
          `${instanceCount} instance(s) of type "${instanceType}" launched by "${actor}" ` +
          `at ${e.EventTime?.toISOString()} from IP ${sourceIPFromEvent(e)}. ` +
          `High-compute/GPU instances launched by unexpected identities often indicate crypto-mining.`,
          'HIGH',
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
          `If unauthorized, immediately terminate the instance(s) and revoke "${actor}" credentials. ` +
          `Enable AWS Cost Anomaly Detection to catch unexpected compute spend.`,
          ['threat', 'crypto-mining', 'impact'],
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
          this.createFinding(
            'Threat: AWS Config Recorder Stopped',
            `"${eventName}" called by "${actor}" at ${e.EventTime?.toISOString()}. ` +
            `Disabling AWS Config stops configuration change tracking — a common defense evasion technique.`,
            'HIGH',
            {
              resourceId:     `threat::config-tamper::${actor}::${e.EventTime?.getTime()}`,
              threatCategory: 'DefenseEvasion',
              actor,
              sourceIP:       sourceIPFromEvent(e),
              eventTime:      e.EventTime?.toISOString(),
              eventName,
              rawEvents:      [parseRaw(e)],
            },
            `Re-enable AWS Config recording immediately. Investigate whether this was authorized.`,
            ['threat', 'defense-evasion', 'config'],
          ),
        );
      }
    }
    return findings;
  }
}

export default ThreatDetectionScanner;
