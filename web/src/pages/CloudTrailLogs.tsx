import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  RefreshCw,
  AlertCircle,
  Clock,
  Calendar,
  Activity,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Diff,
  FileText,
  Code2,
  XCircle,
  CheckCircle,
} from 'lucide-react';
import { cloudtrailApi, type CloudTrailEvent } from '../api/cloudtrail';
import { accountsApi } from '../api/accounts';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';

// ─── Severity Classification ──────────────────────────────────────────────────

export type EventSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';

const CRITICAL_EVENTS = new Set([
  // CloudTrail tampering
  'StopLogging', 'DeleteTrail', 'UpdateTrail',
  // IAM privilege escalation
  'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
  'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
  'CreateLoginProfile', 'UpdateLoginProfile',
  'DeleteAccountPasswordPolicy', 'UpdateAccountPasswordPolicy',
  // Security group – open to world
  'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
  'CreateSecurityGroup',
  // Root activity
  'CreateVirtualMFADevice', 'DeactivateMFADevice', 'DeleteVirtualMFADevice',
  // Public S3 / bucket policy
  'PutBucketPolicy', 'PutBucketAcl', 'DeleteBucketPolicy',
  // Console failures / brute-force indicator
  'ConsoleLoginFailure',
  // Config tampering
  'StopConfigurationRecorder', 'DeleteConfigurationRecorder',
  'DeleteDeliveryChannel', 'StopDeliveryChannel',
  // KMS disabling
  'DisableKey', 'ScheduleKeyDeletion', 'DeleteAlias',
]);

const HIGH_EVENTS = new Set([
  // Resource deletion
  'DeleteBucket', 'DeleteDBInstance', 'DeleteDBCluster',
  'DeleteFunction', 'DeleteSecret', 'DeleteKeyPair',
  'DeleteLoadBalancer', 'DeleteTargetGroup',
  'TerminateInstances', 'StopInstances',
  // IAM changes
  'CreateUser', 'DeleteUser', 'AddUserToGroup', 'RemoveUserFromGroup',
  'CreateRole', 'DeleteRole', 'UpdateRole',
  'DetachUserPolicy', 'DetachRolePolicy', 'DetachGroupPolicy',
  'DeleteUserPolicy', 'DeleteRolePolicy', 'DeleteGroupPolicy',
  // Network changes
  'DeleteVpc', 'DeleteSubnet', 'DeleteInternetGateway',
  'DeleteNatGateway', 'DeleteRouteTable', 'DeleteRoute',
  'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
  // Snapshot / image exposure
  'ModifySnapshotAttribute', 'ModifyImageAttribute',
  'CreateSnapshot', 'CopySnapshot',
  // S3 visibility
  'PutBucketVersioning', 'PutBucketLogging', 'PutBucketPublicAccessBlock',
  // Logging changes
  'PutMetricAlarm', 'DeleteAlarms',
  'DeleteLogGroup', 'DeleteLogStream',
  // Key access
  'CreateAccessKey', 'UpdateAccessKey', 'DeleteAccessKey',
  // RDS exposure
  'ModifyDBInstance', 'RestoreDBInstanceFromDBSnapshot',
  // CloudFront / WAF
  'DeleteDistribution', 'DeleteWebACL',
]);

const MEDIUM_EVENTS = new Set([
  // Infrastructure creation
  'RunInstances', 'CreateDBInstance',
  'CreateBucket', 'CreateFunction',
  'CreateLoadBalancer', 'CreateTargetGroup',
  'CreateVpc', 'CreateSubnet', 'CreateInternetGateway',
  'CreateNatGateway', 'CreateRoute',
  // IAM creation
  'CreatePolicy', 'CreatePolicyVersion',
  'CreateGroup', 'DeleteGroup',
  // KMS key creation
  'CreateKey', 'EnableKey', 'PutKeyPolicy',
  // Secrets
  'CreateSecret', 'PutSecretValue', 'RotateSecret',
  // Access keys
  'GetSecretValue',
  // CloudFormation
  'CreateStack', 'UpdateStack', 'DeleteStack',
  // ECS / ECR
  'CreateCluster', 'CreateService', 'RegisterTaskDefinition',
  // S3 events
  'CreateMultipartUpload', 'PutObject',
]);

export function classifyEventSeverity(event: CloudTrailEvent): EventSeverity {
  const name = event.eventName ?? '';
  if (CRITICAL_EVENTS.has(name)) return 'CRITICAL';
  if (HIGH_EVENTS.has(name))     return 'HIGH';
  if (MEDIUM_EVENTS.has(name))   return 'MEDIUM';
  // Failed write events bump to HIGH regardless
  if (event.errorCode && event.readOnly === 'false') return 'HIGH';
  return 'INFO';
}

// ─── Change Diff Engine ───────────────────────────────────────────────────────

export interface DiffLine {
  type:  'added' | 'removed' | 'context' | 'header';
  label: string;
  value?: string;
}

function sgRuleLines(ipPerms: any[], direction: 'Inbound' | 'Outbound'): DiffLine[] {
  const lines: DiffLine[] = [];
  if (!Array.isArray(ipPerms)) return lines;
  for (const perm of ipPerms) {
    const proto  = perm.ipProtocol === '-1' ? 'All traffic' : (perm.ipProtocol ?? '?').toUpperCase();
    const portRange = perm.fromPort != null
      ? perm.fromPort === perm.toPort
        ? `port ${perm.fromPort}`
        : `ports ${perm.fromPort}–${perm.toPort}`
      : 'all ports';
    const ranges: string[] = [];
    for (const r of perm.ipRanges ?? [])         ranges.push(r.cidrIp ?? r.cidrIpv6 ?? '?');
    for (const r of perm.ipv6Ranges ?? [])        ranges.push(r.cidrIpv6 ?? '?');
    for (const r of perm.userIdGroupPairs ?? [])  ranges.push(`SG:${r.groupId ?? r.groupName ?? '?'}`);
    const cidr = ranges.join(', ') || '?';
    const isWorld = ranges.some(r => r === '0.0.0.0/0' || r === '::/0');
    lines.push({
      type:  'added',
      label: `${direction} rule`,
      value: `${proto} ${portRange} from ${cidr}${isWorld ? ' ⚠ OPEN TO WORLD' : ''}`,
    });
  }
  return lines;
}

export function buildChangeDiff(event: CloudTrailEvent): DiffLine[] {
  const req  = (event.requestParameters  ?? {}) as Record<string, any>;
  const resp = (event.responseElements   ?? {}) as Record<string, any>;
  const name = event.eventName ?? '';
  const lines: DiffLine[] = [];

  // ── Security group ──────────────────────────────────────────────────────────
  if (name === 'AuthorizeSecurityGroupIngress' || name === 'AuthorizeSecurityGroupEgress') {
    const dir = name.includes('Ingress') ? 'Inbound' : 'Outbound';
    lines.push({ type: 'header', label: `Security Group: ${req.groupId ?? req.groupName ?? '?'}` });
    lines.push(...sgRuleLines(req.ipPermissions?.items ?? req.ipPermissions ?? [], dir));
    return lines;
  }
  if (name === 'RevokeSecurityGroupIngress' || name === 'RevokeSecurityGroupEgress') {
    const dir = name.includes('Ingress') ? 'Inbound' : 'Outbound';
    lines.push({ type: 'header', label: `Security Group: ${req.groupId ?? '?'}` });
    const ruleLines = sgRuleLines(req.ipPermissions?.items ?? req.ipPermissions ?? [], dir);
    lines.push(...ruleLines.map(l => ({ ...l, type: 'removed' as const })));
    return lines;
  }

  // ── IAM policy attach/detach ─────────────────────────────────────────────────
  if (name === 'AttachUserPolicy' || name === 'AttachRolePolicy' || name === 'AttachGroupPolicy') {
    const target = req.userName ?? req.roleName ?? req.groupName ?? '?';
    const policy = req.policyArn ?? '?';
    lines.push({ type: 'header', label: 'IAM Policy Attached' });
    lines.push({ type: 'context', label: 'Principal', value: target });
    lines.push({ type: 'added',   label: 'Policy',    value: policy });
    return lines;
  }
  if (name === 'DetachUserPolicy' || name === 'DetachRolePolicy' || name === 'DetachGroupPolicy') {
    const target = req.userName ?? req.roleName ?? req.groupName ?? '?';
    lines.push({ type: 'header',  label: 'IAM Policy Detached' });
    lines.push({ type: 'context', label: 'Principal', value: target });
    lines.push({ type: 'removed', label: 'Policy',    value: req.policyArn ?? '?' });
    return lines;
  }
  if (name === 'PutUserPolicy' || name === 'PutRolePolicy' || name === 'PutGroupPolicy') {
    const target = req.userName ?? req.roleName ?? req.groupName ?? '?';
    lines.push({ type: 'header',  label: 'Inline Policy Modified' });
    lines.push({ type: 'context', label: 'Principal',   value: target });
    lines.push({ type: 'added',   label: 'Policy Name', value: req.policyName ?? '?' });
    if (req.policyDocument) {
      try {
        const doc = typeof req.policyDocument === 'string'
          ? JSON.parse(decodeURIComponent(req.policyDocument))
          : req.policyDocument;
        const statements = doc.Statement ?? [];
        for (const stmt of statements.slice(0, 5)) {
          const actions  = [stmt.Action].flat().join(', ');
          const effect   = stmt.Effect ?? '?';
          const resource = [stmt.Resource].flat().join(', ');
          lines.push({
            type:  effect === 'Allow' ? 'added' : 'removed',
            label: `${effect}`,
            value: `${actions} on ${resource}`,
          });
        }
      } catch { /* ignore */ }
    }
    return lines;
  }

  // ── CloudTrail / Config ──────────────────────────────────────────────────────
  if (name === 'StopLogging' || name === 'DeleteTrail') {
    lines.push({ type: 'header',  label: name === 'StopLogging' ? 'CloudTrail Logging Stopped' : 'CloudTrail Trail Deleted' });
    lines.push({ type: 'removed', label: 'Trail', value: req.name ?? req.trailARN ?? '?' });
    return lines;
  }
  if (name === 'StopConfigurationRecorder' || name === 'DeleteConfigurationRecorder') {
    lines.push({ type: 'header',  label: 'AWS Config Recorder Stopped/Deleted' });
    lines.push({ type: 'removed', label: 'Recorder', value: req.configurationRecorderName ?? '?' });
    return lines;
  }

  // ── KMS ──────────────────────────────────────────────────────────────────────
  if (name === 'DisableKey' || name === 'ScheduleKeyDeletion') {
    lines.push({ type: 'header',  label: name === 'DisableKey' ? 'KMS Key Disabled' : 'KMS Key Deletion Scheduled' });
    lines.push({ type: 'removed', label: 'Key ID', value: req.keyId ?? '?' });
    if (name === 'ScheduleKeyDeletion' && req.pendingWindowInDays) {
      lines.push({ type: 'context', label: 'Deletion in', value: `${req.pendingWindowInDays} days` });
    }
    return lines;
  }

  // ── S3 bucket policy ────────────────────────────────────────────────────────
  if (name === 'PutBucketPolicy') {
    lines.push({ type: 'header',  label: 'S3 Bucket Policy Updated' });
    lines.push({ type: 'context', label: 'Bucket', value: req.bucketName ?? '?' });
    if (req.bucketPolicy) {
      try {
        const policy = typeof req.bucketPolicy === 'string'
          ? JSON.parse(req.bucketPolicy)
          : req.bucketPolicy;
        const stmts = policy.Statement ?? [];
        for (const stmt of stmts.slice(0, 5)) {
          const principal = typeof stmt.Principal === 'string' ? stmt.Principal : JSON.stringify(stmt.Principal);
          const isPublic  = principal === '*';
          lines.push({
            type:  isPublic ? 'added' : 'context',
            label: `${stmt.Effect} ${isPublic ? '⚠ PUBLIC' : ''}`,
            value: `Principal: ${principal} | Action: ${[stmt.Action].flat().slice(0, 3).join(', ')}`,
          });
        }
      } catch { /* ignore */ }
    }
    return lines;
  }
  if (name === 'DeleteBucketPolicy') {
    lines.push({ type: 'header',  label: 'S3 Bucket Policy Deleted' });
    lines.push({ type: 'removed', label: 'Bucket', value: req.bucketName ?? '?' });
    return lines;
  }

  // ── User / access key lifecycle ──────────────────────────────────────────────
  if (name === 'CreateUser') {
    lines.push({ type: 'header', label: 'IAM User Created' });
    lines.push({ type: 'added',  label: 'User',    value: req.userName ?? resp.user?.userName ?? '?' });
    lines.push({ type: 'context',label: 'Path',    value: req.path ?? '/' });
    return lines;
  }
  if (name === 'DeleteUser') {
    lines.push({ type: 'header',  label: 'IAM User Deleted' });
    lines.push({ type: 'removed', label: 'User',   value: req.userName ?? '?' });
    return lines;
  }
  if (name === 'CreateAccessKey') {
    lines.push({ type: 'header', label: 'Access Key Created' });
    lines.push({ type: 'added',  label: 'User',       value: req.userName ?? event.username ?? '?' });
    lines.push({ type: 'added',  label: 'Key ID',     value: resp.accessKey?.accessKeyId ?? '?' });
    lines.push({ type: 'added',  label: 'Status',     value: resp.accessKey?.status ?? 'Active' });
    return lines;
  }
  if (name === 'DeleteAccessKey') {
    lines.push({ type: 'header',  label: 'Access Key Deleted' });
    lines.push({ type: 'removed', label: 'User',   value: req.userName ?? '?' });
    lines.push({ type: 'removed', label: 'Key ID', value: req.accessKeyId ?? '?' });
    return lines;
  }
  if (name === 'AddUserToGroup') {
    lines.push({ type: 'header', label: 'User Added to Group' });
    lines.push({ type: 'added',  label: 'User',  value: req.userName  ?? '?' });
    lines.push({ type: 'added',  label: 'Group', value: req.groupName ?? '?' });
    return lines;
  }

  // ── Instance / RDS lifecycle ─────────────────────────────────────────────────
  if (name === 'TerminateInstances') {
    lines.push({ type: 'header', label: 'EC2 Instances Terminated' });
    const ids: string[] = (req.instancesSet?.items ?? []).map((i: any) => i.instanceId ?? '?');
    for (const id of ids) {
      lines.push({ type: 'removed', label: 'Instance', value: id });
    }
    return lines;
  }
  if (name === 'RunInstances') {
    lines.push({ type: 'header', label: 'EC2 Instances Launched' });
    lines.push({ type: 'added',  label: 'AMI',      value: req.imageId ?? '?' });
    lines.push({ type: 'added',  label: 'Type',     value: req.instanceType ?? '?' });
    lines.push({ type: 'added',  label: 'Count',    value: `${req.minCount ?? 1}–${req.maxCount ?? 1}` });
    lines.push({ type: 'context',label: 'Subnet',   value: req.subnetId ?? '(default)' });
    lines.push({ type: 'context',label: 'Key Pair', value: req.keyName ?? '(none)' });
    return lines;
  }
  if (name === 'DeleteDBInstance') {
    lines.push({ type: 'header',  label: 'RDS Instance Deleted' });
    lines.push({ type: 'removed', label: 'DB Instance', value: req.dBInstanceIdentifier ?? '?' });
    lines.push({ type: 'context', label: 'Snapshot',    value: req.finalDBSnapshotIdentifier ?? '(no final snapshot)' });
    return lines;
  }
  if (name === 'DeleteSecret') {
    lines.push({ type: 'header',  label: 'Secret Deleted' });
    lines.push({ type: 'removed', label: 'Secret', value: req.secretId ?? '?' });
    return lines;
  }

  // ── Generic fallback: just show request/response diff as key-value ──────────
  lines.push({ type: 'header', label: `${name} — Parameters` });
  const topKeys = Object.keys(req).slice(0, 12);
  for (const k of topKeys) {
    const v = req[k];
    if (v === null || v === undefined) continue;
    lines.push({
      type:  'context',
      label: k,
      value: typeof v === 'object' ? JSON.stringify(v).slice(0, 120) : String(v),
    });
  }
  return lines;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const AWS_REGIONS = [
  'us-east-1','us-east-2','us-west-1','us-west-2',
  'eu-west-1','eu-west-2','eu-central-1',
  'ap-southeast-1','ap-southeast-2','ap-northeast-1','ap-south-1',
  'ca-central-1','sa-east-1',
];

const TIME_RANGES = [
  { label: '1h',   hours: 1   },
  { label: '6h',   hours: 6   },
  { label: '24h',  hours: 24  },
  { label: '7d',   hours: 168 },
];

const SEV_FILTER_OPTIONS = [
  { value: '',         label: 'All Severities' },
  { value: 'CRITICAL', label: '🔴 Critical' },
  { value: 'HIGH',     label: '🟠 High' },
  { value: 'MEDIUM',   label: '🟡 Medium' },
  { value: 'INFO',     label: '🟢 Info' },
];

const READ_ONLY_OPTIONS = [
  { value: '', label: 'All Events' },
  { value: 'false', label: 'Write Events Only' },
  { value: 'true',  label: 'Read Events Only' },
];

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEV_CONFIG: Record<EventSeverity, {
  dot: string; bg: string; text: string; border: string; ring: string; icon: React.ReactNode;
}> = {
  CRITICAL: {
    dot: 'bg-red-500', bg: 'bg-red-50', text: 'text-red-700',
    border: 'border-red-200', ring: 'ring-red-300',
    icon: <ShieldAlert size={13} className="text-red-600" />,
  },
  HIGH: {
    dot: 'bg-orange-500', bg: 'bg-orange-50', text: 'text-orange-700',
    border: 'border-orange-200', ring: 'ring-orange-300',
    icon: <AlertTriangle size={13} className="text-orange-500" />,
  },
  MEDIUM: {
    dot: 'bg-yellow-400', bg: 'bg-yellow-50', text: 'text-yellow-700',
    border: 'border-yellow-200', ring: 'ring-yellow-300',
    icon: <AlertCircle size={13} className="text-yellow-500" />,
  },
  INFO: {
    dot: 'bg-green-400', bg: 'bg-green-50', text: 'text-green-700',
    border: 'border-green-100', ring: 'ring-green-200',
    icon: <Info size={13} className="text-green-600" />,
  },
};

function SeverityBadge({ severity }: { severity: EventSeverity }) {
  const c = SEV_CONFIG[severity];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold
      ${c.bg} ${c.text} ring-1 ${c.ring}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${c.dot}`} />
      {severity}
    </span>
  );
}

// ─── Severity Dashboard ───────────────────────────────────────────────────────

interface SeverityDashboardProps {
  events:          CloudTrailEvent[];
  activeSeverity:  string;
  onFilter:        (sev: string) => void;
}

function SeverityDashboard({ events, activeSeverity, onFilter }: SeverityDashboardProps) {
  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 };
    for (const e of events) c[classifyEventSeverity(e)]++;
    return c;
  }, [events]);

  const total = events.length || 1;

  const cards: { sev: EventSeverity; label: string; icon: React.ReactNode }[] = [
    { sev: 'CRITICAL', label: 'Critical',  icon: <ShieldAlert size={18} className="text-red-500" /> },
    { sev: 'HIGH',     label: 'High',      icon: <AlertTriangle size={18} className="text-orange-500" /> },
    { sev: 'MEDIUM',   label: 'Medium',    icon: <AlertCircle size={18} className="text-yellow-500" /> },
    { sev: 'INFO',     label: 'Info',      icon: <Info size={18} className="text-green-500" /> },
  ];

  return (
    <div className="space-y-3">
      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-3">
        {cards.map(({ sev, label, icon }) => {
          const c   = SEV_CONFIG[sev];
          const cnt = counts[sev];
          const active = activeSeverity === sev;
          return (
            <button
              key={sev}
              onClick={() => onFilter(active ? '' : sev)}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl border transition-all text-left
                ${active
                  ? `${c.bg} ${c.border} ring-2 ${c.ring}`
                  : 'bg-white border-gray-200 hover:border-gray-300 hover:shadow-sm'}`}
            >
              <div className={`p-2 rounded-lg ${active ? 'bg-white/60' : c.bg}`}>
                {icon}
              </div>
              <div>
                <div className={`text-2xl font-bold ${active ? c.text : 'text-gray-900'}`}>{cnt}</div>
                <div className="text-xs text-gray-500 font-medium">{label}</div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Stacked bar */}
      {events.length > 0 && (
        <div className="flex rounded-full overflow-hidden h-2.5 gap-px">
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'INFO'] as EventSeverity[]).map(sev => {
            const pct = (counts[sev] / total) * 100;
            if (pct < 0.5) return null;
            return (
              <div
                key={sev}
                className={`${SEV_CONFIG[sev].dot} transition-all`}
                style={{ width: `${pct}%` }}
                title={`${sev}: ${counts[sev]}`}
              />
            );
          })}
        </div>
      )}

      {/* Top event names for CRITICAL/HIGH */}
      {(counts.CRITICAL > 0 || counts.HIGH > 0) && (
        <div className="grid grid-cols-2 gap-3">
          {(['CRITICAL', 'HIGH'] as EventSeverity[]).map(sev => {
            if (counts[sev] === 0) return null;
            const topNames = events
              .filter(e => classifyEventSeverity(e) === sev)
              .reduce((acc: Record<string, number>, e) => {
                const k = e.eventName ?? '?';
                acc[k] = (acc[k] ?? 0) + 1;
                return acc;
              }, {});
            const sorted = Object.entries(topNames).sort(([, a], [, b]) => b - a).slice(0, 5);
            const c = SEV_CONFIG[sev];
            return (
              <div key={sev} className={`rounded-xl border ${c.border} ${c.bg} px-4 py-3`}>
                <div className={`text-xs font-bold uppercase tracking-wide ${c.text} mb-2 flex items-center gap-1.5`}>
                  {c.icon} {sev} Events
                </div>
                <div className="space-y-1">
                  {sorted.map(([name, count]) => (
                    <div key={name} className="flex items-center justify-between gap-2">
                      <span className={`text-xs font-mono ${c.text} truncate`}>{name}</span>
                      <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${c.bg} ${c.text} shrink-0`}>{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Change Diff Panel ────────────────────────────────────────────────────────

function ChangeDiffPanel({ event }: { event: CloudTrailEvent }) {
  const lines = useMemo(() => buildChangeDiff(event), [event]);
  const sev   = classifyEventSeverity(event);

  if (lines.length === 0) {
    return <p className="text-sm text-gray-400 italic">No change diff available for this event.</p>;
  }

  return (
    <div className="space-y-1 font-mono text-xs">
      {lines.map((line, i) => {
        if (line.type === 'header') {
          return (
            <div key={i} className={`flex items-center gap-2 px-3 py-2 rounded-lg font-bold text-sm
              ${sev === 'CRITICAL' ? 'bg-red-900/20 text-red-300' : 'bg-orange-900/20 text-orange-300'}`}>
              <Diff size={13} />
              {line.label}
            </div>
          );
        }
        const colors = {
          added:   'bg-green-950/60 text-green-400 border-l-2 border-green-500',
          removed: 'bg-red-950/60 text-red-400 border-l-2 border-red-500',
          context: 'bg-gray-800/40 text-gray-300',
        }[line.type] ?? '';

        const prefix = line.type === 'added' ? '+' : line.type === 'removed' ? '−' : ' ';

        return (
          <div key={i} className={`flex gap-3 px-3 py-1.5 rounded ${colors}`}>
            <span className="shrink-0 w-4 text-center font-bold opacity-70">{prefix}</span>
            <span className="shrink-0 text-gray-400 w-28 truncate">{line.label}</span>
            <span className="break-all leading-relaxed">{line.value ?? ''}</span>
          </div>
        );
      })}
    </div>
  );
}

// ─── Expanded Event Row ───────────────────────────────────────────────────────

type DetailTab = 'details' | 'diff' | 'raw';

function DetailField({ label, value, mono, error }: {
  label: string; value: React.ReactNode; mono?: boolean; error?: boolean;
}) {
  return (
    <div>
      <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-0.5">{label}</div>
      <div className={`text-sm break-all ${error ? 'text-red-600 font-medium' : mono ? 'font-mono text-gray-800' : 'text-gray-800'}`}>
        {value ?? <span className="text-gray-400">—</span>}
      </div>
    </div>
  );
}

function ExpandedEvent({ event }: { event: CloudTrailEvent }) {
  const sev          = classifyEventSeverity(event);
  const showDiff     = sev === 'CRITICAL' || sev === 'HIGH';
  const [tab, setTab] = useState<DetailTab>(showDiff ? 'diff' : 'details');
  const isWrite      = event.readOnly === 'false' || event.readOnly === false as any;

  const tabs: { id: DetailTab; label: string; icon: React.ReactNode }[] = [
    ...(showDiff ? [{ id: 'diff' as DetailTab, label: 'Change Diff', icon: <Diff size={12} /> }] : []),
    { id: 'details', label: 'Details',  icon: <FileText size={12} /> },
    { id: 'raw',     label: 'Raw JSON', icon: <Code2 size={12} />    },
  ];

  const borderColor = sev === 'CRITICAL' ? 'border-red-500' : sev === 'HIGH' ? 'border-orange-400' : 'border-blue-400';

  return (
    <tr>
      <td colSpan={10} className="border-b border-gray-200">
        <div className={`px-6 py-5 bg-white border-l-4 ${borderColor} space-y-4`}>

          {/* Tab bar */}
          <div className="flex items-center gap-1 border-b border-gray-200 pb-2">
            {tabs.map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-t text-xs font-semibold transition-all
                  ${tab === t.id
                    ? 'bg-gray-100 text-gray-900 border border-gray-200 border-b-transparent -mb-px'
                    : 'text-gray-500 hover:text-gray-700'}`}
              >
                {t.icon} {t.label}
              </button>
            ))}
            {/* Quick meta on right */}
            <div className="ml-auto flex items-center gap-2">
              <SeverityBadge severity={sev} />
              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                isWrite ? 'bg-orange-100 text-orange-700' : 'bg-gray-100 text-gray-600'
              }`}>{isWrite ? 'Write' : 'Read'}</span>
              {event.errorCode && (
                <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-red-100 text-red-700">
                  Failed: {event.errorCode}
                </span>
              )}
            </div>
          </div>

          {/* Tab: Change Diff */}
          {tab === 'diff' && (
            <div className="bg-gray-950 rounded-xl p-4">
              <ChangeDiffPanel event={event} />
            </div>
          )}

          {/* Tab: Details */}
          {tab === 'details' && (
            <div className="space-y-4">
              {event.errorMessage && (
                <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
                  <span className="font-semibold">Error: </span>{event.errorMessage}
                </div>
              )}

              <div className="grid grid-cols-3 gap-x-8 gap-y-4 bg-gray-50 border border-gray-200 rounded-lg p-4">
                <DetailField label="Event time"  value={event.eventTime ? new Date(event.eventTime).toLocaleString('en-US', { month:'long',day:'numeric',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short' }) : null} />
                <DetailField label="AWS access key"  value={event.accessKeyId} mono />
                <DetailField label="AWS region"      value={event.awsRegion}   mono />
                <DetailField label="User name"       value={event.username}    mono />
                <DetailField label="Source IP"       value={event.sourceIPAddress} mono />
                <DetailField label="Error code"      value={event.errorCode ?? '—'} error={!!event.errorCode} />
                <DetailField label="Event name"      value={event.eventName}   mono />
                <DetailField label="Event ID"        value={event.eventId}     mono />
                <DetailField label="Read-only"       value={event.readOnly ?? '—'} mono />
                <DetailField label="Event source"    value={event.eventSource} mono />
                <DetailField label="Request ID"      value={event.requestId}   mono />
                <DetailField label="Event type"      value={event.eventType ?? '—'} />
              </div>

              {event.userAgent && (
                <div>
                  <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">User Agent</div>
                  <div className="text-xs font-mono text-gray-600 bg-gray-50 border border-gray-200 rounded px-3 py-2 break-all">{event.userAgent}</div>
                </div>
              )}

              {event.resources.length > 0 && (
                <div>
                  <h4 className="text-sm font-bold text-gray-900 mb-2">Resources</h4>
                  <table className="min-w-full text-sm border border-gray-200 rounded-lg overflow-hidden">
                    <thead className="bg-gray-50">
                      <tr>
                        {['Resource Type','Resource Name'].map(h => (
                          <th key={h} className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-100">
                      {event.resources.map((r, i) => (
                        <tr key={i}>
                          <td className="px-4 py-2 text-xs text-gray-500">{r.type ?? '—'}</td>
                          <td className="px-4 py-2 text-xs font-mono text-gray-800 break-all">{r.name ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {event.userIdentity && (
                <div>
                  <h4 className="text-sm font-bold text-gray-900 mb-2">User Identity</h4>
                  <pre className="bg-gray-900 text-yellow-300 text-xs p-3 rounded-lg overflow-auto max-h-40 font-mono">
                    {JSON.stringify(event.userIdentity, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Tab: Raw JSON */}
          {tab === 'raw' && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-bold text-gray-900 mb-2">Request Parameters</h4>
                <pre className="bg-gray-900 text-green-400 text-xs p-3 rounded-lg overflow-auto max-h-64 font-mono">
                  {event.requestParameters ? JSON.stringify(event.requestParameters, null, 2) : 'null'}
                </pre>
              </div>
              <div>
                <h4 className="text-sm font-bold text-gray-900 mb-2">Response Elements</h4>
                <pre className="bg-gray-900 text-blue-400 text-xs p-3 rounded-lg overflow-auto max-h-64 font-mono">
                  {event.responseElements ? JSON.stringify(event.responseElements, null, 2) : 'null'}
                </pre>
              </div>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}

// ─── Misc table helpers ───────────────────────────────────────────────────────

function formatEventTime(dateStr: string): string {
  return new Date(dateStr).toLocaleString('en-US', {
    month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit',
  });
}

function eventSourceToService(source: string | null): string {
  return source?.replace('.amazonaws.com', '').toUpperCase() ?? '—';
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function CloudTrailLogs() {
  const [accountId,        setAccountId]        = useState('');
  const [region,           setRegion]           = useState('us-east-1');
  const [selectedRange,    setSelectedRange]    = useState(24);
  const [isCustomRange,    setIsCustomRange]    = useState(false);
  const [customStart,      setCustomStart]      = useState('');
  const [customEnd,        setCustomEnd]        = useState('');
  const [readOnly,         setReadOnly]         = useState<'true'|'false'|''>('');
  const [eventNameInput,   setEventNameInput]   = useState('');
  const [usernameInput,    setUsernameInput]    = useState('');
  const [eventSourceInput, setEventSourceInput] = useState('');
  const [sevFilter,        setSevFilter]        = useState('');
  const [appliedFilters,   setAppliedFilters]   = useState({ eventName:'', username:'', eventSource:'' });
  const [nextToken,        setNextToken]        = useState<string|null>(null);
  const [tokenHistory,     setTokenHistory]     = useState<string[]>([]);
  const [expandedId,       setExpandedId]       = useState<string|null>(null);
  const [committedStart,   setCommittedStart]   = useState('');
  const [committedEnd,     setCommittedEnd]     = useState('');
  const [isLive,           setIsLive]           = useState(true);   // live by default
  const [lastRefreshed,    setLastRefreshed]    = useState<Date|null>(null);

  const { data: accountsPage } = useQuery({
    queryKey: ['accounts'],
    queryFn:  () => accountsApi.list(),
  });
  // Sort alphabetically by name
  const accounts = useMemo(() =>
    [...(accountsPage?.data ?? [])].sort((a: any, b: any) => a.name.localeCompare(b.name)),
    [accountsPage],
  );

  // Auto-select first account when accounts load and none is selected
  useEffect(() => {
    if (accounts.length > 0 && !accountId) {
      setAccountId((accounts[0] as any).id);
    }
  }, [accounts, accountId]);

  const { data: result, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: [
      'cloudtrail-events', accountId, region,
      isLive ? selectedRange : committedStart,
      isLive ? 'live' : committedEnd,
      appliedFilters, readOnly,
      isLive ? null : nextToken,
    ],
    queryFn: () => {
      const now = new Date();
      const start = isLive
        ? new Date(now.getTime() - selectedRange * 3600_000).toISOString()
        : (committedStart || undefined);
      const end = isLive ? now.toISOString() : (committedEnd || undefined);
      return cloudtrailApi.getEvents({
        accountId,
        region:      region      || undefined,
        startTime:   start,
        endTime:     end,
        maxResults:  50,
        nextToken:   isLive ? undefined : (nextToken ?? undefined),
        eventName:   appliedFilters.eventName   || undefined,
        username:    appliedFilters.username    || undefined,
        eventSource: appliedFilters.eventSource || undefined,
        readOnly:    readOnly || undefined,
      });
    },
    enabled: !!accountId && (isLive || !!committedStart),
    staleTime:                  isLive ? 0 : 30_000,
    refetchInterval:            isLive ? 30_000 : false,
    refetchIntervalInBackground: true,   // keep polling even when tab is inactive
  });

  // Track last successful refresh time
  useEffect(() => {
    if (result) setLastRefreshed(new Date());
  }, [result]);

  const allEvents: CloudTrailEvent[] = result?.data ?? [];

  const events = useMemo(() =>
    sevFilter
      ? allEvents.filter(e => classifyEventSeverity(e) === sevFilter)
      : allEvents,
    [allEvents, sevFilter],
  );

  // Commit a time window and reset pagination
  const commit = useCallback((hours: number, customS?: string, customE?: string) => {
    const now = new Date();
    const s = customS ? new Date(customS).toISOString() : new Date(now.getTime() - hours * 3600_000).toISOString();
    const e = customE ? new Date(customE).toISOString() : now.toISOString();
    setCommittedStart(s);
    setCommittedEnd(e);
    setNextToken(null);
    setTokenHistory([]);
    setExpandedId(null);
  }, []);

  const handleAccountChange = (id: string) => {
    setAccountId(id);
    setNextToken(null);
    setTokenHistory([]);
    if (id) {
      if (isCustomRange && customStart && customEnd) commit(0, customStart, customEnd);
      else commit(selectedRange);
    } else {
      setCommittedStart('');
      setCommittedEnd('');
    }
  };

  const handleRegionChange = (r: string) => {
    setRegion(r);
    setNextToken(null);
    setTokenHistory([]);
    if (accountId) {
      if (isCustomRange && customStart && customEnd) commit(0, customStart, customEnd);
      else commit(selectedRange);
    }
  };

  const handleRangeClick = (hours: number) => {
    setIsCustomRange(false);
    setSelectedRange(hours);
    if (accountId && !isLive) commit(hours);
  };

  const toggleLive = () => {
    if (!accountId) return;
    if (isLive) {
      // Turning off: commit the current preset range so the query stays active
      setIsLive(false);
      setIsCustomRange(false);
      commit(selectedRange);
    } else {
      // Turning on: switch to preset range, reset pagination
      setIsLive(true);
      setIsCustomRange(false);
      setNextToken(null);
      setTokenHistory([]);
      setExpandedId(null);
    }
  };

  const handleCustomApply = () => {
    if (!customStart || !customEnd || !accountId) return;
    commit(0, customStart, customEnd);
  };

  const handleReadOnlyChange = (v: string) => {
    setReadOnly(v as 'true' | 'false' | '');
    setNextToken(null);
    setTokenHistory([]);
  };

  const applyTextFilters = useCallback(() => {
    setAppliedFilters({
      eventName:   eventNameInput.trim(),
      username:    usernameInput.trim(),
      eventSource: eventSourceInput.trim(),
    });
    setNextToken(null);
    setTokenHistory([]);
  }, [eventNameInput, usernameInput, eventSourceInput]);

  const handleNext = () => {
    if (result?.nextToken) {
      setTokenHistory(h => [...h, nextToken ?? '']);
      setNextToken(result.nextToken);
    }
  };

  const handlePrev = () => {
    const h = [...tokenHistory];
    setNextToken(h.pop() ?? null);
    setTokenHistory(h);
  };

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">CloudTrail Logs</h2>
          <p className="text-sm text-gray-500 mt-1">AWS API audit trail · real-time monitoring · severity classification</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Live indicator / pause toggle */}
          {isLive ? (
            /* LIVE pill — always visible once account exists, click to pause */
            <button
              onClick={toggleLive}
              title="Live monitoring active — click to pause"
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-semibold bg-green-600 text-white border border-green-600 shadow-sm hover:bg-green-700 transition-all"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-200 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-white" />
              </span>
              LIVE
              {lastRefreshed && (
                <span className="text-green-200 font-normal text-xs">
                  · {lastRefreshed.toLocaleTimeString()}
                </span>
              )}
            </button>
          ) : (
            /* Paused — click to resume */
            <button
              onClick={toggleLive}
              disabled={!accountId}
              title="Live monitoring paused — click to resume"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-semibold bg-gray-100 text-gray-500 border border-gray-300 hover:bg-green-50 hover:border-green-400 hover:text-green-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Activity size={14} />
              Paused
            </button>
          )}
          {/* Manual refresh when paused */}
          {!isLive && accountId && committedStart && (
            <Button
              variant="secondary" size="sm"
              leftIcon={<RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />}
              onClick={() => refetch()} disabled={isFetching}
            >
              Refresh
            </Button>
          )}
        </div>
      </div>

      {/* Severity Dashboard — always at top */}
      <Card>
        <div className="flex items-center gap-2 mb-4">
          <ShieldCheck size={16} className="text-indigo-500" />
          <h3 className="font-semibold text-gray-900 text-sm">Severity Dashboard</h3>
          <span className="text-xs text-gray-400 ml-1">— click a card to filter events</span>
          {sevFilter && (
            <button onClick={() => setSevFilter('')}
              className="ml-auto text-xs text-indigo-600 hover:underline flex items-center gap-1">
              <XCircle size={11} /> Clear filter
            </button>
          )}
        </div>
        {allEvents.length > 0 ? (
          <SeverityDashboard events={allEvents} activeSeverity={sevFilter} onFilter={setSevFilter} />
        ) : (
          <div className="text-center py-6 text-gray-400 text-sm">
            {!accountId
              ? 'Loading accounts…'
              : isLoading
              ? 'Loading events…'
              : 'No events found in the selected time range'}
          </div>
        )}
      </Card>

      {/* Controls */}
      <Card>
        {/* AWS Account + Region */}
        <div className="grid grid-cols-3 gap-4 mb-4">
          <div className="col-span-2">
            <label className="block text-sm font-medium text-gray-700 mb-1">AWS Account</label>
            <select
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={accountId}
              onChange={e => handleAccountChange(e.target.value)}
            >
              <option value="">— Select an account —</option>
              {accounts.map((a: any) => (
                <option key={a.id} value={a.id}>{a.name}  ·  {a.awsAccountId}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Region</label>
            <select
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={region}
              onChange={e => handleRegionChange(e.target.value)}
            >
              {AWS_REGIONS.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
        </div>

        {/* Time Range */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            <Clock size={14} className="inline mr-1" />Time Range
            <span className="ml-2 text-xs font-normal text-gray-400">
              {isLive ? '· refreshes every 30s' : '· paused'}
            </span>
          </label>
          <div className="flex flex-wrap gap-2 items-center">
            {TIME_RANGES.map(r => (
              <button
                key={r.hours}
                onClick={() => handleRangeClick(r.hours)}
                className={`px-4 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                  !isCustomRange && selectedRange === r.hours
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400 hover:text-blue-600'
                }`}
              >
                {r.label}
              </button>
            ))}
            {/* Custom range disabled in live mode */}
            <button
              onClick={() => { if (!isLive) setIsCustomRange(true); }}
              disabled={isLive}
              title={isLive ? 'Disable Live mode to use a custom date range' : undefined}
              className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-sm font-medium border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                isCustomRange
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400 hover:text-blue-600'
              }`}
            >
              <Calendar size={13} />Custom
            </button>
          </div>

          {/* Custom date/time pickers */}
          {isCustomRange && !isLive && (
            <div className="mt-3 flex flex-wrap gap-3 items-end p-3 bg-gray-50 border border-gray-200 rounded-lg">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Start</label>
                <input
                  type="datetime-local"
                  className="rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
                  value={customStart}
                  onChange={e => setCustomStart(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">End</label>
                <input
                  type="datetime-local"
                  className="rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
                  value={customEnd}
                  onChange={e => setCustomEnd(e.target.value)}
                />
              </div>
              <Button
                variant="primary"
                size="sm"
                onClick={handleCustomApply}
                disabled={!customStart || !customEnd || !accountId}
              >
                Apply Range
              </Button>
            </div>
          )}
        </div>

        {/* Filters row */}
        <div className="grid grid-cols-5 gap-3">
          <Select value={readOnly}  onChange={e => handleReadOnlyChange(e.target.value)} options={READ_ONLY_OPTIONS} />
          <Select value={sevFilter} onChange={e => setSevFilter(e.target.value)}         options={SEV_FILTER_OPTIONS} />
          <Input placeholder="Event name (e.g. RunInstances)"
            value={eventNameInput}   onChange={e => setEventNameInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && applyTextFilters()} />
          <Input placeholder="Username / IAM role"
            value={usernameInput}    onChange={e => setUsernameInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && applyTextFilters()} />
          <Input placeholder="Event source (e.g. iam)"
            value={eventSourceInput} onChange={e => setEventSourceInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && applyTextFilters()} />
        </div>
      </Card>

      {/* Results table */}
      {accountId && (isLive || !!committedStart) && (
        <Card padding={false}>
          {/* Table toolbar */}
          <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
            <div className="flex items-center gap-3">
              {/* Live indicator */}
              {isLive && (
                <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-green-50 border border-green-200">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
                  </span>
                  <span className="text-xs font-bold text-green-700">LIVE</span>
                  {lastRefreshed && (
                    <span className="text-xs text-green-500">
                      · updated {lastRefreshed.toLocaleTimeString()}
                    </span>
                  )}
                </div>
              )}
              <span className="text-sm text-gray-600 font-medium">
                {isLoading ? 'Loading…' : `${events.length} events${sevFilter ? ` (${sevFilter})` : ''}`}
              </span>
              {result && (
                <span className="text-xs text-gray-400">
                  {new Date(result.startTime).toLocaleString()} → {new Date(result.endTime).toLocaleString()}
                  {result.region ? ` · ${result.region}` : ' · All Regions'}
                </span>
              )}
            </div>
            <div className="flex gap-2">
              {/* Pagination disabled in live mode */}
              {!isLive && (
                <>
                  <Button variant="ghost" size="sm" disabled={tokenHistory.length === 0} onClick={handlePrev}>← Prev</Button>
                  <Button variant="ghost" size="sm" disabled={!result?.nextToken}        onClick={handleNext}>Next →</Button>
                </>
              )}
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="p-6 flex items-start gap-3 text-red-700 bg-red-50">
              <AlertCircle size={18} className="shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-sm">Failed to load CloudTrail events</p>
                <p className="text-sm mt-1">{(error as Error).message}</p>
                <p className="text-xs text-red-500 mt-2">Ensure IAM has <code>cloudtrail:LookupEvents</code> permission.</p>
              </div>
            </div>
          )}

          {/* Loading */}
          {isLoading && !error && (
            <div className="p-6 space-y-3">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="h-8 bg-gray-100 rounded animate-pulse" />
              ))}
            </div>
          )}

          {/* Table */}
          {!isLoading && !error && (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="w-8 px-3 py-3" />
                    {['Severity','Time','Event Name','Service','Type','User / Role','Source IP','Resources','Status'].map(h => (
                      <th key={h} className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="px-4 py-12 text-center text-gray-500 text-sm">
                        No events found for the selected filters.
                      </td>
                    </tr>
                  ) : events.map((event, idx) => {
                    const rowKey  = event.eventId ?? `evt-${idx}`;
                    const sev     = classifyEventSeverity(event);
                    const sevCfg  = SEV_CONFIG[sev];
                    const isExp   = expandedId === rowKey;
                    const rowBg   = event.errorCode ? 'bg-red-50 hover:bg-red-100' :
                                    sev === 'CRITICAL' ? 'bg-red-50/40 hover:bg-red-50' :
                                    sev === 'HIGH'     ? 'bg-orange-50/40 hover:bg-orange-50' :
                                    'hover:bg-gray-50';
                    return (
                      <React.Fragment key={rowKey}>
                        <tr className={`cursor-pointer ${rowBg}`}
                          onClick={() => setExpandedId(isExp ? null : rowKey)}>
                          <td className="px-3 py-3 text-gray-400">
                            {isExp ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                          </td>
                          <td className="px-3 py-3">
                            <SeverityBadge severity={sev} />
                          </td>
                          <td className="px-3 py-3 text-xs text-gray-500 whitespace-nowrap">
                            {formatEventTime(event.eventTime)}
                          </td>
                          <td className="px-3 py-3 text-sm font-medium text-gray-900">
                            <div className="flex items-center gap-1">
                              {sevCfg.icon}
                              {event.eventName}
                            </div>
                            {event.errorCode && (
                              <span className="ml-1 text-xs px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-mono">
                                {event.errorCode}
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-3 text-xs text-gray-600 font-mono">
                            {eventSourceToService(event.eventSource)}
                          </td>
                          <td className="px-3 py-3">
                            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                              event.readOnly === 'true'
                                ? 'bg-gray-100 text-gray-600'
                                : 'bg-orange-100 text-orange-700'
                            }`}>
                              {event.readOnly === 'true' ? 'Read' : 'Write'}
                            </span>
                          </td>
                          <td className="px-3 py-3 text-sm text-gray-600">
                            {event.username ?? <span className="text-gray-400 italic text-xs">AWS Service</span>}
                          </td>
                          <td className="px-3 py-3 text-xs font-mono text-gray-500">
                            {event.sourceIPAddress ?? '—'}
                          </td>
                          <td className="px-3 py-3 text-xs text-gray-500 max-w-xs">
                            {event.resources.length > 0 ? (
                              <div className="space-y-0.5">
                                {event.resources.slice(0, 2).map((r, i) => (
                                  <div key={i} className="truncate font-mono">{r.name ?? r.type ?? '—'}</div>
                                ))}
                                {event.resources.length > 2 && (
                                  <span className="text-gray-400">+{event.resources.length - 2} more</span>
                                )}
                              </div>
                            ) : <span className="text-gray-300">—</span>}
                          </td>
                          <td className="px-3 py-3">
                            {event.errorCode
                              ? <span className="flex items-center gap-1 text-xs text-red-600 font-medium"><XCircle size={11} />Failed</span>
                              : <span className="flex items-center gap-1 text-xs text-green-600 font-medium"><CheckCircle size={11} />Success</span>}
                          </td>
                        </tr>
                        {isExp && <ExpandedEvent event={event} />}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Bottom pagination (hidden in live mode) */}
          {!isLoading && !isLive && events.length > 0 && (
            <div className="px-4 py-3 border-t border-gray-200 flex items-center justify-between">
              <span className="text-xs text-gray-500">
                {events.length} events · page {tokenHistory.length + 1}
              </span>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" disabled={tokenHistory.length === 0} onClick={handlePrev}>← Previous</Button>
                <Button variant="ghost" size="sm" disabled={!result?.nextToken}        onClick={handleNext}>Next →</Button>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
