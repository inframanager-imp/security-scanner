import type { ReactNode } from 'react';
import clsx from 'clsx';
import type { Severity, ScanStatus, FindingStatus } from '../../types';

interface BadgeProps {
  className?: string;
  children: ReactNode;
}

function BaseBadge({ className, children }: BadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold',
        className,
      )}
    >
      {children}
    </span>
  );
}

const severityStyles: Record<Severity, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-white',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-gray-500 text-white',
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <BaseBadge className={clsx(severityStyles[severity], className)}>
      {severity}
    </BaseBadge>
  );
}

const scanStatusStyles: Record<ScanStatus, string> = {
  QUEUED:     'bg-gray-200 text-gray-700',
  RUNNING:    'bg-blue-100 text-blue-700 animate-pulse',
  COMPLETED:  'bg-green-100 text-green-700',
  FAILED:     'bg-red-100 text-red-700',
  CANCELLED:  'bg-gray-200 text-gray-600',
  MONITORING: 'bg-purple-100 text-purple-700',
};

interface ScanStatusBadgeProps {
  status: ScanStatus;
  className?: string;
}

export function ScanStatusBadge({ status, className }: ScanStatusBadgeProps) {
  return (
    <BaseBadge className={clsx(scanStatusStyles[status], className)}>
      {status}
    </BaseBadge>
  );
}

const findingStatusStyles: Record<FindingStatus, string> = {
  OPEN: 'bg-red-100 text-red-700',
  ACKNOWLEDGED: 'bg-yellow-100 text-yellow-700',
  RESOLVED: 'bg-green-100 text-green-700',
  FALSE_POSITIVE: 'bg-gray-100 text-gray-600',
};

interface FindingStatusBadgeProps {
  status: FindingStatus;
  className?: string;
}

export function FindingStatusBadge({ status, className }: FindingStatusBadgeProps) {
  return (
    <BaseBadge className={clsx(findingStatusStyles[status], className)}>
      {status.replace('_', ' ')}
    </BaseBadge>
  );
}
