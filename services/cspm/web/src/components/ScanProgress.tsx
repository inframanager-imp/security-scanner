import { useScanProgress } from '../hooks/useScanProgress';
import type { ScanStatus } from '../types';
import clsx from 'clsx';

interface ScanProgressProps {
  scanId: string;
  initialStatus: ScanStatus;
  onComplete?: () => void;
}

export function ScanProgress({ scanId, initialStatus, onComplete }: ScanProgressProps) {
  const { status, progress, message, error } = useScanProgress(scanId, initialStatus);

  const effectiveStatus = status ?? initialStatus;

  if (effectiveStatus === 'COMPLETED' || effectiveStatus === 'FAILED' || effectiveStatus === 'CANCELLED') {
    if (effectiveStatus === 'COMPLETED') {
      onComplete?.();
    }
    return null;
  }

  const isRunning = effectiveStatus === 'RUNNING';
  const isQueued = effectiveStatus === 'QUEUED';

  return (
    <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <div
            className={clsx(
              'h-2.5 w-2.5 rounded-full',
              isRunning && 'bg-blue-500 animate-pulse',
              isQueued && 'bg-gray-400',
            )}
          />
          <span className="text-sm font-medium text-blue-800">
            {isQueued ? 'Scan Queued' : 'Scan Running'}
          </span>
        </div>
        <span className="text-sm text-blue-600 font-medium">{Math.round(progress)}%</span>
      </div>

      <div className="w-full bg-blue-200 rounded-full h-2 mb-2">
        <div
          className={clsx(
            'h-2 rounded-full transition-all duration-500',
            isRunning ? 'bg-blue-500' : 'bg-gray-400',
          )}
          style={{ width: `${progress}%` }}
        />
      </div>

      {message && (
        <p className="text-xs text-blue-700 mt-1">{message}</p>
      )}

      {error && (
        <p className="text-xs text-red-600 mt-1">{error}</p>
      )}
    </div>
  );
}
