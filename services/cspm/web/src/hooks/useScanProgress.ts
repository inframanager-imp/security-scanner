import { useEffect, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import type { ScanStatus } from '../types';

interface ScanProgressData {
  status: ScanStatus;
  progress: number;
  message: string;
  service?: string;
  region?: string;
  error?: string;
}

interface UseScanProgressResult {
  status: ScanStatus | null;
  progress: number;
  message: string;
  error: string | null;
}

let socket: Socket | null = null;

function getSocket(): Socket {
  if (!socket) {
    socket = io('/', {
      path: '/socket.io',
      transports: ['websocket', 'polling'],
    });
  }
  return socket;
}

export function useScanProgress(
  scanId: string | null,
  initialStatus: ScanStatus | null = null,
): UseScanProgressResult {
  const [status, setStatus] = useState<ScanStatus | null>(initialStatus);
  const [progress, setProgress] = useState(0);
  const [message, setMessage] = useState('');
  const [error, setError] = useState<string | null>(null);

  const isActive =
    scanId !== null &&
    (initialStatus === 'QUEUED' || initialStatus === 'RUNNING');

  useEffect(() => {
    if (!isActive || !scanId) return;

    const s = getSocket();

    // Join the scan room
    s.emit('scan:join', scanId);

    const onProgress = (data: ScanProgressData) => {
      setStatus(data.status);
      setProgress(data.progress ?? 0);
      setMessage(data.message ?? '');
    };

    const onCompleted = (data: ScanProgressData) => {
      setStatus('COMPLETED');
      setProgress(100);
      setMessage(data.message ?? 'Scan completed');
    };

    const onFailed = (data: ScanProgressData) => {
      setStatus('FAILED');
      setError(data.error ?? 'Scan failed');
      setMessage(data.message ?? 'Scan failed');
    };

    s.on(`scan:progress:${scanId}`, onProgress);
    s.on(`scan:completed:${scanId}`, onCompleted);
    s.on(`scan:failed:${scanId}`, onFailed);

    // Also listen for generic events
    s.on('scan:progress', onProgress);
    s.on('scan:completed', onCompleted);
    s.on('scan:failed', onFailed);

    return () => {
      s.emit('scan:leave', scanId);
      s.off(`scan:progress:${scanId}`, onProgress);
      s.off(`scan:completed:${scanId}`, onCompleted);
      s.off(`scan:failed:${scanId}`, onFailed);
      s.off('scan:progress', onProgress);
      s.off('scan:completed', onCompleted);
      s.off('scan:failed', onFailed);
    };
  }, [scanId, isActive]);

  return { status, progress, message, error };
}
