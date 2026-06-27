import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { useQueryClient } from '@tanstack/react-query';

export interface ConfigChangesPayload {
  provider:      string;
  targetId:      string;
  count:         number;
  changes:       unknown[];
  syncedAt:      string;
}

export interface ConfigSyncHeartbeat {
  provider:      string;
  targetId:      string;
  changesStored: number;
  syncedAt:      string;
}

interface UseConfigSyncOptions {
  provider?: string;
  targetId?: string;
  onNewChanges?: (payload: ConfigChangesPayload) => void;
}

interface UseConfigSyncResult {
  lastSyncedAt:      string | null;
  lastChangesStored: number | null;
  connected:         boolean;
  secondsSinceSync:  number | null;
}

let sharedSocket: Socket | null = null;

function getSocket(): Socket {
  if (!sharedSocket) {
    sharedSocket = io('/', {
      path: '/socket.io',
      transports: ['websocket', 'polling'],
    });
  }
  return sharedSocket;
}

export function useConfigSync({
  provider,
  targetId,
  onNewChanges,
}: UseConfigSyncOptions = {}): UseConfigSyncResult {
  const qc = useQueryClient();
  const [lastSyncedAt,      setLastSyncedAt]      = useState<string | null>(null);
  const [lastChangesStored, setLastChangesStored]  = useState<number | null>(null);
  const [connected,         setConnected]          = useState(false);
  const [secondsSince,      setSecondsSince]       = useState<number | null>(null);

  const cbNewChanges = useRef(onNewChanges);
  cbNewChanges.current = onNewChanges;

  // Tick every second to keep secondsSinceSync fresh
  useEffect(() => {
    const timer = setInterval(() => {
      setLastSyncedAt(prev => {
        if (!prev) return prev;
        setSecondsSince(Math.round((Date.now() - new Date(prev).getTime()) / 1000));
        return prev;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!provider || !targetId) return;

    const s = getSocket();

    const onConnect    = () => setConnected(true);
    const onDisconnect = () => setConnected(false);
    setConnected(s.connected);

    s.on('connect',    onConnect);
    s.on('disconnect', onDisconnect);

    // Join the per-target room
    s.emit('config-changes:subscribe', { provider, targetId });

    const handleChanges = (payload: ConfigChangesPayload) => {
      if (payload.provider !== provider || payload.targetId !== targetId) return;
      setLastSyncedAt(payload.syncedAt);
      setLastChangesStored(payload.count);
      setSecondsSince(0);
      cbNewChanges.current?.(payload);

      // Invalidate react-query cache so the changes list refreshes automatically
      void qc.invalidateQueries({ queryKey: ['config-changes'] });
      void qc.invalidateQueries({ queryKey: ['config-runs', provider, targetId] });
    };

    const handleHeartbeat = (payload: ConfigSyncHeartbeat) => {
      if (payload.provider !== provider || payload.targetId !== targetId) return;
      setLastSyncedAt(payload.syncedAt);
      setLastChangesStored(payload.changesStored);
      setSecondsSince(0);

      // Always refresh the runs query so "Last synced" stays current
      void qc.invalidateQueries({ queryKey: ['config-runs', provider, targetId] });
    };

    s.on('config:changes',   handleChanges);
    s.on('config:heartbeat', handleHeartbeat);

    return () => {
      s.emit('config-changes:unsubscribe', { provider, targetId });
      s.off('connect',    onConnect);
      s.off('disconnect', onDisconnect);
      s.off('config:changes',   handleChanges);
      s.off('config:heartbeat', handleHeartbeat);
    };
  }, [provider, targetId, qc]);

  return { lastSyncedAt, lastChangesStored, connected, secondsSinceSync: secondsSince };
}
