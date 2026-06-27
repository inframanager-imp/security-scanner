import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';

export interface ThreatDetectedPayload {
  accountId: string;
  finding?: {
    title:            string;
    severity:         string;
    description:      string;
    threatCategory?:  string;
    actor?:           string;
    sourceIP?:        string;
    eventTime?:       string;
    affectedResource?: string;
  };
  count?:           number;
  highestSeverity?: string;
  detectedAt:       string;
}

export interface HeartbeatPayload {
  accountId:  string;
  checkedAt:  string;
  newThreats: number;
}

interface UseThreatMonitorOptions {
  /** Subscribe to a specific account's threats room */
  accountId?: string;
  /** Subscribe to the global 'all' room (receives summary events from every account) */
  all?: boolean;
  onThreatDetected?: (payload: ThreatDetectedPayload) => void;
  onHeartbeat?:      (payload: HeartbeatPayload)      => void;
}

interface UseThreatMonitorResult {
  lastHeartbeat:  HeartbeatPayload | null;
  lastThreat:     ThreatDetectedPayload | null;
  /** Seconds since the last heartbeat (updated every second) */
  secondsSinceCheck: number | null;
  connected: boolean;
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

export function useThreatMonitor({
  accountId,
  all = false,
  onThreatDetected,
  onHeartbeat,
}: UseThreatMonitorOptions = {}): UseThreatMonitorResult {
  const [lastHeartbeat,  setLastHeartbeat]  = useState<HeartbeatPayload | null>(null);
  const [lastThreat,     setLastThreat]     = useState<ThreatDetectedPayload | null>(null);
  const [connected,      setConnected]      = useState(false);
  const [secondsSince,   setSecondsSince]   = useState<number | null>(null);

  const cbThreat     = useRef(onThreatDetected);
  const cbHeartbeat  = useRef(onHeartbeat);
  cbThreat.current   = onThreatDetected;
  cbHeartbeat.current = onHeartbeat;

  // Tick every second to update secondsSinceCheck
  useEffect(() => {
    const timer = setInterval(() => {
      setLastHeartbeat(prev => {
        if (!prev) return prev;
        const secs = Math.round((Date.now() - new Date(prev.checkedAt).getTime()) / 1000);
        setSecondsSince(secs);
        return prev;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!accountId && !all) return;

    const s = getSocket();

    const onConnect = () => setConnected(true);
    const onDisconnect = () => setConnected(false);
    setConnected(s.connected);

    s.on('connect',    onConnect);
    s.on('disconnect', onDisconnect);

    // Subscribe to rooms
    if (accountId) s.emit('threats:subscribe', { accountId });
    if (all)       s.emit('threats:subscribe:all');

    const handleThreat = (payload: ThreatDetectedPayload) => {
      setLastThreat(payload);
      cbThreat.current?.(payload);
    };

    const handleHeartbeat = (payload: HeartbeatPayload) => {
      // Only update if relevant to our account (or we're watching all)
      if (!accountId || payload.accountId === accountId) {
        setLastHeartbeat(payload);
        const secs = Math.round((Date.now() - new Date(payload.checkedAt).getTime()) / 1000);
        setSecondsSince(secs);
        cbHeartbeat.current?.(payload);
      }
    };

    s.on('threat:detected',  handleThreat);
    s.on('threat:heartbeat', handleHeartbeat);

    return () => {
      if (accountId) s.emit('threats:unsubscribe', { accountId });
      if (all)       s.emit('threats:unsubscribe:all');
      s.off('connect',    onConnect);
      s.off('disconnect', onDisconnect);
      s.off('threat:detected',  handleThreat);
      s.off('threat:heartbeat', handleHeartbeat);
    };
  }, [accountId, all]);

  return {
    lastHeartbeat,
    lastThreat,
    secondsSinceCheck: secondsSince,
    connected,
  };
}
