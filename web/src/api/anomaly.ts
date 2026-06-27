import { api } from './client';

export type AnomalyType =
  | 'FREQUENCY'
  | 'GEOGRAPHIC'
  | 'TEMPORAL'
  | 'ACCESS_DENIED'
  | 'IMPOSSIBLE_TRAVEL'
  | 'RARE_EVENT'
  | 'LATERAL_MOVEMENT'
  | 'DATA_EXFIL';

export type AnomalySeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AnomalyStatus   = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface AnomalyEvent {
  id:              string;
  provider:        string;
  accountId:       string;
  actorId:         string;
  anomalyType:     AnomalyType;
  severity:        AnomalySeverity;
  score:           number;
  description:     string;
  detail:          Record<string, unknown>;
  sourceIp:        string | null;
  country:         string | null;
  eventName:       string | null;
  relatedEventIds: string[];
  status:          AnomalyStatus;
  resolvedAt:      string | null;
  notes:           string | null;
  detectedAt:      string;
  createdAt:       string;
  updatedAt:       string;
}

export interface AnomalySummary {
  byType:     Record<AnomalyType, number>;
  bySeverity: Record<AnomalySeverity, number>;
  byStatus:   Record<AnomalyStatus, number>;
  trend:      Array<{ day: string; count: number }>;
  total:      number;
}

export interface BaselineStats {
  actorId:        string;
  metricKey:      string;
  ewmaMean:       number;
  ewmaStddev:     number;
  sampleCount:    number;
  lastUpdated:    string;
  knownIpCount:   number;
  knownCountries: string[];
}

export interface AnomalyActor {
  actorId:      string;
  anomalyCount: number;
  maxScore:     number | null;
  lastSeen:     string | null;
}

export const anomalyApi = {
  // Events
  listEvents: (params?: {
    provider?: string; accountId?: string; type?: AnomalyType;
    severity?: AnomalySeverity; status?: AnomalyStatus; limit?: number; offset?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.provider)  qs.set('provider',  params.provider);
    if (params?.accountId) qs.set('accountId', params.accountId);
    if (params?.type)      qs.set('type',       params.type);
    if (params?.severity)  qs.set('severity',   params.severity);
    if (params?.status)    qs.set('status',     params.status);
    if (params?.limit)     qs.set('limit',      String(params.limit));
    if (params?.offset)    qs.set('offset',     String(params.offset));
    return api.get<{ data: AnomalyEvent[]; total: number }>(`/anomaly/events?${qs}`);
  },

  getEvent: (id: string) =>
    api.get<AnomalyEvent>(`/anomaly/events/${id}`),

  updateEvent: (id: string, data: { status?: AnomalyStatus; notes?: string }) =>
    api.patch<AnomalyEvent>(`/anomaly/events/${id}`, data),

  // Summary
  getSummary: (params?: { provider?: string; accountId?: string; days?: number }) => {
    const qs = new URLSearchParams();
    if (params?.provider)  qs.set('provider',  params.provider);
    if (params?.accountId) qs.set('accountId', params.accountId);
    if (params?.days)      qs.set('days',      String(params.days));
    return api.get<AnomalySummary>(`/anomaly/summary?${qs}`);
  },

  // Baselines
  getBaselines: (provider: string, accountId: string, actorId?: string) => {
    const qs = new URLSearchParams({ provider, accountId });
    if (actorId) qs.set('actorId', actorId);
    return api.get<BaselineStats[]>(`/anomaly/baselines?${qs}`);
  },

  resetBaselines: (provider: string, accountId: string, actorId?: string) => {
    const qs = new URLSearchParams({ provider, accountId });
    if (actorId) qs.set('actorId', actorId);
    return api.delete<{ deleted: number }>(`/anomaly/baselines?${qs}`);
  },

  seedBaselines: (provider: string, accountId: string, lookbackDays = 30) =>
    api.post<{ message: string }>('/anomaly/baselines/seed', { provider, accountId, lookbackDays }),

  // Actors
  getActors: (params?: { provider?: string; accountId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.provider)  qs.set('provider',  params.provider);
    if (params?.accountId) qs.set('accountId', params.accountId);
    return api.get<AnomalyActor[]>(`/anomaly/actors?${qs}`);
  },
};
