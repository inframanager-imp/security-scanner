import { api } from './client';

export interface CloudTrailEvent {
  eventId: string | null;
  eventName: string | null;
  eventTime: string;
  eventSource: string | null;
  username: string | null;
  accessKeyId: string | null;
  readOnly: string | null;
  sourceIPAddress: string | null;
  userAgent: string | null;
  awsRegion: string;
  requestId: string | null;
  eventType: string | null;
  managementEvent: boolean | null;
  recipientAccountId: string | null;
  userIdentity: Record<string, unknown> | null;
  errorCode: string | null;
  errorMessage: string | null;
  requestParameters: Record<string, unknown> | null;
  responseElements: Record<string, unknown> | null;
  resources: { type: string | null; name: string | null }[];
}

// client.ts merges { data, meta } into a flat object
export interface CloudTrailEventsResult {
  data: CloudTrailEvent[];
  count: number;
  nextToken: string | null;
  startTime: string;
  endTime: string;
  region: string;
}

export interface CloudTrailTrail {
  name: string | null;
  arn: string | null;
  homeRegion: string | null;
  isMultiRegion: boolean | null;
  s3Bucket: string | null;
}

export interface CloudTrailFilter {
  accountId: string;
  region?: string;
  startTime?: string;
  endTime?: string;
  maxResults?: number;
  nextToken?: string;
  eventName?: string;
  username?: string;
  readOnly?: 'true' | 'false' | '';
  eventSource?: string;
}

export const cloudtrailApi = {
  getEvents: (filter: CloudTrailFilter) => {
    const params = new URLSearchParams();
    params.set('accountId', filter.accountId);
    if (filter.region) params.set('region', filter.region);
    if (filter.startTime) params.set('startTime', filter.startTime);
    if (filter.endTime) params.set('endTime', filter.endTime);
    if (filter.maxResults) params.set('maxResults', String(filter.maxResults));
    if (filter.nextToken) params.set('nextToken', filter.nextToken);
    if (filter.eventName?.trim()) params.set('eventName', filter.eventName.trim());
    if (filter.username?.trim()) params.set('username', filter.username.trim());
    if (filter.readOnly) params.set('readOnly', filter.readOnly);
    if (filter.eventSource?.trim()) params.set('eventSource', filter.eventSource.trim());
    return api.get<CloudTrailEventsResult>(`/cloudtrail/events?${params.toString()}`);
  },

  getTrails: (accountId: string, region = 'us-east-1') =>
    api.get<CloudTrailTrail[]>(
      `/cloudtrail/trails?accountId=${accountId}&region=${encodeURIComponent(region)}`,
    ),
};
