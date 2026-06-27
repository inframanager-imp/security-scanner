import { Router, Request, Response } from 'express';
import {
  CloudTrailClient,
  LookupEventsCommand,
  DescribeTrailsCommand,
  LookupAttributeKey,
} from '@aws-sdk/client-cloudtrail';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import * as credentialService from '../services/credentialService';

const router = Router();
router.use(authenticate);

/** Build a CloudTrailClient using stored account credentials (handles ASSUME_ROLE too) */
async function getCloudTrailClient(
  accountId: string,
  region: string,
): Promise<CloudTrailClient> {
  const cred = await prisma.awsCredential.findUnique({ where: { accountId } });
  if (!cred) throw new Error('No credentials configured for this account');

  const decrypted = credentialService.decryptCredentials(cred);
  if (!decrypted.accessKeyId || !decrypted.secretAccessKey) {
    throw new Error('Missing access key credentials');
  }

  let credentials: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  } = {
    accessKeyId: decrypted.accessKeyId,
    secretAccessKey: decrypted.secretAccessKey,
  };

  if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
    const stsClient = new STSClient({ region, credentials });
    const assumed = await stsClient.send(
      new AssumeRoleCommand({
        RoleArn: cred.roleArn,
        RoleSessionName: 'cloudtrail-viewer',
        DurationSeconds: 900,
        ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
      }),
    );
    if (!assumed.Credentials) throw new Error('STS AssumeRole returned no credentials');
    credentials = {
      accessKeyId: assumed.Credentials.AccessKeyId!,
      secretAccessKey: assumed.Credentials.SecretAccessKey!,
      sessionToken: assumed.Credentials.SessionToken,
    };
  }

  return new CloudTrailClient({ region, credentials });
}

// GET /api/cloudtrail/trails?accountId=X&region=us-east-1
// Returns configured trails so the UI can show which regions are available
router.get('/trails', async (req: Request, res: Response) => {
  try {
    const { accountId, region = 'us-east-1' } = req.query as Record<string, string>;
    if (!accountId) {
      res.status(400).json({ error: 'accountId is required' });
      return;
    }

    const client = await getCloudTrailClient(accountId, region);
    const result = await client.send(
      new DescribeTrailsCommand({ includeShadowTrails: true }),
    );
    await client.destroy();

    const trails = (result.trailList ?? []).map((t) => ({
      name: t.Name,
      arn: t.TrailARN,
      homeRegion: t.HomeRegion,
      isMultiRegion: t.IsMultiRegionTrail,
      s3Bucket: t.S3BucketName,
    }));

    res.json({ data: trails });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/cloudtrail/events
// Query params:
//   accountId     — required
//   region        — default us-east-1
//   startTime     — ISO string, default now-24h
//   endTime       — ISO string, default now
//   maxResults    — 1-50, default 50
//   nextToken     — pagination token
//   eventName     — filter by event name (single LookupAttribute)
//   username      — filter by IAM username
//   readOnly      — "true" | "false" | "" (all)
//   eventSource   — filter by event source (e.g. iam.amazonaws.com)
router.get('/events', async (req: Request, res: Response) => {
  try {
    const {
      accountId,
      region = 'us-east-1',
      startTime,
      endTime,
      maxResults = '50',
      nextToken,
      eventName,
      username,
      readOnly,
      eventSource,
    } = req.query as Record<string, string>;

    if (!accountId) {
      res.status(400).json({ error: 'accountId is required' });
      return;
    }

    const now = new Date();
    const start = startTime ? new Date(startTime) : new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const end = endTime ? new Date(endTime) : now;
    const max = Math.min(Math.max(parseInt(maxResults) || 50, 1), 50);

    const client = await getCloudTrailClient(accountId, region);

    // LookupEvents only supports ONE LookupAttribute — pick the most selective
    const lookupAttributes: { AttributeKey: LookupAttributeKey; AttributeValue: string }[] = [];

    if (eventName) {
      lookupAttributes.push({
        AttributeKey: LookupAttributeKey.EVENT_NAME,
        AttributeValue: eventName,
      });
    } else if (username) {
      lookupAttributes.push({
        AttributeKey: LookupAttributeKey.USERNAME,
        AttributeValue: username,
      });
    } else if (eventSource) {
      lookupAttributes.push({
        AttributeKey: LookupAttributeKey.EVENT_SOURCE,
        AttributeValue: eventSource,
      });
    } else if (readOnly === 'true' || readOnly === 'false') {
      lookupAttributes.push({
        AttributeKey: LookupAttributeKey.READ_ONLY,
        AttributeValue: readOnly,
      });
    }

    const result = await client.send(
      new LookupEventsCommand({
        StartTime: start,
        EndTime: end,
        MaxResults: max,
        ...(nextToken ? { NextToken: nextToken } : {}),
        ...(lookupAttributes.length > 0 ? { LookupAttributes: lookupAttributes } : {}),
      }),
    );
    await client.destroy();

    let events = (result.Events ?? []).map((e) => {
      let parsedEvent: Record<string, unknown> = {};
      try {
        parsedEvent = e.CloudTrailEvent ? JSON.parse(e.CloudTrailEvent) : {};
      } catch {
        // ignore parse errors
      }

      // userIdentity may contain more detail about who made the call
      const userIdentity = (parsedEvent.userIdentity ?? {}) as Record<string, unknown>;

      return {
        eventId: e.EventId ?? (parsedEvent.eventID as string) ?? null,
        eventName: e.EventName ?? (parsedEvent.eventName as string) ?? null,
        eventTime: e.EventTime ?? null,
        eventSource: e.EventSource ?? (parsedEvent.eventSource as string) ?? null,
        username: e.Username ?? (userIdentity.userName as string) ?? (userIdentity.sessionContext as Record<string,unknown>)?.sessionIssuer?.toString() ?? null,
        accessKeyId: e.AccessKeyId ?? (userIdentity.accessKeyId as string) ?? null,
        // readOnly: AWS SDK returns string "true"/"false"; parsed JSON has boolean
        readOnly: e.ReadOnly ?? String(parsedEvent.readOnly ?? ''),
        sourceIPAddress: (parsedEvent.sourceIPAddress as string) ?? null,
        userAgent: (parsedEvent.userAgent as string) ?? null,
        awsRegion: (parsedEvent.awsRegion as string) ?? region,
        requestId: (parsedEvent.requestID as string) ?? null,
        eventType: (parsedEvent.eventType as string) ?? null,
        managementEvent: (parsedEvent.managementEvent as boolean) ?? null,
        recipientAccountId: (parsedEvent.recipientAccountId as string) ?? null,
        userIdentity: Object.keys(userIdentity).length > 0 ? userIdentity : null,
        requestParameters: parsedEvent.requestParameters ?? null,
        responseElements: parsedEvent.responseElements ?? null,
        errorCode: (parsedEvent.errorCode as string) ?? null,
        errorMessage: (parsedEvent.errorMessage as string) ?? null,
        resources: (e.Resources ?? []).map((r) => ({
          type: r.ResourceType,
          name: r.ResourceName,
        })),
      };
    });

    // Client-side secondary filters (for fields not used as LookupAttribute)
    if (eventName && username) {
      events = events.filter((e) =>
        e.username?.toLowerCase().includes(username.toLowerCase()),
      );
    }
    if (eventSource && (eventName || username)) {
      events = events.filter((e) =>
        e.eventSource?.toLowerCase().includes(eventSource.toLowerCase()),
      );
    }
    if (readOnly !== undefined && readOnly !== '' && !lookupAttributes.find((a) => a.AttributeKey === LookupAttributeKey.READ_ONLY)) {
      events = events.filter((e) => String(e.readOnly) === readOnly);
    }

    res.json({
      data: events,
      meta: {
        count: events.length,
        nextToken: result.NextToken ?? null,
        startTime: start.toISOString(),
        endTime: end.toISOString(),
        region,
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
