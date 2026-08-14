import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import {
  CloudTrailClient,
  LookupEventsCommand,
  DescribeTrailsCommand,
} from '@aws-sdk/client-cloudtrail';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockCredentialFindUnique = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    awsCredential: {
      findUnique: mockCredentialFindUnique,
    },
  },
}));

jest.mock('../../../src/services/credentialService', () => ({
  decryptCredentials: jest.fn(() => ({
    accessKeyId: 'AKIAFAKE',
    secretAccessKey: 'fake-secret',
  })),
}));

const ctMock = mockClient(CloudTrailClient);
const stsMock = mockClient(STSClient);

import router from '../../../src/routes/cloudtrail';

describe('cloudtrail routes', () => {
  let server: TestServer;

  beforeAll(async () => {
    const app = buildTestApp('/api/cloudtrail', router);
    server = await TestServer.start(app);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    ctMock.reset();
    stsMock.reset();
  });

  describe('GET /trails', () => {
    it('returns 400 when accountId is missing', async () => {
      const res = await server.get('/api/cloudtrail/trails', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('accountId is required');
    });

    it('returns 500 with the error message when no credentials are configured', async () => {
      mockCredentialFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/cloudtrail/trails?accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('No credentials configured for this account');
    });

    it('returns mapped trail list for a direct-credential account', async () => {
      mockCredentialFindUnique.mockResolvedValueOnce({ authMethod: 'ACCESS_KEY' });
      ctMock.on(DescribeTrailsCommand).resolves({
        trailList: [
          { Name: 'trail-1', TrailARN: 'arn:aws:cloudtrail:...', HomeRegion: 'us-east-1', IsMultiRegionTrail: true, S3BucketName: 'bucket-1' },
        ],
      });

      const res = await server.get('/api/cloudtrail/trails?accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0]).toEqual({
        name: 'trail-1',
        arn: 'arn:aws:cloudtrail:...',
        homeRegion: 'us-east-1',
        isMultiRegion: true,
        s3Bucket: 'bucket-1',
      });
    });

    it('assumes role first when authMethod is ASSUME_ROLE', async () => {
      mockCredentialFindUnique.mockResolvedValueOnce({
        authMethod: 'ASSUME_ROLE',
        roleArn: 'arn:aws:iam::1:role/scanner',
        externalId: 'ext-1',
      });
      stsMock.on(AssumeRoleCommand).resolves({
        Credentials: {
          AccessKeyId: 'ASSUMEDKEY',
          SecretAccessKey: 'assumed-secret',
          SessionToken: 'assumed-token',
          Expiration: new Date(),
        },
      });
      ctMock.on(DescribeTrailsCommand).resolves({ trailList: [] });

      const res = await server.get('/api/cloudtrail/trails?accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([]);
      expect(stsMock.commandCalls(AssumeRoleCommand)).toHaveLength(1);
    });
  });

  describe('GET /events', () => {
    it('returns 400 when accountId is missing', async () => {
      const res = await server.get('/api/cloudtrail/events', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('accountId is required');
    });

    it('returns mapped events for a valid request', async () => {
      mockCredentialFindUnique.mockResolvedValueOnce({ authMethod: 'ACCESS_KEY' });
      ctMock.on(LookupEventsCommand).resolves({
        Events: [
          {
            EventId: 'evt-1',
            EventName: 'CreateUser',
            EventTime: new Date('2026-01-01T00:00:00.000Z'),
            EventSource: 'iam.amazonaws.com',
            Username: 'admin',
            CloudTrailEvent: JSON.stringify({ eventID: 'evt-1', sourceIPAddress: '1.2.3.4' }),
            Resources: [{ ResourceType: 'AWS::IAM::User', ResourceName: 'new-user' }],
          },
        ],
        NextToken: undefined,
      });

      const res = await server.get('/api/cloudtrail/events?accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].eventName).toBe('CreateUser');
      expect(res.body.data[0].username).toBe('admin');
      expect(res.body.meta.count).toBe(1);
    });

    it('returns 500 with the error message when the SDK call fails', async () => {
      mockCredentialFindUnique.mockResolvedValueOnce({ authMethod: 'ACCESS_KEY' });
      ctMock.on(LookupEventsCommand).rejects(new Error('AccessDenied'));

      const res = await server.get('/api/cloudtrail/events?accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('AccessDenied');
    });
  });
});
