import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  GlueClient,
  GetConnectionsCommand,
  GetJobsCommand,
  GetSecurityConfigurationsCommand,
  GetDataCatalogEncryptionSettingsCommand,
  GetResourcePolicyCommand,
  SearchTablesCommand,
  GetMLTransformsCommand,
  GetDevEndpointsCommand,
} from '@aws-sdk/client-glue';

import GlueScanner from '../../../src/scanners/glue';

// The scanner reaches AWS exclusively through its own `new GlueClient(client.getClientConfig())`.
const glueMock = mockClient(GlueClient);

function makeClient(): any {
  return {
    getClientConfig: () => ({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
  };
}

/** Default empty-world stubs so scan() doesn't throw when a test doesn't care about a given call. */
function stubEmptyDefaults() {
  glueMock.on(GetJobsCommand).resolves({ Jobs: [] });
  glueMock.on(GetSecurityConfigurationsCommand).resolves({ SecurityConfigurations: [] });
  glueMock.on(GetConnectionsCommand).resolves({ ConnectionList: [] });
  glueMock.on(GetDevEndpointsCommand).resolves({ DevEndpoints: [] });
  glueMock.on(SearchTablesCommand).resolves({ TableList: [] });
  glueMock.on(GetDataCatalogEncryptionSettingsCommand).resolves({ DataCatalogEncryptionSettings: {} });
  glueMock.on(GetResourcePolicyCommand).rejects({ name: 'EntityNotFoundException', message: 'EntityNotFoundException' });
  glueMock.on(GetMLTransformsCommand).resolves({ Transforms: [] });
}

describe('GlueScanner', () => {
  beforeEach(() => {
    glueMock.reset();
    stubEmptyDefaults();
  });

  describe('scan()', () => {
    it('returns no findings when the account has no Glue resources at all', async () => {
      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });

    it('flags a Glue job with no security configuration and no S3 encryption argument, no CloudWatch logging, and no bookmark encryption', async () => {
      glueMock.on(GetJobsCommand).resolves({
        Jobs: [{ Name: 'unencrypted-job', DefaultArguments: {} }],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      const byCheckId = (id: string) => findings.find(f => f.checkId === id);

      const s3Finding = byCheckId('glue_etl_jobs_amazon_s3_encryption_enabled');
      expect(s3Finding).toBeDefined();
      expect(s3Finding).toMatchObject({ checkId: 'glue_etl_jobs_amazon_s3_encryption_enabled', service: 'Glue' });
      expect(s3Finding?.evidence).toMatchObject({ job: 'unencrypted-job' });

      expect(byCheckId('glue_etl_jobs_cloudwatch_logs_encryption_enabled')).toBeDefined();
      expect(byCheckId('glue_etl_jobs_job_bookmark_encryption_enabled')).toBeDefined();

      const loggingFinding = byCheckId('glue_etl_jobs_logging_enabled');
      expect(loggingFinding).toBeDefined();
      expect(loggingFinding?.evidence).toMatchObject({ job: 'unencrypted-job', continuousLogging: 'false' });
    });

    it('does not flag a Glue job that has sse-s3 argument encryption and continuous logging enabled, with no security configuration attached', async () => {
      glueMock.on(GetJobsCommand).resolves({
        Jobs: [
          {
            Name: 'compliant-job',
            DefaultArguments: {
              '--encryption-type': 'sse-s3',
              '--enable-continuous-cloudwatch-log': 'true',
            },
          },
        ],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'glue_etl_jobs_amazon_s3_encryption_enabled')).toBe(false);
      expect(findings.some(f => f.checkId === 'glue_etl_jobs_logging_enabled')).toBe(false);
      // Job still has no security configuration, so CW logs + bookmark encryption remain disabled.
      expect(findings.some(f => f.checkId === 'glue_etl_jobs_cloudwatch_logs_encryption_enabled')).toBe(true);
      expect(findings.some(f => f.checkId === 'glue_etl_jobs_job_bookmark_encryption_enabled')).toBe(true);
    });

    it('does not flag encryption checks for a Glue job whose attached security configuration has all three encryption modes enabled', async () => {
      glueMock.on(GetSecurityConfigurationsCommand).resolves({
        SecurityConfigurations: [
          {
            Name: 'fully-encrypted-config',
            EncryptionConfiguration: {
              S3Encryption: [{ S3EncryptionMode: 'SSE-KMS' }],
              CloudWatchEncryption: { CloudWatchEncryptionMode: 'SSE-KMS' },
              JobBookmarksEncryption: { JobBookmarksEncryptionMode: 'CSE-KMS' },
            },
          },
        ],
      });
      glueMock.on(GetJobsCommand).resolves({
        Jobs: [
          {
            Name: 'secure-job',
            SecurityConfiguration: 'fully-encrypted-config',
            DefaultArguments: { '--enable-continuous-cloudwatch-log': 'true' },
          },
        ],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.evidence?.job === 'secure-job')).toBe(false);
    });

    it('flags a Glue job whose default arguments contain a secret-looking inline value, but not one that references Secrets Manager', async () => {
      glueMock.on(GetJobsCommand).resolves({
        Jobs: [
          {
            Name: 'leaky-job',
            DefaultArguments: {
              '--enable-continuous-cloudwatch-log': 'true',
              '--encryption-type': 'sse-s3',
              '--db-password': 'hunter2literalpassword',
              '--api-key': '{{resolve:secretsmanager:my-secret}}',
            },
          },
        ],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      const secretsFinding = findings.find(f => f.checkId === 'glue_etl_jobs_no_secrets_in_arguments');
      expect(secretsFinding).toBeDefined();
      expect(secretsFinding?.evidence).toMatchObject({ job: 'leaky-job', suspectArguments: ['--db-password'] });
    });

    it('flags a Glue connection that does not enforce SSL and has a suspect inline credential property', async () => {
      glueMock.on(GetConnectionsCommand).resolves({
        ConnectionList: [
          {
            Name: 'insecure-conn',
            ConnectionType: 'JDBC',
            ConnectionProperties: {
              JDBC_ENFORCE_SSL: 'false',
              PASSWORD: 'plaintextpassword123',
            },
          },
        ],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      const sslFinding = findings.find(f => f.checkId === 'glue_database_connections_ssl_enabled');
      expect(sslFinding).toBeDefined();
      expect(sslFinding).toMatchObject({ checkId: 'glue_database_connections_ssl_enabled', service: 'Glue' });
      expect(sslFinding?.evidence).toMatchObject({ connection: 'insecure-conn' });

      const secretsFinding = findings.find(f => f.checkId === 'glue_catalog_connection_no_secrets');
      expect(secretsFinding).toBeDefined();
      expect(secretsFinding?.evidence).toMatchObject({ connection: 'insecure-conn', suspectProperties: ['PASSWORD'] });
    });

    it('does not flag a Glue connection that enforces SSL and references Secrets Manager for its credential', async () => {
      glueMock.on(GetConnectionsCommand).resolves({
        ConnectionList: [
          {
            Name: 'secure-conn',
            ConnectionType: 'JDBC',
            ConnectionProperties: {
              JDBC_ENFORCE_SSL: 'true',
              SECRET_ID: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:conn-secret',
            },
          },
        ],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.evidence?.connection === 'secure-conn')).toBe(false);
    });

    it('flags a development endpoint without a security configuration on all three encryption checks', async () => {
      glueMock.on(GetDevEndpointsCommand).resolves({
        DevEndpoints: [{ EndpointName: 'dev-ep-1' }],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      const ids = [
        'glue_development_endpoints_s3_encryption_enabled',
        'glue_development_endpoints_cloudwatch_logs_encryption_enabled',
        'glue_development_endpoints_job_bookmark_encryption_enabled',
      ];
      for (const id of ids) {
        const finding = findings.find(f => f.checkId === id);
        expect(finding).toBeDefined();
        expect(finding?.evidence).toMatchObject({ devEndpoint: 'dev-ep-1' });
      }
    });

    it('does not flag a development endpoint whose security configuration has all encryption modes enabled', async () => {
      glueMock.on(GetSecurityConfigurationsCommand).resolves({
        SecurityConfigurations: [
          {
            Name: 'dev-secure-config',
            EncryptionConfiguration: {
              S3Encryption: [{ S3EncryptionMode: 'SSE-KMS' }],
              CloudWatchEncryption: { CloudWatchEncryptionMode: 'SSE-KMS' },
              JobBookmarksEncryption: { JobBookmarksEncryptionMode: 'CSE-KMS' },
            },
          },
        ],
      });
      glueMock.on(GetDevEndpointsCommand).resolves({
        DevEndpoints: [{ EndpointName: 'dev-ep-secure', SecurityConfiguration: 'dev-secure-config' }],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.evidence?.devEndpoint === 'dev-ep-secure')).toBe(false);
    });

    it('flags catalog metadata encryption and connection password encryption as disabled when tables exist and settings are unset', async () => {
      glueMock.on(SearchTablesCommand).resolves({ TableList: [{ Name: 'some-table' }] });
      glueMock.on(GetDataCatalogEncryptionSettingsCommand).resolves({
        DataCatalogEncryptionSettings: {
          EncryptionAtRest: { CatalogEncryptionMode: 'DISABLED' },
          ConnectionPasswordEncryption: { ReturnConnectionPasswordEncrypted: false },
        },
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'glue_data_catalogs_metadata_encryption_enabled')).toBe(true);
      expect(findings.some(f => f.checkId === 'glue_data_catalogs_connection_passwords_encryption_enabled')).toBe(true);
    });

    it('does not evaluate catalog encryption settings when the region has no Glue tables', async () => {
      glueMock.on(SearchTablesCommand).resolves({ TableList: [] });
      // Even if encryption settings would fail the check, they should never be requested/evaluated.
      glueMock.on(GetDataCatalogEncryptionSettingsCommand).resolves({
        DataCatalogEncryptionSettings: {
          EncryptionAtRest: { CatalogEncryptionMode: 'DISABLED' },
          ConnectionPasswordEncryption: { ReturnConnectionPasswordEncrypted: false },
        },
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'glue_data_catalogs_metadata_encryption_enabled')).toBe(false);
      expect(findings.some(f => f.checkId === 'glue_data_catalogs_connection_passwords_encryption_enabled')).toBe(false);
      expect(glueMock.commandCalls(GetDataCatalogEncryptionSettingsCommand)).toHaveLength(0);
    });

    it('flags the Data Catalog as publicly accessible when the resource policy has a wildcard principal without a condition', async () => {
      glueMock.on(GetResourcePolicyCommand).resolves({
        PolicyInJson: JSON.stringify({
          Statement: [{ Effect: 'Allow', Principal: '*', Action: 'glue:GetTable' }],
        }),
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      const publicFinding = findings.find(f => f.checkId === 'glue_data_catalogs_not_publicly_accessible');
      expect(publicFinding).toBeDefined();
      expect(publicFinding).toMatchObject({ checkId: 'glue_data_catalogs_not_publicly_accessible', service: 'Glue' });
    });

    it('does not flag the Data Catalog as publicly accessible when the resource policy restricts the wildcard principal with a condition', async () => {
      glueMock.on(GetResourcePolicyCommand).resolves({
        PolicyInJson: JSON.stringify({
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: 'glue:GetTable',
              Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-1234567890' } },
            },
          ],
        }),
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'glue_data_catalogs_not_publicly_accessible')).toBe(false);
    });

    it('does not flag public accessibility when no resource policy exists (EntityNotFoundException)', async () => {
      glueMock.on(GetResourcePolicyCommand).rejects({ name: 'EntityNotFoundException', message: 'EntityNotFoundException: no policy' });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'glue_data_catalogs_not_publicly_accessible')).toBe(false);
    });

    it('flags an ML transform that is not encrypted at rest', async () => {
      glueMock.on(GetMLTransformsCommand).resolves({
        Transforms: [{ Name: 'my-transform', TransformId: 'tfm-1' }],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      const mlFinding = findings.find(f => f.checkId === 'glue_ml_transform_encrypted_at_rest');
      expect(mlFinding).toBeDefined();
      expect(mlFinding?.evidence).toMatchObject({ transform: 'my-transform', transformId: 'tfm-1' });
    });

    it('does not flag an ML transform that has user data encryption enabled', async () => {
      glueMock.on(GetMLTransformsCommand).resolves({
        Transforms: [
          {
            Name: 'secure-transform',
            TransformId: 'tfm-2',
            TransformEncryption: { MlUserDataEncryption: { MlUserDataEncryptionMode: 'SSE-KMS' } },
          },
        ],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'glue_ml_transform_encrypted_at_rest')).toBe(false);
    });

    it('paginates through GetJobsCommand using NextToken and scans every page', async () => {
      glueMock
        .on(GetJobsCommand)
        .resolvesOnce({ Jobs: [{ Name: 'page1-job', DefaultArguments: {} }], NextToken: 'token-2' })
        .resolvesOnce({ Jobs: [{ Name: 'page2-job', DefaultArguments: {} }] });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(glueMock.commandCalls(GetJobsCommand)).toHaveLength(2);
      const flaggedJobs = findings
        .filter(f => f.checkId === 'glue_etl_jobs_logging_enabled')
        .map(f => f.evidence.job)
        .sort();
      expect(flaggedJobs).toEqual(['page1-job', 'page2-job']);
    });

    it('paginates through GetMLTransformsCommand using NextToken and scans every page', async () => {
      glueMock
        .on(GetMLTransformsCommand)
        .resolvesOnce({ Transforms: [{ Name: 'transform-a', TransformId: 'a' }], NextToken: 'next' })
        .resolvesOnce({ Transforms: [{ Name: 'transform-b', TransformId: 'b' }] });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      expect(glueMock.commandCalls(GetMLTransformsCommand)).toHaveLength(2);
      const flagged = findings
        .filter(f => f.checkId === 'glue_ml_transform_encrypted_at_rest')
        .map(f => f.evidence.transform)
        .sort();
      expect(flagged).toEqual(['transform-a', 'transform-b']);
    });

    it('does not throw and returns gracefully when GetJobsCommand fails repeatedly', async () => {
      glueMock.on(GetJobsCommand).rejects(new Error('Access Denied'));

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      // Jobs are unreachable, but other resource types with no findings still return normally.
      expect(findings.some(f => f.checkId?.startsWith('glue_etl_jobs'))).toBe(false);
    }, 15000);

    it('does not throw and returns gracefully when every Glue API call fails repeatedly', async () => {
      glueMock.onAnyCommand().rejects(new Error('ThrottlingException'));

      const scanner = new GlueScanner(makeClient());
      await expect(scanner.scan()).resolves.toEqual([]);
    }, 60000);

    it('does not throw when GetDevEndpointsCommand fails (dev endpoints unsupported in region), scan still completes', async () => {
      glueMock.on(GetDevEndpointsCommand).rejects(new Error('Operation is not supported'));
      glueMock.on(GetJobsCommand).resolves({
        Jobs: [{ Name: 'job-x', DefaultArguments: { '--enable-continuous-cloudwatch-log': 'true', '--encryption-type': 'sse-s3' } }],
      });

      const scanner = new GlueScanner(makeClient());
      const findings = await scanner.scan();

      // Dev endpoint listing failed, so no dev-endpoint findings should be produced.
      expect(findings.some(f => f.checkId?.startsWith('glue_development_endpoints'))).toBe(false);
      // job-x has no security configuration, so CW logs + bookmark encryption checks still fire,
      // but the S3 encryption and continuous-logging checks (which it satisfies) do not.
      expect(findings.some(f => f.checkId === 'glue_etl_jobs_amazon_s3_encryption_enabled' && f.evidence?.job === 'job-x')).toBe(false);
      expect(findings.some(f => f.checkId === 'glue_etl_jobs_logging_enabled' && f.evidence?.job === 'job-x')).toBe(false);
    }, 15000);
  });
});
