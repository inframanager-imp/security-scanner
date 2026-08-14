import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  ECRClient,
  DescribeRepositoriesCommand,
  DescribeImagesCommand,
  GetAuthorizationTokenCommand,
  GetRegistryScanningConfigurationCommand,
  GetLifecyclePolicyCommand,
  GetRepositoryPolicyCommand,
} from '@aws-sdk/client-ecr';
import ECRScanner from '../../../src/scanners/ecr';

// The scanner reaches AWS exclusively through `client.ecr` (a pre-built ECRClient
// on the AWSClient wrapper), so the mock AWSClient only needs that one property.
const ecrMock = mockClient(ECRClient);

function makeClient(): any {
  return {
    ecr: new ECRClient({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
    getClientConfig: () => ({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
  };
}

describe('ECRScanner', () => {
  beforeEach(() => {
    ecrMock.reset();
    // No registry auth by default → image/CVE-layer scanning path (network fetch) is
    // skipped entirely, keeping these tests scoped to the SDK-mockable config checks.
    ecrMock.on(GetAuthorizationTokenCommand).resolves({ authorizationData: [] });
    // Defaults so checkRepositoryConfiguration's calls resolve to "compliant" unless overridden.
    ecrMock.on(GetLifecyclePolicyCommand).resolves({ lifecyclePolicyText: '{"rules":[]}' });
    ecrMock.on(GetRepositoryPolicyCommand).rejects({ name: 'RepositoryPolicyNotFoundException' });
    ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
      scanningConfiguration: { scanType: 'ENHANCED', rules: [{ repositoryFilters: [] }] },
    });
  });

  describe('scan()', () => {
    it('returns no findings when the account has no repositories', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({ repositories: [] });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });

    it('flags a repository with MUTABLE tags and IMMUTABLE-passes one that is already immutable', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({
        repositories: [
          {
            repositoryName: 'mutable-repo',
            registryId: '123456789012',
            imageTagMutability: 'MUTABLE',
            imageScanningConfiguration: { scanOnPush: true },
          },
          {
            repositoryName: 'immutable-repo',
            registryId: '123456789012',
            imageTagMutability: 'IMMUTABLE',
            imageScanningConfiguration: { scanOnPush: true },
          },
        ],
      });
      ecrMock.on(DescribeImagesCommand).resolves({ imageDetails: [] });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      const immutabilityFindings = findings.filter(f => f.checkId === 'ecr_repositories_tag_immutability');
      expect(immutabilityFindings).toHaveLength(1);
      expect(immutabilityFindings[0]).toMatchObject({
        checkId: 'ecr_repositories_tag_immutability',
        service: 'ECR',
        severity: expect.any(String),
      });
      expect(immutabilityFindings[0].evidence).toMatchObject({
        repositoryName: 'mutable-repo',
        imageTagMutability: 'MUTABLE',
      });
      // The already-immutable repo must not be flagged.
      expect(
        immutabilityFindings.some(f => f.evidence.repositoryName === 'immutable-repo')
      ).toBe(false);
    });

    it('flags repositories missing scan-on-push and a lifecycle policy', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({
        repositories: [
          {
            repositoryName: 'no-scan-repo',
            registryId: '123456789012',
            imageTagMutability: 'IMMUTABLE',
            imageScanningConfiguration: { scanOnPush: false },
          },
        ],
      });
      ecrMock.on(DescribeImagesCommand).resolves({ imageDetails: [] });
      ecrMock.on(GetLifecyclePolicyCommand).rejects({ name: 'LifecyclePolicyNotFoundException' });
      // ecr_repositories_scan_images_on_push_enabled is only evaluated inside the
      // per-repository image-scan path, which requires a valid registry auth token.
      // With zero images returned, that path exits immediately after the check —
      // no network fetch is triggered.
      ecrMock.on(GetAuthorizationTokenCommand).resolves({
        authorizationData: [{ authorizationToken: Buffer.from('AWS:password').toString('base64'), proxyEndpoint: 'https://123456789012.dkr.ecr.us-east-1.amazonaws.com' }],
      });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      const scanOnPushFinding = findings.find(f => f.checkId === 'ecr_repositories_scan_images_on_push_enabled');
      expect(scanOnPushFinding).toBeDefined();
      expect(scanOnPushFinding?.evidence).toMatchObject({ repositoryName: 'no-scan-repo' });

      const lifecycleFinding = findings.find(f => f.checkId === 'ecr_repositories_lifecycle_policy_enabled');
      expect(lifecycleFinding).toBeDefined();
      expect(lifecycleFinding?.evidence).toMatchObject({ repositoryName: 'no-scan-repo', lifecyclePolicy: null });
    });

    it('flags a repository policy that allows a wildcard principal without a restrictive condition', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({
        repositories: [
          {
            repositoryName: 'public-repo',
            registryId: '123456789012',
            imageTagMutability: 'IMMUTABLE',
            imageScanningConfiguration: { scanOnPush: true },
          },
        ],
      });
      ecrMock.on(DescribeImagesCommand).resolves({ imageDetails: [] });
      ecrMock.on(GetRepositoryPolicyCommand).resolves({
        policyText: JSON.stringify({
          Statement: [{ Effect: 'Allow', Principal: '*', Action: 'ecr:GetDownloadUrlForLayer' }],
        }),
      });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      const publicFinding = findings.find(f => f.checkId === 'ecr_repositories_not_publicly_accessible');
      expect(publicFinding).toBeDefined();
      expect(publicFinding?.evidence).toMatchObject({ repositoryName: 'public-repo' });
    });

    it('does not flag a repository policy scoped by a restrictive source-account condition', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({
        repositories: [
          {
            repositoryName: 'scoped-repo',
            registryId: '123456789012',
            imageTagMutability: 'IMMUTABLE',
            imageScanningConfiguration: { scanOnPush: true },
          },
        ],
      });
      ecrMock.on(DescribeImagesCommand).resolves({ imageDetails: [] });
      ecrMock.on(GetRepositoryPolicyCommand).resolves({
        policyText: JSON.stringify({
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: 'ecr:GetDownloadUrlForLayer',
              Condition: { StringEquals: { 'aws:SourceAccount': '123456789012' } },
            },
          ],
        }),
      });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'ecr_repositories_not_publicly_accessible')).toBe(false);
    });

    it('flags the registry when scan-on-push is not configured at the registry level', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({
        repositories: [
          {
            repositoryName: 'repo-a',
            registryId: '123456789012',
            imageTagMutability: 'IMMUTABLE',
            imageScanningConfiguration: { scanOnPush: true },
          },
        ],
      });
      ecrMock.on(DescribeImagesCommand).resolves({ imageDetails: [] });
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
        scanningConfiguration: { scanType: 'BASIC', rules: [] },
      });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      const registryFinding = findings.find(f => f.checkId === 'ecr_registry_scan_images_on_push_enabled');
      expect(registryFinding).toBeDefined();
      expect(registryFinding?.evidence).toMatchObject({ registryId: '123456789012', scanType: 'BASIC' });
    });

    it('does not flag the registry when a rule with no repository filters covers everything', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({
        repositories: [
          {
            repositoryName: 'repo-a',
            registryId: '123456789012',
            imageTagMutability: 'IMMUTABLE',
            imageScanningConfiguration: { scanOnPush: true },
          },
        ],
      });
      ecrMock.on(DescribeImagesCommand).resolves({ imageDetails: [] });
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
        scanningConfiguration: { scanType: 'ENHANCED', rules: [{ repositoryFilters: [] }] },
      });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'ecr_registry_scan_images_on_push_enabled')).toBe(false);
    });

    it('paginates through DescribeRepositoriesCommand using nextToken and scans every page', async () => {
      ecrMock
        .on(DescribeRepositoriesCommand)
        .resolvesOnce({
          repositories: [
            {
              repositoryName: 'page1-repo',
              registryId: '123456789012',
              imageTagMutability: 'MUTABLE',
              imageScanningConfiguration: { scanOnPush: true },
            },
          ],
          nextToken: 'token-2',
        })
        .resolvesOnce({
          repositories: [
            {
              repositoryName: 'page2-repo',
              registryId: '123456789012',
              imageTagMutability: 'MUTABLE',
              imageScanningConfiguration: { scanOnPush: true },
            },
          ],
        });
      ecrMock.on(DescribeImagesCommand).resolves({ imageDetails: [] });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      expect(ecrMock.commandCalls(DescribeRepositoriesCommand)).toHaveLength(2);
      const flaggedRepos = findings
        .filter(f => f.checkId === 'ecr_repositories_tag_immutability')
        .map(f => f.evidence.repositoryName);
      expect(flaggedRepos.sort()).toEqual(['page1-repo', 'page2-repo']);
    });

    it('does not throw and returns gracefully when DescribeRepositoriesCommand fails repeatedly', async () => {
      ecrMock.on(DescribeRepositoriesCommand).rejects(new Error('Access Denied'));

      const scanner = new ECRScanner(makeClient());
      await expect(scanner.scan()).resolves.toEqual([]);
    }, 15000);

    it('does not throw when GetRegistryScanningConfigurationCommand fails for a reason other than the feature being disabled', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({
        repositories: [
          {
            repositoryName: 'repo-a',
            registryId: '123456789012',
            imageTagMutability: 'IMMUTABLE',
            imageScanningConfiguration: { scanOnPush: true },
          },
        ],
      });
      ecrMock.on(DescribeImagesCommand).resolves({ imageDetails: [] });
      ecrMock.on(GetRegistryScanningConfigurationCommand).rejects(new Error('Internal Server Error'));

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      // Registry-level check is skipped on unexpected error, but repo-level checks still run.
      expect(findings.some(f => f.checkId === 'ecr_registry_scan_images_on_push_enabled')).toBe(false);
      expect(findings.some(f => f.checkId === 'ecr_repositories_lifecycle_policy_enabled')).toBe(false);
    });

    it('skips image/CVE scanning entirely when no registry auth token can be obtained', async () => {
      ecrMock.on(DescribeRepositoriesCommand).resolves({
        repositories: [
          {
            repositoryName: 'repo-a',
            registryId: '123456789012',
            imageTagMutability: 'IMMUTABLE',
            imageScanningConfiguration: { scanOnPush: true },
          },
        ],
      });
      ecrMock.on(GetAuthorizationTokenCommand).resolves({ authorizationData: [] });

      const scanner = new ECRScanner(makeClient());
      const findings = await scanner.scan();

      // Only config-check findings are possible; nothing CVE-related was emitted,
      // and DescribeImages (used only by the image-scanning path) was never called.
      expect(findings.every(f =>
        !['ecr_repositories_scan_vulnerabilities_in_latest_image', 'ecr_image_high_severity_cves', 'ecr_image_medium_low_cves']
          .includes(f.checkId!)
      )).toBe(true);
      expect(ecrMock.commandCalls(DescribeImagesCommand)).toHaveLength(0);
    });
  });
});
