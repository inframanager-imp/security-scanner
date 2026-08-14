import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';

import {
  SageMakerClient,
  ListNotebookInstancesCommand,
  DescribeNotebookInstanceCommand,
  DescribeNotebookInstanceLifecycleConfigCommand,
  ListModelsCommand,
  DescribeModelCommand,
  ListTrainingJobsCommand,
  DescribeTrainingJobCommand,
  ListDomainsCommand,
  DescribeDomainCommand,
  ListEndpointConfigsCommand,
  DescribeEndpointConfigCommand,
  ListProcessingJobsCommand,
  DescribeProcessingJobCommand,
  ListMonitoringSchedulesCommand,
  ListModelPackageGroupsCommand,
  ListModelPackagesCommand,
} from '@aws-sdk/client-sagemaker';

import SageMakerScanner from '../../../src/scanners/sagemaker';
import type { ScanningResult } from '../../../src/utils/types';

const sagemakerMock = mockClient(SageMakerClient);

// Minimal AWSClient-shaped stub: SageMakerScanner calls getClientConfig() in its
// constructor to build its own SDK v3 client, and getRegion() for region-level checks.
const fakeAwsClient: any = {
  getClientConfig: () => ({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
  getRegion: () => 'us-east-1',
};

function findByCheckId(findings: ScanningResult[], checkId: string): ScanningResult[] {
  return findings.filter((f) => f.checkId === checkId);
}

// Benign empty-ish defaults so scan() completes without throwing/hanging on any
// command not explicitly overridden by a test.
function setBenignDefaults(): void {
  sagemakerMock.on(ListNotebookInstancesCommand).resolves({ NotebookInstances: [] } as any);
  sagemakerMock.on(ListModelsCommand).resolves({ Models: [] } as any);
  sagemakerMock.on(ListTrainingJobsCommand).resolves({ TrainingJobSummaries: [] } as any);
  sagemakerMock.on(ListDomainsCommand).resolves({ Domains: [] } as any);
  sagemakerMock.on(ListEndpointConfigsCommand).resolves({ EndpointConfigs: [] } as any);
  sagemakerMock.on(ListProcessingJobsCommand).resolves({ ProcessingJobSummaries: [] } as any);
  sagemakerMock.on(ListMonitoringSchedulesCommand).resolves({ MonitoringScheduleSummaries: [] } as any);
  sagemakerMock.on(ListModelPackageGroupsCommand).resolves({ ModelPackageGroupSummaryList: [] } as any);
}

describe('SageMakerScanner', () => {
  beforeEach(() => {
    sagemakerMock.reset();
    setBenignDefaults();
  });

  describe('notebook instances', () => {
    it('flags an unencrypted, root-enabled, non-VPC, internet-exposed notebook instance', async () => {
      sagemakerMock.on(ListNotebookInstancesCommand).resolves({
        NotebookInstances: [{ NotebookInstanceName: 'nb-1', NotebookInstanceArn: 'arn:aws:sagemaker:us-east-1:123:notebook-instance/nb-1' }],
      } as any);
      sagemakerMock.on(DescribeNotebookInstanceCommand).resolves({
        KmsKeyId: undefined,
        RootAccess: 'Enabled',
        SubnetId: undefined,
        DirectInternetAccess: 'Enabled',
        NotebookInstanceLifecycleConfigName: undefined,
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const encryption = findByCheckId(findings, 'sagemaker_notebook_instance_encryption_enabled');
      expect(encryption).toHaveLength(1);
      expect(encryption[0].service).toBe('SageMaker');
      expect(encryption[0].evidence).toMatchObject({ notebookInstance: 'nb-1', kmsKeyId: null });

      expect(findByCheckId(findings, 'sagemaker_notebook_instance_root_access_disabled')).toHaveLength(1);
      expect(findByCheckId(findings, 'sagemaker_notebook_instance_vpc_settings_configured')).toHaveLength(1);
      expect(findByCheckId(findings, 'sagemaker_notebook_instance_without_direct_internet_access_configured')).toHaveLength(1);
    });

    it('emits no notebook findings for a fully compliant instance', async () => {
      sagemakerMock.on(ListNotebookInstancesCommand).resolves({
        NotebookInstances: [{ NotebookInstanceName: 'nb-good', NotebookInstanceArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeNotebookInstanceCommand).resolves({
        KmsKeyId: 'arn:aws:kms:us-east-1:123:key/abc',
        RootAccess: 'Disabled',
        SubnetId: 'subnet-123',
        DirectInternetAccess: 'Disabled',
        NotebookInstanceLifecycleConfigName: undefined,
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_notebook_instance_encryption_enabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'sagemaker_notebook_instance_root_access_disabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'sagemaker_notebook_instance_vpc_settings_configured')).toHaveLength(0);
      expect(findByCheckId(findings, 'sagemaker_notebook_instance_without_direct_internet_access_configured')).toHaveLength(0);
    });

    it('detects a hardcoded AWS access key in the lifecycle OnCreate script', async () => {
      sagemakerMock.on(ListNotebookInstancesCommand).resolves({
        NotebookInstances: [{ NotebookInstanceName: 'nb-secret', NotebookInstanceArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeNotebookInstanceCommand).resolves({
        KmsKeyId: 'arn:aws:kms:us-east-1:123:key/abc',
        RootAccess: 'Disabled',
        SubnetId: 'subnet-123',
        DirectInternetAccess: 'Disabled',
        NotebookInstanceLifecycleConfigName: 'my-lifecycle-config',
      } as any);
      const scriptWithSecret = 'export AWS_ACCESS_KEY=AKIAXXXXXXXXXXXXXXXX\necho done';
      sagemakerMock.on(DescribeNotebookInstanceLifecycleConfigCommand).resolves({
        OnCreate: [{ Content: Buffer.from(scriptWithSecret, 'utf-8').toString('base64') }],
        OnStart: [],
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_notebook_instance_no_secrets');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ notebookInstance: 'nb-secret', lifecycleConfig: 'my-lifecycle-config' });
      expect((matches[0].evidence as any).secrets[0]).toContain('AWS Access Key ID');
    });

    it('does not flag lifecycle scripts containing no secret patterns', async () => {
      sagemakerMock.on(ListNotebookInstancesCommand).resolves({
        NotebookInstances: [{ NotebookInstanceName: 'nb-clean', NotebookInstanceArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeNotebookInstanceCommand).resolves({
        KmsKeyId: 'arn:aws:kms:us-east-1:123:key/abc',
        RootAccess: 'Disabled',
        SubnetId: 'subnet-123',
        DirectInternetAccess: 'Disabled',
        NotebookInstanceLifecycleConfigName: 'clean-config',
      } as any);
      sagemakerMock.on(DescribeNotebookInstanceLifecycleConfigCommand).resolves({
        OnCreate: [{ Content: Buffer.from('echo hello world', 'utf-8').toString('base64') }],
        OnStart: [],
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_notebook_instance_no_secrets')).toHaveLength(0);
    });

    it('paginates through ListNotebookInstances using NextToken and evaluates every page', async () => {
      sagemakerMock
        .on(ListNotebookInstancesCommand)
        .resolvesOnce({ NotebookInstances: [{ NotebookInstanceName: 'nb-page1', NotebookInstanceArn: 'arn:1' }], NextToken: 'page2' } as any)
        .resolvesOnce({ NotebookInstances: [{ NotebookInstanceName: 'nb-page2', NotebookInstanceArn: 'arn:2' }] } as any);
      sagemakerMock.on(DescribeNotebookInstanceCommand).resolves({
        KmsKeyId: undefined,
        RootAccess: 'Disabled',
        SubnetId: 'subnet-1',
        DirectInternetAccess: 'Disabled',
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(sagemakerMock.commandCalls(ListNotebookInstancesCommand)).toHaveLength(2);
      const encryptionFindings = findByCheckId(findings, 'sagemaker_notebook_instance_encryption_enabled');
      const names = encryptionFindings.map((f: any) => f.evidence.notebookInstance).sort();
      expect(names).toEqual(['nb-page1', 'nb-page2']);
    });
  });

  describe('models', () => {
    it('flags a model with network isolation disabled and no VPC config', async () => {
      sagemakerMock.on(ListModelsCommand).resolves({
        Models: [{ ModelName: 'model-1', ModelArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeModelCommand).resolves({
        EnableNetworkIsolation: false,
        VpcConfig: undefined,
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const isolationFindings = findByCheckId(findings, 'sagemaker_models_network_isolation_enabled');
      expect(isolationFindings).toHaveLength(1);
      expect(isolationFindings[0].evidence).toMatchObject({ model: 'model-1', networkIsolation: false });

      const vpcFindings = findByCheckId(findings, 'sagemaker_models_vpc_settings_configured');
      expect(vpcFindings).toHaveLength(1);
      expect(vpcFindings[0].evidence).toMatchObject({ model: 'model-1', vpcConfigSubnets: [] });
    });

    it('emits no model findings when network isolation and VPC subnets are configured', async () => {
      sagemakerMock.on(ListModelsCommand).resolves({
        Models: [{ ModelName: 'model-good', ModelArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeModelCommand).resolves({
        EnableNetworkIsolation: true,
        VpcConfig: { Subnets: ['subnet-1', 'subnet-2'] },
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_models_network_isolation_enabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'sagemaker_models_vpc_settings_configured')).toHaveLength(0);
    });
  });

  describe('training jobs', () => {
    it('flags a training job missing inter-container encryption, network isolation, volume encryption and VPC config', async () => {
      sagemakerMock.on(ListTrainingJobsCommand).resolves({
        TrainingJobSummaries: [{ TrainingJobName: 'job-1', TrainingJobArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeTrainingJobCommand).resolves({
        EnableInterContainerTrafficEncryption: false,
        EnableNetworkIsolation: false,
        ResourceConfig: { VolumeKmsKeyId: undefined },
        VpcConfig: undefined,
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_training_jobs_intercontainer_encryption_enabled')).toHaveLength(1);
      expect(findByCheckId(findings, 'sagemaker_training_jobs_network_isolation_enabled')).toHaveLength(1);
      const volumeFindings = findByCheckId(findings, 'sagemaker_training_jobs_volume_and_output_encryption_enabled');
      expect(volumeFindings).toHaveLength(1);
      expect(volumeFindings[0].evidence).toMatchObject({ trainingJob: 'job-1', volumeKmsKeyId: null });
      expect(findByCheckId(findings, 'sagemaker_training_jobs_vpc_settings_configured')).toHaveLength(1);
    });

    it('emits no training job findings for a fully compliant job', async () => {
      sagemakerMock.on(ListTrainingJobsCommand).resolves({
        TrainingJobSummaries: [{ TrainingJobName: 'job-good', TrainingJobArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeTrainingJobCommand).resolves({
        EnableInterContainerTrafficEncryption: true,
        EnableNetworkIsolation: true,
        ResourceConfig: { VolumeKmsKeyId: 'arn:aws:kms:us-east-1:123:key/abc' },
        VpcConfig: { Subnets: ['subnet-1'] },
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_training_jobs_intercontainer_encryption_enabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'sagemaker_training_jobs_network_isolation_enabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'sagemaker_training_jobs_volume_and_output_encryption_enabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'sagemaker_training_jobs_vpc_settings_configured')).toHaveLength(0);
    });
  });

  describe('domains', () => {
    it('flags an SSO-mode domain not associated with an Identity Center instance', async () => {
      sagemakerMock.on(ListDomainsCommand).resolves({
        Domains: [{ DomainId: 'd-1', DomainName: 'my-domain', DomainArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeDomainCommand).resolves({
        AuthMode: 'SSO',
        SingleSignOnManagedApplicationInstanceId: undefined,
        SingleSignOnApplicationArn: undefined,
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_domain_sso_configured');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ domain: 'my-domain', domainId: 'd-1', authMode: 'SSO', identityCenterAssociated: false });
    });

    it('flags a domain not using SSO auth mode at all', async () => {
      sagemakerMock.on(ListDomainsCommand).resolves({
        Domains: [{ DomainId: 'd-2', DomainName: 'iam-domain', DomainArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeDomainCommand).resolves({ AuthMode: 'IAM' } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_domain_sso_configured');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ domain: 'iam-domain', authMode: 'IAM' });
    });

    it('emits no finding for an SSO domain associated with an Identity Center instance', async () => {
      sagemakerMock.on(ListDomainsCommand).resolves({
        Domains: [{ DomainId: 'd-3', DomainName: 'sso-domain', DomainArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeDomainCommand).resolves({
        AuthMode: 'SSO',
        SingleSignOnManagedApplicationInstanceId: 'ssoins-abc',
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_domain_sso_configured')).toHaveLength(0);
    });
  });

  describe('endpoint configs', () => {
    it('flags a single-instance production variant and missing KMS encryption', async () => {
      sagemakerMock.on(ListEndpointConfigsCommand).resolves({
        EndpointConfigs: [{ EndpointConfigName: 'cfg-1', EndpointConfigArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeEndpointConfigCommand).resolves({
        ProductionVariants: [{ VariantName: 'variant-1', InitialInstanceCount: 1 }],
        KmsKeyId: undefined,
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const variantFindings = findByCheckId(findings, 'sagemaker_endpoint_config_prod_variant_instances');
      expect(variantFindings).toHaveLength(1);
      expect(variantFindings[0].evidence).toMatchObject({ endpointConfig: 'cfg-1', nonCompliantVariants: ['variant-1'] });

      const kmsFindings = findByCheckId(findings, 'sagemaker_endpoint_config_kms_encryption_enabled');
      expect(kmsFindings).toHaveLength(1);
      expect(kmsFindings[0].evidence).toMatchObject({ endpointConfig: 'cfg-1', kmsKeyId: null });
    });

    it('emits no findings for a config with 2+ instance variants and KMS encryption', async () => {
      sagemakerMock.on(ListEndpointConfigsCommand).resolves({
        EndpointConfigs: [{ EndpointConfigName: 'cfg-good', EndpointConfigArn: 'arn:x' }],
      } as any);
      sagemakerMock.on(DescribeEndpointConfigCommand).resolves({
        ProductionVariants: [{ VariantName: 'variant-1', InitialInstanceCount: 2 }],
        KmsKeyId: 'arn:aws:kms:us-east-1:123:key/abc',
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_endpoint_config_prod_variant_instances')).toHaveLength(0);
      expect(findByCheckId(findings, 'sagemaker_endpoint_config_kms_encryption_enabled')).toHaveLength(0);
    });
  });

  describe('region-level checks (Clarify, monitoring, model registry)', () => {
    it('flags sagemaker_clarify_exists when no processing job uses the Clarify image', async () => {
      sagemakerMock.on(ListProcessingJobsCommand).resolves({
        ProcessingJobSummaries: [{ ProcessingJobName: 'job-1' }],
      } as any);
      sagemakerMock.on(DescribeProcessingJobCommand).resolves({
        AppSpecification: { ImageUri: '123.dkr.ecr.us-east-1.amazonaws.com/some-other-image:latest' },
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_clarify_exists');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ region: 'us-east-1', clarifyJobFound: false });
    });

    it('does not flag sagemaker_clarify_exists when a Clarify processing job is found', async () => {
      sagemakerMock.on(ListProcessingJobsCommand).resolves({
        ProcessingJobSummaries: [{ ProcessingJobName: 'clarify-job' }],
      } as any);
      sagemakerMock.on(DescribeProcessingJobCommand).resolves({
        AppSpecification: { ImageUri: '123.dkr.ecr.us-east-1.amazonaws.com/sagemaker-clarify-processing:1.0' },
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_clarify_exists')).toHaveLength(0);
    });

    it('flags sagemaker_models_monitor_enabled when no monitoring schedule exists', async () => {
      sagemakerMock.on(ListMonitoringSchedulesCommand).resolves({ MonitoringScheduleSummaries: [] } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_models_monitor_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ region: 'us-east-1', hasSchedules: false, isScheduled: false });
    });

    it('flags sagemaker_models_monitor_enabled when schedules exist but none are Scheduled', async () => {
      sagemakerMock.on(ListMonitoringSchedulesCommand).resolves({
        MonitoringScheduleSummaries: [{ MonitoringScheduleName: 'sched-1', MonitoringScheduleStatus: 'Stopped' }],
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_models_monitor_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ hasSchedules: true, isScheduled: false });
    });

    it('does not flag sagemaker_models_monitor_enabled when an active schedule exists', async () => {
      sagemakerMock.on(ListMonitoringSchedulesCommand).resolves({
        MonitoringScheduleSummaries: [{ MonitoringScheduleName: 'sched-1', MonitoringScheduleStatus: 'Scheduled' }],
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_models_monitor_enabled')).toHaveLength(0);
    });

    it('flags sagemaker_models_registry_in_use when there are no model package groups', async () => {
      sagemakerMock.on(ListModelPackageGroupsCommand).resolves({ ModelPackageGroupSummaryList: [] } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_models_registry_in_use');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ hasGroups: false, hasApprovedPackages: false });
    });

    it('flags sagemaker_models_registry_in_use when groups exist but no package is approved', async () => {
      sagemakerMock.on(ListModelPackageGroupsCommand).resolves({
        ModelPackageGroupSummaryList: [{ ModelPackageGroupName: 'group-1' }],
      } as any);
      sagemakerMock.on(ListModelPackagesCommand).resolves({ ModelPackageSummaryList: [] } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_models_registry_in_use');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ hasGroups: true, hasApprovedPackages: false, groupCount: 1 });
    });

    it('does not flag sagemaker_models_registry_in_use when an approved model package exists', async () => {
      sagemakerMock.on(ListModelPackageGroupsCommand).resolves({
        ModelPackageGroupSummaryList: [{ ModelPackageGroupName: 'group-1' }],
      } as any);
      sagemakerMock.on(ListModelPackagesCommand).resolves({
        ModelPackageSummaryList: [{ ModelPackageArn: 'arn:x', ModelApprovalStatus: 'Approved' }],
      } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_models_registry_in_use')).toHaveLength(0);
    });
  });

  describe('no-resources / empty account', () => {
    it('emits only the region-level "not in use" findings when the account has no SageMaker resources at all', async () => {
      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId).sort();
      expect(checkIds).toEqual([
        'sagemaker_clarify_exists',
        'sagemaker_models_monitor_enabled',
        'sagemaker_models_registry_in_use',
      ]);
    });
  });

  describe('error handling', () => {
    it('does not throw and returns gracefully when ListNotebookInstances fails on every retry', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      sagemakerMock.on(ListNotebookInstancesCommand).rejects(new Error('AccessDenied'));

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'sagemaker_notebook_instance_encryption_enabled')).toHaveLength(0);
      // Rest of the scan still completes and returns other region-level findings.
      expect(findByCheckId(findings, 'sagemaker_clarify_exists')).toHaveLength(1);
      jest.useRealTimers();
    });

    it('continues scanning other notebook instances when one instance describe call fails', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      sagemakerMock.on(ListNotebookInstancesCommand).resolves({
        NotebookInstances: [
          { NotebookInstanceName: 'broken-nb', NotebookInstanceArn: 'arn:1' },
          { NotebookInstanceName: 'fine-nb', NotebookInstanceArn: 'arn:2' },
        ],
      } as any);
      sagemakerMock
        .on(DescribeNotebookInstanceCommand, { NotebookInstanceName: 'broken-nb' } as any)
        .rejects(new Error('ThrottlingException'));
      sagemakerMock
        .on(DescribeNotebookInstanceCommand, { NotebookInstanceName: 'fine-nb' } as any)
        .resolves({ KmsKeyId: undefined, RootAccess: 'Disabled', SubnetId: 'subnet-1', DirectInternetAccess: 'Disabled' } as any);

      const scanner = new SageMakerScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'sagemaker_notebook_instance_encryption_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ notebookInstance: 'fine-nb' });
      jest.useRealTimers();
    });

    it('does not throw when the whole scan is exercised and every list call fails', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      sagemakerMock.on(ListNotebookInstancesCommand).rejects(new Error('AccessDenied'));
      sagemakerMock.on(ListModelsCommand).rejects(new Error('AccessDenied'));
      sagemakerMock.on(ListTrainingJobsCommand).rejects(new Error('AccessDenied'));
      sagemakerMock.on(ListDomainsCommand).rejects(new Error('AccessDenied'));
      sagemakerMock.on(ListEndpointConfigsCommand).rejects(new Error('AccessDenied'));
      sagemakerMock.on(ListProcessingJobsCommand).rejects(new Error('AccessDenied'));
      sagemakerMock.on(ListMonitoringSchedulesCommand).rejects(new Error('AccessDenied'));
      sagemakerMock.on(ListModelPackageGroupsCommand).rejects(new Error('AccessDenied'));

      const scanner = new SageMakerScanner(fakeAwsClient);
      await expect(scanner.scan()).resolves.toEqual([]);
      jest.useRealTimers();
    });
  });
});
