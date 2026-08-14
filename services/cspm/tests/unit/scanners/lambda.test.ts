import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  LambdaClient,
  ListFunctionsCommand,
  GetFunctionCommand,
  GetPolicyCommand,
  ListAliasesCommand,
  GetFunctionConcurrencyCommand,
  GetFunctionUrlConfigCommand,
} from '@aws-sdk/client-lambda';
import { EC2Client, DescribeSubnetsCommand } from '@aws-sdk/client-ec2';
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
} from '@aws-sdk/client-cloudtrail';
import { LambdaScanner } from '../../../src/scanners/lambda';
import AWSClient from '../../../src/aws/client';

const lambdaMock = mockClient(LambdaClient);
const ec2Mock = mockClient(EC2Client);
const cloudtrailMock = mockClient(CloudTrailClient);

/**
 * LambdaScanner talks to this.client.lambda / .ec2 / .cloudtrail / .getAccountId()
 * directly (it does not construct its own SDK client from getClientConfig()),
 * so the mock AWSClient-shaped object must expose real (mocked) SDK client
 * instances under those property names.
 */
function makeMockClient(accountId: string | null = '111111111111'): AWSClient {
  return {
    lambda: new LambdaClient({ region: 'us-east-1', credentials: {} as any }),
    ec2: new EC2Client({ region: 'us-east-1', credentials: {} as any }),
    cloudtrail: new CloudTrailClient({ region: 'us-east-1', credentials: {} as any }),
    getAccountId: async () => {
      if (!accountId) throw new Error('no account id');
      return accountId;
    },
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
  } as unknown as AWSClient;
}

// Default "nothing configured" responses so every per-function sub-check
// resolves cleanly unless a test overrides it. Keeps each test focused on
// the one code path it's exercising instead of hand-wiring every command.
function stubDefaults() {
  lambdaMock.on(GetPolicyCommand).rejects(
    Object.assign(new Error('The resource you requested does not exist.'), {
      name: 'ResourceNotFoundException',
    })
  );
  lambdaMock.on(GetFunctionUrlConfigCommand).rejects(
    Object.assign(new Error('no url config'), { name: 'ResourceNotFoundException' })
  );
  lambdaMock.on(GetFunctionCommand).rejects(new Error('no code available'));
  lambdaMock.on(GetFunctionConcurrencyCommand).resolves({ ReservedConcurrentExecutions: 5 });
  lambdaMock.on(ListAliasesCommand).resolves({ Aliases: [] });
  cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [] });
  ec2Mock.on(DescribeSubnetsCommand).resolves({ Subnets: [] });
}

describe('LambdaScanner', () => {
  beforeEach(() => {
    lambdaMock.reset();
    ec2Mock.reset();
    cloudtrailMock.reset();
    stubDefaults();
  });

  describe('scan() — no functions', () => {
    it('returns an empty array when the account has no Lambda functions', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({ Functions: [] });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });

  describe('scan() — pagination', () => {
    it('follows the Marker/NextMarker pagination loop across two pages of functions', async () => {
      lambdaMock
        .on(ListFunctionsCommand)
        .resolvesOnce({
          Functions: [
            {
              FunctionName: 'page-one-fn',
              FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:page-one-fn',
              Runtime: 'nodejs20.x',
            },
          ],
          NextMarker: 'page2',
        })
        .resolvesOnce({
          Functions: [
            {
              FunctionName: 'page-two-fn',
              FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:page-two-fn',
              Runtime: 'nodejs20.x',
            },
          ],
        });

      const scanner = new LambdaScanner(makeMockClient());
      await scanner.scan();

      const calls = lambdaMock.commandCalls(ListFunctionsCommand);
      expect(calls).toHaveLength(2);
      expect(calls[0].args[0].input.Marker).toBeUndefined();
      expect(calls[1].args[0].input.Marker).toBe('page2');
    });
  });

  describe('scan() — EOL / deprecated runtime', () => {
    it('emits awslambda_function_using_supported_runtimes for an EOL runtime', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'old-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:old-fn',
            Runtime: 'python2.7',
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'awslambda_function_using_supported_runtimes');
      expect(finding).toBeDefined();
      expect(finding!.service).toBe('Lambda');
      expect(finding!.evidence.runtime).toBe('python2.7');
      expect(finding!.evidence.functionName).toBe('old-fn');
    });

    it('emits lambda_function_deprecated_runtime for a deprecated (but not EOL) runtime', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'aging-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:aging-fn',
            Runtime: 'nodejs16.x',
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'lambda_function_deprecated_runtime');
      expect(finding).toBeDefined();
      expect(finding!.evidence.runtime).toBe('nodejs16.x');
    });

    it('does not flag a current, supported runtime', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'current-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:current-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'awslambda_function_using_supported_runtimes')).toBeUndefined();
      expect(findings.find((f) => f.checkId === 'lambda_function_deprecated_runtime')).toBeUndefined();
    });
  });

  describe('scan() — environment variable secrets', () => {
    it('flags a suspicious environment variable value that is not a safe reference', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'env-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:env-fn',
            Runtime: 'nodejs20.x',
            Environment: { Variables: { DB_PASSWORD: 'hunter2literal' } },
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'awslambda_function_no_secrets_in_variables');
      expect(finding).toBeDefined();
      expect(finding!.evidence.variableName).toBe('DB_PASSWORD');
      expect(finding!.evidence.variableNames).toContain('DB_PASSWORD');
    });

    it('does not flag a sensitive-looking key whose value is a safe reference', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'safe-env-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:safe-env-fn',
            Runtime: 'nodejs20.x',
            Environment: {
              Variables: { API_TOKEN: 'arn:aws:secretsmanager:us-east-1:111111111111:secret:foo' },
            },
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'awslambda_function_no_secrets_in_variables')).toBeUndefined();
    });
  });

  describe('scan() — resource policy (public access)', () => {
    it('emits awslambda_function_not_publicly_accessible when the policy allows Principal "*"', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'public-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:public-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      lambdaMock.on(GetPolicyCommand).resolves({
        Policy: JSON.stringify({
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: 'lambda:InvokeFunction',
            },
          ],
        }),
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'awslambda_function_not_publicly_accessible');
      expect(finding).toBeDefined();
      expect(finding!.evidence.functionName).toBe('public-fn');
      expect(finding!.severity).toBeDefined();
    });

    it('does not flag a function with no resource policy (ResourceNotFoundException)', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'private-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:private-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      // stubDefaults() already rejects GetPolicyCommand with ResourceNotFoundException

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'awslambda_function_not_publicly_accessible')).toBeUndefined();
    });
  });

  describe('scan() — function URL', () => {
    it('emits awslambda_function_url_public and awslambda_function_url_cors_policy for an unauthenticated, wildcard-CORS URL', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'url-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:url-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      lambdaMock.on(GetFunctionUrlConfigCommand).resolves({
        FunctionUrl: 'https://abc123.lambda-url.us-east-1.on.aws/',
        AuthType: 'NONE',
        Cors: { AllowOrigins: ['*'] },
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const publicFinding = findings.find((f) => f.checkId === 'awslambda_function_url_public');
      expect(publicFinding).toBeDefined();
      expect(publicFinding!.evidence.authType).toBe('NONE');

      const corsFinding = findings.find((f) => f.checkId === 'awslambda_function_url_cors_policy');
      expect(corsFinding).toBeDefined();
      expect(corsFinding!.evidence.allowOrigins).toContain('*');
    });

    it('does not flag a function URL that requires AWS_IAM auth and has no wildcard CORS', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'secure-url-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:secure-url-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      lambdaMock.on(GetFunctionUrlConfigCommand).resolves({
        FunctionUrl: 'https://def456.lambda-url.us-east-1.on.aws/',
        AuthType: 'AWS_IAM',
        Cors: { AllowOrigins: ['https://trusted.example.com'] },
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'awslambda_function_url_public')).toBeUndefined();
      expect(findings.find((f) => f.checkId === 'awslambda_function_url_cors_policy')).toBeUndefined();
    });
  });

  describe('scan() — dead letter queue / VPC / code signing config', () => {
    it('emits no-DLQ and no-code-signing findings for a bare-minimum function', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'bare-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:bare-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'awslambda_function_no_dead_letter_queue')).toBeDefined();
      expect(findings.find((f) => f.checkId === 'lambda_function_code_signing_enabled')).toBeDefined();
    });

    it('flags awslambda_function_inside_vpc only when the function name matches the sensitive pattern and has no VPC', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'payment-processor',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:payment-processor',
            Runtime: 'nodejs20.x',
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'awslambda_function_inside_vpc')).toBeDefined();
    });
  });

  describe('scan() — reserved concurrency', () => {
    it('emits lambda_function_no_reserved_concurrency for a sensitive-named function with no reserved concurrency', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'billing-worker',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:billing-worker',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      lambdaMock.on(GetFunctionConcurrencyCommand).resolves({ ReservedConcurrentExecutions: undefined });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'lambda_function_no_reserved_concurrency');
      expect(finding).toBeDefined();
      expect(finding!.evidence.functionName).toBe('billing-worker');
    });

    it('does not check concurrency for a function whose name has no sensitive-pattern match', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'generic-handler',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:generic-handler',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      lambdaMock.on(GetFunctionConcurrencyCommand).resolves({ ReservedConcurrentExecutions: undefined });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'lambda_function_no_reserved_concurrency')).toBeUndefined();
      expect(lambdaMock.commandCalls(GetFunctionConcurrencyCommand)).toHaveLength(0);
    });
  });

  describe('scan() — aliases pointing to $LATEST', () => {
    it('emits lambda_function_alias_points_to_latest when an alias targets $LATEST', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'alias-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:alias-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      lambdaMock.on(ListAliasesCommand).resolves({
        Aliases: [{ Name: 'prod', FunctionVersion: '$LATEST' }],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'lambda_function_alias_points_to_latest');
      expect(finding).toBeDefined();
      expect(finding!.evidence.aliases).toContain('prod');
    });

    it('does not flag aliases pointing to a numbered version', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'alias-fn-2',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:alias-fn-2',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      lambdaMock.on(ListAliasesCommand).resolves({
        Aliases: [{ Name: 'prod', FunctionVersion: '3' }],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'lambda_function_alias_points_to_latest')).toBeUndefined();
    });
  });

  describe('scan() — CMK encryption of environment variables', () => {
    it('flags env vars encrypted with the default key (no KMSKeyArn)', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'cmk-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:cmk-fn',
            Runtime: 'nodejs20.x',
            Environment: { Variables: { FOO: 'bar' } },
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find(
        (f) => f.checkId === 'awslambda_function_env_vars_not_encrypted_with_cmk'
      );
      expect(finding).toBeDefined();
      expect(finding!.evidence.environmentVariableCount).toBe(1);
    });

    it('does not flag when a customer-managed KMS key is set', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'cmk-fn-2',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:cmk-fn-2',
            Runtime: 'nodejs20.x',
            Environment: { Variables: { FOO: 'bar' } },
            KMSKeyArn: 'arn:aws:kms:us-east-1:111111111111:key/abcd-1234',
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(
        findings.find((f) => f.checkId === 'awslambda_function_env_vars_not_encrypted_with_cmk')
      ).toBeUndefined();
    });
  });

  describe('scan() — cross-account layers', () => {
    it('emits awslambda_function_using_cross_account_layers for a layer owned by a different account', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'layered-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:layered-fn',
            Runtime: 'nodejs20.x',
            Layers: [{ Arn: 'arn:aws:lambda:us-east-1:999999999999:layer:external-layer:1' }],
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient('111111111111'));
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'awslambda_function_using_cross_account_layers');
      expect(finding).toBeDefined();
      expect(finding!.evidence.crossAccountLayers).toContain(
        'arn:aws:lambda:us-east-1:999999999999:layer:external-layer:1'
      );
    });

    it('does not flag a layer owned by the audited account', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'own-layer-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:own-layer-fn',
            Runtime: 'nodejs20.x',
            Layers: [{ Arn: 'arn:aws:lambda:us-east-1:111111111111:layer:internal-layer:2' }],
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient('111111111111'));
      const findings = await scanner.scan();

      expect(
        findings.find((f) => f.checkId === 'awslambda_function_using_cross_account_layers')
      ).toBeUndefined();
    });

    it('skips the cross-account layer check entirely when the account ID cannot be resolved', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'no-account-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:no-account-fn',
            Runtime: 'nodejs20.x',
            Layers: [{ Arn: 'arn:aws:lambda:us-east-1:999999999999:layer:external-layer:1' }],
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient(null));
      const findings = await scanner.scan();

      expect(
        findings.find((f) => f.checkId === 'awslambda_function_using_cross_account_layers')
      ).toBeUndefined();
    });
  });

  describe('scan() — VPC multi-AZ', () => {
    it('flags a non-sensitive-named function with no VPC config', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'no-vpc-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:no-vpc-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'awslambda_function_vpc_multi_az');
      expect(finding).toBeDefined();
      expect(finding!.evidence.vpcId).toBeNull();
    });

    it('flags a VPC-attached function whose subnets resolve to only one Availability Zone', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'single-az-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:single-az-fn',
            Runtime: 'nodejs20.x',
            VpcConfig: { VpcId: 'vpc-123', SubnetIds: ['subnet-a', 'subnet-b'] },
          },
        ],
      });
      ec2Mock.on(DescribeSubnetsCommand).resolves({
        Subnets: [
          { SubnetId: 'subnet-a', AvailabilityZone: 'us-east-1a' },
          { SubnetId: 'subnet-b', AvailabilityZone: 'us-east-1a' },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'awslambda_function_vpc_multi_az');
      expect(finding).toBeDefined();
      expect(finding!.evidence.vpcId).toBe('vpc-123');
      expect(finding!.evidence.availabilityZones).toEqual(['us-east-1a']);
    });

    it('does not flag a VPC-attached function whose subnets span two Availability Zones', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'multi-az-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:multi-az-fn',
            Runtime: 'nodejs20.x',
            VpcConfig: { VpcId: 'vpc-456', SubnetIds: ['subnet-c', 'subnet-d'] },
          },
        ],
      });
      ec2Mock.on(DescribeSubnetsCommand).resolves({
        Subnets: [
          { SubnetId: 'subnet-c', AvailabilityZone: 'us-east-1a' },
          { SubnetId: 'subnet-d', AvailabilityZone: 'us-east-1b' },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'awslambda_function_vpc_multi_az')).toBeUndefined();
    });
  });

  describe('scan() — CloudTrail Invoke logging coverage', () => {
    it('emits the cloudtrail-logging finding when no trail covers Lambda data events', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'untrailed-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:untrailed-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      cloudtrailMock.on(DescribeTrailsCommand).resolves({
        trailList: [{ Name: 'main-trail', TrailARN: 'arn:aws:cloudtrail:us-east-1:111111111111:trail/main-trail' }],
      });
      cloudtrailMock.on(GetEventSelectorsCommand).resolves({
        EventSelectors: [{ DataResources: [] }],
        AdvancedEventSelectors: [],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      const finding = findings.find(
        (f) => f.checkId === 'awslambda_function_invoke_api_operations_cloudtrail_logging_enabled'
      );
      expect(finding).toBeDefined();
      expect(finding!.evidence.functionName).toBe('untrailed-fn');
    });

    it('does not flag when an advanced event selector covers all Lambda functions', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'trailed-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:trailed-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      cloudtrailMock.on(DescribeTrailsCommand).resolves({
        trailList: [{ Name: 'main-trail', TrailARN: 'arn:aws:cloudtrail:us-east-1:111111111111:trail/main-trail' }],
      });
      cloudtrailMock.on(GetEventSelectorsCommand).resolves({
        EventSelectors: [],
        AdvancedEventSelectors: [
          {
            FieldSelectors: [
              { Field: 'eventCategory', Equals: ['Data'] },
              { Field: 'resources.type', Equals: ['AWS::Lambda::Function'] },
            ],
          },
        ],
      });

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(
        findings.find(
          (f) => f.checkId === 'awslambda_function_invoke_api_operations_cloudtrail_logging_enabled'
        )
      ).toBeUndefined();
    });

    it('skips the cloudtrail-logging check when trails cannot be listed', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'trail-error-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:trail-error-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      cloudtrailMock.on(DescribeTrailsCommand).rejects(new Error('AccessDenied'));

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(
        findings.find(
          (f) => f.checkId === 'awslambda_function_invoke_api_operations_cloudtrail_logging_enabled'
        )
      ).toBeUndefined();
    }, 20000);
  });

  describe('scan() — error handling', () => {
    it('does not throw and returns an empty array when ListFunctions itself fails repeatedly', async () => {
      lambdaMock.on(ListFunctionsCommand).rejects(new Error('ThrottlingException'));

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    }, 20000);

    it('continues scanning a function when its GetPolicy call fails with an unexpected error', async () => {
      lambdaMock.on(ListFunctionsCommand).resolves({
        Functions: [
          {
            FunctionName: 'policy-error-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:111111111111:function:policy-error-fn',
            Runtime: 'nodejs20.x',
          },
        ],
      });
      lambdaMock.on(GetPolicyCommand).rejects(new Error('InternalServiceError'));

      const scanner = new LambdaScanner(makeMockClient());
      const findings = await scanner.scan();

      // The policy check itself yields nothing (error swallowed by the caller's
      // try/catch in scan()), but other checks for the same function still run.
      expect(findings.find((f) => f.checkId === 'awslambda_function_no_dead_letter_queue')).toBeDefined();
      expect(findings.find((f) => f.checkId === 'awslambda_function_not_publicly_accessible')).toBeUndefined();
    }, 20000);
  });
});
