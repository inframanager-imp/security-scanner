// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const datapipelineChecks: CheckMetadata[] = [
  {
    checkId: 'datapipeline_pipeline_no_secrets_in_definition',
    provider: 'aws',
    service: 'datapipeline',
    title: 'Data Pipeline Definition Contains Hardcoded Secrets',
    severity: 'HIGH',
    description: 'Checks Data Pipeline definitions (pipeline objects, parameter objects and parameter values) for hardcoded credentials such as keys, tokens, passwords and database credentials, which are visible to anyone with pipeline read access and can leak through scripts and logs.',
    remediation: 'Remove plaintext credentials from the pipeline definition; store them in AWS Secrets Manager or SSM Parameter Store, grant the pipeline role least-privilege access to retrieve them at runtime, and rotate any exposed credentials.',
    tags: ['datapipeline', 'secrets', 'credentials'],
  },
];
