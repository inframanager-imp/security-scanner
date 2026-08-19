import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const ssmChecks: CheckMetadata[] = [
  {
    checkId: 'ssm_parameter_store_plaintext_secrets',
    provider: 'aws',
    service: 'ssm',
    title: 'SSM Parameter Store Plaintext Secrets Detected',
    severity: 'HIGH',
    description: 'Checks for SSM Parameters with secret-like names stored as plaintext "String" type instead of "SecureString"; plaintext parameters are readable by anyone with ssm:GetParameter permission and appear in logs unredacted.',
    remediation: 'Convert to SecureString type: aws ssm put-parameter --name <name> --value <value> --type SecureString --key-id <kms-key-id> --overwrite. Use KMS CMK for encryption.',
    tags: ['ssm', 'secrets', 'encryption'],
  },
  {
    checkId: 'ssm_parameter_confirmed_credential',
    provider: 'aws',
    service: 'ssm',
    title: 'SSM Plaintext Parameter Contains Real Credential',
    severity: 'CRITICAL',
    description: 'Checks whether plaintext SSM Parameters contain values matching known credential formats (AWS keys, GitHub/Slack/OpenAI tokens, private keys) — a confirmed credential leak, not a heuristic match.',
    remediation: 'Rotate the credential immediately and re-create the parameter as SecureString with a KMS CMK.',
    tags: ['ssm', 'secrets', 'confirmed-credential'],
  },
  {
    checkId: 'ssm_managed_compliant_patching',
    provider: 'aws',
    service: 'ssm',
    title: 'EC2 Instances Missing Critical Security Patches',
    severity: 'HIGH',
    description: 'Checks SSM-managed instances for unresolved patch compliance issues (missing critical or security patches).',
    remediation: 'Run patch remediation via SSM Patch Manager: aws ssm send-command --document-name AWS-RunPatchBaseline --targets Key=InstanceIds,Values=<instance-ids> --parameters Operation=Install',
    tags: ['ssm', 'patch', 'compliance'],
  },
  {
    checkId: 'ec2_instance_managed_by_ssm',
    provider: 'aws',
    service: 'ssm',
    title: 'EC2 Instances Not Managed by SSM',
    severity: 'MEDIUM',
    description: 'Checks that running EC2 instances are registered with AWS Systems Manager; unmanaged instances cannot use Session Manager (SSH-free access), patch management, or Run Command.',
    remediation: 'Install the SSM Agent on unmanaged instances and attach an IAM role with AmazonSSMManagedInstanceCore policy. Use Session Manager instead of SSH to eliminate the need for inbound port 22.',
    tags: ['ssm', 'ec2', 'access'],
  },
];
