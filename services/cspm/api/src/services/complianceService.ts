/**
 * Compliance scoring engine — PCI DSS, SOC 2, ISO 27001, HIPAA, CIS AWS Foundations Benchmark.
 *
 * A control PASSES when zero OPEN/ACKNOWLEDGED findings map to it.
 * A control is NOT_EVALUATED when no scanner covers it (findingTitles is empty).
 * Score = passing / (passing + failing) * 100  (NOT_EVALUATED excluded from denominator).
 */

export type FrameworkId = 'PCI_DSS' | 'SOC2' | 'ISO27001' | 'HIPAA' | 'CIS_AWS' | 'NIST_800_53' | 'GDPR' | 'FEDRAMP';

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  /** Empty array = control cannot be evaluated by our scanners → NOT_EVALUATED */
  findingTitles: string[];
}

export interface ComplianceFramework {
  id: FrameworkId;
  name: string;
  shortName: string;
  controls: ComplianceControl[];
}

export interface ControlResult extends ComplianceControl {
  status: 'PASS' | 'FAIL' | 'NOT_EVALUATED';
  failingFindings: number;
}

export interface FrameworkScore {
  frameworkId: FrameworkId;
  frameworkName: string;
  shortName: string;
  score: number;           // 0–100 (excludes NOT_EVALUATED from denominator)
  passingControls: number;
  failingControls: number;
  notEvaluatedControls: number;
  totalControls: number;
  controls: ControlResult[];
}

// ---------------------------------------------------------------------------
// Shared finding title sets used across multiple frameworks
// ---------------------------------------------------------------------------

const LAMBDA_FINDINGS = [
  'Lambda EOL Runtime',
  'Lambda Deprecated Runtime',
  'Lambda Sensitive Environment Variable',
  'Lambda Public Function',
  'Lambda Vulnerable Dependency',
  'Lambda No Dead Letter Queue',
  'Lambda Sensitive Function Not in VPC',
  'Lambda No Code Signing',
];

// ECR container image findings
const ECR_CVE_FINDINGS = [
  'ECR Image OS Package CVE',
  'ECR Image High Severity CVEs',
  'ECR Image Medium/Low CVEs',
];

const ECR_CONFIG_FINDINGS = [
  'ECR Enhanced Scanning Not Enabled',
  'ECR Scan on Push Disabled',
  'ECR Image Scan Failed',
];

const ECR_FINDINGS = [...ECR_CONFIG_FINDINGS, ...ECR_CVE_FINDINGS];

const CIS_MONITORING_FINDINGS = [
  'Unauthorized API Calls Not Monitored',
  'Console Sign-In Without MFA Not Monitored',
  'Root Account Usage Not Monitored',
  'IAM Policy Changes Not Monitored',
  'CloudTrail Config Changes Not Monitored',
  'Console Authentication Failures Not Monitored',
  'CMK Deletion Not Monitored',
  'S3 Bucket Policy Changes Not Monitored',
  'AWS Config Changes Not Monitored',
  'Security Group Changes Not Monitored',
  'NACL Changes Not Monitored',
  'Network Gateway Changes Not Monitored',
  'Route Table Changes Not Monitored',
  'VPC Changes Not Monitored',
  'AWS Organization Changes Not Monitored',
  'CloudWatch Monitoring Not Configured',
];

// ---------------------------------------------------------------------------
// Framework definitions
// ---------------------------------------------------------------------------

export const FRAMEWORKS: ComplianceFramework[] = [
  // ─────────────────────────────────────────────────────────────────────────
  // PCI DSS v3.2.1
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'PCI_DSS',
    name: 'PCI DSS v3.2.1',
    shortName: 'PCI DSS',
    controls: [
      {
        id: 'PCI-1.1',
        name: 'Network Access Controls',
        description: 'Restrict inbound and outbound traffic to only that which is necessary.',
        findingTitles: [
          'Overly Permissive Security Group Rule',
          'Overly Permissive Network ACL',
          'Instance Has Public IP Without Security Group',
          'Publicly Reachable EC2 Instance',
          'Default Security Group Not Restricted',
          'VPC Peering Route Not Least Access',
        ],
      },
      {
        id: 'PCI-2.1',
        name: 'Secure System Configurations',
        description: 'Do not use vendor-supplied defaults; disable unnecessary services.',
        findingTitles: [
          'IMDSv1 Enabled',
          'Detailed Monitoring Not Enabled',
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          'Lambda No Code Signing',
          ...ECR_CONFIG_FINDINGS,
        ],
      },
      {
        id: 'PCI-3.4',
        name: 'Data-at-Rest Encryption',
        description: 'Render PAN unreadable anywhere it is stored.',
        findingTitles: [
          'S3 Bucket Not Encrypted',
          'Using SSE-S3 Instead of KMS',
          'RDS Not Encrypted',
          'RDS Cluster Not Encrypted',
          'Secret Using Default Encryption',
          'EBS Default Encryption Not Enabled',
          'S3 MFA Delete Not Enabled',
          'Lambda Vulnerable Dependency',
          ...ECR_CVE_FINDINGS,
        ],
      },
      {
        id: 'PCI-3.6',
        name: 'Key Management',
        description: 'Fully document and implement key-management processes and procedures.',
        findingTitles: [
          'KMS Key Pending Deletion',
          'KMS Key Disabled',
          'KMS Key Rotation Not Enabled',
        ],
      },
      {
        id: 'PCI-4.1',
        name: 'Encryption in Transit',
        description: 'Use strong cryptography to safeguard PAN during transmission over open, public networks.',
        findingTitles: ['S3 HTTPS Not Enforced'],
      },
      {
        id: 'PCI-7.1',
        name: 'Least Privilege Access',
        description: 'Limit access to system components to only those individuals whose job requires such access.',
        findingTitles: [
          'Overly Permissive Policy',
          'No Policies Attached',
          'Root Account Security',
          'Root Access Key Exists',
          'Root Account MFA Not Enabled',
          'IAM Support Role Not Configured',
          'Lambda Public Function',
          'Lambda Sensitive Environment Variable',
        ],
      },
      {
        id: 'PCI-8.1',
        name: 'User Authentication',
        description: 'Assign a unique ID to each person with computer access.',
        findingTitles: [
          'MFA Not Verified for User',
          'Console Access Without MFA',
          'Old Access Key',
          'Unused Access Key',
          'Inactive Access Key',
          'Multiple Access Keys',
          'User Never Logged In',
          'Inactive User',
          'Password Policy Review Required',
          'Password Policy Minimum Length',
          'Password Policy Reuse Prevention',
          'IAM Access Analyzer Not Enabled',
        ],
      },
      {
        id: 'PCI-10.1',
        name: 'Audit Logging & Monitoring',
        description: 'Implement audit trails to link all access to system components to each individual user.',
        findingTitles: [
          'No CloudTrail Found',
          'CloudTrail Not Logging',
          'Single Region CloudTrail',
          'Log File Validation Not Enabled',
          'CloudWatch Logs Not Configured',
          'Management Events Not Logged',
          'S3 Access Logging Not Enabled',
          'S3 Logs Not KMS Encrypted',
          'S3 Bucket Not Configured',
          'VPC Flow Logs Not Enabled',
          'AWS Config Not Enabled',
          'S3 Object Logging Not Enabled',
          ...CIS_MONITORING_FINDINGS,
        ],
      },
      {
        id: 'PCI-11.2',
        name: 'Public Exposure Controls',
        description: 'Run internal and external network vulnerability scans.',
        findingTitles: [
          'Database Publicly Accessible',
          'Public Access Not Fully Blocked',
          'Bucket Has Public ACL Grants',
          'Publicly Reachable EC2 Instance',
          'Default Security Group Not Restricted',
          'VPC Peering Route Not Least Access',
          ...ECR_CVE_FINDINGS,
        ],
      },
      {
        id: 'PCI-12.1',
        name: 'Data Backup & Recovery',
        description: 'Maintain and test incident response and business continuity plans.',
        findingTitles: [
          'Secret Scheduled for Deletion',
          'Secret Rotation Not Enabled',
          'Short Backup Retention',
          'Short Cluster Backup Retention',
          'Deletion Protection Not Enabled',
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // SOC 2 Type II
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'SOC2',
    name: 'SOC 2 Type II',
    shortName: 'SOC 2',
    controls: [
      {
        id: 'CC6.1',
        name: 'Logical Access Security',
        description: 'Logical access security software, infrastructure, and architectures are implemented.',
        findingTitles: [
          'MFA Not Verified for User',
          'Console Access Without MFA',
          'Root Account Security',
          'Root Access Key Exists',
          'Root Account MFA Not Enabled',
          'Overly Permissive Policy',
          'No Policies Attached',
          'Multiple Access Keys',
          'Inactive User',
          'User Never Logged In',
          'Password Policy Review Required',
          'Password Policy Minimum Length',
          'Password Policy Reuse Prevention',
          'IAM Access Analyzer Not Enabled',
          'IAM Support Role Not Configured',
        ],
      },
      {
        id: 'CC6.2',
        name: 'Access Credential Management',
        description: 'Prior to issuing system credentials, registered users are authorized.',
        findingTitles: [
          'Old Access Key',
          'Unused Access Key',
          'Inactive Access Key',
        ],
      },
      {
        id: 'CC6.7',
        name: 'Data Transmission & Exposure',
        description: 'Restrict transmission of data to authorized parties.',
        findingTitles: [
          'Database Publicly Accessible',
          'Public Access Not Fully Blocked',
          'Bucket Has Public ACL Grants',
          'Instance Has Public IP Without Security Group',
          'Publicly Reachable EC2 Instance',
          'S3 HTTPS Not Enforced',
          'Default Security Group Not Restricted',
          'VPC Peering Route Not Least Access',
        ],
      },
      {
        id: 'CC7.2',
        name: 'System Monitoring',
        description: 'System performance is monitored and deviations from expectations are investigated.',
        findingTitles: [
          'No CloudTrail Found',
          'CloudTrail Not Logging',
          'Log File Validation Not Enabled',
          'CloudWatch Logs Not Configured',
          'Management Events Not Logged',
          'S3 Access Logging Not Enabled',
          'Detailed Monitoring Not Enabled',
          'VPC Flow Logs Not Enabled',
          'AWS Config Not Enabled',
          'S3 Object Logging Not Enabled',
          ...CIS_MONITORING_FINDINGS,
        ],
      },
      {
        id: 'CC8.1',
        name: 'Change Management',
        description: 'Infrastructure and software changes are authorized, designed, developed, configured, documented, tested, approved, and implemented.',
        findingTitles: [
          'KMS Key Pending Deletion',
          'KMS Key Disabled',
          'KMS Key Rotation Not Enabled',
          'Secret Scheduled for Deletion',
          'Secret Rotation Not Enabled',
        ],
      },
      {
        id: 'A1.2',
        name: 'Availability & Resiliency',
        description: 'Current processing capacity and usage are maintained to meet availability commitments.',
        findingTitles: [
          'Multi-AZ Not Enabled',
          'Short Backup Retention',
          'Deletion Protection Not Enabled',
          'Short Cluster Backup Retention',
          'Secret Not Replicated',
        ],
      },
      {
        id: 'C1.1',
        name: 'Confidentiality of Data',
        description: 'Confidential information is identified and handled per policies.',
        findingTitles: [
          'S3 Bucket Not Encrypted',
          'Using SSE-S3 Instead of KMS',
          'RDS Not Encrypted',
          'RDS Cluster Not Encrypted',
          'Secret Using Default Encryption',
          'EBS Default Encryption Not Enabled',
          'S3 MFA Delete Not Enabled',
          'S3 HTTPS Not Enforced',
          'Overly Permissive Security Group Rule',
          'Overly Permissive Network ACL',
          'Default Security Group Not Restricted',
          'Lambda Sensitive Environment Variable',
          'Lambda Vulnerable Dependency',
        ],
      },
      {
        id: 'CC6.8',
        name: 'Software Vulnerability Management',
        description: 'The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.',
        findingTitles: [
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          'Lambda Vulnerable Dependency',
          'Lambda No Code Signing',
          'Lambda Public Function',
          ...ECR_FINDINGS,
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // ISO/IEC 27001:2022
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'ISO27001',
    name: 'ISO/IEC 27001:2022',
    shortName: 'ISO 27001',
    controls: [
      {
        id: 'A.5.15',
        name: 'Access Control',
        description: 'Rules to control physical and logical access to information assets.',
        findingTitles: [
          'MFA Not Verified for User',
          'Console Access Without MFA',
          'Overly Permissive Policy',
          'No Policies Attached',
          'Root Account Security',
          'Root Access Key Exists',
          'Root Account MFA Not Enabled',
          'Multiple Access Keys',
          'Inactive User',
          'User Never Logged In',
        ],
      },
      {
        id: 'A.5.16',
        name: 'Identity Management',
        description: 'Full lifecycle management of identities and their access.',
        findingTitles: [
          'Old Access Key',
          'Unused Access Key',
          'Inactive Access Key',
          'Password Policy Review Required',
          'Password Policy Minimum Length',
          'Password Policy Reuse Prevention',
          'IAM Access Analyzer Not Enabled',
          'IAM Support Role Not Configured',
        ],
      },
      {
        id: 'A.8.24',
        name: 'Cryptography',
        description: 'Proper use of cryptography to protect information confidentiality, integrity, and availability.',
        findingTitles: [
          'S3 Bucket Not Encrypted',
          'Using SSE-S3 Instead of KMS',
          'RDS Not Encrypted',
          'RDS Cluster Not Encrypted',
          'KMS Key Rotation Not Enabled',
          'KMS Key Disabled',
          'KMS Key Pending Deletion',
          'Secret Using Default Encryption',
          'EBS Default Encryption Not Enabled',
          'S3 MFA Delete Not Enabled',
          'S3 HTTPS Not Enforced',
        ],
      },
      {
        id: 'A.8.15',
        name: 'Logging & Monitoring',
        description: 'Event logs recording user activities, exceptions, faults, and information security events.',
        findingTitles: [
          'No CloudTrail Found',
          'CloudTrail Not Logging',
          'Log File Validation Not Enabled',
          'CloudWatch Logs Not Configured',
          'S3 Access Logging Not Enabled',
          'Detailed Monitoring Not Enabled',
          'Management Events Not Logged',
          'S3 Logs Not KMS Encrypted',
          'S3 Bucket Not Configured',
          'Single Region CloudTrail',
          'VPC Flow Logs Not Enabled',
          'AWS Config Not Enabled',
          'S3 Object Logging Not Enabled',
          ...CIS_MONITORING_FINDINGS,
        ],
      },
      {
        id: 'A.8.20',
        name: 'Network Security',
        description: 'Networks and network devices are managed and controlled.',
        findingTitles: [
          'Overly Permissive Security Group Rule',
          'Overly Permissive Network ACL',
          'Database Publicly Accessible',
          'Public Access Not Fully Blocked',
          'Bucket Has Public ACL Grants',
          'Instance Has Public IP Without Security Group',
          'Publicly Reachable EC2 Instance',
          'Default Security Group Not Restricted',
          'VPC Peering Route Not Least Access',
        ],
      },
      {
        id: 'A.8.9',
        name: 'Configuration Management',
        description: 'Configurations of hardware, software, services, and networks shall be established and managed.',
        findingTitles: [
          'IMDSv1 Enabled',
          'EBS Default Encryption Not Enabled',
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          'Lambda No Code Signing',
          'Lambda Sensitive Function Not in VPC',
          ...ECR_CONFIG_FINDINGS,
        ],
      },
      {
        id: 'A.8.8',
        name: 'Software Vulnerabilities',
        description: 'Information about technical vulnerabilities of information systems shall be obtained and the exposure evaluated.',
        findingTitles: [
          'Lambda Vulnerable Dependency',
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          ...ECR_CVE_FINDINGS,
        ],
      },
      {
        id: 'A.8.13',
        name: 'Information Backup',
        description: 'Backup copies of information, software, and systems shall be maintained and regularly tested.',
        findingTitles: [
          'Multi-AZ Not Enabled',
          'Short Backup Retention',
          'Deletion Protection Not Enabled',
          'Short Cluster Backup Retention',
          'Secret Not Replicated',
        ],
      },
      {
        id: 'A.8.12',
        name: 'Data Leakage Prevention',
        description: 'Measures applied to systems, networks, and devices to prevent data leakage.',
        findingTitles: [
          'Secret Scheduled for Deletion',
          'Secret Rotation Not Enabled',
          'S3 HTTPS Not Enforced',
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // HIPAA Security Rule
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'HIPAA',
    name: 'HIPAA Security Rule',
    shortName: 'HIPAA',
    controls: [
      {
        id: 'HIPAA-164.312(a)',
        name: 'Access Controls',
        description: 'Implement technical policies and procedures for allowing access only to authorized persons.',
        findingTitles: [
          'MFA Not Verified for User',
          'Console Access Without MFA',
          'Overly Permissive Policy',
          'Root Account Security',
          'Root Access Key Exists',
          'Root Account MFA Not Enabled',
          'No Policies Attached',
          'Multiple Access Keys',
        ],
      },
      {
        id: 'HIPAA-164.312(b)',
        name: 'Audit Controls',
        description: 'Implement hardware, software, and/or procedural mechanisms to record access to ePHI.',
        findingTitles: [
          'No CloudTrail Found',
          'CloudTrail Not Logging',
          'Log File Validation Not Enabled',
          'CloudWatch Logs Not Configured',
          'S3 Access Logging Not Enabled',
          'Management Events Not Logged',
          'Single Region CloudTrail',
          'S3 Logs Not KMS Encrypted',
          'S3 Bucket Not Configured',
          'VPC Flow Logs Not Enabled',
          'AWS Config Not Enabled',
          'S3 Object Logging Not Enabled',
          ...CIS_MONITORING_FINDINGS,
        ],
      },
      {
        id: 'HIPAA-164.312(c)',
        name: 'Integrity Controls',
        description: 'Implement electronic mechanisms to authenticate ePHI and detect unauthorized alteration.',
        findingTitles: [
          'KMS Key Pending Deletion',
          'KMS Key Disabled',
          'Deletion Protection Not Enabled',
          'S3 MFA Delete Not Enabled',
        ],
      },
      {
        id: 'HIPAA-164.312(e)',
        name: 'Transmission Security / Encryption',
        description: 'Implement technical security measures to guard against unauthorized access to ePHI transmitted over networks.',
        findingTitles: [
          'S3 Bucket Not Encrypted',
          'Using SSE-S3 Instead of KMS',
          'RDS Not Encrypted',
          'RDS Cluster Not Encrypted',
          'Secret Using Default Encryption',
          'KMS Key Rotation Not Enabled',
          'Database Publicly Accessible',
          'Public Access Not Fully Blocked',
          'Bucket Has Public ACL Grants',
          'EBS Default Encryption Not Enabled',
          'S3 HTTPS Not Enforced',
          'Lambda Sensitive Environment Variable',
          'Lambda Vulnerable Dependency',
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          'Lambda Public Function',
          ...ECR_FINDINGS,
        ],
      },
      {
        id: 'HIPAA-164.308(a)(3)',
        name: 'Workforce Access Management',
        description: 'Implement policies and procedures for granting access to ePHI.',
        findingTitles: [
          'Old Access Key',
          'Unused Access Key',
          'Inactive Access Key',
          'User Never Logged In',
          'Inactive User',
          'Password Policy Review Required',
          'Password Policy Minimum Length',
          'Password Policy Reuse Prevention',
          'IAM Access Analyzer Not Enabled',
          'IAM Support Role Not Configured',
        ],
      },
      {
        id: 'HIPAA-164.308(a)(5)',
        name: 'Security Awareness & Training',
        description: 'Implement a security awareness and training program.',
        findingTitles: [
          'Overly Permissive Security Group Rule',
          'Overly Permissive Network ACL',
          'Instance Has Public IP Without Security Group',
          'Publicly Reachable EC2 Instance',
          'IMDSv1 Enabled',
          'Default Security Group Not Restricted',
          ...ECR_CONFIG_FINDINGS,
        ],
      },
      {
        id: 'HIPAA-164.308(a)(7)',
        name: 'Contingency Plan',
        description: 'Establish policies for responding to emergencies or disasters that damage ePHI.',
        findingTitles: [
          'Short Backup Retention',
          'Short Cluster Backup Retention',
          'Multi-AZ Not Enabled',
          'Secret Not Replicated',
          'Secret Scheduled for Deletion',
          'Secret Rotation Not Enabled',
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // CIS AWS Foundations Benchmark v2.0
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'CIS_AWS',
    name: 'CIS AWS Foundations Benchmark v2.0',
    shortName: 'CIS AWS',
    controls: [
      // ── Section 1: Identity and Access Management ──────────────────────
      {
        id: 'CIS-1.1',
        name: 'Maintain current contact details',
        description: 'Ensure AWS account has current contact details registered.',
        findingTitles: [], // cannot be evaluated programmatically
      },
      {
        id: 'CIS-1.2',
        name: 'Ensure security contact information is registered',
        description: 'Ensure a security contact email address is registered for the AWS account.',
        findingTitles: [], // cannot be evaluated programmatically
      },
      {
        id: 'CIS-1.4',
        name: 'Ensure no root user access key exists',
        description: 'The root user must not have active access keys.',
        findingTitles: ['Root Access Key Exists', 'Root Account Security'],
      },
      {
        id: 'CIS-1.5',
        name: 'Ensure MFA is enabled for the root user',
        description: 'The root user account should have MFA enabled.',
        findingTitles: ['Root Account MFA Not Enabled', 'Root Account Security'],
      },
      {
        id: 'CIS-1.6',
        name: 'Ensure hardware MFA is enabled for the root user',
        description: 'A hardware MFA device should be used to protect the root account.',
        findingTitles: [], // cannot distinguish hardware from virtual MFA programmatically
      },
      {
        id: 'CIS-1.7',
        name: 'Eliminate use of the root user for administrative tasks',
        description: 'The root user should not be used for day-to-day administrative tasks.',
        findingTitles: [], // requires reviewing CloudTrail usage patterns — not evaluated
      },
      {
        id: 'CIS-1.8',
        name: 'Ensure IAM password policy requires minimum length of 14',
        description: 'Password policies are a way to enforce the creation and use of password complexity.',
        findingTitles: ['Password Policy Minimum Length', 'Password Policy Review Required'],
      },
      {
        id: 'CIS-1.9',
        name: 'Ensure IAM password policy prevents password reuse',
        description: 'Preventing password reuse increases account resiliency against brute force login.',
        findingTitles: ['Password Policy Reuse Prevention', 'Password Policy Review Required'],
      },
      {
        id: 'CIS-1.10',
        name: 'Ensure MFA is enabled for all IAM users with console access',
        description: 'Multi-Factor Authentication (MFA) adds an extra layer of protection on top of a username and password.',
        findingTitles: ['MFA Not Verified for User', 'Console Access Without MFA'],
      },
      {
        id: 'CIS-1.11',
        name: 'Do not setup access keys during initial user setup',
        description: 'Access keys should not be created for new users; they should use temporary credentials.',
        findingTitles: [], // cannot evaluate initial setup retroactively
      },
      {
        id: 'CIS-1.12',
        name: 'Ensure credentials unused for 45 days or greater are disabled',
        description: 'Dormant credentials should be removed to reduce the attack surface.',
        findingTitles: ['Unused Access Key', 'Inactive Access Key', 'Inactive User', 'User Never Logged In'],
      },
      {
        id: 'CIS-1.13',
        name: 'Ensure there is only one active access key available for any single IAM user',
        description: 'Access keys are long-term credentials for an IAM user. Having only one key reduces risk.',
        findingTitles: ['Multiple Access Keys'],
      },
      {
        id: 'CIS-1.14',
        name: 'Ensure access keys are rotated every 90 days or less',
        description: 'Access keys should be rotated to reduce the risk from compromised credentials.',
        findingTitles: ['Old Access Key'],
      },
      {
        id: 'CIS-1.15',
        name: 'Ensure IAM users receive permissions only through groups',
        description: 'IAM users should receive permissions via groups, not direct policy attachments.',
        findingTitles: ['Overly Permissive Policy'],
      },
      {
        id: 'CIS-1.16',
        name: 'Ensure IAM policies that allow full administrative privileges are not attached',
        description: 'IAM policies should not have full administrative privileges (*:*).',
        findingTitles: ['Overly Permissive Policy', 'No Policies Attached'],
      },
      {
        id: 'CIS-1.17',
        name: 'Ensure a support role has been created to manage incidents with AWS Support',
        description: 'A dedicated support role with AWSSupportAccess policy should exist.',
        findingTitles: ['IAM Support Role Not Configured'],
      },
      {
        id: 'CIS-1.18',
        name: 'Ensure IAM instance roles are used for AWS resource access from instances',
        description: 'EC2 instances should use IAM roles rather than access keys for AWS API access.',
        findingTitles: [], // cannot be evaluated without inspecting instance metadata
      },
      {
        id: 'CIS-1.20',
        name: 'Ensure that IAM Access Analyzer is enabled for all regions',
        description: 'IAM Access Analyzer helps identify external access to AWS resources.',
        findingTitles: ['IAM Access Analyzer Not Enabled'],
      },
      {
        id: 'CIS-1.22',
        name: 'Ensure access to AWSCloudShellFullAccess is restricted',
        description: 'AWS CloudShell is a browser-based shell; unrestricted access can lead to data exfiltration.',
        findingTitles: [], // requires inspecting specific policy usage — not evaluated
      },
      // ── Section 2: Storage ─────────────────────────────────────────────
      {
        id: 'CIS-2.1.1',
        name: 'Ensure S3 Bucket Policy is set to deny HTTP requests',
        description: 'S3 buckets should enforce HTTPS-only access via bucket policy.',
        findingTitles: ['S3 HTTPS Not Enforced'],
      },
      {
        id: 'CIS-2.1.2',
        name: 'Ensure MFA Delete is enabled on S3 buckets',
        description: 'MFA Delete requires additional authentication before deleting versioned objects.',
        findingTitles: ['S3 MFA Delete Not Enabled'],
      },
      {
        id: 'CIS-2.1.3',
        name: 'Ensure all data in Amazon S3 has been discovered, classified and secured',
        description: 'All S3 data should be encrypted at rest.',
        findingTitles: ['S3 Bucket Not Encrypted', 'Using SSE-S3 Instead of KMS'],
      },
      {
        id: 'CIS-2.1.4',
        name: 'Ensure that S3 Buckets are configured with Block Public Access',
        description: 'Block Public Access settings should prevent all public access to S3 buckets.',
        findingTitles: ['Public Access Not Fully Blocked', 'Bucket Has Public ACL Grants'],
      },
      {
        id: 'CIS-2.2.1',
        name: 'Ensure EBS Volume Encryption is Enabled in all Regions',
        description: 'EBS default encryption should be enabled to automatically encrypt all new volumes.',
        findingTitles: ['EBS Default Encryption Not Enabled'],
      },
      {
        id: 'CIS-2.3.1',
        name: 'Ensure that Amazon RDS database instances are not publicly accessible',
        description: 'RDS instances should not be publicly accessible from the internet.',
        findingTitles: ['Database Publicly Accessible'],
      },
      {
        id: 'CIS-2.3.2',
        name: 'Ensure that Amazon RDS instances are encrypted at rest',
        description: 'RDS instances should use encrypted storage.',
        findingTitles: ['RDS Not Encrypted', 'RDS Cluster Not Encrypted'],
      },
      {
        id: 'CIS-2.3.3',
        name: 'Ensure that Amazon RDS clusters have automatic minor version upgrade enabled',
        description: 'Enabling automatic minor upgrades ensures patch levels remain current.',
        findingTitles: [], // not yet evaluated by our scanners
      },
      // ── Section 3: Logging ─────────────────────────────────────────────
      {
        id: 'CIS-3.1',
        name: 'Ensure CloudTrail is enabled in all regions',
        description: 'CloudTrail should be enabled in all regions to capture all API activity.',
        findingTitles: ['No CloudTrail Found', 'CloudTrail Not Logging', 'Single Region CloudTrail'],
      },
      {
        id: 'CIS-3.2',
        name: 'Ensure CloudTrail log file validation is enabled',
        description: 'Log file validation ensures integrity of CloudTrail log files.',
        findingTitles: ['Log File Validation Not Enabled'],
      },
      {
        id: 'CIS-3.3',
        name: 'Ensure AWS Config is enabled in all regions',
        description: 'AWS Config should be enabled to continuously monitor resource configurations.',
        findingTitles: ['AWS Config Not Enabled'],
      },
      {
        id: 'CIS-3.4',
        name: 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
        description: 'S3 access logging should be enabled for the CloudTrail S3 bucket.',
        findingTitles: ['S3 Access Logging Not Enabled', 'S3 Bucket Not Configured'],
      },
      {
        id: 'CIS-3.5',
        name: 'Ensure CloudTrail trails are integrated with CloudWatch Logs',
        description: 'CloudTrail logs should flow into CloudWatch Logs for real-time monitoring.',
        findingTitles: ['CloudWatch Logs Not Configured'],
      },
      {
        id: 'CIS-3.7',
        name: 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
        description: 'CloudTrail log files should be encrypted using AWS KMS.',
        findingTitles: ['S3 Logs Not KMS Encrypted'],
      },
      {
        id: 'CIS-3.8',
        name: 'Ensure rotation for customer-created CMKs is enabled',
        description: 'Annual key rotation reduces the risk from a compromised key.',
        findingTitles: ['KMS Key Rotation Not Enabled'],
      },
      {
        id: 'CIS-3.9',
        name: 'Ensure VPC flow logging is enabled in all VPCs',
        description: 'VPC Flow Logs capture network traffic information for troubleshooting and security.',
        findingTitles: ['VPC Flow Logs Not Enabled'],
      },
      {
        id: 'CIS-3.10',
        name: 'Ensure object-level logging for write events is enabled for S3 buckets',
        description: 'CloudTrail data events should capture S3 object-level write operations.',
        findingTitles: ['S3 Object Logging Not Enabled'],
      },
      {
        id: 'CIS-3.11',
        name: 'Ensure object-level logging for read events is enabled for S3 buckets',
        description: 'CloudTrail data events should capture S3 object-level read operations.',
        findingTitles: ['S3 Object Logging Not Enabled'],
      },
      // ── Section 4: Monitoring ──────────────────────────────────────────
      {
        id: 'CIS-4.1',
        name: 'Unauthorized API Calls',
        description: 'Ensure a log metric filter and alarm exist for unauthorized API calls.',
        findingTitles: ['Unauthorized API Calls Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.2',
        name: 'Console Sign-In Without MFA',
        description: 'Ensure a log metric filter and alarm exist for console sign-ins without MFA.',
        findingTitles: ['Console Sign-In Without MFA Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.3',
        name: 'Root Account Usage',
        description: 'Ensure a log metric filter and alarm exist for root account usage.',
        findingTitles: ['Root Account Usage Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.4',
        name: 'IAM Policy Changes',
        description: 'Ensure a log metric filter and alarm exist for IAM policy changes.',
        findingTitles: ['IAM Policy Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.5',
        name: 'CloudTrail Configuration Changes',
        description: 'Ensure a log metric filter and alarm exist for CloudTrail configuration changes.',
        findingTitles: ['CloudTrail Config Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.6',
        name: 'AWS Console Authentication Failures',
        description: 'Ensure a log metric filter and alarm exist for console authentication failures.',
        findingTitles: ['Console Authentication Failures Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.7',
        name: 'Disabling or Scheduled Deletion of Customer-Managed Keys',
        description: 'Ensure a log metric filter and alarm exist for CMK disabling or scheduled deletion.',
        findingTitles: ['CMK Deletion Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.8',
        name: 'S3 Bucket Policy Changes',
        description: 'Ensure a log metric filter and alarm exist for S3 bucket policy changes.',
        findingTitles: ['S3 Bucket Policy Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.9',
        name: 'AWS Config Configuration Changes',
        description: 'Ensure a log metric filter and alarm exist for AWS Config configuration changes.',
        findingTitles: ['AWS Config Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.10',
        name: 'Security Group Changes',
        description: 'Ensure a log metric filter and alarm exist for security group changes.',
        findingTitles: ['Security Group Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.11',
        name: 'Network Access Control List Changes',
        description: 'Ensure a log metric filter and alarm exist for NACL changes.',
        findingTitles: ['NACL Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.12',
        name: 'Network Gateway Changes',
        description: 'Ensure a log metric filter and alarm exist for network gateway changes.',
        findingTitles: ['Network Gateway Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.13',
        name: 'Route Table Changes',
        description: 'Ensure a log metric filter and alarm exist for route table changes.',
        findingTitles: ['Route Table Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.14',
        name: 'VPC Changes',
        description: 'Ensure a log metric filter and alarm exist for VPC changes.',
        findingTitles: ['VPC Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      {
        id: 'CIS-4.15',
        name: 'AWS Organizations Changes',
        description: 'Ensure a log metric filter and alarm exist for AWS Organizations changes.',
        findingTitles: ['AWS Organization Changes Not Monitored', 'CloudWatch Monitoring Not Configured'],
      },
      // ── Section 5: Networking ──────────────────────────────────────────
      {
        id: 'CIS-5.1',
        name: 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote admin ports',
        description: 'Network ACLs should not allow unrestricted ingress to remote server administration ports.',
        findingTitles: ['Overly Permissive Network ACL'],
      },
      {
        id: 'CIS-5.2',
        name: 'Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports',
        description: 'Security groups should not allow unrestricted ingress to remote server administration ports.',
        findingTitles: [
          'Overly Permissive Security Group Rule',
          'Publicly Reachable EC2 Instance',
          'Sensitive Port 22 (SSH) Exposed to Internet',
          'Sensitive Port 3389 (RDP) Exposed to Internet',
          'Sensitive Port 3306 (MySQL) Exposed to Internet',
          'Sensitive Port 5432 (PostgreSQL) Exposed to Internet',
          'Sensitive Port 1433 (MSSQL) Exposed to Internet',
          'Sensitive Port 27017 (MongoDB) Exposed to Internet',
          'Sensitive Port 6379 (Redis) Exposed to Internet',
          'Sensitive Port 9200 (Elasticsearch) Exposed to Internet',
        ],
      },
      {
        id: 'CIS-5.3',
        name: 'Ensure the default security group restricts all traffic',
        description: 'The default security group should not allow inbound or outbound traffic.',
        findingTitles: ['Default Security Group Not Restricted'],
      },
      {
        id: 'CIS-5.4',
        name: 'Ensure routing tables for VPC peering are "least access"',
        description: 'VPC peering routes should restrict access to only the specific CIDR blocks required.',
        findingTitles: ['VPC Peering Route Not Least Access'],
      },
      {
        id: 'CIS-5.5',
        name: 'Ensure that EC2 Metadata Service only allows IMDSv2',
        description: 'IMDSv2 protects against SSRF attacks by requiring session-oriented requests.',
        findingTitles: ['IMDSv1 Enabled'],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // NIST SP 800-53 Rev 5
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'NIST_800_53',
    name: 'NIST SP 800-53 Rev 5',
    shortName: 'NIST 800-53',
    controls: [
      {
        id: 'AC-2',
        name: 'Account Management',
        description: 'Manage information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts.',
        findingTitles: [
          'Inactive User',
          'User Never Logged In',
          'Multiple Access Keys',
          'Old Access Key',
          'Unused Access Key',
          'Inactive Access Key',
          'MFA Not Verified for User',
          'Console Access Without MFA',
          'IAM Access Analyzer Not Enabled',
          'IAM Support Role Not Configured',
        ],
      },
      {
        id: 'AC-3',
        name: 'Access Enforcement',
        description: 'Enforce approved authorizations for logical access in accordance with applicable policy.',
        findingTitles: [
          'Overly Permissive Policy',
          'No Policies Attached',
          'Root Account Security',
          'Root Access Key Exists',
          'Root Account MFA Not Enabled',
          'Lambda Public Function',
          'Lambda Sensitive Function Not in VPC',
        ],
      },
      {
        id: 'AC-17',
        name: 'Remote Access',
        description: 'Establish and document usage restrictions and implementation guidance for remote access.',
        findingTitles: [
          'Overly Permissive Security Group Rule',
          'Overly Permissive Network ACL',
          'Publicly Reachable EC2 Instance',
          'Instance Has Public IP Without Security Group',
          'Database Publicly Accessible',
          'Default Security Group Not Restricted',
          'Sensitive Port 22 (SSH) Exposed to Internet',
          'Sensitive Port 3389 (RDP) Exposed to Internet',
        ],
      },
      {
        id: 'AU-2',
        name: 'Audit Events',
        description: 'Identify the types of events that the system is capable of logging in support of the audit function.',
        findingTitles: [
          'No CloudTrail Found',
          'CloudTrail Not Logging',
          'Single Region CloudTrail',
          'Management Events Not Logged',
          'S3 Object Logging Not Enabled',
          'VPC Flow Logs Not Enabled',
          'AWS Config Not Enabled',
        ],
      },
      {
        id: 'AU-9',
        name: 'Protection of Audit Information',
        description: 'Protect audit information and tools from unauthorized access, modification, and deletion.',
        findingTitles: [
          'Log File Validation Not Enabled',
          'S3 Logs Not KMS Encrypted',
          'S3 Access Logging Not Enabled',
          'S3 MFA Delete Not Enabled',
          'CloudWatch Logs Not Configured',
        ],
      },
      {
        id: 'AU-12',
        name: 'Audit Record Generation',
        description: 'Provide audit record generation capability and allow designated personnel to select auditable events.',
        findingTitles: [
          ...CIS_MONITORING_FINDINGS,
          'S3 Bucket Not Configured',
          'Detailed Monitoring Not Enabled',
        ],
      },
      {
        id: 'CM-2',
        name: 'Baseline Configuration',
        description: 'Develop, document, and maintain a current baseline configuration of the information system.',
        findingTitles: [
          'IMDSv1 Enabled',
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          'Lambda No Code Signing',
          ...ECR_CONFIG_FINDINGS,
        ],
      },
      {
        id: 'CM-6',
        name: 'Configuration Settings',
        description: 'Establish and document configuration settings that reflect the most restrictive mode consistent with operational requirements.',
        findingTitles: [
          'EBS Default Encryption Not Enabled',
          'Public Access Not Fully Blocked',
          'Bucket Has Public ACL Grants',
          'VPC Peering Route Not Least Access',
        ],
      },
      {
        id: 'IA-2',
        name: 'Identification and Authentication (Org. Users)',
        description: 'Uniquely identify and authenticate organizational users.',
        findingTitles: [
          'MFA Not Verified for User',
          'Console Access Without MFA',
          'Root Account MFA Not Enabled',
          'Password Policy Review Required',
          'Password Policy Minimum Length',
          'Password Policy Reuse Prevention',
        ],
      },
      {
        id: 'IA-5',
        name: 'Authenticator Management',
        description: 'Manage information system authenticators by verifying identity before distribution.',
        findingTitles: [
          'Old Access Key',
          'Unused Access Key',
          'Inactive Access Key',
          'Multiple Access Keys',
          'Secret Rotation Not Enabled',
          'Secret Scheduled for Deletion',
        ],
      },
      {
        id: 'SC-8',
        name: 'Transmission Confidentiality and Integrity',
        description: 'Implement cryptographic mechanisms to prevent unauthorized disclosure of information during transmission.',
        findingTitles: [
          'S3 HTTPS Not Enforced',
          'Database Publicly Accessible',
          'Lambda Sensitive Environment Variable',
        ],
      },
      {
        id: 'SC-28',
        name: 'Protection of Information at Rest',
        description: 'Implement cryptographic mechanisms to prevent unauthorized disclosure of information at rest.',
        findingTitles: [
          'S3 Bucket Not Encrypted',
          'Using SSE-S3 Instead of KMS',
          'RDS Not Encrypted',
          'RDS Cluster Not Encrypted',
          'Secret Using Default Encryption',
          'EBS Default Encryption Not Enabled',
          'KMS Key Rotation Not Enabled',
          'KMS Key Disabled',
          'KMS Key Pending Deletion',
        ],
      },
      {
        id: 'SI-2',
        name: 'Flaw Remediation',
        description: 'Identify, report, and correct information system flaws; test software updates before installation.',
        findingTitles: [
          'Lambda Vulnerable Dependency',
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          ...ECR_CVE_FINDINGS,
        ],
      },
      {
        id: 'CP-9',
        name: 'Information System Backup',
        description: 'Conduct backups of user-level and system-level information and store backup information at a separate facility.',
        findingTitles: [
          'Short Backup Retention',
          'Short Cluster Backup Retention',
          'Multi-AZ Not Enabled',
          'Deletion Protection Not Enabled',
          'Secret Not Replicated',
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // GDPR (EU General Data Protection Regulation)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'GDPR',
    name: 'GDPR (EU) 2016/679',
    shortName: 'GDPR',
    controls: [
      {
        id: 'GDPR-Art5',
        name: 'Article 5 — Principles of Processing',
        description: 'Personal data must be processed lawfully, fairly, and transparently; collected for specified purposes; adequate, accurate, and kept no longer than necessary.',
        findingTitles: [
          'S3 Bucket Not Encrypted',
          'Public Access Not Fully Blocked',
          'Bucket Has Public ACL Grants',
          'S3 Access Logging Not Enabled',
          'Database Publicly Accessible',
          'Short Backup Retention',
        ],
      },
      {
        id: 'GDPR-Art25',
        name: 'Article 25 — Data Protection by Design and by Default',
        description: 'Implement appropriate technical measures to integrate data protection principles into processing activities.',
        findingTitles: [
          'EBS Default Encryption Not Enabled',
          'S3 Bucket Not Encrypted',
          'Using SSE-S3 Instead of KMS',
          'RDS Not Encrypted',
          'RDS Cluster Not Encrypted',
          'Secret Using Default Encryption',
          'Lambda Sensitive Environment Variable',
          'IMDSv1 Enabled',
        ],
      },
      {
        id: 'GDPR-Art32',
        name: 'Article 32 — Security of Processing',
        description: 'Implement appropriate technical and organisational measures to ensure security appropriate to the risk.',
        findingTitles: [
          'S3 HTTPS Not Enforced',
          'KMS Key Rotation Not Enabled',
          'KMS Key Disabled',
          'KMS Key Pending Deletion',
          'Overly Permissive Policy',
          'Overly Permissive Security Group Rule',
          'Overly Permissive Network ACL',
          'MFA Not Verified for User',
          'Console Access Without MFA',
          'Root Account MFA Not Enabled',
          'Root Access Key Exists',
          'Lambda Vulnerable Dependency',
          ...ECR_CVE_FINDINGS,
        ],
      },
      {
        id: 'GDPR-Art33',
        name: 'Article 33 — Breach Notification',
        description: 'Notify supervisory authority of personal data breach within 72 hours; requires audit logs to detect breaches.',
        findingTitles: [
          'No CloudTrail Found',
          'CloudTrail Not Logging',
          'Single Region CloudTrail',
          'Log File Validation Not Enabled',
          'VPC Flow Logs Not Enabled',
          'S3 Access Logging Not Enabled',
          'AWS Config Not Enabled',
          ...CIS_MONITORING_FINDINGS,
        ],
      },
      {
        id: 'GDPR-Art5(1)(f)',
        name: 'Article 5(1)(f) — Integrity and Confidentiality',
        description: 'Process personal data in a manner that ensures appropriate security, including protection against unauthorised or unlawful processing and against accidental loss.',
        findingTitles: [
          'Publicly Reachable EC2 Instance',
          'Instance Has Public IP Without Security Group',
          'Database Publicly Accessible',
          'Default Security Group Not Restricted',
          'VPC Peering Route Not Least Access',
          'Sensitive Port 22 (SSH) Exposed to Internet',
          'Sensitive Port 3389 (RDP) Exposed to Internet',
          'Sensitive Port 3306 (MySQL) Exposed to Internet',
          'Sensitive Port 5432 (PostgreSQL) Exposed to Internet',
        ],
      },
      {
        id: 'GDPR-Art35',
        name: 'Article 35 — Data Protection Impact Assessment',
        description: 'Carry out DPIA for processing likely to result in high risk; requires knowing what personal data is processed.',
        findingTitles: [
          'IAM Access Analyzer Not Enabled',
          'Public Access Not Fully Blocked',
          'Bucket Has Public ACL Grants',
          'Lambda Public Function',
          ...ECR_CONFIG_FINDINGS,
        ],
      },
      {
        id: 'GDPR-Art17',
        name: 'Article 17 — Right to Erasure',
        description: 'Ensure personal data can be identified and deleted; requires inventory of data stores and access controls.',
        findingTitles: [
          'S3 MFA Delete Not Enabled',
          'Deletion Protection Not Enabled',
          'Secret Scheduled for Deletion',
        ],
      },
      {
        id: 'GDPR-Art28',
        name: 'Article 28 — Processor Obligations',
        description: 'Controllers must only use processors providing sufficient guarantees; requires access control over third-party access.',
        findingTitles: [
          'No Policies Attached',
          'Overly Permissive Policy',
          'IAM Support Role Not Configured',
          'Old Access Key',
          'Unused Access Key',
          'Inactive Access Key',
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // FedRAMP / FISMA (Moderate Baseline — aligned with NIST 800-53)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'FEDRAMP',
    name: 'FedRAMP Moderate / FISMA',
    shortName: 'FedRAMP',
    controls: [
      {
        id: 'FR-AC-2',
        name: 'Account Management (AC-2)',
        description: 'Manage information system accounts; enforce regular review and disable inactive accounts.',
        findingTitles: [
          'Inactive User',
          'User Never Logged In',
          'Multiple Access Keys',
          'Old Access Key',
          'Unused Access Key',
          'Inactive Access Key',
          'IAM Access Analyzer Not Enabled',
        ],
      },
      {
        id: 'FR-AC-3',
        name: 'Access Enforcement (AC-3)',
        description: 'Enforce least-privilege access to all system resources.',
        findingTitles: [
          'Overly Permissive Policy',
          'No Policies Attached',
          'Root Account Security',
          'Root Access Key Exists',
          'Root Account MFA Not Enabled',
          'Lambda Public Function',
        ],
      },
      {
        id: 'FR-IA-2',
        name: 'Multi-Factor Authentication (IA-2)',
        description: 'Require multi-factor authentication for all privileged and non-privileged accounts.',
        findingTitles: [
          'MFA Not Verified for User',
          'Console Access Without MFA',
          'Root Account MFA Not Enabled',
          'Password Policy Review Required',
          'Password Policy Minimum Length',
          'Password Policy Reuse Prevention',
        ],
      },
      {
        id: 'FR-AU-2',
        name: 'Audit Logging (AU-2 / AU-12)',
        description: 'Audit all security-relevant events; CloudTrail must be enabled in all regions.',
        findingTitles: [
          'No CloudTrail Found',
          'CloudTrail Not Logging',
          'Single Region CloudTrail',
          'Management Events Not Logged',
          'VPC Flow Logs Not Enabled',
          'S3 Object Logging Not Enabled',
          'AWS Config Not Enabled',
          ...CIS_MONITORING_FINDINGS,
        ],
      },
      {
        id: 'FR-AU-9',
        name: 'Audit Log Protection (AU-9)',
        description: 'Protect audit logs from unauthorized access or modification.',
        findingTitles: [
          'Log File Validation Not Enabled',
          'S3 Logs Not KMS Encrypted',
          'S3 Access Logging Not Enabled',
          'CloudWatch Logs Not Configured',
          'S3 MFA Delete Not Enabled',
        ],
      },
      {
        id: 'FR-SC-28',
        name: 'Encryption at Rest (SC-28)',
        description: 'Encrypt all federal data at rest using FIPS 140-2 validated cryptographic modules.',
        findingTitles: [
          'S3 Bucket Not Encrypted',
          'Using SSE-S3 Instead of KMS',
          'RDS Not Encrypted',
          'RDS Cluster Not Encrypted',
          'Secret Using Default Encryption',
          'EBS Default Encryption Not Enabled',
          'KMS Key Rotation Not Enabled',
          'KMS Key Disabled',
          'KMS Key Pending Deletion',
        ],
      },
      {
        id: 'FR-SC-8',
        name: 'Encryption in Transit (SC-8)',
        description: 'Protect data in transit using TLS/HTTPS.',
        findingTitles: [
          'S3 HTTPS Not Enforced',
          'Database Publicly Accessible',
          'Lambda Sensitive Environment Variable',
        ],
      },
      {
        id: 'FR-CM-2',
        name: 'Configuration Management (CM-2 / CM-6)',
        description: 'Maintain secure baseline configurations; use only approved software versions.',
        findingTitles: [
          'IMDSv1 Enabled',
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          'Lambda No Code Signing',
          'Lambda Sensitive Function Not in VPC',
          ...ECR_CONFIG_FINDINGS,
          'EBS Default Encryption Not Enabled',
        ],
      },
      {
        id: 'FR-SI-2',
        name: 'Vulnerability Remediation (SI-2)',
        description: 'Identify and remediate vulnerabilities; scan for flaws and apply patches.',
        findingTitles: [
          'Lambda Vulnerable Dependency',
          'Lambda EOL Runtime',
          'Lambda Deprecated Runtime',
          ...ECR_CVE_FINDINGS,
        ],
      },
      {
        id: 'FR-CP-9',
        name: 'Backup & Continuity (CP-9)',
        description: 'Conduct backups and ensure business continuity with appropriate retention and redundancy.',
        findingTitles: [
          'Short Backup Retention',
          'Short Cluster Backup Retention',
          'Multi-AZ Not Enabled',
          'Deletion Protection Not Enabled',
          'Secret Not Replicated',
        ],
      },
      {
        id: 'FR-RA-5',
        name: 'Vulnerability Scanning (RA-5)',
        description: 'Scan for vulnerabilities in the information system and hosted applications.',
        findingTitles: [
          'ECR Enhanced Scanning Not Enabled',
          'ECR Scan on Push Disabled',
          'ECR Image Scan Failed',
          'ECR Image OS Package CVE',
          'ECR Image High Severity CVEs',
        ],
      },
      {
        id: 'FR-SC-7',
        name: 'Boundary Protection (SC-7)',
        description: 'Monitor and control communications at external system boundaries.',
        findingTitles: [
          'Overly Permissive Security Group Rule',
          'Overly Permissive Network ACL',
          'Default Security Group Not Restricted',
          'VPC Peering Route Not Least Access',
          'Public Access Not Fully Blocked',
          'Bucket Has Public ACL Grants',
          'Sensitive Port 22 (SSH) Exposed to Internet',
          'Sensitive Port 3389 (RDP) Exposed to Internet',
          'Sensitive Port 3306 (MySQL) Exposed to Internet',
          'Sensitive Port 5432 (PostgreSQL) Exposed to Internet',
          'Sensitive Port 1433 (MSSQL) Exposed to Internet',
          'Sensitive Port 27017 (MongoDB) Exposed to Internet',
          'Sensitive Port 6379 (Redis) Exposed to Internet',
          'Sensitive Port 9200 (Elasticsearch) Exposed to Internet',
        ],
      },
    ],
  },
];

// ---------------------------------------------------------------------------
// Scoring helper
// ---------------------------------------------------------------------------

/**
 * Given a set of active (OPEN or ACKNOWLEDGED) finding titles for an account,
 * compute the compliance score for every framework.
 *
 * NOT_EVALUATED controls (empty findingTitles) are excluded from the score
 * denominator so they do not artificially inflate compliance.
 */
export function scoreFrameworks(
  activeFindingTitles: Set<string>,
  activeFindingCounts: Map<string, number>,
): FrameworkScore[] {
  return FRAMEWORKS.map((fw) => {
    const controls: ControlResult[] = fw.controls.map((ctrl) => {
      if (ctrl.findingTitles.length === 0) {
        return { ...ctrl, status: 'NOT_EVALUATED', failingFindings: 0 };
      }
      const failingFindings = ctrl.findingTitles.reduce(
        (sum, t) => sum + (activeFindingCounts.get(t) ?? 0),
        0,
      );
      const hasFailing = ctrl.findingTitles.some((t) => activeFindingTitles.has(t));
      return {
        ...ctrl,
        status: hasFailing ? 'FAIL' : 'PASS',
        failingFindings,
      };
    });

    const evaluated = controls.filter((c) => c.status !== 'NOT_EVALUATED');
    const passingControls = evaluated.filter((c) => c.status === 'PASS').length;
    const failingControls = evaluated.filter((c) => c.status === 'FAIL').length;
    const notEvaluatedControls = controls.filter((c) => c.status === 'NOT_EVALUATED').length;
    const score =
      evaluated.length > 0 ? Math.round((passingControls / evaluated.length) * 100) : 100;

    return {
      frameworkId: fw.id,
      frameworkName: fw.name,
      shortName: fw.shortName,
      score,
      passingControls,
      failingControls,
      notEvaluatedControls,
      totalControls: controls.length,
      controls,
    };
  });
}
