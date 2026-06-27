# AWS Vulnerability Scanner

A comprehensive Node.js/TypeScript CLI tool for scanning AWS environments for security vulnerabilities and compliance issues without requiring Docker.

## 🎯 Overview

The AWS Vulnerability Scanner performs automated security audits across AWS CloudTrail, IAM, S3, EC2, RDS, KMS, and Secrets Manager. It detects misconfigurations, compliance violations, and security risks with actionable remediation guidance.

**Key Features:**
- ✅ **7 AWS Services** - CloudTrail, IAM, S3, EC2, RDS, KMS, Secrets Manager
- 📊 **Multiple Report Formats** - JSON, HTML, CSV, Console
- 🔍 **50+ Security Checks** - Comprehensive vulnerability detection
- 🚀 **No Docker Required** - Native Node.js, runs on Windows/Mac/Linux
- 🔐 **Read-Only** - Never modifies AWS resources
- 📈 **Severity Levels** - CRITICAL, HIGH, MEDIUM, LOW, INFO
- 🌍 **Multi-Region** - Scan across AWS regions
- 🎛️  **Flexible Configuration** - CLI, YAML, environment variables

## 🚀 Quick Start

### Installation

```bash
# Global installation
npm install -g aws-scanner

# or local installation
npm install aws-scanner
```

### Prerequisites

- Node.js 18+ 
- AWS credentials configured (see [Authentication](#authentication))

### Basic Usage

```bash
# Quick scan with defaults
aws-scanner scan

# Scan production account
aws-scanner scan --profile production --format html

# Scan specific regions
aws-scanner scan --region us-east-1 --region eu-west-1

# Scan only IAM and S3
aws-scanner scan --services iam,s3

# List available options
aws-scanner scan --help
```

## 📋 Scanned Resources

### CloudTrail
- Trail discovery and configuration
- Logging status and multi-region setup
- S3 bucket security for logs
- Log file validation
- CloudWatch Logs integration
- KMS encryption

### Identity & Access Management (IAM)
- User audit and access keys
- MFA enforcement
- Password policy validation
- Inactive user detection
- Overly permissive policies
- Root account security

### S3 Buckets
- Encryption at rest
- Versioning and backup
- Public access blocking
- ACL configuration
- Access logging
- Server-side encryption

### EC2
- Security group rules
- Network ACLs
- Public IP accessibility
- IMDSv2 enforcement
- CloudWatch monitoring

### RDS
- Encryption at rest
- Backup retention
- Public accessibility
- Deletion protection
- Multi-AZ deployment
- Backup tagging

### KMS
- Key rotation
- Key state and management
- Customer-managed keys

### Secrets Manager
- Rotation policies
- Encryption configuration
- Replication status
- Secret deletion schedules

## 🔧 Configuration

### Command Line

```bash
aws-scanner scan \
  --region us-west-2 \
  --services iam,s3,cloudtrail \
  --profile production \
  --format html \
  --output report
```

### Configuration File (YAML)

```yaml
aws:
  region: us-east-1
  profile: production
  regions:
    - us-east-1
    - us-west-2

scanner:
  services:
    - cloudtrail
    - iam
    - s3
  timeout: 300000

report:
  format: html
  outputDir: ./reports
```

Run with config:
```bash
aws-scanner scan --config config.yaml
```

### Environment Variables

```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=production
export LOG_LEVEL=debug
export CACHE_ENABLED=true
aws-scanner scan
```

## 🔐 Authentication

### Option 1: AWS CLI Profile (Recommended)

```bash
aws configure --profile production
aws-scanner scan --profile production
```

### Option 2: Environment Variables

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=us-east-1
aws-scanner scan
```

### Option 3: AWS Credentials File

```bash
# ~/.aws/credentials
[production]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# ~/.aws/config
[profile production]
region = us-east-1
```

## 📊 Report Formats

### Console (Default)
Human-readable, colored output in the terminal

```bash
aws-scanner scan --format console
```

### HTML
Interactive dashboard with charts and detailed findings

```bash
aws-scanner scan --format html --output scan-report
```

### JSON
Machine-readable format for CI/CD integration

```bash
aws-scanner scan --format json --output scan-report
```

### CSV
Spreadsheet-compatible format

```bash
aws-scanner scan --format csv --output scan-report
```

##⚙️ Commands

### scan
Execute a security scan

```bash
aws-scanner scan [options]
```

Options:
- `--region <region>` - AWS region (default: us-east-1)
- `--services <services>` - Services to scan (default: all)
- `--profile <profile>` - AWS CLI profile
- `--format <format>` - Report format (json, html, csv, console)
- `--output <file>` - Output file path
- `--config <file>` - Configuration file
- `--dry-run` - Preview without executing
- `--verbose` - Detailed logging

### list-regions
Show available AWS regions

```bash
aws-scanner list-regions
```

### list-services
Show available services

```bash
aws-scanner list-services
```

## 📈 Severity Levels

- 🔴 **CRITICAL** - Immediate security risk, urgent action required
- 🟠 **HIGH** - Serious vulnerability, address promptly
- 🟡 **MEDIUM** - Important security issue
- 🔵 **LOW** - Best practice recommendation
- ⚪ **INFO** - Informational finding

## 🔄 Cross-Account Scanning

Scan multiple AWS accounts using IAM role assumption:

```bash
export AWS_ROLE_ARN="arn:aws:iam::123456789012:role/ScannerRole"
aws-scanner scan --profile default
```

## 📦 CI/CD Integration

### GitLab CI

```yaml
scan_security:
  stage: security
  image: node:18
  script:
    - npm install -g aws-scanner
    - aws-scanner scan --profile ci --format json --output report.json
  artifacts:
    reports:
      sast: report.json
```

### GitHub Actions

```yaml
name: AWS Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm install -g aws-scanner
      - run: aws-scanner scan --format html --output report
      - uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: report.html
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

## 🛠️ Development

### Setup

```bash
git clone <repository>
cd aws-scanner
npm install
npm run build
```

### Development Server

```bash
npm run dev
```

### Build

```bash
npm run build
```

### Lint & Format

```bash
npm run lint
npm run format
```

## 📚 Project Structure

```
aws-scanner/
├── src/
│   ├── cli/               # CLI interface
│   ├── scanners/          # Service scanners (CloudTrail, IAM, S3, etc.)
│   ├── reporters/         # Report generators (JSON, HTML, CSV)
│   ├── aws/               # AWS SDK wrapper
│   ├── utils/             # Utilities and helpers
│   └── index.ts           # Main entry point
├── tests/
│   ├── unit/              # Unit tests
│   └── integration/       # Integration tests
├── config/                # Configuration examples
├── docs/                  # Documentation
└── package.json
```

## 🚨 Common Issues

### "No AWS credentials found"
**Solution:** Configure AWS credentials using `aws configure`

### "Access Denied" errors
**Solution:** Ensure IAM user has permissions for scanned services

### Slow scanning
**Solution:** Reduce number of regions or services scanned

## 📝 Remediation Examples

### CloudTrail not logging
```
Finding: CloudTrail Not Logging
Remediation: Enable logging for the CloudTrail trail in AWS Console → CloudTrail → Enable Logging
```

### S3 bucket not encrypted
```
Finding: S3 Bucket Not Encrypted
Remediation: Enable encryption via: S3 Console → Bucket → Properties → Default Encryption → Enable
```

### IAM user lacks MFA
```
Finding: MFA Not Enabled
Remediation: Enable MFA via: IAM Console → Users → User → Security Credentials → Manage MFA
```

## 📄 License

MIT License - see LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create your feature branch
3. Submit a pull request

## 📞 Support

- 📖 [Full Documentation](./docs/README.md)
- 📋 [CLI Reference](./docs/CLI.md)
- 🐛 [Issue Tracker](#)
- 💬 [Discussions](#)

---

**Built with ❤️ for AWS security**
