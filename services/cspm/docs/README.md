# AWS Scanner Documentation

## Installation

```bash
npm install -g aws-scanner
# or
npm install aws-scanner
```

## Quick Start

```bash
# Basic scan (requires AWS credentials)
aws-scanner scan

# Scan specific region
aws-scanner scan --region us-west-2

# Scan multiple regions
aws-scanner scan --region us-east-1 --region eu-west-1

# Use specific AWS profile
aws-scanner scan --profile production

# Output to HTML
aws-scanner scan --format html --output my-report

# Scan specific services only
aws-scanner scan --services iam,s3,cloudtrail

# Use configuration file
aws-scanner scan --config ./config/production-scan.yaml

# List available options
aws-scanner scan --help
```

## Commands

### scan
Execute a comprehensive AWS security scan.

Options:
- `-r, --region <region>` - AWS region (default: us-east-1)
- `-s, --services <services>` - Services to scan (comma-separated)
- `-p, --profile <profile>` - AWS CLI profile
- `-f, --format <format>` - Output format: json, html, csv, console
- `-o, --output <file>` - Output file path
- `--config <file>` - Load config from YAML file
- `--dry-run` - Preview without executing
- `--verbose` - Enable detailed logging

### list-regions
Show available AWS regions for scanning.

### list-services
Show available services that can be scanned.

## Scanned Services

1. **CloudTrail** - API logging and audit trails
2. **IAM** - Identity and access management
3. **S3** - Object storage security
4. **EC2** - Compute instances and security groups
5. **RDS** - Database instances
6. **KMS** - Key management service
7. **Secrets Manager** - Secret storage and rotation

## Findings Severity Levels

- **CRITICAL** - Immediate security risk, requires urgent action
- **HIGH** - Serious security issue, should be addressed soon
- **MEDIUM** - Important security consideration
- **LOW** - Best practice recommendation
- **INFO** - Informational finding

## Configuration Files

Create scan configurations in YAML format:

```yaml
aws:
  region: us-east-1
  profile: production

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

## AWS Credentials

Credentials can be provided via:
1. AWS CLI configuration (~/.aws/credentials)
2. AWS CLI profile (`--profile` option)
3. Environment variables:
   - AWS_ACCESS_KEY_ID
   - AWS_SECRET_ACCESS_KEY
   - AWS_SESSION_TOKEN (optional)
   - AWS_REGION

## Output Formats

### Console
Human-readable output in the terminal (default)

### JSON
Machine-readable JSON format for integration with other tools

### HTML
Interactive HTML report with charts and severity breakdown

### CSV
Excel-compatible CSV format for spreadsheet analysis

## Examples

### Production Setup
```bash
aws-scanner scan \
  --profile production \
  --region us-east-1 \
  --region us-west-2 \
  --format html \
  --output ./prod-report
```

### Development Quick Check
```bash
aws-scanner scan \
  --profile dev \
  --services iam,s3 \
  --format console
```

### Continuous Integration
```bash
aws-scanner scan \
  --profile ci \
  --format json \
  --output report.json
```

## Exit Codes

- `0` - Scan completed successfully
- `1` - Scan failed with error

## Troubleshooting

### "No AWS credentials found"
Ensure AWS credentials are configured:
```bash
aws configure
```

### "Access Denied" errors
Verify IAM user has required permissions for the services being scanned.

### Slow scanning
- Reduce number of regions
- Reduce number of services
- Check network connectivity

## Performance

Typical scan times:
- Small account (1-5 resources): 30-60 seconds
- Medium account (50-100 resources): 2-5 minutes
- Large account (1000+ resources): 10-30 minutes

## Support

For issues and questions, please refer to documentation or submit an issue on GitHub.
