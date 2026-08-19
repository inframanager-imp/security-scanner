# CLI Reference

## aws-scanner scan

Execute a comprehensive AWS security scan.

### Syntax
```bash
aws-scanner scan [options]
```

### Options

#### `-r, --region <region>`
AWS region to scan.

- **Type:** string
- **Default:** us-east-1
- **Example:** `aws-scanner scan --region eu-west-1`

#### `-s, --services <services>`
Comma-separated list of services to scan.

- **Type:** string
- **Default:** all services
- **Available services:** cloudtrail, iam, s3, ec2, rds, kms, secretsmanager
- **Example:** `aws-scanner scan --services iam,s3,cloudtrail`

#### `-p, --profile <profile>`
AWS CLI profile to use for authentication.

- **Type:** string
- **Default:** default profile
- **Example:** `aws-scanner scan --profile production`

#### `-f, --format <format>`
Output report format.

- **Type:** string
- **Default:** console
- **Options:** json, html, csv, console
- **Example:** `aws-scanner scan --format html`

#### `-o, --output <file>`
File path for the report output (without extension).

- **Type:** string
- **Example:** `aws-scanner scan --output ./reports/scan-report`

#### `--config <file>`
Load configuration from YAML file.

- **Type:** string
- **Example:** `aws-scanner scan --config ./config.yaml`

#### `--dry-run`
Preview scan without executing AWS API calls.

- **Type:** boolean
- **Example:** `aws-scanner scan --dry-run`

#### `--verbose`
Enable verbose logging output.

- **Type:** boolean
- **Example:** `aws-scanner scan --verbose`

#### `-h, --help`
Display help information.

### Examples

#### Basic scan with default settings
```bash
aws-scanner scan
```

#### Scan multiple regions
```bash
aws-scanner scan \
  --region us-east-1 \
  --region us-west-2 \
  --region eu-west-1
```

#### Scan production account and generate HTML report
```bash
aws-scanner scan \
  --profile production \
  --format html \
  --output ./reports/prod-scan
```

#### Quick development scan
```bash
aws-scanner scan \
  --profile dev \
  --services iam,s3 \
  --format console
```

#### Use configuration file
```bash
aws-scanner scan --config ./config/production-scan.yaml
```

#### Preview scan before executing
```bash
aws-scanner scan --dry-run --verbose
```

## aws-scanner list-regions

List all AWS regions available for scanning.

### Syntax
```bash
aws-scanner list-regions
```

### Example
```bash
$ aws-scanner list-regions
Available regions:
  us-east-1
  us-east-2
  us-west-1
  us-west-2
  eu-west-1
  eu-central-1
  ap-southeast-1
  ap-northeast-1
```

## aws-scanner list-services

List all services that can be scanned.

### Syntax
```bash
aws-scanner list-services
```

### Example
```bash
$ aws-scanner list-services
Available services:
  cloudtrail
  iam
  s3
  ec2
  rds
  kms
  secretsmanager
```

## Configuration File Format

Configuration files use YAML format (.yaml or .yml).

### Example Configuration
```yaml
aws:
  region: us-east-1
  regions:
    - us-east-1
    - us-west-2
  profile: production

scanner:
  services:
    - cloudtrail
    - iam
    - s3
  timeout: 300000
  parallel: 5

report:
  format: html
  outputDir: ./reports

filters:
  severity:
    - CRITICAL
    - HIGH
```

### Configuration Sections

#### aws
AWS-related settings.

- `region` - Primary region
- `regions` - List of regions to scan
- `profile` - AWS CLI profile name

#### scanner
Scan execution settings.

- `services` - Services to scan (list)
- `timeout` - Scan timeout in milliseconds
- `parallel` - Number of parallel API calls
- `verbose` - Enable verbose logging
- `dryRun` - Preview mode

#### report
Report generation settings.

- `format` - Output format (json, html, csv, console)
- `outputDir` - Directory for reports

#### filters
Filter findings.

- `severity` - List of severity levels to include
- `services` - Services to include (empty = all)
- `tags` - Finding tags to include (empty = all)
