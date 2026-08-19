# AWS Scanner - Feature List

## Project Overview
**AWS Vulnerability & Security Compliance Scanner** - A Node.js/TypeScript CLI tool for scanning AWS CloudTrail, IAM, and general security posture without requiring Docker.

---

## Core Features

### 1. CloudTrail Compliance & Auditing
- [ ] **Trail Discovery** - Detect all CloudTrail trails in AWS account
- [ ] **Trail Configuration Validation** - Verify trail settings (multi-region, S3 logging, encryption)
- [ ] **Event Analysis** - Parse and analyze CloudTrail events
- [ ] **Suspicious Activity Detection** - Identify unusual or high-risk API calls
- [ ] **LogGroup Monitoring** - Check if CloudWatch logs are enabled
- [ ] **S3 Bucket Validation** - Verify CloudTrail logs stored securely (encryption, versioning)
- [ ] **Trail Integrity** - Enable/verify log file validation
- [ ] **Management Events** - Check if management events are being logged
- [ ] **Data Events** - Verify S3 and Lambda data events logging (if configured)

### 2. IAM Security & Compliance
- [ ] **User Audit** - List all IAM users and check for unused accounts (90+ days)
- [ ] **Access Key Analysis** - Detect old, unused, or inactive access keys
- [ ] **Password Policy** - Validate password complexity requirements
- [ ] **MFA Detection** - Verify MFA is enabled for all users
- [ ] **Root Account Check** - Alert if root account access keys exist
- [ ] **Privilege Analysis** - Identify overly permissive policies (wildcards, full permissions)
- [ ] **Role Assumption** - Track trust relationships and cross-account access
- [ ] **Service Role Review** - Audit roles granted to EC2, Lambda, etc.
- [ ] **Console Access Check** - Verify only necessary users have console login
- [ ] **Inactive User Detection** - Find users with no activity
- [ ] **Credentials Report** - Generate and analyze AWS credential reports

### 3. General AWS Security Posture
- [ ] **S3 Bucket Security** - Check public access, encryption, versioning
- [ ] **EC2 Security Groups** - Detect overly open inbound/outbound rules
- [ ] **Network ACLs** - Validate VPC network access control lists
- [ ] **Encryption Audit** - Check if EBS, RDS, S3 use encryption
- [ ] **VPC Configuration** - Verify VPCs have proper security group defaults
- [ ] **RDS Database Security** - Check backup retention, encryption, backup locations
- [ ] **Secrets Manager** - Audit stored secrets and rotation policies
- [ ] **KMS Key Usage** - List and validate customer-managed keys
- [ ] **CloudWatch Logs** - Verify log retention and encryption
- [ ] **Enable Logging** - Check if logging is enabled for major services

### 4. Advanced Compliance Checks
- [ ] **CIS AWS Foundations Benchmark** - Automated checks against CIS benchmark
- [ ] **NIST Controls** - Map findings to NIST framework
- [ ] **PCI-DSS Requirements** - Payment card industry requirements validation
- [ ] **HIPAA/GDPR** - Health/privacy compliance checks
- [ ] **Custom Rules Engine** - Define custom compliance rules via YAML/JSON

### 5. Reporting & Output
- [ ] **JSON Report** - Structured JSON output for programmatic use
- [ ] **HTML Report** - Interactive HTML dashboard with charts
- [ ] **CSV Export** - Export findings to CSV for spreadsheet analysis
- [ ] **Executive Summary** - High-level overview with risk scores
- [ ] **Severity Levels** - Critical, High, Medium, Low, Informational
- [ ] **Trend Analysis** - Track findings over time
- [ ] **Filtering & Search** - Filter by service, severity, status
- [ ] **Remediation Steps** - Automated remediation suggestions

### 6. CLI Interface & Configuration
- [ ] **Command Structure** - `aws-scanner scan [service] [options]`
- [ ] **Service Selection** - Scan specific AWS services or all
- [ ] **Region Targeting** - Scan single or multiple regions
- [ ] **Config File Support** - YAML/JSON configuration for recurring scans
- [ ] **AWS Credential Management** - Support profiles, environment variables, credentials file
- [ ] **Dry-Run Mode** - Preview changes without executing
- [ ] **Quiet/Verbose Modes** - Control output verbosity
- [ ] **Schedule Integration** - Support for cron/task scheduler
- [ ] **Concurrent Scanning** - Parallel API calls for faster scanning
- [ ] **Rate Limiting** - Handle AWS API throttling gracefully

### 7. Authentication & Authorization
- [ ] **IAM Policy Validation** - Validate user has required permissions
- [ ] **Error Handling** - Clear errors when permissions are missing
- [ ] **Multiple Profiles** - Support AWS CLI profiles
- [ ] **Temporary Credentials** - Support STS assumed roles
- [ ] **Cross-Account Scanning** - Scan multiple AWS accounts
- [ ] **Role Assumption** - Support STS assume role functionality

### 8. Data Management
- [ ] **Local Caching** - Cache results to reduce API calls
- [ ] **Result History** - Store historical scan results
- [ ] **Database Integration** - Optional: store results in SQLite/PostgreSQL
- [ ] **Export to Dashboards** - Integration ready (Splunk, DataDog, etc.)
- [ ] **API Mode** - Optional HTTP API for integration

### 9. Performance & Reliability
- [ ] **Progress Indicators** - Show scan progress and ETA
- [ ] **Retry Logic** - Handle transient API failures
- [ ] **Resource Cleanup** - Proper cleanup on interruption
- [ ] **Timeout Handling** - Configurable timeouts for long operations
- [ ] **Logging** - Debug/info/error logs to file and console
- [ ] **Async Processing** - Non-blocking operations for CLI responsiveness

### 10. Developer Features
- [ ] **Plugin System** - Custom scanner modules
- [ ] **Test Suite** - Unit & integration tests
- [ ] **Documentation** - Complete API and CLI documentation
- [ ] **Examples** - Sample configurations and use cases
- [ ] **Contribution Guidelines** - For community contributions

---

## Implementation Priority (Phase-based)

### Phase 1: MVP (Weeks 1-2)
- CloudTrail discovery and configuration validation
- IAM user audit and access key analysis
- S3 bucket security checks
- Basic JSON report output
- CLI with basic commands

### Phase 2: Enhanced Scanning (Weeks 3-4)
- EC2 security groups audit
- RDS and secrets manager checks
- HTML report generation
- CSV export
- Config file support

### Phase 3: Advanced Features (Weeks 5-6)
- CIS benchmark checks
- Custom rules engine
- Historical tracking
- Advanced filtering and search
- API mode

### Phase 4: Polish & Scale (Week 7+)
- Performance optimization
- Cross-account scanning
- Plugin system
- Comprehensive documentation
- Community release

---

## Project Structure (Proposed)

```
aws-scanner/
├── src/
│   ├── cli/
│   │   ├── commands.ts         # CLI command definitions
│   │   └── parser.ts            # Command-line argument parsing
│   ├── scanners/
│   │   ├── cloudtrail.ts        # CloudTrail scanner
│   │   ├── iam.ts               # IAM scanner
│   │   ├── s3.ts                # S3 bucket scanner
│   │   ├── ec2.ts               # EC2 security group scanner
│   │   ├── rds.ts               # RDS database scanner
│   │   ├── networking.ts        # VPC/Network scanner
│   │   └── compliance.ts        # CIS/NIST checks
│   ├── aws/
│   │   ├── client.ts            # AWS SDK wrapper
│   │   └── credentials.ts       # Credential handling
│   ├── reporters/
│   │   ├── json.ts              # JSON reporter
│   │   ├── html.ts              # HTML reporter
│   │   ├── csv.ts               # CSV reporter
│   │   └── console.ts           # Console/terminal output
│   ├── rules/
│   │   ├── builtin.ts           # Built-in rules
│   │   └── custom.ts            # Custom rules engine
│   ├── config/
│   │   ├── parser.ts            # Config file parsing
│   │   └── defaults.ts          # Default configurations
│   ├── utils/
│   │   ├── logger.ts            # Logging utility
│   │   ├── cache.ts             # Caching layer
│   │   └── helpers.ts           # Utility functions
│   └── index.ts                 # Entry point
├── tests/
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── fixtures/                # Test data
├── config/
│   ├── default.yaml             # Default configuration
│   ├── cis-benchmark.yaml       # CIS checks
│   └── examples/                # Example configs
├── docs/
│   ├── README.md                # Getting started
│   ├── CLI.md                   # CLI reference
│   ├── RULES.md                 # Rules documentation
│   └── API.md                   # API documentation
├── package.json
├── tsconfig.json
├── .env.example
└── FEATURES.md                  # This file
```

---

## Technology Stack

- **Language**: TypeScript
- **Runtime**: Node.js 18+
- **AWS SDK**: AWS SDK v3 for JavaScript
- **CLI**: Commander.js or Yargs
- **Logging**: Winston or Pino
- **Testing**: Jest
- **HTML Reports**: EJS + Chart.js
- **CSV**: papaparse or csv-parser
- **Configuration**: YAML (js-yaml) or TOML

---

## Success Metrics

- [ ] Scan 10+ AWS services
- [ ] Generate 20+ vulnerability checks
- [ ] Complete scan in <5 minutes (typical account)
- [ ] Support multi-region and cross-account scanning
- [ ] Generate actionable reports with remediation steps
- [ ] 90%+ test coverage
- [ ] Works on Windows, macOS, and Linux

---

## Notes

- **No Docker Required**: Runs natively on any system with Node.js 18+
- **AWS Account Required**: User provides AWS credentials via CLI or environment
- **Read-Only**: Scanner only reads data, doesn't make changes (safe)
- **Open Source**: Consider GPL/MIT license for community contributions
