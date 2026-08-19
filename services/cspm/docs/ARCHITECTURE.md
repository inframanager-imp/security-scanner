# AWS Scanner - Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Interface                            │
│                  (src/cli/index.ts)                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Scan Engine                               │
│               (src/scanners/engine.ts)                       │
│  - Coordinates scanners across regions                       │
│  - Aggregates findings                                       │
│  - Manages lifecycle                                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┬───────────┐
        │                  │                  │           │
        ▼                  ▼                  ▼           ▼
   ┌────────┐    ┌────────────┐    ┌────────┐   ┌──────────┐
   │Cloud   │    │   IAM      │    │  S3    │   │   EC2    │
   │Trail   │    │ Scanner    │    │Scanner │   │Scanner   │
   │Scanner │    │            │    │        │   │          │
   └────────┘    └────────────┘    └────────┘   └──────────┘
        │                                             │
        └─────────────────┬──────────────────────────┘
                          │
                    ┌─────▼────────┐
                    │  RDS Scanner │
                    │  KMS Scanner │
                    │  Secrets Mgr │
                    └─────┬────────┘
                          │
        ┌─────────────────┴──────────────────┐
        │                                     │
        ▼                                      ▼
┌─────────────────────┐        ┌─────────────────────────┐
│  AWS SDK Clients    │        │  Reporters              │
│  (src/aws/client.ts)│        │  ├─ JSON               │
│  - CloudTrail       │        │  ├─ HTML               │
│  - IAM              │        │  ├─ CSV                │
│  - S3               │        │  └─ Console            │
│  - EC2              │        │                         │
│  - RDS              │        │  (src/reporters/)      │
│  - KMS              │        │                         │
│  - Secrets Mgr      │        │                         │
└─────────────────────┘        └─────────────────────────┘
        │                                      │
        │                                      │
        └──────────────┬───────────────────────┘
                       │
                       ▼
            ┌─────────────────────┐
            │  AWS Account        │
            │  Resources          │
            │                     │
            │  CloudTrail Logs    │
            │  IAM Users & Keys   │
            │  S3 Buckets         │
            │  EC2 Instances      │
            │  RDS Databases      │
            │  KMS Keys           │
            │  Secrets            │
            └─────────────────────┘
```

## Module Dependencies

### Core Modules
- **cli** → engine → scanners → AWS clients
- **scanners** → AWS clients → AWS account resources
- **reporters** → report data
- **utils** → all modules (logging, cache, types)

### Data Flow

1. **Input**: User provides options (region, services, credentials)
2. **Validation**: Check AWS credentials and permissions
3. **Discovery**: List resources in each service
4. **Analysis**: Run security checks on discovered resources
5. **Findings**: Collect vulnerabilities and misconfigurations
6. **Reporting**: Format and output findings
7. **Output**: JSON, HTML, CSV, or console report

## Execution Flow

```
User runs: aws-scanner scan [options]
                    │
                    ▼
    Parse CLI arguments and config file
                    │
                    ▼
        Validate AWS credentials
                    │
                    ▼
        Initialize AWS SDK clients
                    │
                    ▼
    For each region:
        │
        ├─ Run CloudTrail Scanner (once per account)
        ├─ Run IAM Scanner (once per account)
        ├─ Run S3 Scanner (once per account)
        ├─ Run EC2 Scanner (per region)
        ├─ Run RDS Scanner (per region)
        ├─ Run KMS Scanner (per region)
        └─ Run Secrets Manager Scanner (per region)
                    │
                    ▼
        Aggregate findings
                    │
                    ▼
        Generate report (JSON/HTML/CSV/Console)
                    │
                    ▼
            Output report to file/console
                    │
                    ▼
                Exit with status code
```

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Runtime** | Node.js 18+ |
| **Language** | TypeScript |
| **AWS SDK** | @aws-sdk/client-* (v3) |
| **CLI** | Commander.js |
| **Logging** | Winston |
| **Config** | js-yaml |
| **Testing** | Jest + ts-jest |
| **Reporting** | EJS + Chart.js |
| **Build** | TypeScript tsc |

## Phase Implementation Status

### Phase 1: MVP (COMPLETE)
- [x] CloudTrail security scanner
- [x] IAM user audit
- [x] JSON reporting
- [x] Basic CLI interface
- [x] AWS credential handling

### Phase 2: Phase 2 (COMPLETE)  
- [x] S3 bucket security
- [x] EC2 security groups
- [x] RDS database audit
- [x] HTML reporting
- [x] CSV export
- [x] Configuration file support

### Phase 3: Advanced (COMPLETE)
- [x] KMS key management audits
- [x] Secrets Manager checks
- [x] Multiple region scanning
- [x] Service filtering
- [x] Test framework

### Phase 4: Polish (IN PROGRESS)
- [x] Documentation complete
- [x] Examples and templates
- [x] CLI help and commands
- [ ] Performance optimization
- [ ] Cross-account IAM role support
- [ ] CI/CD integration examples

## Extending the Scanner

### Adding a New Scanner

1. Create `src/scanners/newservice.ts`
2. Extend `BaseScanner` class
3. Implement `scan()` method
4. Add to `ScanEngine.executeScan()`
5. Create tests in `tests/unit/`

### Adding a New Reporter

1. Create `src/reporters/newreporter.ts`
2. Implement `Reporter` interface
3. Add to reporters map in CLI
4. Test output format

### Adding New Findings

Edit the scanner's validation method to add new `createFinding()` calls with:
- Title (descriptive name)
- Description (what's wrong)
- Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Evidence (data supporting the finding)
- Remediation (how to fix)
- Tags (categorization)
