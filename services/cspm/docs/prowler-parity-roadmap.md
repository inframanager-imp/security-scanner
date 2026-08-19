# AWS Coverage Parity Roadmap (vs Prowler)

Goal: close the AWS breadth gap with Prowler (621 checks / 86 services vs our ~180 / 25 as of
2026-07) by **natively porting** check logic into our TypeScript scanner engine, using the
Apache-2.0 Prowler project as the reference specification.

## Licensing

Prowler is Apache License 2.0. Porting its check logic is permitted, including commercial use.
Obligations we follow:

- Every ported scanner/registry file carries the header
  `// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)`.
- Keep an attribution entry in a NOTICE file at the repo root before shipping.
- Never use the "Prowler" name/trademark in product marketing.

## Foundation (Phase 0) — DONE

- Check-metadata registry: `src/checks/types.ts`, `src/checks/registry/` — one `CheckMetadata`
  entry per check with a **stable, Prowler-compatible checkId** (e.g. `s3_bucket_default_encryption`),
  severity, generic description/remediation, tags, and `compliance` framework mappings.
- `BaseScanner.emit(checkId, evidence, opts)` — title/severity/remediation come from the registry;
  call sites pass resource-specific `message`. `createFinding` is deprecated.
- `Finding.checkId` column (nullable) + index in Prisma; scan worker persists it.
- Dedup still keys on `service:title:fingerprint`, so **registry titles must stay byte-identical**
  to the pre-migration hardcoded titles. Once all scanners are migrated and one full scan cycle has
  run, switch the dedup key to `checkId:fingerprint`.

## Migration of existing scanners — IN PROGRESS

All 25 existing AWS scanners move onto `emit()` + registry entries (batches: iam/ec2/vpc/
cloudwatch/cloudtrail/ebs, threatdetection/rds/kms/secretsmanager/lambda/ecr, and the 12 smaller
services). Azure (298 checks) and GCP (114) migrate in a later phase using the same pattern
(`provider: 'azure' | 'gcp'`).

## New-service tranches

A tranche = new scanner + registry file per service, ported from
`prowler/providers/aws/services/<service>/`. Wiring (engine imports, `getAvailableServices()`,
`AWSClient`/`getClientConfig()`, `@aws-sdk/client-*` deps) is done centrally after each tranche.

| Tranche | Services (Prowler check count) | Status |
|---|---|---|
| 1 | eks (7), efs (6), route53 (5), opensearch (12), backup (7), cognito (16), kinesis (2+), glue (13) | IN PROGRESS |
| 2 | bedrock (13), sagemaker (16), autoscaling (8), cloudformation (5), codebuild (10), athena (4), emr (6), macie (3), ses (4), organizations (4), accessanalyzer (3), account (3), config (3), guardduty (10, merge into threatdetection), securityhub (2) | planned |
| 3 | kafka/MSK (8), mq (5), neptune (10), documentdb (6), memorydb (3), networkfirewall (7), fsx (3), storagegateway (3), transfer (3), dms (9), directoryservice (6), workspaces (3), appstream (5), lightsail (5) | planned |
| 4 (long tail) | acmpca, amplify, apigatewayv2, appsync, awslambda-extras, codeartifact, codepipeline, datapipeline, datasync, directconnect, dlm, drs, elasticbeanstalk, eventbridge, firehose, fms, glacier, globalaccelerator, inspector2, resourceexplorer2, rolesanywhere, servicecatalog, shield, ssmincidents, stepfunctions, trustedadvisor, wellarchitected | planned |

## Deepening existing services

Breadth is not only new services — Prowler is far deeper on services we already cover.
Biggest deltas to port as "deepening" work items: **ec2 (74 Prowler checks), iam (49), rds (35),
cloudwatch (23), s3 (22), cloudtrail (15), cloudfront (14), elbv2 (13), lambda (12), vpc (11),
ecs (11), redshift (10), apigateway (10)**. Same recipe: add registry entries with Prowler
checkIds + new check methods in the existing scanner.

## Porting recipe (per service)

1. `ls prowler/providers/aws/services/<svc>/` — one dir per check; read `<check>.metadata.json`
   (CheckTitle/Severity/Description/Remediation) and `<check>.py` (logic), plus `<svc>_service.py`
   for the API calls that gather state.
2. Scanner: `src/scanners/<svc>.ts` extending `BaseScanner`; SDK clients built via
   `client.getClientConfig()`; per-resource errors → `logger.debug`, continue.
3. Registry: `src/checks/registry/aws/<svc>.ts` — checkId = Prowler ID verbatim; concise
   title/description/remediation in product voice.
4. Central wiring: registry barrel (`registry/aws/index.ts`), `engine.ts` import + service key
   (account-level vs per-region placement), `package.json` dependency.
5. Verify: `npx tsc --noEmit` on the Docker build host (no Node/Docker on the dev box), then a
   test scan against a sandbox account.

## Compliance expansion (after checkId adoption)

Prowler ships framework mappings as JSON (`prowler/compliance/aws/*.json`, 47 frameworks) keyed by
checkId. Because our checkIds match Prowler's, these translate directly into
`CheckMetadata.compliance` entries / framework definition files, replacing the title-string
matching in `api/src/services/complianceService.ts`. Target: CIS v2/v3, NIST 800-53 r5, NIST CSF,
PCI 4.0, HIPAA, SOC2, ISO 27001, GDPR, FedRAMP first; long tail after.

## Post-parity unlocks

- OCSF / SARIF exporters (registry fields map ~1:1).
- AWS Security Hub (ASFF) push integration.
- Dedup key migration to `checkId:fingerprint`.
