-- Multi-tenancy: Tenant + TenantMembership, User flags, orgId on every domain table.
-- Existing rows are backfilled into a default organization so nothing is orphaned.

CREATE TABLE "Tenant" (
    "id"        TEXT NOT NULL,
    "slug"      TEXT NOT NULL,
    "name"      TEXT NOT NULL,
    "isActive"  BOOLEAN NOT NULL DEFAULT true,
    "settings"  JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "Tenant_slug_key" ON "Tenant"("slug");
CREATE INDEX "Tenant_isActive_idx" ON "Tenant"("isActive");

CREATE TABLE "TenantMembership" (
    "id"        TEXT NOT NULL,
    "tenantId"  TEXT NOT NULL,
    "userId"    TEXT NOT NULL,
    "role"      "Role" NOT NULL DEFAULT 'VIEWER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "TenantMembership_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "TenantMembership_tenantId_userId_key" ON "TenantMembership"("tenantId", "userId");
CREATE INDEX "TenantMembership_userId_idx" ON "TenantMembership"("userId");
ALTER TABLE "TenantMembership" ADD CONSTRAINT "TenantMembership_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "TenantMembership" ADD CONSTRAINT "TenantMembership_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "User" ADD COLUMN "isSuperAdmin" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "User" ADD COLUMN "lastTenantId" TEXT;
ALTER TABLE "User" ADD COLUMN "isActive" BOOLEAN NOT NULL DEFAULT true;

-- Default organization for all pre-existing data
INSERT INTO "Tenant" ("id","slug","name","isActive","settings","createdAt","updatedAt")
VALUES ('00000000-0000-4000-8000-000000000001','default','Default Organization',true,'{}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);

-- Every existing user becomes a member of the default organization with their legacy role
INSERT INTO "TenantMembership" ("id","tenantId","userId","role","createdAt","updatedAt")
SELECT gen_random_uuid()::text, '00000000-0000-4000-8000-000000000001', u."id", u."role", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM "User" u;
UPDATE "User" SET "lastTenantId" = '00000000-0000-4000-8000-000000000001';

-- orgId on every domain table: add nullable, backfill, then enforce NOT NULL
ALTER TABLE "Account" ADD COLUMN "orgId" TEXT;
UPDATE "Account" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "Account" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "Account_orgId_idx" ON "Account"("orgId");
ALTER TABLE "AwsCredential" ADD COLUMN "orgId" TEXT;
UPDATE "AwsCredential" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AwsCredential" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AwsCredential_orgId_idx" ON "AwsCredential"("orgId");
ALTER TABLE "Scan" ADD COLUMN "orgId" TEXT;
UPDATE "Scan" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "Scan" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "Scan_orgId_idx" ON "Scan"("orgId");
ALTER TABLE "ScanSummary" ADD COLUMN "orgId" TEXT;
UPDATE "ScanSummary" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ScanSummary" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ScanSummary_orgId_idx" ON "ScanSummary"("orgId");
ALTER TABLE "Finding" ADD COLUMN "orgId" TEXT;
UPDATE "Finding" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "Finding" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "Finding_orgId_idx" ON "Finding"("orgId");
ALTER TABLE "AzureSubscription" ADD COLUMN "orgId" TEXT;
UPDATE "AzureSubscription" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AzureSubscription" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AzureSubscription_orgId_idx" ON "AzureSubscription"("orgId");
ALTER TABLE "AzureCredential" ADD COLUMN "orgId" TEXT;
UPDATE "AzureCredential" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AzureCredential" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AzureCredential_orgId_idx" ON "AzureCredential"("orgId");
ALTER TABLE "AzureScan" ADD COLUMN "orgId" TEXT;
UPDATE "AzureScan" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AzureScan" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AzureScan_orgId_idx" ON "AzureScan"("orgId");
ALTER TABLE "AzureScanSummary" ADD COLUMN "orgId" TEXT;
UPDATE "AzureScanSummary" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AzureScanSummary" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AzureScanSummary_orgId_idx" ON "AzureScanSummary"("orgId");
ALTER TABLE "AzureFinding" ADD COLUMN "orgId" TEXT;
UPDATE "AzureFinding" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AzureFinding" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AzureFinding_orgId_idx" ON "AzureFinding"("orgId");
ALTER TABLE "ConfigChange" ADD COLUMN "orgId" TEXT;
UPDATE "ConfigChange" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ConfigChange" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ConfigChange_orgId_idx" ON "ConfigChange"("orgId");
ALTER TABLE "ConfigSyncRun" ADD COLUMN "orgId" TEXT;
UPDATE "ConfigSyncRun" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ConfigSyncRun" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ConfigSyncRun_orgId_idx" ON "ConfigSyncRun"("orgId");
ALTER TABLE "ResourceInventory" ADD COLUMN "orgId" TEXT;
UPDATE "ResourceInventory" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ResourceInventory" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ResourceInventory_orgId_idx" ON "ResourceInventory"("orgId");
ALTER TABLE "ResourceSnapshot" ADD COLUMN "orgId" TEXT;
UPDATE "ResourceSnapshot" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ResourceSnapshot" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ResourceSnapshot_orgId_idx" ON "ResourceSnapshot"("orgId");
ALTER TABLE "ResourceDependency" ADD COLUMN "orgId" TEXT;
UPDATE "ResourceDependency" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ResourceDependency" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ResourceDependency_orgId_idx" ON "ResourceDependency"("orgId");
ALTER TABLE "ExposurePath" ADD COLUMN "orgId" TEXT;
UPDATE "ExposurePath" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ExposurePath" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ExposurePath_orgId_idx" ON "ExposurePath"("orgId");
ALTER TABLE "GcpProject" ADD COLUMN "orgId" TEXT;
UPDATE "GcpProject" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "GcpProject" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "GcpProject_orgId_idx" ON "GcpProject"("orgId");
ALTER TABLE "GcpCredential" ADD COLUMN "orgId" TEXT;
UPDATE "GcpCredential" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "GcpCredential" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "GcpCredential_orgId_idx" ON "GcpCredential"("orgId");
ALTER TABLE "GcpScan" ADD COLUMN "orgId" TEXT;
UPDATE "GcpScan" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "GcpScan" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "GcpScan_orgId_idx" ON "GcpScan"("orgId");
ALTER TABLE "GcpScanSummary" ADD COLUMN "orgId" TEXT;
UPDATE "GcpScanSummary" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "GcpScanSummary" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "GcpScanSummary_orgId_idx" ON "GcpScanSummary"("orgId");
ALTER TABLE "GcpFinding" ADD COLUMN "orgId" TEXT;
UPDATE "GcpFinding" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "GcpFinding" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "GcpFinding_orgId_idx" ON "GcpFinding"("orgId");
ALTER TABLE "AlertConfig" ADD COLUMN "orgId" TEXT;
UPDATE "AlertConfig" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AlertConfig" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AlertConfig_orgId_idx" ON "AlertConfig"("orgId");
ALTER TABLE "AlertLog" ADD COLUMN "orgId" TEXT;
UPDATE "AlertLog" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AlertLog" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AlertLog_orgId_idx" ON "AlertLog"("orgId");
ALTER TABLE "FreezeWindow" ADD COLUMN "orgId" TEXT;
UPDATE "FreezeWindow" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "FreezeWindow" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "FreezeWindow_orgId_idx" ON "FreezeWindow"("orgId");
ALTER TABLE "PostureScore" ADD COLUMN "orgId" TEXT;
UPDATE "PostureScore" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "PostureScore" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "PostureScore_orgId_idx" ON "PostureScore"("orgId");
ALTER TABLE "ConfigBaseline" ADD COLUMN "orgId" TEXT;
UPDATE "ConfigBaseline" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ConfigBaseline" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ConfigBaseline_orgId_idx" ON "ConfigBaseline"("orgId");
ALTER TABLE "BaselineSnapshot" ADD COLUMN "orgId" TEXT;
UPDATE "BaselineSnapshot" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "BaselineSnapshot" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "BaselineSnapshot_orgId_idx" ON "BaselineSnapshot"("orgId");
ALTER TABLE "DriftResult" ADD COLUMN "orgId" TEXT;
UPDATE "DriftResult" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "DriftResult" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "DriftResult_orgId_idx" ON "DriftResult"("orgId");
ALTER TABLE "RemediationLog" ADD COLUMN "orgId" TEXT;
UPDATE "RemediationLog" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "RemediationLog" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "RemediationLog_orgId_idx" ON "RemediationLog"("orgId");
ALTER TABLE "BaselineVersion" ADD COLUMN "orgId" TEXT;
UPDATE "BaselineVersion" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "BaselineVersion" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "BaselineVersion_orgId_idx" ON "BaselineVersion"("orgId");
ALTER TABLE "BaselineVersionSnapshot" ADD COLUMN "orgId" TEXT;
UPDATE "BaselineVersionSnapshot" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "BaselineVersionSnapshot" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "BaselineVersionSnapshot_orgId_idx" ON "BaselineVersionSnapshot"("orgId");
ALTER TABLE "ApprovalRequest" ADD COLUMN "orgId" TEXT;
UPDATE "ApprovalRequest" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ApprovalRequest" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ApprovalRequest_orgId_idx" ON "ApprovalRequest"("orgId");
ALTER TABLE "ReportSchedule" ADD COLUMN "orgId" TEXT;
UPDATE "ReportSchedule" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ReportSchedule" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ReportSchedule_orgId_idx" ON "ReportSchedule"("orgId");
ALTER TABLE "ReportRun" ADD COLUMN "orgId" TEXT;
UPDATE "ReportRun" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ReportRun" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ReportRun_orgId_idx" ON "ReportRun"("orgId");
ALTER TABLE "IntegrationConfig" ADD COLUMN "orgId" TEXT;
UPDATE "IntegrationConfig" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "IntegrationConfig" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "IntegrationConfig_orgId_idx" ON "IntegrationConfig"("orgId");
ALTER TABLE "IntegrationLog" ADD COLUMN "orgId" TEXT;
UPDATE "IntegrationLog" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "IntegrationLog" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "IntegrationLog_orgId_idx" ON "IntegrationLog"("orgId");
ALTER TABLE "IamEscalationEvent" ADD COLUMN "orgId" TEXT;
UPDATE "IamEscalationEvent" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "IamEscalationEvent" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "IamEscalationEvent_orgId_idx" ON "IamEscalationEvent"("orgId");
ALTER TABLE "ComplianceEvidence" ADD COLUMN "orgId" TEXT;
UPDATE "ComplianceEvidence" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "ComplianceEvidence" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "ComplianceEvidence_orgId_idx" ON "ComplianceEvidence"("orgId");
ALTER TABLE "RiskItem" ADD COLUMN "orgId" TEXT;
UPDATE "RiskItem" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "RiskItem" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "RiskItem_orgId_idx" ON "RiskItem"("orgId");
ALTER TABLE "AnomalyBaseline" ADD COLUMN "orgId" TEXT;
UPDATE "AnomalyBaseline" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AnomalyBaseline" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AnomalyBaseline_orgId_idx" ON "AnomalyBaseline"("orgId");
ALTER TABLE "AnomalyEvent" ADD COLUMN "orgId" TEXT;
UPDATE "AnomalyEvent" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AnomalyEvent" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AnomalyEvent_orgId_idx" ON "AnomalyEvent"("orgId");
ALTER TABLE "PrincipalPermission" ADD COLUMN "orgId" TEXT;
UPDATE "PrincipalPermission" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "PrincipalPermission" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "PrincipalPermission_orgId_idx" ON "PrincipalPermission"("orgId");
ALTER TABLE "AttackPath" ADD COLUMN "orgId" TEXT;
UPDATE "AttackPath" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "AttackPath" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "AttackPath_orgId_idx" ON "AttackPath"("orgId");
ALTER TABLE "WorkloadVulnerability" ADD COLUMN "orgId" TEXT;
UPDATE "WorkloadVulnerability" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "WorkloadVulnerability" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "WorkloadVulnerability_orgId_idx" ON "WorkloadVulnerability"("orgId");
ALTER TABLE "DataClassification" ADD COLUMN "orgId" TEXT;
UPDATE "DataClassification" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
ALTER TABLE "DataClassification" ALTER COLUMN "orgId" SET NOT NULL;
CREATE INDEX "DataClassification_orgId_idx" ON "DataClassification"("orgId");
ALTER TABLE "AuditLog" ADD COLUMN "orgId" TEXT;
UPDATE "AuditLog" SET "orgId" = '00000000-0000-4000-8000-000000000001' WHERE "orgId" IS NULL;
CREATE INDEX "AuditLog_orgId_idx" ON "AuditLog"("orgId");

-- Prisma types treat orgId as optional (schema default ''), so the DB refuses an unstamped row.
ALTER TABLE "Account" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "Account" ADD CONSTRAINT "Account_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AwsCredential" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AwsCredential" ADD CONSTRAINT "AwsCredential_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "Scan" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ScanSummary" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ScanSummary" ADD CONSTRAINT "ScanSummary_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "Finding" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AzureSubscription" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AzureSubscription" ADD CONSTRAINT "AzureSubscription_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AzureCredential" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AzureCredential" ADD CONSTRAINT "AzureCredential_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AzureScan" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AzureScan" ADD CONSTRAINT "AzureScan_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AzureScanSummary" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AzureScanSummary" ADD CONSTRAINT "AzureScanSummary_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AzureFinding" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AzureFinding" ADD CONSTRAINT "AzureFinding_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ConfigChange" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ConfigChange" ADD CONSTRAINT "ConfigChange_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ConfigSyncRun" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ConfigSyncRun" ADD CONSTRAINT "ConfigSyncRun_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ResourceInventory" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ResourceInventory" ADD CONSTRAINT "ResourceInventory_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ResourceSnapshot" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ResourceSnapshot" ADD CONSTRAINT "ResourceSnapshot_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ResourceDependency" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ResourceDependency" ADD CONSTRAINT "ResourceDependency_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ExposurePath" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ExposurePath" ADD CONSTRAINT "ExposurePath_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "GcpProject" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "GcpProject" ADD CONSTRAINT "GcpProject_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "GcpCredential" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "GcpCredential" ADD CONSTRAINT "GcpCredential_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "GcpScan" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "GcpScan" ADD CONSTRAINT "GcpScan_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "GcpScanSummary" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "GcpScanSummary" ADD CONSTRAINT "GcpScanSummary_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "GcpFinding" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "GcpFinding" ADD CONSTRAINT "GcpFinding_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AlertConfig" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AlertConfig" ADD CONSTRAINT "AlertConfig_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AlertLog" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AlertLog" ADD CONSTRAINT "AlertLog_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "FreezeWindow" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "FreezeWindow" ADD CONSTRAINT "FreezeWindow_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "PostureScore" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "PostureScore" ADD CONSTRAINT "PostureScore_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ConfigBaseline" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ConfigBaseline" ADD CONSTRAINT "ConfigBaseline_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "BaselineSnapshot" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "BaselineSnapshot" ADD CONSTRAINT "BaselineSnapshot_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "DriftResult" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "DriftResult" ADD CONSTRAINT "DriftResult_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "RemediationLog" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "RemediationLog" ADD CONSTRAINT "RemediationLog_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "BaselineVersion" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "BaselineVersion" ADD CONSTRAINT "BaselineVersion_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "BaselineVersionSnapshot" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "BaselineVersionSnapshot" ADD CONSTRAINT "BaselineVersionSnapshot_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ApprovalRequest" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ApprovalRequest" ADD CONSTRAINT "ApprovalRequest_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ReportSchedule" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ReportSchedule" ADD CONSTRAINT "ReportSchedule_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ReportRun" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ReportRun" ADD CONSTRAINT "ReportRun_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "IntegrationConfig" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "IntegrationConfig" ADD CONSTRAINT "IntegrationConfig_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "IntegrationLog" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "IntegrationLog" ADD CONSTRAINT "IntegrationLog_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "IamEscalationEvent" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "IamEscalationEvent" ADD CONSTRAINT "IamEscalationEvent_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "ComplianceEvidence" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "ComplianceEvidence" ADD CONSTRAINT "ComplianceEvidence_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "RiskItem" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "RiskItem" ADD CONSTRAINT "RiskItem_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AnomalyBaseline" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AnomalyBaseline" ADD CONSTRAINT "AnomalyBaseline_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AnomalyEvent" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AnomalyEvent" ADD CONSTRAINT "AnomalyEvent_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "PrincipalPermission" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "PrincipalPermission" ADD CONSTRAINT "PrincipalPermission_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "AttackPath" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "AttackPath" ADD CONSTRAINT "AttackPath_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "WorkloadVulnerability" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "WorkloadVulnerability" ADD CONSTRAINT "WorkloadVulnerability_orgId_not_blank" CHECK ("orgId" <> '');
ALTER TABLE "DataClassification" ALTER COLUMN "orgId" SET DEFAULT '';
ALTER TABLE "DataClassification" ADD CONSTRAINT "DataClassification_orgId_not_blank" CHECK ("orgId" <> '');
