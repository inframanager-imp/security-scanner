-- CreateEnum
CREATE TYPE "GcpAuthMethod" AS ENUM ('SERVICE_ACCOUNT_KEY', 'WORKLOAD_IDENTITY');

-- CreateTable
CREATE TABLE "GcpProject" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "description" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GcpProject_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GcpCredential" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "authMethod" "GcpAuthMethod" NOT NULL,
    "encryptedServiceAccountKey" TEXT,
    "serviceAccountEmail" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GcpCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GcpScan" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'QUEUED',
    "jobId" TEXT,
    "services" TEXT[],
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "durationMs" INTEGER,
    "errorMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GcpScan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GcpScanSummary" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "critical" INTEGER NOT NULL DEFAULT 0,
    "high" INTEGER NOT NULL DEFAULT 0,
    "medium" INTEGER NOT NULL DEFAULT 0,
    "low" INTEGER NOT NULL DEFAULT 0,
    "info" INTEGER NOT NULL DEFAULT 0,
    "total" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "GcpScanSummary_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GcpFinding" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "service" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "evidence" JSONB NOT NULL,
    "remediation" TEXT NOT NULL,
    "findingStatus" "FindingStatus" NOT NULL DEFAULT 'OPEN',
    "tags" TEXT[],
    "resourceName" TEXT,
    "region" TEXT,
    "discoveredAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GcpFinding_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "GcpProject_projectId_key" ON "GcpProject"("projectId");

-- CreateIndex
CREATE UNIQUE INDEX "GcpCredential_projectId_key" ON "GcpCredential"("projectId");

-- CreateIndex
CREATE UNIQUE INDEX "GcpScan_jobId_key" ON "GcpScan"("jobId");

-- CreateIndex
CREATE UNIQUE INDEX "GcpScanSummary_scanId_key" ON "GcpScanSummary"("scanId");

-- CreateIndex
CREATE INDEX "GcpFinding_scanId_idx" ON "GcpFinding"("scanId");

-- CreateIndex
CREATE INDEX "GcpFinding_severity_idx" ON "GcpFinding"("severity");

-- CreateIndex
CREATE INDEX "GcpFinding_service_idx" ON "GcpFinding"("service");

-- CreateIndex
CREATE INDEX "GcpFinding_findingStatus_idx" ON "GcpFinding"("findingStatus");

-- AddForeignKey
ALTER TABLE "GcpProject" ADD CONSTRAINT "GcpProject_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GcpCredential" ADD CONSTRAINT "GcpCredential_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "GcpProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GcpScan" ADD CONSTRAINT "GcpScan_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "GcpProject"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GcpScanSummary" ADD CONSTRAINT "GcpScanSummary_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "GcpScan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GcpFinding" ADD CONSTRAINT "GcpFinding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "GcpScan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
