-- CreateEnum
CREATE TYPE "AzureAuthMethod" AS ENUM ('SERVICE_PRINCIPAL', 'MANAGED_IDENTITY');

-- CreateTable
CREATE TABLE "AzureSubscription" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "subscriptionId" TEXT NOT NULL,
    "tenantId" TEXT,
    "description" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AzureSubscription_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AzureCredential" (
    "id" TEXT NOT NULL,
    "subscriptionId" TEXT NOT NULL,
    "authMethod" "AzureAuthMethod" NOT NULL,
    "encryptedTenantId" TEXT,
    "encryptedClientId" TEXT,
    "encryptedClientSecret" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AzureCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AzureScan" (
    "id" TEXT NOT NULL,
    "subscriptionId" TEXT NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'QUEUED',
    "jobId" TEXT,
    "services" TEXT[],
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "durationMs" INTEGER,
    "errorMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AzureScan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AzureScanSummary" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "critical" INTEGER NOT NULL DEFAULT 0,
    "high" INTEGER NOT NULL DEFAULT 0,
    "medium" INTEGER NOT NULL DEFAULT 0,
    "low" INTEGER NOT NULL DEFAULT 0,
    "info" INTEGER NOT NULL DEFAULT 0,
    "total" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "AzureScanSummary_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AzureFinding" (
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
    "resourceGroup" TEXT,
    "resourceId" TEXT,
    "discoveredAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AzureFinding_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AzureCredential_subscriptionId_key" ON "AzureCredential"("subscriptionId");

-- CreateIndex
CREATE UNIQUE INDEX "AzureScan_jobId_key" ON "AzureScan"("jobId");

-- CreateIndex
CREATE UNIQUE INDEX "AzureScanSummary_scanId_key" ON "AzureScanSummary"("scanId");

-- CreateIndex
CREATE INDEX "AzureFinding_scanId_idx" ON "AzureFinding"("scanId");

-- CreateIndex
CREATE INDEX "AzureFinding_severity_idx" ON "AzureFinding"("severity");

-- CreateIndex
CREATE INDEX "AzureFinding_service_idx" ON "AzureFinding"("service");

-- CreateIndex
CREATE INDEX "AzureFinding_findingStatus_idx" ON "AzureFinding"("findingStatus");

-- AddForeignKey
ALTER TABLE "AzureSubscription" ADD CONSTRAINT "AzureSubscription_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AzureCredential" ADD CONSTRAINT "AzureCredential_subscriptionId_fkey" FOREIGN KEY ("subscriptionId") REFERENCES "AzureSubscription"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AzureScan" ADD CONSTRAINT "AzureScan_subscriptionId_fkey" FOREIGN KEY ("subscriptionId") REFERENCES "AzureSubscription"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AzureScanSummary" ADD CONSTRAINT "AzureScanSummary_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "AzureScan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AzureFinding" ADD CONSTRAINT "AzureFinding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "AzureScan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
