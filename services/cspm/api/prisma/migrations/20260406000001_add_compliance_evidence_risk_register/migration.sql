-- CreateTable
CREATE TABLE "ComplianceEvidence" (
    "id"           TEXT NOT NULL,
    "frameworkId"  TEXT NOT NULL,
    "controlId"    TEXT NOT NULL,
    "provider"     TEXT NOT NULL,
    "accountId"    TEXT,
    "evidenceType" TEXT NOT NULL,
    "status"       TEXT NOT NULL,
    "summary"      TEXT NOT NULL,
    "detail"       JSONB,
    "sourceType"   TEXT,
    "sourceId"     TEXT,
    "collectedAt"  TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt"    TIMESTAMP(3),
    "createdAt"    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"    TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ComplianceEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskItem" (
    "id"                  TEXT NOT NULL,
    "title"               TEXT NOT NULL,
    "description"         TEXT NOT NULL,
    "category"            TEXT NOT NULL,
    "likelihood"          INTEGER NOT NULL,
    "impact"              INTEGER NOT NULL,
    "riskScore"           INTEGER NOT NULL,
    "status"              TEXT NOT NULL DEFAULT 'OPEN',
    "owner"               TEXT,
    "dueDate"             TIMESTAMP(3),
    "provider"            TEXT,
    "accountId"           TEXT,
    "linkedFindingIds"    JSONB NOT NULL DEFAULT '[]',
    "linkedControlIds"    JSONB NOT NULL DEFAULT '[]',
    "mitigationPlan"      TEXT,
    "acceptanceRationale" TEXT,
    "createdAt"           TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"           TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RiskItem_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ComplianceEvidence_frameworkId_controlId_idx"  ON "ComplianceEvidence"("frameworkId", "controlId");
CREATE INDEX "ComplianceEvidence_provider_accountId_idx"     ON "ComplianceEvidence"("provider", "accountId");
CREATE INDEX "ComplianceEvidence_collectedAt_idx"            ON "ComplianceEvidence"("collectedAt" DESC);
CREATE INDEX "ComplianceEvidence_status_idx"                 ON "ComplianceEvidence"("status");

CREATE INDEX "RiskItem_status_idx"           ON "RiskItem"("status");
CREATE INDEX "RiskItem_riskScore_idx"        ON "RiskItem"("riskScore" DESC);
CREATE INDEX "RiskItem_provider_accountId_idx" ON "RiskItem"("provider", "accountId");
CREATE INDEX "RiskItem_category_idx"         ON "RiskItem"("category");
