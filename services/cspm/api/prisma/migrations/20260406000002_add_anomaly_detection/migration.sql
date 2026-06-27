-- CreateTable: AnomalyBaseline
CREATE TABLE "AnomalyBaseline" (
    "id"              TEXT NOT NULL,
    "provider"        TEXT NOT NULL,
    "accountId"       TEXT NOT NULL,
    "actorId"         TEXT NOT NULL,
    "metricKey"       TEXT NOT NULL,
    "ewmaMean"        DOUBLE PRECISION NOT NULL DEFAULT 0,
    "ewmaVariance"    DOUBLE PRECISION NOT NULL DEFAULT 0,
    "sampleCount"     INTEGER NOT NULL DEFAULT 0,
    "lastValue"       DOUBLE PRECISION NOT NULL DEFAULT 0,
    "lastUpdated"     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "knownIps"        JSONB NOT NULL DEFAULT '[]',
    "knownCountries"  JSONB NOT NULL DEFAULT '[]',
    "knownRegions"    JSONB NOT NULL DEFAULT '[]',
    "hourlyActivity"  JSONB NOT NULL DEFAULT '{}',
    "createdAt"       TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"       TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AnomalyBaseline_pkey" PRIMARY KEY ("id")
);

-- CreateTable: AnomalyEvent
CREATE TABLE "AnomalyEvent" (
    "id"              TEXT NOT NULL,
    "provider"        TEXT NOT NULL,
    "accountId"       TEXT NOT NULL,
    "actorId"         TEXT NOT NULL,
    "anomalyType"     TEXT NOT NULL,
    "severity"        TEXT NOT NULL,
    "score"           DOUBLE PRECISION NOT NULL,
    "description"     TEXT NOT NULL,
    "detail"          JSONB NOT NULL,
    "sourceIp"        TEXT,
    "country"         TEXT,
    "eventName"       TEXT,
    "relatedEventIds" JSONB NOT NULL DEFAULT '[]',
    "status"          TEXT NOT NULL DEFAULT 'OPEN',
    "resolvedAt"      TIMESTAMP(3),
    "notes"           TEXT,
    "detectedAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt"       TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"       TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AnomalyEvent_pkey" PRIMARY KEY ("id")
);

-- Unique constraint
CREATE UNIQUE INDEX "AnomalyBaseline_provider_accountId_actorId_metricKey_key"
    ON "AnomalyBaseline"("provider", "accountId", "actorId", "metricKey");

-- Indexes
CREATE INDEX "AnomalyBaseline_provider_accountId_idx" ON "AnomalyBaseline"("provider", "accountId");
CREATE INDEX "AnomalyBaseline_actorId_idx"            ON "AnomalyBaseline"("actorId");

CREATE INDEX "AnomalyEvent_provider_accountId_detectedAt_idx" ON "AnomalyEvent"("provider", "accountId", "detectedAt" DESC);
CREATE INDEX "AnomalyEvent_anomalyType_idx"    ON "AnomalyEvent"("anomalyType");
CREATE INDEX "AnomalyEvent_severity_idx"       ON "AnomalyEvent"("severity");
CREATE INDEX "AnomalyEvent_status_idx"         ON "AnomalyEvent"("status");
CREATE INDEX "AnomalyEvent_actorId_idx"        ON "AnomalyEvent"("actorId");
