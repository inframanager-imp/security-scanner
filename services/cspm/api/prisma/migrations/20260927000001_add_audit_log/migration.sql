-- CreateTable: AuditLog (user-action audit trail)
CREATE TABLE "AuditLog" (
    "id"          TEXT NOT NULL,
    "createdAt"   TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId"      TEXT,
    "userRole"    TEXT,
    "actorEmail"  TEXT,
    "action"      TEXT NOT NULL,
    "method"      TEXT NOT NULL,
    "path"        TEXT NOT NULL,
    "query"       TEXT,
    "statusCode"  INTEGER NOT NULL,
    "outcome"     TEXT NOT NULL,
    "ip"          TEXT,
    "userAgent"   TEXT,
    "requestBody" TEXT,
    "durationMs"  INTEGER,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- Indexes
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt" DESC);
CREATE INDEX "AuditLog_userId_createdAt_idx" ON "AuditLog"("userId", "createdAt" DESC);
CREATE INDEX "AuditLog_action_idx" ON "AuditLog"("action");
CREATE INDEX "AuditLog_outcome_idx" ON "AuditLog"("outcome");

-- Foreign key: keep the audit row if the user is deleted
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey"
    FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
