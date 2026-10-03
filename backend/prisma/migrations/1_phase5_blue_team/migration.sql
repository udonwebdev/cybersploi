-- Phase 5: Blue Team / Incident Response schema additions

-- CreateTable "Incident"
CREATE TABLE "Incident" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organizationId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" TEXT NOT NULL DEFAULT 'medium',
    "status" TEXT NOT NULL DEFAULT 'open',
    "detectionSource" TEXT,
    "detectedAt" DATETIME,
    "assignedTo" TEXT,
    "confidence" REAL DEFAULT 0.0,
    "indicators" TEXT NOT NULL DEFAULT '[]',
    "metadata" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Incident_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization" ("id") ON DELETE CASCADE
);

CREATE INDEX "Incident_organizationId_idx" ON "Incident"("organizationId");
CREATE INDEX "Incident_status_idx" ON "Incident"("status");
CREATE INDEX "Incident_severity_idx" ON "Incident"("severity");

-- CreateTable "Playbook"
CREATE TABLE "Playbook" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Playbook_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization" ("id") ON DELETE CASCADE
);

CREATE INDEX "Playbook_organizationId_idx" ON "Playbook"("organizationId");

-- CreateTable "PlaybookStep"
CREATE TABLE "PlaybookStep" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "playbookId" TEXT NOT NULL,
    "sequence" INTEGER NOT NULL DEFAULT 0,
    "action" TEXT NOT NULL,
    "parameters" TEXT,
    "timeoutMs" INTEGER DEFAULT 60000,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "PlaybookStep_playbookId_fkey" FOREIGN KEY ("playbookId") REFERENCES "Playbook" ("id") ON DELETE CASCADE
);

CREATE INDEX "PlaybookStep_playbookId_idx" ON "PlaybookStep"("playbookId");

-- CreateTable "RemediationTask"
CREATE TABLE "RemediationTask" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "incidentId" TEXT NOT NULL,
    "playbookStepId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "executor" TEXT,
    "startedAt" DATETIME,
    "completedAt" DATETIME,
    "result" TEXT,
    "logs" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "RemediationTask_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident" ("id") ON DELETE CASCADE,
    CONSTRAINT "RemediationTask_playbookStepId_fkey" FOREIGN KEY ("playbookStepId") REFERENCES "PlaybookStep" ("id") ON DELETE SET NULL
);

CREATE INDEX "RemediationTask_incidentId_idx" ON "RemediationTask"("incidentId");
CREATE INDEX "RemediationTask_status_idx" ON "RemediationTask"("status");

-- CreateTable "Alert"
CREATE TABLE "Alert" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organizationId" TEXT NOT NULL,
    "incidentId" TEXT,
    "provider" TEXT,
    "externalId" TEXT,
    "severity" TEXT,
    "payload" TEXT,
    "receivedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Alert_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization" ("id") ON DELETE CASCADE,
    CONSTRAINT "Alert_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident" ("id") ON DELETE SET NULL
);

CREATE INDEX "Alert_organizationId_idx" ON "Alert"("organizationId");
CREATE INDEX "Alert_incidentId_idx" ON "Alert"("incidentId");

-- CreateTable "EndpointAction"
CREATE TABLE "EndpointAction" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "remediationTaskId" TEXT NOT NULL,
    "endpointId" TEXT,
    "actionType" TEXT,
    "parameters" TEXT,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "startedAt" DATETIME,
    "completedAt" DATETIME,
    "result" TEXT,
    CONSTRAINT "EndpointAction_remediationTaskId_fkey" FOREIGN KEY ("remediationTaskId") REFERENCES "RemediationTask" ("id") ON DELETE CASCADE
);

CREATE INDEX "EndpointAction_remediationTaskId_idx" ON "EndpointAction"("remediationTaskId");

-- End Phase 5 migration
