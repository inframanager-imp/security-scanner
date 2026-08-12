export type Role = 'ADMIN' | 'ANALYST' | 'VIEWER';
export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'MONITORING';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';
export type AuthMethod = 'ACCESS_KEY' | 'ASSUME_ROLE';
export type AzureAuthMethod = 'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY';

export interface User {
  id: string;
  email: string;
  role: Role;
}

export type InventoryStatus = 'PENDING' | 'INITIALIZING' | 'READY' | 'FAILED';

export interface Account {
  id: string;
  name: string;
  awsAccountId: string;
  description?: string;
  createdAt: string;
  updatedAt: string;
  latestScan?: Scan;
  hasCredentials?: boolean;
  lastSuccessfulScanId?: string | null;
  inventoryStatus?:  InventoryStatus;
  inventoryInitAt?:  string | null;
  lastDiscoveryAt?:  string | null;
  lastConfigSyncAt?: string | null;
  pipelineError?:    string | null;
}

export interface Scan {
  id: string;
  accountId: string;
  status: ScanStatus;
  services: string[];
  regions: string[];
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
  createdAt: string;
  summary?: ScanSummary;
  account?: { name: string; awsAccountId: string };
  errorMessage?: string | null;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ComplianceTag {
  frameworkShortName: string;
  controlId: string;
}

export interface Finding {
  id: string;
  scanId: string;
  accountId?: string;
  accountName?: string;
  service: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  remediation: string;
  findingStatus: FindingStatus;
  tags: string[];
  discoveredAt: string;
  complianceTags?: ComplianceTag[];
}

export interface DashboardSummary {
  totalAccounts: number;
  totalScans: number;
  activeScans: number;
  lastScanAt?: string;
  findingsBySeverity: ScanSummary;
  accountsAtRisk: number;
}

export interface TrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AccountSummary {
  id: string;
  name: string;
  awsAccountId: string;
  lastScanAt?: string;
  lastScanStatus?: ScanStatus;
  summary: ScanSummary | null;
}

export interface Credential {
  id: string;
  accountId: string;
  authMethod: AuthMethod;
  accessKeyId?: string;
  roleArn?: string;
  externalId?: string;
  isVerified: boolean;
  lastVerifiedAt?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// ─── Azure Types ──────────────────────────────────────────────────────────────

export interface AzureSubscription {
  id:                  string;
  name:                string;
  subscriptionId:      string;
  tenantId?:           string | null;
  description?:        string | null;
  createdAt:           string;
  updatedAt:           string;
  hasCredentials:      boolean;
  credential?:         AzureCredential | null;
  scans?:              AzureScan[];
  lastSuccessfulScanId?: string | null;
  latestScan?:         AzureScan | null;
  inventoryStatus?:    InventoryStatus;
  inventoryInitAt?:    string | null;
  lastDiscoveryAt?:    string | null;
  lastConfigSyncAt?:   string | null;
  pipelineError?:      string | null;
}

export interface AzureCredential {
  id:             string;
  subscriptionId: string;
  authMethod:     AzureAuthMethod;
  createdAt:      string;
  updatedAt:      string;
}

export interface AzureScan {
  id:             string;
  subscriptionId: string;
  status:         ScanStatus;
  services:       string[];
  startedAt?:     string | null;
  completedAt?:   string | null;
  durationMs?:    number | null;
  createdAt:      string;
  errorMessage?:  string | null;
  summary?:       AzureScanSummary | null;
  subscription?:  { id: string; name: string; subscriptionId: string };
}

export interface AzureScanSummary {
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
  info:     number;
  total:    number;
}

export interface AzureFinding {
  id:             string;
  scanId:         string;
  service:        string;
  severity:       Severity;
  title:          string;
  description:    string;
  evidence:       Record<string, unknown>;
  remediation:    string;
  findingStatus:  FindingStatus;
  tags:           string[];
  resourceGroup?: string | null;
  resourceId?:    string | null;
  discoveredAt:   string;
  createdAt:      string;
  complianceTags?: ComplianceTag[];
}

export interface AzureActivityEvent {
  id:              string;
  eventTimestamp:  string | null;
  operationName:   string | null;
  status:          string | null;
  caller:          string | null;
  level:           string | null;
  severity:        Severity;
  resourceGroup:   string | null;
  resourceId:      string | null;
  description:     string | null;
  category:        string | null;
}

export interface FindingsFilter {
  severity?: Severity;
  service?: string;
  services?: string[];
  findingStatus?: FindingStatus;
  search?: string;
  page?: number;
  pageSize?: number;
  accountId?: string;
  sortBy?: 'severity' | 'service' | 'status' | 'discoveredAt' | 'title';
  sortOrder?: 'asc' | 'desc';
}

// ─── GCP Types ────────────────────────────────────────────────────────────────

export type GcpAuthMethod = 'SERVICE_ACCOUNT_KEY' | 'WORKLOAD_IDENTITY';

export interface GcpProject {
  id:                  string;
  name:                string;
  projectId:           string;
  description?:        string | null;
  createdAt:           string;
  updatedAt:           string;
  hasCredentials:      boolean;
  credential?:         GcpCredential | null;
  scans?:              GcpScan[];
  lastSuccessfulScanId?: string | null;
  latestScan?:         GcpScan | null;
  inventoryStatus?:    InventoryStatus;
  inventoryInitAt?:    string | null;
  lastDiscoveryAt?:    string | null;
  lastConfigSyncAt?:   string | null;
  pipelineError?:      string | null;
}

export interface GcpCredential {
  id:                  string;
  projectId:           string;
  authMethod:          GcpAuthMethod;
  serviceAccountEmail?: string | null;
  createdAt:           string;
  updatedAt:           string;
}

export interface GcpScan {
  id:           string;
  projectId:    string;
  status:       ScanStatus;
  services:     string[];
  startedAt?:   string | null;
  completedAt?: string | null;
  durationMs?:  number | null;
  createdAt:    string;
  errorMessage?: string | null;
  summary?:     GcpScanSummary | null;
  project?:     { id: string; name: string; projectId: string };
}

export interface GcpScanSummary {
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
  info:     number;
  total:    number;
}

export interface GcpFinding {
  id:            string;
  scanId:        string;
  service:       string;
  severity:      Severity;
  title:         string;
  description:   string;
  evidence:      Record<string, unknown>;
  remediation:   string;
  findingStatus: FindingStatus;
  tags:          string[];
  resourceName?: string | null;
  region?:       string | null;
  discoveredAt:  string;
  createdAt:     string;
}

// ─── Config Change Tracking ───────────────────────────────────────────────────

export type ChangeAction   = 'CREATED' | 'MODIFIED' | 'DELETED';
export type ChangeCategory = 'IAM' | 'NETWORK' | 'STORAGE' | 'COMPUTE' | 'DATABASE' | 'ENCRYPTION' | 'LOGGING' | 'OTHER';
export type ChangeStatus   = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';
export type CloudProvider  = 'AWS' | 'AZURE' | 'GCP';

export interface ConfigChange {
  id:            string;
  provider:      CloudProvider;
  changeAction:  ChangeAction;
  category:      ChangeCategory;
  riskScore:     number;
  severity:      Severity;
  sourceEventId: string;
  eventName:     string;
  eventTime:     string;
  region?:       string | null;
  actor?:        string | null;
  actorType?:    string | null;
  sourceIp?:     string | null;
  resourceType?: string | null;
  resourceId?:   string | null;
  resourceName?: string | null;
  summary:       string;
  previousValue?: Record<string, unknown> | null;
  newValue?:     Record<string, unknown> | null;
  changeStatus:  ChangeStatus;
  acknowledgedBy?: string | null;
  acknowledgedAt?: string | null;
  notes?:        string | null;
  createdAt:     string;
}

export interface ConfigChangeStats {
  bySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  byCategory: Partial<Record<ChangeCategory, number>>;
  topActors:  { actor: string | null; count: number }[];
  timeline:   { date: string; critical: number; high: number; medium: number; low: number }[];
  total:      number;
}

// ─── Resource Inventory ───────────────────────────────────────────────────────

export type ResourceState   = 'ACTIVE' | 'DELETED';
export type DependencyType  = 'NETWORK' | 'IAM' | 'STORAGE' | 'COMPUTE' | 'DATABASE' | 'OTHER';

export interface ResourceInventoryItem {
  id:                 string;
  provider:           CloudProvider;
  nativeId:           string;
  resourceType:       string;
  resourceName?:      string | null;
  region?:            string | null;
  resourceGroup?:     string | null;
  tags?:              Record<string, string> | null;
  state:              ResourceState;
  discoveredAt:       string;              // when scanner first found this resource
  resourceCreatedAt?: string | null;       // when cloud actually created it (from API metadata)
  lastSeenAt:         string;
  deletedAt?:         string | null;
  _count?:            { snapshots: number; depsFrom: number; depsTo: number };
}

export interface ResourceDetail extends ResourceInventoryItem {
  configState:   Record<string, unknown>;
}

export interface ResourceSnapshot {
  id:          string;
  inventoryId: string;
  configState: Record<string, unknown>;
  changeType:  'CREATED' | 'MODIFIED' | 'DELETED';
  capturedAt:  string;
  diff?:       Record<string, { from: unknown; to: unknown }> | null;
}

export interface ResourceDependencyEdge {
  id:          string;
  depType:     DependencyType;
  description?: string | null;
  resource:    {
    id:           string;
    resourceType: string;
    resourceName?: string | null;
    nativeId:     string;
    provider:     CloudProvider;
    state:        ResourceState;
  };
}

export interface ResourceDeps {
  dependsOn: ResourceDependencyEdge[];
  usedBy:    ResourceDependencyEdge[];
}

export interface ResourceInventoryStats {
  total:      number;
  byProvider: Record<string, number>;
  byType:     { type: string; count: number }[];
  byState:    Record<string, number>;
  // snapshot activity counts (present when windowDays param > 0)
  windowDays?: number;
  created?:   number;
  modified?:  number;
  deleted?:   number;
}

export interface ResourceActivityLogEntry {
  id:         string;
  changeType: 'MODIFIED' | 'DELETED';
  capturedAt: string;
  inventory: {
    id:           string;
    nativeId:     string;
    resourceType: string;
    resourceName?: string | null;
    region?:      string | null;
    provider:     CloudProvider;
    state:        ResourceState;
  };
}

export interface ResourceActivityLogResponse {
  data:       ResourceActivityLogEntry[];
  total:      number;
  page:       number;
  pageSize:   number;
  totalPages: number;
}

export interface ConfigSyncRun {
  id:            string;
  provider:      CloudProvider;
  targetId:      string;
  status:        ScanStatus;
  windowStart:   string;
  windowEnd:     string;
  eventsFound?:  number | null;
  changesStored?: number | null;
  errorMessage?: string | null;
  startedAt?:    string | null;
  completedAt?:  string | null;
  createdAt:     string;
}

