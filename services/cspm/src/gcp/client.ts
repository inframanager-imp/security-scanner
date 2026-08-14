import { GoogleAuth } from 'google-auth-library';
import { cloudresourcemanager as cloudresourcemanagerApi } from '@googleapis/cloudresourcemanager';
import { iam as iamApi } from '@googleapis/iam';
import { storage as storageApi } from '@googleapis/storage';
import { compute as computeApi } from '@googleapis/compute';
import { sqladmin as sqladminApi } from '@googleapis/sqladmin';
import { container as containerApi } from '@googleapis/container';
import { run as runApi } from '@googleapis/run';
import { bigquery as bigqueryApi } from '@googleapis/bigquery';
import { cloudkms as cloudkmsApi } from '@googleapis/cloudkms';
import { secretmanager as secretmanagerApi } from '@googleapis/secretmanager';
import { cloudfunctions as cloudfunctionsApi } from '@googleapis/cloudfunctions';
import { pubsub as pubsubApi } from '@googleapis/pubsub';
import { artifactregistry as artifactregistryApi } from '@googleapis/artifactregistry';
import { logging as loggingApi } from '@googleapis/logging';
import { monitoring as monitoringApi } from '@googleapis/monitoring';
import { apikeys as apikeysApi } from '@googleapis/apikeys';
import { dns as dnsApi } from '@googleapis/dns';
import { dataproc as dataprocApi } from '@googleapis/dataproc';
import { serviceusage as serviceusageApi } from '@googleapis/serviceusage';
import { accessapproval as accessapprovalApi } from '@googleapis/accessapproval';
import { essentialcontacts as essentialcontactsApi } from '@googleapis/essentialcontacts';

export interface GcpClientOptions {
  projectId:           string;
  credentials?:        Record<string, unknown>; // parsed service account JSON (omit for Workload Identity)
  serviceAccountEmail?: string;
  authMethod?:         'SERVICE_ACCOUNT_KEY' | 'WORKLOAD_IDENTITY';
}

export default class GcpClient {
  readonly projectId:   string;
  readonly auth:        GoogleAuth;

  constructor(options: GcpClientOptions) {
    this.projectId = options.projectId;
    this.auth = new GoogleAuth({
      ...(options.credentials ? { credentials: options.credentials as any } : {}),
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
  }

  async verifyCredentials(): Promise<{ valid: boolean; error?: string; projectId?: string }> {
    try {
      const rm      = this.cloudresourcemanager();
      const project = await rm.projects.get({ name: `projects/${this.projectId}` });
      return { valid: true, projectId: project.data.projectId ?? this.projectId };
    } catch (err) {
      return { valid: false, error: (err as Error).message };
    }
  }

  cloudresourcemanager() { return cloudresourcemanagerApi({ version: 'v3', auth: this.auth }); }
  iam()                  { return iamApi({ version: 'v1', auth: this.auth }); }
  storage()              { return storageApi({ version: 'v1', auth: this.auth }); }
  compute()              { return computeApi({ version: 'v1', auth: this.auth }); }
  sqladmin()             { return sqladminApi({ version: 'v1', auth: this.auth }); }
  container()            { return containerApi({ version: 'v1', auth: this.auth }); }
  run()                  { return runApi({ version: 'v2', auth: this.auth }); }
  bigquery()             { return bigqueryApi({ version: 'v2', auth: this.auth }); }
  cloudkms()             { return cloudkmsApi({ version: 'v1', auth: this.auth }); }
  secretmanager()        { return secretmanagerApi({ version: 'v1', auth: this.auth }); }
  cloudfunctions()       { return cloudfunctionsApi({ version: 'v2', auth: this.auth }); }
  pubsub()               { return pubsubApi({ version: 'v1', auth: this.auth }); }
  artifactregistry()     { return artifactregistryApi({ version: 'v1', auth: this.auth }); }
  logging()              { return loggingApi({ version: 'v2', auth: this.auth }); }
  monitoring()           { return monitoringApi({ version: 'v3', auth: this.auth }); }
  cloudresourcemanagerV1() { return cloudresourcemanagerApi({ version: 'v1', auth: this.auth }); }
  apikeys()               { return apikeysApi({ version: 'v2', auth: this.auth }); }
  dns()                   { return dnsApi({ version: 'v1', auth: this.auth }); }
  dataproc()               { return dataprocApi({ version: 'v1', auth: this.auth }); }
  serviceusage()           { return serviceusageApi({ version: 'v1', auth: this.auth }); }
  accessapproval()         { return accessapprovalApi({ version: 'v1', auth: this.auth }); }
  essentialcontacts()      { return essentialcontactsApi({ version: 'v1', auth: this.auth }); }
}
