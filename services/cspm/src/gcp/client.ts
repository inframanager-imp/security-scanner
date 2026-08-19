import { google, Auth } from 'googleapis';

export interface GcpClientOptions {
  projectId:           string;
  credentials?:        Record<string, unknown>; // parsed service account JSON (omit for Workload Identity)
  serviceAccountEmail?: string;
  authMethod?:         'SERVICE_ACCOUNT_KEY' | 'WORKLOAD_IDENTITY';
}

export default class GcpClient {
  readonly projectId:   string;
  readonly auth:        Auth.GoogleAuth;

  constructor(options: GcpClientOptions) {
    this.projectId = options.projectId;
    this.auth = new google.auth.GoogleAuth({
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

  cloudresourcemanager() { return google.cloudresourcemanager({ version: 'v3', auth: this.auth }); }
  iam()                  { return google.iam({ version: 'v1', auth: this.auth }); }
  storage()              { return google.storage({ version: 'v1', auth: this.auth }); }
  compute()              { return google.compute({ version: 'v1', auth: this.auth }); }
  sqladmin()             { return google.sqladmin({ version: 'v1', auth: this.auth }); }
  container()            { return google.container({ version: 'v1', auth: this.auth }); }
  run()                  { return google.run({ version: 'v2', auth: this.auth }); }
  bigquery()             { return google.bigquery({ version: 'v2', auth: this.auth }); }
  cloudkms()             { return google.cloudkms({ version: 'v1', auth: this.auth }); }
  secretmanager()        { return google.secretmanager({ version: 'v1', auth: this.auth }); }
  cloudfunctions()       { return google.cloudfunctions({ version: 'v2', auth: this.auth }); }
  pubsub()               { return google.pubsub({ version: 'v1', auth: this.auth }); }
  artifactregistry()     { return google.artifactregistry({ version: 'v1', auth: this.auth }); }
  logging()              { return google.logging({ version: 'v2', auth: this.auth }); }
  monitoring()           { return google.monitoring({ version: 'v3', auth: this.auth }); }
  cloudresourcemanagerV1() { return google.cloudresourcemanager({ version: 'v1', auth: this.auth }); }
  apikeys()               { return google.apikeys({ version: 'v2', auth: this.auth }); }
  dns()                   { return google.dns({ version: 'v1', auth: this.auth }); }
  dataproc()              { return google.dataproc({ version: 'v1', auth: this.auth }); }
  serviceusage()          { return google.serviceusage({ version: 'v1', auth: this.auth }); }
}
