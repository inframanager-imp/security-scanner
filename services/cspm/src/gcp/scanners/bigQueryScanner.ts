import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class GcpBigQueryScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-BigQuery');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const bq  = this.client.bigquery();
      const res = await bq.datasets.list({ projectId: project, all: false });
      const datasets = res.data.datasets ?? [];

      if (datasets.length === 0) return findings;

      for (const ds of datasets) {
        const datasetId = ds.datasetReference?.datasetId ?? 'unknown';
        const location  = ds.location ?? 'unknown';

        // Get full dataset metadata for detailed checks
        let fullDs: any = ds;
        try {
          const full = await bq.datasets.get({ projectId: project, datasetId });
          fullDs = full.data;
        } catch { /* use partial data */ }

        // 1. Public access — allUsers or allAuthenticatedUsers
        const access = fullDs.access ?? [];
        const publicBindings = access.filter((a: any) =>
          a.specialGroup === 'allUsers' || a.specialGroup === 'allAuthenticatedUsers',
        );
        if (publicBindings.length > 0) {
          const roles = publicBindings.map((a: any) => a.role).join(', ');
          findings.push(this.finding(
            'BigQuery dataset is publicly accessible',
            `BigQuery dataset "${datasetId}" in project "${project}" (${location}) has ${publicBindings.length} public access binding(s) with roles: ${roles}. Anyone on the internet can query this dataset.`,
            'CRITICAL',
            { dataset: datasetId, project, location, publicRoles: roles },
            'Remove allUsers and allAuthenticatedUsers from the dataset access policy. Grant access only to specific users, groups, or service accounts.',
            ['bigquery', 'public-access'],
          ));
        }

        // 2. No CMEK
        if (!fullDs.defaultEncryptionConfiguration?.kmsKeyName) {
          findings.push(this.finding(
            'BigQuery dataset does not use a customer-managed encryption key',
            `BigQuery dataset "${datasetId}" (${location}) uses Google-managed encryption. CMEK provides control over encryption key lifecycle and enables data access revocation.`,
            'MEDIUM',
            { dataset: datasetId, project, location },
            'Configure a Cloud KMS key as the default encryption key for the dataset. Grant the BigQuery service account the Cloud KMS CryptoKey Encrypter/Decrypter role.',
            ['bigquery', 'encryption', 'cmek'],
          ));
        }

        // 3. No expiration configured on dataset
        const defaultExpiry = fullDs.defaultTableExpirationMs;
        if (!defaultExpiry) {
          findings.push(this.finding(
            'BigQuery dataset has no default table expiration configured',
            `BigQuery dataset "${datasetId}" (${location}) has no default table expiration. Tables created without explicit expiration persist indefinitely, accumulating sensitive data beyond its useful lifetime.`,
            'LOW',
            { dataset: datasetId, project, location },
            'Set a default table expiration on the dataset for datasets containing time-limited data. Individual tables can override this with their own expiration.',
            ['bigquery', 'data-retention'],
          ));
        }

        // 4. No row-level security (check for row access policies)
        try {
          // BigQuery Data Policy API — check for column-level security
          // This is informational since many datasets legitimately don't need it
          const tableRes = await bq.tables.list({ projectId: project, datasetId });
          const tables   = tableRes.data.tables ?? [];
          if (tables.length > 20) {
            findings.push(this.finding(
              'Large BigQuery dataset lacks verified row/column-level security',
              `BigQuery dataset "${datasetId}" (${location}) has ${tables.length} tables. For datasets with sensitive data, ensure Row Access Policies and Column-Level Security are configured to restrict data access beyond dataset-level permissions.`,
              'LOW',
              { dataset: datasetId, project, location, tableCount: tables.length },
              'Implement Row Access Policies for user-specific data filtering. Use Column-Level Security (Data Masking) for sensitive columns like PII, PCI data.',
              ['bigquery', 'access-control'],
            ));
          }
        } catch { /* optional */ }

        // 5. Broad project-level access in dataset (Editor/Owner)
        const broadAccess = access.filter((a: any) =>
          a.projectView || (a.groupByEmail && (a.role === 'OWNER' || a.role === 'WRITER')),
        );
        if (broadAccess.length > 0) {
          findings.push(this.finding(
            'BigQuery dataset has overly broad group access',
            `BigQuery dataset "${datasetId}" (${location}) has ${broadAccess.length} group(s) with OWNER or WRITER roles. Broad write access to BigQuery datasets can result in data modification, deletion, or exfiltration.`,
            'MEDIUM',
            { dataset: datasetId, project, location, broadGroups: broadAccess.map((a: any) => a.groupByEmail) },
            'Review and reduce group access to BigQuery datasets. Grant READER access where possible and restrict WRITER/OWNER access to specific service accounts or administrators.',
            ['bigquery', 'access-control'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP BigQuery scan error',
        `Could not complete BigQuery scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/bigquery.metadataViewer on the project.',
      ));
    }

    return findings;
  }
}
