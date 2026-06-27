import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

// CIS GCP Benchmark required log metric filters
const REQUIRED_LOG_FILTERS = [
  {
    id:    'project-ownership-changes',
    title: 'Project ownership assignment/changes',
    filter: 'resource.type="project" AND (protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")',
    cisControl: 'CIS-2.4',
  },
  {
    id:    'audit-config-changes',
    title: 'Audit configuration changes',
    filter: 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
    cisControl: 'CIS-2.5',
  },
  {
    id:    'custom-role-changes',
    title: 'Custom role changes',
    filter: 'resource.type="iam_role" AND protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"',
    cisControl: 'CIS-2.6',
  },
  {
    id:    'vpc-firewall-rule-changes',
    title: 'VPC network firewall rule changes',
    filter: 'resource.type="gce_firewall_rule" AND jsonPayload.event_subtype="compute.firewalls.patch" OR jsonPayload.event_subtype="compute.firewalls.insert"',
    cisControl: 'CIS-2.7',
  },
  {
    id:    'vpc-route-changes',
    title: 'VPC network route changes',
    filter: 'resource.type="gce_route" AND jsonPayload.event_subtype="compute.routes.delete" OR jsonPayload.event_subtype="compute.routes.insert"',
    cisControl: 'CIS-2.8',
  },
  {
    id:    'vpc-network-changes',
    title: 'VPC network changes',
    filter: 'resource.type=gce_network AND jsonPayload.event_subtype="compute.networks.insert" OR jsonPayload.event_subtype="compute.networks.patch" OR jsonPayload.event_subtype="compute.networks.delete" OR jsonPayload.event_subtype="compute.networks.removePeering" OR jsonPayload.event_subtype="compute.networks.addPeering"',
    cisControl: 'CIS-2.9',
  },
  {
    id:    'cloud-storage-iam-changes',
    title: 'Cloud Storage IAM permission changes',
    filter: 'resource.type=gcs_bucket AND protoPayload.methodName="storage.setIamPermissions"',
    cisControl: 'CIS-2.10',
  },
  {
    id:    'sql-instance-config-changes',
    title: 'Cloud SQL instance configuration changes',
    filter: 'protoPayload.methodName="cloudsql.instances.update"',
    cisControl: 'CIS-2.11',
  },
];

export class GcpLoggingScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-Logging');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const logging = this.client.logging();

      // 1. Check Data Access audit logs are enabled
      try {
        const rm = this.client.cloudresourcemanagerV1();
        const iamRes = await rm.projects.getIamPolicy({
          resource: project,
          requestBody: {},
        });
        const auditConfigs = iamRes.data.auditConfigs ?? [];
        const allServicesConfig = auditConfigs.find(c => c.service === 'allServices');
        const hasDataRead  = allServicesConfig?.auditLogConfigs?.some(c => c.logType === 'DATA_READ');
        const hasDataWrite = allServicesConfig?.auditLogConfigs?.some(c => c.logType === 'DATA_WRITE');

        if (!hasDataRead) {
          findings.push(this.finding(
            'Data Access audit logs (DATA_READ) not enabled for all services',
            `Project "${project}" does not have DATA_READ audit logs enabled for all services. Read operations on sensitive resources (storage, secrets, databases) are not logged, making it impossible to detect unauthorized data access.`,
            'HIGH',
            { project, missingLogType: 'DATA_READ' },
            'Enable DATA_READ audit logs for "allServices" in the project IAM audit configuration. Note: DATA_READ logs can generate significant volume — review costs and configure exclusions as needed.',
            ['logging', 'audit-logs', 'data-access'],
          ));
        }

        if (!hasDataWrite) {
          findings.push(this.finding(
            'Data Access audit logs (DATA_WRITE) not enabled for all services',
            `Project "${project}" does not have DATA_WRITE audit logs enabled for all services. Write operations on sensitive resources are not logged, reducing visibility into data modification events.`,
            'MEDIUM',
            { project, missingLogType: 'DATA_WRITE' },
            'Enable DATA_WRITE audit logs for "allServices" in the project IAM audit configuration.',
            ['logging', 'audit-logs', 'data-access'],
          ));
        }
      } catch { /* audit config check optional */ }

      // 2. Check for required log metric filters (CIS Benchmark)
      try {
        const metricsRes = await logging.projects.metrics.list({
          parent: `projects/${project}`,
        });
        const metrics = metricsRes.data.metrics ?? [];

        for (const required of REQUIRED_LOG_FILTERS) {
          // Check if any metric has a filter that covers this requirement
          // We look for simplified keyword matching since exact filter strings vary
          const keyword = required.id.split('-')[0]; // e.g., 'project', 'audit', 'custom', 'vpc', 'cloud', 'sql'
          const hasMetric = metrics.some(m =>
            m.filter?.toLowerCase().includes(keyword) ||
            m.name?.toLowerCase().includes(required.id),
          );

          if (!hasMetric) {
            findings.push(this.finding(
              `Missing log metric filter: ${required.title}`,
              `Project "${project}" does not have a log-based metric for "${required.title}" (${required.cisControl}). Without this metric, changes to critical resources cannot trigger alerts.`,
              'MEDIUM',
              { project, missingFilter: required.id, cisControl: required.cisControl },
              `Create a log-based metric with filter for ${required.title}. Then create a Cloud Monitoring alert policy that triggers when this metric exceeds a threshold.`,
              ['logging', 'metrics', 'alerting', required.cisControl.toLowerCase()],
            ));
          }
        }
      } catch { /* metrics check optional */ }

      // 3. Check for log sinks (export to long-term storage)
      try {
        const sinksRes = await logging.projects.sinks.list({
          parent: `projects/${project}`,
        });
        const sinks = sinksRes.data.sinks ?? [];

        if (sinks.length === 0) {
          findings.push(this.finding(
            'No log sinks configured — audit logs are not exported for long-term retention',
            `Project "${project}" has no log sinks configured. Cloud Logging retains logs for only 30 days (admin activity) or 30 days (data access) by default. Without a sink, logs cannot be retained for compliance requirements (e.g., 1-year retention for SOC2, PCI).`,
            'HIGH',
            { project },
            'Create a log sink to export audit logs to Cloud Storage (for long-term archival), BigQuery (for analysis), or Pub/Sub (for real-time SIEM integration).',
            ['logging', 'retention', 'compliance'],
          ));
        } else {
          // Check if any sink covers _Required or _Default logs
          const hasAdminSink = sinks.some(s =>
            !s.filter || s.filter === '' || s.filter?.includes('logName'),
          );
          if (!hasAdminSink) {
            findings.push(this.finding(
              'Log sinks do not appear to capture admin activity logs',
              `Project "${project}" has ${sinks.length} log sink(s) but none appear to capture all admin activity logs. Admin activity logs document all privileged operations and should be retained for audit trails.`,
              'MEDIUM',
              { project, sinkCount: sinks.length },
              'Ensure at least one log sink exports admin activity logs. Use an empty filter or include "logName:cloudaudit.googleapis.com/activity" to capture all admin logs.',
              ['logging', 'retention', 'audit-logs'],
            ));
          }
        }
      } catch { /* sinks check optional */ }

    } catch (err) {
      findings.push(this.finding(
        'GCP Logging scan error',
        `Could not complete Cloud Logging scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/logging.viewer and roles/iam.securityReviewer on the project.',
      ));
    }

    return findings;
  }
}
