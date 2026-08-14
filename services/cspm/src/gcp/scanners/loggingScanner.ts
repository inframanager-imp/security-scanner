// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

// CIS GCP Benchmark required log metric filters. `checkId` matches the
// corresponding Prowler logging_log_metric_filter_and_alert_for_* check
// verbatim; `filter` is the exact log-based-metric filter string Prowler
// looks for (substring match against LogMetric.filter, same as upstream).
const REQUIRED_LOG_FILTERS = [
  {
    checkId: 'logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled',
    title: 'Project ownership assignment/changes',
    filter: '(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")',
  },
  {
    checkId: 'logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled',
    title: 'Audit configuration changes',
    filter: 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
  },
  {
    checkId: 'logging_log_metric_filter_and_alert_for_custom_role_changes_enabled',
    title: 'Custom role changes',
    filter: 'resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")',
  },
  {
    checkId: 'logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled',
    title: 'VPC network firewall rule changes',
    filter: 'resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.patch" OR protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete")',
  },
  {
    checkId: 'logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled',
    title: 'VPC network route changes',
    filter: 'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")',
  },
  {
    checkId: 'logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled',
    title: 'VPC network changes',
    filter: 'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")',
  },
  {
    checkId: 'logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled',
    title: 'Cloud Storage IAM permission changes',
    filter: 'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"',
  },
  {
    checkId: 'logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled',
    title: 'Cloud SQL instance configuration changes',
    filter: 'protoPayload.methodName="cloudsql.instances.update"',
  },
  {
    checkId: 'logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled',
    title: 'Compute Engine configuration changes',
    filter: 'protoPayload.serviceName="compute.googleapis.com"',
  },
] as const;

interface LogMetricLite {
  name?: string | null;
  filter?: string | null;
}

interface AlertPolicyLite {
  name?: string | null;
  displayName?: string | null;
  /** Flattened filter/query strings pulled from every condition on the policy. */
  conditionFilters: string[];
}

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

      // 2. Check for required log metric filters (CIS Benchmark) AND that each
      // matching metric has a Cloud Monitoring alert policy attached to it.
      // A log-based metric with no alert policy is a silent counter — nobody
      // is notified when the condition it tracks actually occurs — so we
      // treat "filter exists but unalerted" as a finding, same as Prowler.
      try {
        const metricsRes = await logging.projects.metrics.list({
          parent: `projects/${project}`,
        });
        const metrics: LogMetricLite[] = metricsRes.data.metrics ?? [];

        const alertPolicies = await this.listAlertPolicies(project);

        for (const required of REQUIRED_LOG_FILTERS) {
          // Prowler matches on exact substring containment of the literal
          // filter string within the metric's filter, not fuzzy keywords.
          const matchingMetrics = metrics.filter(m => (m.filter ?? '').includes(required.filter));

          if (matchingMetrics.length === 0) {
            findings.push(this.emit(
              required.checkId,
              { project, missingFilter: required.title },
              {
                message: `Project "${project}" does not have a log-based metric for "${required.title}". Without this metric, changes to critical resources cannot trigger alerts.`,
              },
            ));
            continue;
          }

          // At least one metric with the required filter exists. It only
          // satisfies the check if some alert policy's condition filter
          // references that specific metric by name (Prowler: `metric.name
          // in filter`) — matching the metric's short/user name inside the
          // alert condition's filter/query string.
          const unalertedMetric = matchingMetrics.find((m) => {
            const metricName = m.name ?? '';
            if (!metricName) return true;
            return !alertPolicies.some((policy) =>
              policy.conditionFilters.some((f) => f.includes(metricName)),
            );
          });

          if (unalertedMetric) {
            findings.push(this.emit(
              required.checkId,
              { project, metric: unalertedMetric.name, missingFilter: required.title },
              {
                message: `Log metric filter for "${required.title}" exists in project "${project}" (metric "${unalertedMetric.name}") but no Cloud Monitoring alert policy references it, so matching events are recorded but nobody is notified.`,
                remediation: `Create a Cloud Monitoring alert policy whose condition filter references metric.type="logging.googleapis.com/user/${unalertedMetric.name}" so that changes to "${required.title}" actually raise a notification instead of only incrementing a metric.`,
              },
            ));
          }
        }
      } catch { /* metrics/alert-policy check optional */ }

      // 3. Check for log sinks (export to long-term storage)
      try {
        const sinksRes = await logging.projects.sinks.list({
          parent: `projects/${project}`,
        });
        const sinks = sinksRes.data.sinks ?? [];

        if (sinks.length === 0) {
          findings.push(this.emit(
            'logging_sink_created',
            { project },
            {
              message: `Project "${project}" has no log sinks configured. Cloud Logging retains logs for only 30 days (admin activity) or 30 days (data access) by default. Without a sink, logs cannot be retained for compliance requirements (e.g., 1-year retention for SOC2, PCI).`,
            },
          ));
        } else {
          // Check if any sink covers all log entries (empty/unfiltered filter)
          const hasAllLogsSink = sinks.some(s => !s.filter || s.filter === '');
          if (!hasAllLogsSink) {
            findings.push(this.emit(
              'logging_sink_created',
              { project, sinkCount: sinks.length },
              {
                message: `Project "${project}" has ${sinks.length} log sink(s) but none appear to export all log entries. Filtered sinks may miss admin activity or data access logs needed for a complete audit trail.`,
                remediation: 'Ensure at least one log sink exports all log entries. Use an empty inclusion filter (or a covering org-level sink with includeChildren) so no log category is silently dropped.',
              },
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
        'Ensure the service account has roles/logging.viewer, roles/monitoring.viewer, and roles/iam.securityReviewer on the project.',
      ));
    }

    return findings;
  }

  /**
   * List alert policies for the project and flatten each policy's condition
   * filters/queries into a single searchable array — mirrors Prowler's
   * AlertPolicy.filters (conditionThreshold / conditionAbsent / conditionMatchedLog
   * .filter, or conditionMonitoringQueryLanguage.query).
   */
  private async listAlertPolicies(project: string): Promise<AlertPolicyLite[]> {
    const monitoring = this.client.monitoring();
    const policies: AlertPolicyLite[] = [];
    let pageToken: string | undefined;

    do {
      const res: any = await monitoring.projects.alertPolicies.list({
        name: `projects/${project}`,
        pageToken,
      });
      const alertPolicies = res.data.alertPolicies ?? [];

      for (const policy of alertPolicies) {
        const conditionFilters: string[] = [];
        for (const condition of policy.conditions ?? []) {
          const filterValue =
            condition.conditionThreshold?.filter ??
            condition.conditionAbsent?.filter ??
            condition.conditionMatchedLog?.filter ??
            condition.conditionMonitoringQueryLanguage?.query;
          if (filterValue) conditionFilters.push(filterValue);
        }
        policies.push({
          name: policy.name,
          displayName: policy.displayName,
          conditionFilters,
        });
      }

      pageToken = res.data.nextPageToken ?? undefined;
    } while (pageToken);

    return policies;
  }
}
