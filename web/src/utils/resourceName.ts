/**
 * Extracts a human-readable AWS resource identifier from a finding's evidence object.
 * Each scanner stores different keys in evidence — this maps service → primary key.
 */
export function getResourceName(
  service: string,
  evidence: Record<string, unknown>,
): string {
  const e = evidence ?? {};

  switch (service.toLowerCase()) {
    case 'cloudtrail':
      return String(e.trailName ?? e.region ?? '—');

    case 'ec2':
      return String(
        e.instanceId ?? e.sgName ?? e.sgId ?? e.naclId ?? e.vpcId ?? '—',
      );

    case 'iam':
      return String(e.username ?? e.accessKeyId ?? 'Account-level');

    case 'kms':
      return String(e.keyId ?? '—');

    case 'rds':
      return String(e.dbId ?? e.clusterId ?? '—');

    case 's3':
      return String(e.bucket ?? '—');

    case 'secretsmanager':
      return String(e.secretName ?? '—');

    case 'lambda':
      return String(e.functionName ?? e.lambdaFunction ?? e.arn ?? '—');

    case 'ecr':
      return String(
        e.repositoryName
          ? e.imageTag
            ? `${e.repositoryName}:${e.imageTag}`
            : String(e.repositoryName)
          : e.imageDigest ?? '—',
      );

    case 'cloudwatch':
    case 'vpc':
      return String(e.requirementId ?? e.sgId ?? e.vpcId ?? e.peeringConnectionId ?? '—');

    case 'accessanalyzer':
      return String(e.analyzer ?? e.arn ?? '—');

    case 'codeartifact':
      return String(e.domain ?? e.repository ?? '—');

    case 'codecommit':
      return String(e.repository ?? '—');

    case 'config':
      return String(e.recorder ?? e.region ?? 'Account-level');

    case 'datapipeline':
      return String(e.pipeline ?? e.pipelineId ?? '—');

    case 'resourceexplorer2':
      return String(e.region ?? 'Account-level');

    case 'securityhub':
      return String(e.region ?? 'Account-level');

    case 'servicecatalog':
      return String(e.portfolio ?? e.portfolioId ?? '—');

    case 'shield':
      return String(
        e.loadBalancer ?? e.distributionId ?? e.accelerator ?? e.zone ?? e.publicIp ?? e.arn ?? '—',
      );

    case 'ssmincidents':
      return String(e.region ?? 'Account-level');

    case 'trustedadvisor':
      return String(e.checkId ?? e.region ?? 'Account-level');

    case 'wellarchitected':
      return String(e.workload ?? e.workloadId ?? '—');

    case 'gcp-apikeys':
      return String(e.key ?? e.keyId ?? e.project ?? '—');

    case 'gcp-dataproc':
      return String(e.cluster ?? e.region ?? '—');

    case 'gcp-dns':
      return String(e.zone ?? e.dnsName ?? '—');

    case 'gcp-gemini':
      return String(e.project ?? 'Project-level');

    case 'azure-appinsights':
      return String(e.subscriptionId ?? 'Subscription-level');

    case 'azure-databricks':
      return String(e.workspace ?? e.workspaceId ?? '—');

    case 'azure-defender':
      return String(e.plan ?? e.contact ?? e.solution ?? e.resourceId ?? e.subscriptionId ?? 'Subscription-level');

    case 'azure-monitor':
      return String(e.settingName ?? e.alertRuleName ?? e.account ?? e.subscriptionId ?? 'Subscription-level');

    case 'azure-policy':
      return String(e.policyAssignment ?? e.id ?? '—');

    default: {
      // Fallback: try common generic keys
      for (const key of ['resourceId', 'resourceName', 'arn', 'name', 'id']) {
        if (e[key] != null) return String(e[key]);
      }
      return '—';
    }
  }
}
