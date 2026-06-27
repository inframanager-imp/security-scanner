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

    default: {
      // Fallback: try common generic keys
      for (const key of ['resourceId', 'resourceName', 'arn', 'name', 'id']) {
        if (e[key] != null) return String(e[key]);
      }
      return '—';
    }
  }
}
