// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const codeartifactChecks: CheckMetadata[] = [
  {
    checkId: 'codeartifact_packages_external_public_publishing_disabled',
    provider: 'aws',
    service: 'codeartifact',
    title: 'CodeArtifact Internal Package Open to Dependency Confusion',
    severity: 'CRITICAL',
    description: 'Checks CodeArtifact packages with internal or unknown origin for origin controls that still allow upstream ingestion, leaving builds exposed to dependency confusion from public registries.',
    remediation: 'Set package origin controls on internal packages to upstream=BLOCK so higher versions cannot be ingested from public repositories; use private namespaces, pin versions and monitor package origin events.',
    tags: ['codeartifact', 'dependency-confusion', 'supply-chain'],
  },
];
