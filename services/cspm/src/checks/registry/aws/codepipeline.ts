// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const codepipelineChecks: CheckMetadata[] = [
  {
    checkId: 'codepipeline_project_repo_private',
    provider: 'aws',
    service: 'codepipeline',
    title: 'CodePipeline Source Repository Publicly Accessible',
    severity: 'MEDIUM',
    description: 'Checks that CodePipeline source stages using CodeStar Connections pull from private GitHub/GitLab repositories; public sources expose CI/CD logic and enable supply-chain attacks.',
    remediation: 'Make the source repository private and connect it through AWS CodeStar Connections with least-privilege permissions; enable branch protection, code review and signed commits.',
    tags: ['codepipeline', 'public-access', 'supply-chain'],
  },
];
