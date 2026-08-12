// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const resourceexplorer2Checks: CheckMetadata[] = [
  {
    checkId: 'resourceexplorer2_indexes_found',
    provider: 'aws',
    service: 'resourceexplorer2',
    title: 'Resource Explorer Indexes Not Configured',
    severity: 'LOW',
    description: 'Checks that at least one AWS Resource Explorer index exists in the account, providing resource inventory and search coverage for asset visibility.',
    remediation: 'Turn on AWS Resource Explorer by creating indexes in your active regions and designate an aggregator index for cross-region search of account resources.',
    tags: ['resourceexplorer2', 'inventory', 'governance', 'forensics-ready'],
  },
];
