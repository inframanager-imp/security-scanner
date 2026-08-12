// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const accessanalyzerChecks: CheckMetadata[] = [
  {
    checkId: 'accessanalyzer_enabled_without_findings',
    provider: 'aws',
    service: 'accessanalyzer',
    title: 'Access Analyzer Has Active Findings',
    severity: 'LOW',
    description: 'Checks that active IAM Access Analyzer analyzers have no active findings; active findings indicate resources shared with external or otherwise unintended principals.',
    remediation: 'Review each active Access Analyzer finding, remove or restrict unintended external access to the flagged resources, and archive findings that represent intended access.',
    tags: ['accessanalyzer', 'external-access', 'iam'],
  },
];
