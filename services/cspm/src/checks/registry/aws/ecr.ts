// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const ecrChecks: CheckMetadata[] = [
  {
    checkId: 'ecr_repositories_scan_images_on_push_enabled',
    provider: 'aws',
    service: 'ecr',
    title: 'ECR Scan on Push Disabled',
    severity: 'LOW',
    description: 'Checks that ECR repositories have scan-on-push enabled as a baseline alongside the independent layer scan.',
    remediation: 'Enable scan-on-push: aws ecr put-image-scanning-configuration --repository-name <repo> --image-scanning-configuration scanOnPush=true.',
    tags: ['ecr', 'config'],
  },
  {
    checkId: 'ecr_repositories_scan_vulnerabilities_in_latest_image',
    provider: 'aws',
    service: 'ecr',
    title: 'ECR Image OS Package CVE',
    severity: 'CRITICAL',
    description: 'Checks packages installed in ECR container images against the OSV database and reports critical vulnerabilities.',
    remediation: 'Rebuild the image with the affected package upgraded to a fixed version.',
    tags: ['ecr', 'cve', 'container'],
  },
  {
    checkId: 'ecr_image_high_severity_cves',
    provider: 'aws',
    service: 'ecr',
    title: 'ECR Image High Severity CVEs',
    severity: 'HIGH',
    description: 'Checks packages installed in ECR container images against the OSV database and reports high severity vulnerabilities.',
    remediation: 'Run a full image rebuild with updated base image and all dependencies to resolve all CVEs.',
    tags: ['ecr', 'cve', 'container'],
  },
  {
    // Emitted as MEDIUM or LOW depending on the summarized bucket — the emit
    // call always passes a severity override; MEDIUM is the metadata default.
    checkId: 'ecr_image_medium_low_cves',
    provider: 'aws',
    service: 'ecr',
    title: 'ECR Image Medium/Low CVEs',
    severity: 'MEDIUM',
    description: 'Summarizes medium and low severity vulnerabilities found in packages installed in ECR container images.',
    remediation: 'Rebuild the image with an updated base image and updated dependencies.',
    tags: ['ecr', 'cve', 'container'],
  },
  {
    checkId: 'ecr_registry_scan_images_on_push_enabled',
    provider: 'aws',
    service: 'ecr',
    title: 'ECR Registry Scan on Push Not Enforced',
    severity: 'MEDIUM',
    description: 'Checks that the ECR registry scanning configuration has scan-on-push rules covering all repositories (no restrictive repository filters) for basic or enhanced scanning.',
    remediation: 'Configure registry-wide scan on push: aws ecr put-registry-scanning-configuration --rules scanFrequency=SCAN_ON_PUSH with a WILDCARD "*" repository filter; prefer enhanced scanning.',
    tags: ['ecr', 'scanning', 'registry'],
  },
  {
    checkId: 'ecr_repositories_lifecycle_policy_enabled',
    provider: 'aws',
    service: 'ecr',
    title: 'ECR Repository Lifecycle Policy Missing',
    severity: 'LOW',
    description: 'Checks that ECR repositories have a lifecycle policy configured so old, untagged or excess images are expired automatically.',
    remediation: 'Add a lifecycle policy: aws ecr put-lifecycle-policy --repository-name <repo> --lifecycle-policy-text with rules expiring untagged and outdated images.',
    tags: ['ecr', 'lifecycle', 'hygiene'],
  },
  {
    checkId: 'ecr_repositories_not_publicly_accessible',
    provider: 'aws',
    service: 'ecr',
    title: 'ECR Repository Publicly Accessible',
    severity: 'CRITICAL',
    description: 'Checks ECR repository policies for wildcard principals without restrictive conditions that expose the repository to anonymous image pulls or pushes.',
    remediation: 'Remove wildcard principals from the repository policy (or delete it: aws ecr delete-repository-policy --repository-name <repo>) and grant access only to specific AWS principals.',
    tags: ['ecr', 'public-access', 'resource-policy'],
  },
  {
    checkId: 'ecr_repositories_tag_immutability',
    provider: 'aws',
    service: 'ecr',
    title: 'ECR Repository Tag Immutability Disabled',
    severity: 'MEDIUM',
    description: 'Checks that ECR repositories enforce image tag immutability so a trusted tag cannot be repointed to a different image.',
    remediation: 'Enable immutability: aws ecr put-image-tag-mutability --repository-name <repo> --image-tag-mutability IMMUTABLE and use versioned tags per build.',
    tags: ['ecr', 'supply-chain', 'container'],
  },
];
