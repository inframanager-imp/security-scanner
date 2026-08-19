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
];
