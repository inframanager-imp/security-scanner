// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const GEMINI_SERVICE_NAME = 'generativelanguage.googleapis.com';

export class GcpGeminiScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-Gemini');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const serviceusage = this.client.serviceusage();
      const res = await serviceusage.services.list({ parent: `projects/${project}`, filter: 'state:ENABLED', pageSize: 200 });
      const services = res.data.services ?? [];
      const geminiEnabled = services.some(s => (s.config?.name ?? s.name?.split('/').pop()) === GEMINI_SERVICE_NAME);

      // gemini_api_disabled: PASS when the API is off; we only emit a finding for the FAIL case.
      if (geminiEnabled) {
        findings.push(this.emit(
          'gemini_api_disabled',
          { project },
          { message: `The Gemini (Generative Language) API is enabled for project "${project}". This API authenticates via API keys rather than IAM and is not covered by standard compliance certifications.` },
        ));
      }
    } catch (err) {
      findings.push(this.emit(
        'gemini_api_disabled',
        { error: (err as Error).message },
        { severity: 'INFO', message: `GCP Gemini API scan error: ${(err as Error).message}`, remediation: 'Ensure the service account has the roles/serviceusage.serviceUsageViewer permission.' },
      ));
    }

    return findings;
  }
}

export default GcpGeminiScanner;
