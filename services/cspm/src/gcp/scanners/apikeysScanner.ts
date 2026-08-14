// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const GEMINI_SERVICE_NAME = 'generativelanguage.googleapis.com';
const ALL_APIS_TARGET = 'cloudapis.googleapis.com';
const MAX_KEY_AGE_DAYS = 90;

interface ApiKey {
  name?: string | null;
  displayName?: string | null;
  uid?: string | null;
  createTime?: string | null;
  restrictions?: { apiTargets?: { service?: string | null }[] | null } | null;
}

export class GcpApiKeysScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-ApiKeys');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const keys = await this.listKeys(project);

      // apikeys_key_exists: any active key at all increases exposure surface.
      if (keys.length > 0) {
        findings.push(this.emit(
          'apikeys_key_exists',
          { project, keyCount: keys.length },
          { message: `Project "${project}" has ${keys.length} active API key(s). API keys are bearer tokens with no attached identity.` },
        ));
      }

      let geminiEnabled = false;
      try {
        geminiEnabled = await this.isGeminiEnabled(project);
      } catch { /* serviceusage optional — Gemini-specific check skipped if inconclusive */ }

      for (const key of keys) {
        const displayName = key.displayName ?? key.uid ?? 'unnamed-key';
        const targets = key.restrictions?.apiTargets ?? [];

        // apikeys_api_restrictions_configured
        const unrestricted = targets.length === 0 || targets.some(t => t.service === ALL_APIS_TARGET);
        if (unrestricted) {
          findings.push(this.emit(
            'apikeys_api_restrictions_configured',
            { project, key: displayName, keyId: key.uid },
            { message: `API key "${displayName}" in project "${project}" has no API restrictions configured (or allows all Google APIs), letting a leaked key call any enabled API.` },
          ));
        }

        // apikeys_key_rotated_in_90_days
        if (key.createTime) {
          const ageDays = (Date.now() - new Date(key.createTime).getTime()) / (1000 * 60 * 60 * 24);
          if (ageDays > MAX_KEY_AGE_DAYS) {
            findings.push(this.emit(
              'apikeys_key_rotated_in_90_days',
              { project, key: displayName, keyId: key.uid, ageDays: Math.round(ageDays) },
              { message: `API key "${displayName}" in project "${project}" was created ${Math.round(ageDays)} days ago, exceeding the 90-day rotation window.` },
            ));
          }
        }

        // apikeys_api_restricted_with_gemini_api
        if (geminiEnabled) {
          const targetsGeminiPlusOthers = targets.length > 1 && targets.some(t => t.service === GEMINI_SERVICE_NAME);
          const noRestrictionOrAllApis = targets.length === 0 || targets.some(t => t.service === ALL_APIS_TARGET);
          if (targetsGeminiPlusOthers || noRestrictionOrAllApis) {
            findings.push(this.emit(
              'apikeys_api_restricted_with_gemini_api',
              { project, key: displayName, keyId: key.uid },
              {
                message: targetsGeminiPlusOthers
                  ? `API key "${displayName}" in project "${project}" is restricted to the Gemini API as well as other APIs — the Gemini API should be the key's sole target if used at all.`
                  : `API key "${displayName}" in project "${project}" has no API restrictions while the Gemini (Generative Language) API is enabled, exposing uploaded files and cached content to any holder of the key.`,
              },
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.emit(
        'apikeys_key_exists',
        { error: (err as Error).message },
        { severity: 'INFO', message: `GCP API Keys scan error: ${(err as Error).message}`, remediation: 'Ensure the service account has the roles/serviceusage.apiKeysViewer permission.' },
      ));
    }

    return findings;
  }

  private async listKeys(project: string): Promise<ApiKey[]> {
    const apikeys = this.client.apikeys();
    const keys: ApiKey[] = [];
    let pageToken: string | undefined;
    do {
      const res = await apikeys.projects.locations.keys.list({
        parent: `projects/${project}/locations/global`,
        pageToken,
      });
      keys.push(...(res.data.keys ?? []));
      pageToken = res.data.nextPageToken ?? undefined;
    } while (pageToken);
    return keys;
  }

  private async isGeminiEnabled(project: string): Promise<boolean> {
    const serviceusage = this.client.serviceusage();
    const res = await serviceusage.services.list({ parent: `projects/${project}`, filter: 'state:ENABLED', pageSize: 200 });
    const services = res.data.services ?? [];
    return services.some(s => (s.config?.name ?? s.name?.split('/').pop()) === GEMINI_SERVICE_NAME);
  }
}

export default GcpApiKeysScanner;
