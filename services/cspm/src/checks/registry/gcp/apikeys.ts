// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const apikeysChecks: CheckMetadata[] = [
  {
    checkId: 'apikeys_key_exists',
    provider: 'gcp',
    service: 'apikeys',
    title: 'Project Has No Active API Keys',
    severity: 'MEDIUM',
    description: 'Checks whether the project has any active API keys. API keys are bearer tokens with no attached identity, and any active key increases the exposure surface regardless of its restrictions or usage.',
    remediation: 'Prefer service accounts with short-lived credentials or OAuth 2.0. If a key is genuinely required, restrict it by API and application, store it in a secrets manager, and remove it once it is no longer needed.',
    tags: ['apikeys', 'secrets'],
  },
  {
    checkId: 'apikeys_api_restrictions_configured',
    provider: 'gcp',
    service: 'apikeys',
    title: 'API Key Is Restricted To Specific Google APIs',
    severity: 'HIGH',
    description: 'Checks that each API key has API restrictions configured limiting it to named Google APIs, and does not allow the broad "cloudapis.googleapis.com" target (equivalent to no restriction at all).',
    remediation: 'Edit the API key in APIs & Services > Credentials, select "Restrict key", and choose only the specific API(s) it needs. Never leave a key unrestricted or targeting all Google APIs.',
    tags: ['apikeys', 'secrets', 'least-privilege'],
  },
  {
    checkId: 'apikeys_key_rotated_in_90_days',
    provider: 'gcp',
    service: 'apikeys',
    title: 'API Key Was Created Within The Last 90 Days',
    severity: 'MEDIUM',
    description: 'Checks the creation timestamp of each API key; keys older than 90 days are treated as overdue for rotation.',
    remediation: 'Rotate the API key: create a replacement, update dependent applications to use it, then delete the old key. Rotate on at least a 90-day cadence and prefer service accounts or OAuth for anything longer-lived.',
    tags: ['apikeys', 'secrets', 'key-rotation'],
  },
  {
    checkId: 'apikeys_api_restricted_with_gemini_api',
    provider: 'gcp',
    service: 'apikeys',
    title: 'API Key Is Not Broadly Scoped While Gemini API Is Enabled',
    severity: 'HIGH',
    description: 'When the Gemini (Generative Language) API is enabled for a project, checks that its API keys are restricted to that API alone rather than also granting access to other Google APIs, since a leaked key would otherwise expose more than uploaded files and cached content.',
    remediation: 'Restrict any API key used for the Gemini API to only the Generative Language API target — do not combine it with "All Google APIs" or other service targets. If the Gemini API is not required, disable generativelanguage.googleapis.com for the project.',
    tags: ['apikeys', 'secrets', 'gen-ai', 'identity-access'],
  },
];
