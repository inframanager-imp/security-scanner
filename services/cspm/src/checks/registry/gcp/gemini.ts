// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const geminiChecks: CheckMetadata[] = [
  {
    checkId: 'gemini_api_disabled',
    provider: 'gcp',
    service: 'gemini',
    title: 'Gemini (Generative Language) API Is Disabled',
    severity: 'MEDIUM',
    description: 'Checks that the Gemini API, also known as the Generative Language API (generativelanguage.googleapis.com), is not enabled for the project. This API authenticates with API keys rather than IAM, carries no SLA, and is not covered by standard compliance certifications.',
    remediation: 'Disable the Generative Language API for the project (gcloud services disable generativelanguage.googleapis.com). Use Gemini through the Vertex AI API instead, which authenticates via IAM and carries standard compliance coverage.',
    tags: ['gemini', 'gen-ai', 'identity-access'],
  },
];
