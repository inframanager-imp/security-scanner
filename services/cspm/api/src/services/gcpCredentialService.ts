import { encrypt, decrypt } from './credentialService';
import type { GcpCredential } from '@prisma/client';

/** Encrypt a service account JSON key (the full JSON string) */
export function encryptGcpCredentials(creds: {
  serviceAccountKey?: string;
  serviceAccountEmail?: string;
}): {
  encryptedServiceAccountKey?: string;
  serviceAccountEmail?: string;
} {
  const result: {
    encryptedServiceAccountKey?: string;
    serviceAccountEmail?: string;
  } = {};

  if (creds.serviceAccountKey) {
    result.encryptedServiceAccountKey = encrypt(creds.serviceAccountKey);
  }
  if (creds.serviceAccountEmail) {
    result.serviceAccountEmail = creds.serviceAccountEmail;
  }

  return result;
}

/** Decrypt a GcpCredential record to usable values */
export function decryptGcpCredentials(cred: GcpCredential): {
  serviceAccountKey?: string;
  serviceAccountEmail?: string;
  authMethod: string;
} {
  const result: {
    serviceAccountKey?: string;
    serviceAccountEmail?: string;
    authMethod: string;
  } = {
    authMethod: cred.authMethod,
    serviceAccountEmail: cred.serviceAccountEmail ?? undefined,
  };

  if (cred.encryptedServiceAccountKey) {
    result.serviceAccountKey = decrypt(cred.encryptedServiceAccountKey);
  }

  return result;
}
