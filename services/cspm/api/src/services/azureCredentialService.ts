import { encrypt, decrypt } from './credentialService';
import type { AzureCredential } from '@prisma/client';

export function encryptAzureCredentials(creds: {
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
}): {
  encryptedTenantId?: string;
  encryptedClientId?: string;
  encryptedClientSecret?: string;
} {
  const result: {
    encryptedTenantId?: string;
    encryptedClientId?: string;
    encryptedClientSecret?: string;
  } = {};
  if (creds.tenantId)     result.encryptedTenantId     = encrypt(creds.tenantId);
  if (creds.clientId)     result.encryptedClientId     = encrypt(creds.clientId);
  if (creds.clientSecret) result.encryptedClientSecret = encrypt(creds.clientSecret);
  return result;
}

export function decryptAzureCredentials(cred: AzureCredential): {
  tenantId?:     string;
  clientId?:     string;
  clientSecret?: string;
  authMethod:    string;
} {
  const result: {
    tenantId?:     string;
    clientId?:     string;
    clientSecret?: string;
    authMethod:    string;
  } = { authMethod: cred.authMethod };

  if (cred.encryptedTenantId)     result.tenantId     = decrypt(cred.encryptedTenantId);
  if (cred.encryptedClientId)     result.clientId     = decrypt(cred.encryptedClientId);
  if (cred.encryptedClientSecret) result.clientSecret = decrypt(cred.encryptedClientSecret);

  return result;
}
