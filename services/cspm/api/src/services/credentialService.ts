import crypto from 'crypto';
import { env } from '../config/env';
import type { AwsCredential } from '@prisma/client';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV for GCM
const AUTH_TAG_LENGTH = 16;

function getKey(): Buffer {
  return Buffer.from(env.CREDENTIAL_ENCRYPTION_KEY, 'hex');
}

export function encrypt(text: string): string {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv) as crypto.CipherGCM;

  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Format: iv:authTag:ciphertext (all base64)
  return [
    iv.toString('base64'),
    authTag.toString('base64'),
    encrypted.toString('base64'),
  ].join(':');
}

export function decrypt(encryptedData: string): string {
  const key = getKey();
  const parts = encryptedData.split(':');

  if (parts.length !== 3) {
    throw new Error('Invalid encrypted data format');
  }

  const [ivBase64, authTagBase64, ciphertextBase64] = parts;
  const iv = Buffer.from(ivBase64, 'base64');
  const authTag = Buffer.from(authTagBase64, 'base64');
  const ciphertext = Buffer.from(ciphertextBase64, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv) as crypto.DecipherGCM;
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

export function encryptCredentials(creds: {
  accessKeyId?: string;
  secretAccessKey?: string;
}): { encryptedAccessKeyId?: string; encryptedSecretAccessKey?: string } {
  const result: { encryptedAccessKeyId?: string; encryptedSecretAccessKey?: string } = {};

  if (creds.accessKeyId) {
    result.encryptedAccessKeyId = encrypt(creds.accessKeyId);
  }

  if (creds.secretAccessKey) {
    result.encryptedSecretAccessKey = encrypt(creds.secretAccessKey);
  }

  return result;
}

export function decryptCredentials(creds: AwsCredential): {
  accessKeyId?: string;
  secretAccessKey?: string;
  roleArn?: string;
  defaultRegion: string;
  authMethod: string;
} {
  const result: {
    accessKeyId?: string;
    secretAccessKey?: string;
    roleArn?: string;
    defaultRegion: string;
    authMethod: string;
  } = {
    defaultRegion: creds.defaultRegion,
    authMethod: creds.authMethod,
  };

  if (creds.encryptedAccessKeyId) {
    result.accessKeyId = decrypt(creds.encryptedAccessKeyId);
  }

  if (creds.encryptedSecretAccessKey) {
    result.secretAccessKey = decrypt(creds.encryptedSecretAccessKey);
  }

  if (creds.roleArn) {
    result.roleArn = creds.roleArn;
  }

  return result;
}
