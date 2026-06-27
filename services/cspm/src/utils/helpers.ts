import logger from './logger';

export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function retry<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  delayMs: number = 1000
): Promise<T> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      logger.warn(`Retry ${i + 1}/${maxRetries} after ${delayMs}ms: ${(error as Error).message}`);
      await sleep(delayMs * Math.pow(2, i)); // Exponential backoff
    }
  }
  throw new Error('Retry failed');
}

export function formatSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }

  return `${size.toFixed(2)} ${units[unitIndex]}`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
}

export function maskSensitiveData(obj: any, keys: string[] = ['password', 'secret', 'key', 'token']): any {
  if (typeof obj !== 'object' || obj === null) return obj;

  if (Array.isArray(obj)) {
    return obj.map(item => maskSensitiveData(item, keys));
  }

  const result: any = {};
  for (const [key, value] of Object.entries(obj)) {
    if (keys.some(k => key.toLowerCase().includes(k.toLowerCase()))) {
      result[key] = '***REDACTED***';
    } else if (typeof value === 'object') {
      result[key] = maskSensitiveData(value, keys);
    } else {
      result[key] = value;
    }
  }

  return result;
}
