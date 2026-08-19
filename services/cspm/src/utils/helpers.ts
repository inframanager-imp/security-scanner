import logger from './logger';

export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Error names/codes that are permanent — retrying them wastes the full
// backoff window for no chance of success (e.g. S3's PermanentRedirect when
// a bucket lives in a different region than the client, which used to turn
// one out-of-region bucket into ~6 checks x multiple retries of dead time;
// same story for Lambda's GetPolicy on a function with no resource policy —
// ResourceNotFoundException there just means "none configured", not a
// transient failure, but a 184-function account still turned that into
// ~184 x 2 retries x exponential backoff of pure dead time).
const NON_RETRYABLE_ERROR_NAMES = new Set([
  'PermanentRedirect',
  'NoSuchBucket',
  'NoSuchBucketPolicy',
  'AccessDenied',
  'ResourceNotFoundException',
  'GetPolicyException',
  'NoSuchEntityException',
  'NoSuchEntity',
]);

function isRetryable(error: unknown): boolean {
  const err = error as { name?: string; Code?: string };
  const code = err?.name ?? err?.Code;
  return !code || !NON_RETRYABLE_ERROR_NAMES.has(code);
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
      if (i === maxRetries - 1 || !isRetryable(error)) throw error;
      logger.warn(`Retry ${i + 1}/${maxRetries} after ${delayMs}ms: ${(error as Error).message}`);
      await sleep(delayMs * Math.pow(2, i)); // Exponential backoff
    }
  }
  throw new Error('Retry failed');
}

/**
 * Runs `fn` over `items` with at most `concurrency` in flight at once —
 * for per-resource API calls (one IAM role, one Lambda function, ...) that
 * would otherwise run one at a time in a `for` loop. A sequential loop over
 * a few hundred roles/functions, each a real network round-trip, silently
 * turns into minutes of wall-clock time with zero progress visibility.
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;

  async function worker(): Promise<void> {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
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
