/** Bounded-concurrency map — for per-item enrichment calls (one IAM role, one
 * S3 bucket, ...) that would otherwise run one at a time in a for loop. Same
 * fix applied repeatedly across this codebase (IAM security scanner, IAM
 * role/policy discovery, now DSPM bucket scanning) — a large account (50+
 * buckets, 1000+ roles) doing sequential per-item API calls turns a few
 * seconds of real work into many minutes. */
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
