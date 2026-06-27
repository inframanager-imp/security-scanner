import { describe, it, expect, beforeEach } from '@jest/globals';
import { Cache } from '../../src/utils/cache';

describe('Cache', () => {
  let cache: Cache;

  beforeEach(() => {
    cache = new Cache(true, 10); // 10 second TTL
  });

  it('should store and retrieve cache entries', () => {
    cache.set('test-key', { data: 'test-value' });
    const result = cache.get('test-key');
    expect(result).toEqual({ data: 'test-value' });
  });

  it('should return null for expired entries', (done) => {
    cache.set('expire-key', { data: 'value' }, 1); // 1 second TTL
    
    setTimeout(() => {
      const result = cache.get('expire-key');
      expect(result).toBeNull();
      done();
    }, 1100);
  });

  it('should clear all cache entries', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.clear();

    expect(cache.get('key1')).toBeNull();
    expect(cache.get('key2')).toBeNull();
  });

  it('should return null when cache is disabled', () => {
    const disabledCache = new Cache(false);
    disabledCache.set('key', 'value');
    expect(disabledCache.get('key')).toBeNull();
  });
});
