import { describe, it, expect } from '@jest/globals';
import { generateId, sleep, formatSize, formatDuration } from '../../src/utils/helpers';

describe('Helpers', () => {
  describe('generateId', () => {
    it('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      expect(id1).not.toEqual(id2);
    });

    it('should return a string', () => {
      const id = generateId();
      expect(typeof id).toBe('string');
    });
  });

  describe('sleep', () => {
    it('should delay execution', async () => {
      const start = Date.now();
      await sleep(100);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(100);
    });
  });

  describe('formatSize', () => {
    it('should format bytes correctly', () => {
      expect(formatSize(512)).toContain('B');
      expect(formatSize(1024)).toContain('KB');
      expect(formatSize(1024 * 1024)).toContain('MB');
      expect(formatSize(1024 * 1024 * 1024)).toContain('GB');
    });
  });

  describe('formatDuration', () => {
    it('should format milliseconds correctly', () => {
      expect(formatDuration(500)).toContain('ms');
      expect(formatDuration(5000)).toContain('s');
      expect(formatDuration(300000)).toContain('m');
      expect(formatDuration(3600000)).toContain('h');
    });
  });
});
