import { describe, it, expect } from '@jest/globals';
import { allChecks } from '../../src/checks/registry';
import { CheckSeverity } from '../../src/checks/types';

// Keep in sync with the CheckSeverity union in src/checks/types.ts. There is
// no runtime representation of a TS union, so the valid set is duplicated
// here deliberately — a change to the union that isn't mirrored here should
// be caught by whichever severities show up (or stop showing up) below.
const VALID_SEVERITIES: CheckSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const CHECK_ID_PATTERN = /^[a-z0-9_]+$/;

describe('check registry: data quality', () => {
  const checks = allChecks();

  describe('each check entry', () => {
    for (const check of checks) {
      describe(check.checkId || '<missing checkId>', () => {
        it('has a non-empty checkId matching the snake_case pattern', () => {
          expect(typeof check.checkId).toBe('string');
          expect(check.checkId.length).toBeGreaterThan(0);
          expect(check.checkId).toMatch(CHECK_ID_PATTERN);
        });

        it('has a non-empty title', () => {
          expect(typeof check.title).toBe('string');
          expect(check.title.trim().length).toBeGreaterThan(0);
        });

        it('has a valid severity', () => {
          expect(VALID_SEVERITIES).toContain(check.severity);
        });

        it('has a non-empty description', () => {
          expect(typeof check.description).toBe('string');
          expect(check.description.trim().length).toBeGreaterThan(0);
        });

        it('has a non-empty remediation', () => {
          expect(typeof check.remediation).toBe('string');
          expect(check.remediation.trim().length).toBeGreaterThan(0);
        });

        it('has tags as an array (possibly empty)', () => {
          expect(Array.isArray(check.tags)).toBe(true);
        });
      });
    }
  });

  describe('registry-wide invariants', () => {
    it('has no duplicate checkIds', () => {
      // registry/index.ts already throws at import time on duplicates, so by
      // the time this test runs the invariant necessarily holds — this
      // assertion documents and locks the invariant rather than being the
      // primary guard against it.
      const ids = checks.map((c) => c.checkId);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it('has a reasonably large number of registered checks', () => {
      // Sanity floor so an accidental empty-import regression (e.g. awsChecks
      // resolving to []) is caught instead of silently passing an empty suite.
      expect(checks.length).toBeGreaterThan(50);
    });
  });
});
