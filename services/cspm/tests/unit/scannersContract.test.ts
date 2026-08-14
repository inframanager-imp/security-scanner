import { describe, it, expect } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner } from '../../src/scanners/baseScanner';
import { hasCheck } from '../../src/checks/registry';

// Directory containing every scanner implementation. baseScanner.ts (the
// abstract base class) and engine.ts (the orchestrator, not a scanner) are
// excluded — every other .ts file here is expected to be a BaseScanner
// subclass with a default export.
const SCANNERS_DIR = path.resolve(__dirname, '../../src/scanners');
const EXCLUDED_FILES = new Set(['baseScanner.ts', 'engine.ts', 'index.ts']);

const scannerFiles = fs
  .readdirSync(SCANNERS_DIR)
  .filter((f) => f.endsWith('.ts') && !EXCLUDED_FILES.has(f))
  .sort();

// Sanity check on the discovery itself: fail loudly (rather than silently
// passing an empty suite) if the scanners directory ever stops resolving.
if (scannerFiles.length === 0) {
  throw new Error(`No scanner files discovered under ${SCANNERS_DIR} — check EXCLUDED_FILES / directory layout`);
}

/**
 * Minimal stand-in for AWSClient. Every real scanner constructor only ever
 * touches `client.getClientConfig()` (to build its own SDK v3 client(s)) —
 * confirmed by inspecting every constructor body in src/scanners/. SDK v3
 * client constructors do not make network calls on instantiation, so this
 * requires no mocking of AWS calls themselves.
 */
function makeMockAWSClient() {
  return {
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
  } as any;
}

describe('scanner contract: every scanner extends BaseScanner and exposes scan()', () => {
  for (const file of scannerFiles) {
    const modulePath = path.join(SCANNERS_DIR, file);

    describe(file, () => {
      it('has a usable default export that constructs a BaseScanner subclass instance', () => {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const mod = require(modulePath);
        const ScannerClass = mod.default;

        expect(typeof ScannerClass).toBe('function');

        const instance = new ScannerClass(makeMockAWSClient());
        expect(instance).toBeInstanceOf(BaseScanner);
      });

      it('has a callable async scan() method', () => {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const mod = require(modulePath);
        const ScannerClass = mod.default;
        const instance = new ScannerClass(makeMockAWSClient());

        expect(typeof instance.scan).toBe('function');
        // Confirms `scan` was declared `async` (an AsyncFunction, distinct
        // from a plain function that merely returns a Promise) without
        // actually invoking it — invoking it would perform real retry-with-
        // backoff loops against unmocked/undefined AWS clients (slow, noisy,
        // and unrelated to what this structural contract test checks).
        expect(instance.scan.constructor.name).toBe('AsyncFunction');
      });
    });
  }
});

describe('scanner contract: every checkId passed to this.emit() exists in the check registry', () => {
  // Matches `this.emit('someCheckId'` / `this.emit("someCheckId"`, tolerating
  // any whitespace/newlines between the opening paren and the quoted literal
  // (most call sites in this codebase wrap arguments across multiple lines).
  // Calls where the checkId is a variable/expression (e.g.
  // `this.emit(check.checkId as any, ...)`) are intentionally not matched —
  // this is a static string-literal lint, not a full parser.
  const EMIT_LITERAL_RE = /this\.emit\(\s*['"]([a-zA-Z0-9_]+)['"]/g;

  // Collect file/checkId pairs referencing an unregistered checkId across
  // every scanner file, so a single assertion can report every mismatch at
  // once instead of failing on just the first one found.
  const mismatches: Array<{ file: string; checkId: string }> = [];
  const literalPairs: Array<{ file: string; checkId: string }> = [];

  for (const file of scannerFiles) {
    const source = fs.readFileSync(path.join(SCANNERS_DIR, file), 'utf8');
    let match: RegExpExecArray | null;
    EMIT_LITERAL_RE.lastIndex = 0;
    while ((match = EMIT_LITERAL_RE.exec(source)) !== null) {
      const checkId = match[1];
      literalPairs.push({ file, checkId });
      if (!hasCheck(checkId)) {
        mismatches.push({ file, checkId });
      }
    }
  }

  it('found at least one this.emit(checkId) literal to verify (sanity check on the regex/discovery itself)', () => {
    expect(literalPairs.length).toBeGreaterThan(0);
  });

  it('every statically-referenced checkId is registered in src/checks/registry', () => {
    if (mismatches.length > 0) {
      const details = mismatches
        .map((m) => `  - ${m.file}: this.emit('${m.checkId}', ...) — "${m.checkId}" not found in registry`)
        .join('\n');
      throw new Error(
        `${mismatches.length} checkId(s) referenced via this.emit() are missing from the check registry:\n${details}`
      );
    }
    expect(mismatches).toEqual([]);
  });

  // Individual per-pair assertions too, so a test report shows exactly which
  // file/checkId combination is passing/failing rather than only a single
  // aggregate test.
  for (const { file, checkId } of literalPairs) {
    it(`${file}: this.emit('${checkId}', ...) references a registered checkId`, () => {
      expect(hasCheck(checkId)).toBe(true);
    });
  }
});
