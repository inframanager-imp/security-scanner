import { describe, it, expect } from '@jest/globals';
import { JSONReporter } from '../../src/reporters/reporters';
import * as fs from 'fs';
import * as os from 'os';
import { ScanReport } from '../../src/utils/types';

describe('JSONReporter', () => {
  it('should generate valid JSON report', async () => {
    const tmpFile = `${os.tmpdir()}/test-report.json`;
    const reporter = new JSONReporter(tmpFile);

    const report: ScanReport = {
      id: 'test-report',
      timestamp: new Date(),
      account: '123456789012',
      regions: ['us-east-1'],
      services: ['iam'],
      totalFindings: 0,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    };

    await reporter.report(report);

    expect(fs.existsSync(tmpFile)).toBe(true);
    const content = fs.readFileSync(tmpFile, 'utf-8');
    const parsed = JSON.parse(content);
    expect(parsed.id).toEqual('test-report');

    // Cleanup
    if (fs.existsSync(tmpFile)) {
      fs.unlinkSync(tmpFile);
    }
  });
});
