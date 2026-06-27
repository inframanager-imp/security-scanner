import { describe, it, expect } from '@jest/globals';
import ScanEngine from '../../src/scanners/engine';

describe('ScanEngine', () => {
  let engine: ScanEngine;

  beforeEach(() => {
    engine = new ScanEngine();
  });

  it('should have available regions', () => {
    const regions = engine.getAvailableRegions();
    expect(regions.length).toBeGreaterThan(0);
    expect(regions).toContain('us-east-1');
  });

  it('should have available services', () => {
    const services = engine.getAvailableServices();
    expect(services.length).toBeGreaterThan(0);
    expect(services).toContain('iam');
    expect(services).toContain('s3');
    expect(services).toContain('cloudtrail');
  });
});
