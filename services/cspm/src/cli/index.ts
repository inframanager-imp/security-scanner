#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import ScanEngine from '../scanners/engine';
import { JSONReporter, CSVReporter, ConsoleReporter } from '../reporters/reporters';
import HTMLReporter from '../reporters/htmlreporter';
import { ScanOptions } from '../utils/types';
import logger from '../utils/logger';

const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf-8'));
const program = new Command();

program
  .name('aws-scanner')
  .description('AWS Vulnerability & Security Compliance Scanner')
  .version(packageJson.version);

program
  .command('scan')
  .description('Execute AWS security scan')
  .option('-r, --region <region>', 'AWS region to scan', 'us-east-1')
  .option('-s, --services <services>', 'Services to scan (comma-separated; default: all available services)')
  .option('-p, --profile <profile>', 'AWS CLI profile to use')
  .option('-f, --format <format>', 'Output format (json, html, csv, console)', 'console')
  .option('-o, --output <file>', 'Output file path')
  .option('--dry-run', 'Preview scan without executing')
  .option('--config <file>', 'Configuration file (YAML)')
  .option('--verbose', 'Enable verbose logging')
  .action(async (options) => {
    try {
      if (options.verbose) {
        process.env.LOG_LEVEL = 'debug';
      }

      logger.info('AWS Scanner initialized');

      // Load config file if provided
      let scanOptions: ScanOptions = {
        region: options.region,
        services: options.services ? options.services.split(',').map((s: string) => s.trim()) : undefined,
        profile: options.profile,
        outputFormat: options.format,
        outputFile: options.output,
        dryRun: options.dryRun,
        verbose: options.verbose
      };

      if (options.config) {
        logger.info(`Loading config from ${options.config}`);
        const configContent = fs.readFileSync(options.config, 'utf-8');
        const configData = yaml.load(configContent) as any;
        scanOptions = { ...scanOptions, ...configData };
      }

      // Execute scan
      const engine = new ScanEngine();
      const report = await engine.executeScan(scanOptions);

      // Generate report
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const outputFile = scanOptions.outputFile || `scan-report-${timestamp}`;

      const reporters: Record<string, any> = {
        json: () => new JSONReporter(`${outputFile}.json`),
        html: () => new HTMLReporter(`${outputFile}.html`),
        csv: () => new CSVReporter(`${outputFile}.csv`),
        console: () => new ConsoleReporter()
      };

      const reporterClass = reporters[scanOptions.outputFormat || 'console'];
      if (!reporterClass) {
        throw new Error(`Unknown output format: ${scanOptions.outputFormat}`);
      }

      const reporter = reporterClass();
      await reporter.report(report);

      logger.info('Scan completed successfully');
      process.exit(0);
    } catch (error) {
      logger.error('Scan execution failed', { error: (error as Error).message });
      console.error(`\n❌ Error: ${(error as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('list-regions')
  .description('List available AWS regions')
  .action(() => {
    const engine = new ScanEngine();
    const regions = engine.getAvailableRegions();
    console.log('Available regions:');
    regions.forEach(r => console.log(`  ${r}`));
  });

program
  .command('list-services')
  .description('List available services to scan')
  .action(() => {
    const engine = new ScanEngine();
    const services = engine.getAvailableServices();
    console.log('Available services:');
    services.forEach(s => console.log(`  ${s}`));
  });

program.parse(process.argv);

if (process.argv.length < 3) {
  program.outputHelp();
}
