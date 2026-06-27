import * as fs from 'fs';
import { ScanReport } from '../utils/types';
import logger from '../utils/logger';

export interface Reporter {
  report(report: ScanReport): Promise<void>;
}

export class JSONReporter implements Reporter {
  private outputPath: string;

  constructor(outputPath: string = 'scan-report.json') {
    this.outputPath = outputPath;
  }

  async report(report: ScanReport): Promise<void> {
    try {
      const json = JSON.stringify(report, null, 2);
      fs.writeFileSync(this.outputPath, json, 'utf-8');
      logger.info(`JSON report saved to ${this.outputPath}`);
    } catch (error) {
      logger.error('Failed to generate JSON report', { error: (error as Error).message });
      throw error;
    }
  }
}

export class CSVReporter implements Reporter {
  private outputPath: string;

  constructor(outputPath: string = 'scan-report.csv') {
    this.outputPath = outputPath;
  }

  async report(report: ScanReport): Promise<void> {
    try {
      const headers = ['ID', 'Service', 'Severity', 'Title', 'Description', 'Remediation', 'Timestamp'];
      const rows = report.findings.map(f => [
        f.id,
        f.service,
        f.severity,
        f.title,
        f.description,
        f.remediation,
        f.timestamp.toISOString()
      ]);

      const csv = [
        headers.map(h => `"${h}"`).join(','),
        ...rows.map(r => r.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      ].join('\n');

      fs.writeFileSync(this.outputPath, csv, 'utf-8');
      logger.info(`CSV report saved to ${this.outputPath}`);
    } catch (error) {
      logger.error('Failed to generate CSV report', { error: (error as Error).message });
      throw error;
    }
  }
}

export class ConsoleReporter implements Reporter {
  async report(report: ScanReport): Promise<void> {
    console.log('\n' + '='.repeat(80));
    console.log('AWS SCANNER - SECURITY SCAN REPORT');
    console.log('='.repeat(80));

    console.log(`\nAccount: ${report.account}`);
    console.log(`Timestamp: ${report.timestamp.toISOString()}`);
    console.log(`Regions: ${report.regions.join(', ')}`);
    console.log(`Services: ${report.services.join(', ')}`);
    console.log(`Duration: ${report.duration}ms`);

    console.log(`\n📊 SUMMARY`);
    console.log('─'.repeat(80));
    console.log(`Total Findings: ${report.totalFindings}`);
    console.log(`  🔴 CRITICAL: ${report.summary.critical}`);
    console.log(`  🟠 HIGH: ${report.summary.high}`);
    console.log(`  🟡 MEDIUM: ${report.summary.medium}`);
    console.log(`  🔵 LOW: ${report.summary.low}`);
    console.log(`  ⚪ INFO: ${report.summary.info}`);

    if (report.findings.length > 0) {
      console.log(`\n🔍 FINDINGS (Top 20)`);
      console.log('─'.repeat(80));

      const sorted = [...report.findings].sort((a, b) => {
        const severityOrder: Record<string, number> = {
          CRITICAL: 0,
          HIGH: 1,
          MEDIUM: 2,
          LOW: 3,
          INFO: 4
        };
        return severityOrder[a.severity] - severityOrder[b.severity];
      });

      const displayed = sorted.slice(0, 20);
      for (const finding of displayed) {
        console.log(`\n${getSeverityIcon(finding.severity)} [${finding.severity}] ${finding.title}`);
        console.log(`   Service: ${finding.service}`);
        console.log(`   Description: ${finding.description}`);
        console.log(`   Remediation: ${finding.remediation}`);
        if (finding.tags?.length) {
          console.log(`   Tags: ${finding.tags.join(', ')}`);
        }
      }

      if (report.findings.length > 20) {
        console.log(`\n... and ${report.findings.length - 20} more findings`);
      }
    } else {
      console.log('\n✅ No findings - system is secure!');
    }

    console.log('\n' + '='.repeat(80) + '\n');
  }
}

function getSeverityIcon(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return '🔴';
    case 'HIGH':
      return '🟠';
    case 'MEDIUM':
      return '🟡';
    case 'LOW':
      return '🔵';
    case 'INFO':
      return '⚪';
    default:
      return '❓';
  }
}

export default { JSONReporter, CSVReporter, ConsoleReporter };
