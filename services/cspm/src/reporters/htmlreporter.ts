import * as fs from 'fs';
import { ScanReport } from '../utils/types';
import logger from '../utils/logger';

export class HTMLReporter {
  private outputPath: string;

  constructor(outputPath: string = 'scan-report.html') {
    this.outputPath = outputPath;
  }

  async report(report: ScanReport): Promise<void> {
    try {
      const html = this.generateHTML(report);
      fs.writeFileSync(this.outputPath, html, 'utf-8');
      logger.info(`HTML report saved to ${this.outputPath}`);
    } catch (error) {
      logger.error('Failed to generate HTML report', { error: (error as Error).message });
      throw error;
    }
  }

  private generateHTML(report: ScanReport): string {
    const severityColors: Record<string, string> = {
      CRITICAL: '#dc3545',
      HIGH: '#fd7e14',
      MEDIUM: '#ffc107',
      LOW: '#17a2b8',
      INFO: '#6c757d'
    };

    const chartData = JSON.stringify({
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      datasets: [{
        data: [
          report.summary.critical,
          report.summary.high,
          report.summary.medium,
          report.summary.low,
          report.summary.info
        ],
        backgroundColor: [
          severityColors.CRITICAL,
          severityColors.HIGH,
          severityColors.MEDIUM,
          severityColors.LOW,
          severityColors.INFO
        ]
      }]
    });

    const findingRows = report.findings
      .sort((a, b) => {
        const order: Record<string, number> = {
          CRITICAL: 0,
          HIGH: 1,
          MEDIUM: 2,
          LOW: 3,
          INFO: 4
        };
        return order[a.severity] - order[b.severity];
      })
      .map(f => `
        <tr>
          <td style="color: ${severityColors[f.severity]}; font-weight: bold;">
            ${f.severity}
          </td>
          <td>${f.service}</td>
          <td>${f.title}</td>
          <td>${f.description}</td>
          <td>${f.remediation}</td>
          <td>${f.timestamp.toISOString()}</td>
        </tr>
      `).join('');

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AWS Scanner - Security Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f5f5f5;
      color: #333;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }

    header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px;
      border-radius: 8px;
      margin-bottom: 30px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }

    header h1 {
      font-size: 2.5em;
      margin-bottom: 10px;
    }

    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      margin-top: 20px;
    }

    .info-item {
      background: rgba(255,255,255,0.1);
      padding: 15px;
      border-radius: 6px;
      backdrop-filter: blur(10px);
    }

    .info-label {
      font-size: 0.9em;
      opacity: 0.9;
      margin-bottom: 5px;
    }

    .info-value {
      font-size: 1.3em;
      font-weight: bold;
    }

    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .summary-card {
      background: white;
      padding: 25px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      border-left: 5px solid;
    }

    .summary-card.critical { border-color: #dc3545; }
    .summary-card.high { border-color: #fd7e14; }
    .summary-card.medium { border-color: #ffc107; }
    .summary-card.low { border-color: #17a2b8; }
    .summary-card.info { border-color: #6c757d; }

    .summary-card h3 {
      margin-bottom: 10px;
      color: #333;
    }

    .summary-card .count {
      font-size: 2.5em;
      font-weight: bold;
      margin: 10px 0;
    }

    .chart-container {
      background: white;
      padding: 30px;
      border-radius: 8px;
      margin-bottom: 30px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .chart-container h2 {
      margin-bottom: 20px;
      color: #333;
    }

    .chart-wrapper {
      position: relative;
      height: 400px;
    }

    .findings-container {
      background: white;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .findings-container h2 {
      padding: 20px;
      background: #f8f9fa;
      border-bottom: 1px solid #dee2e6;
      margin: 0;
    }

    table {
      width: 100%;
      border-collapse: collapse;
    }

    th {
      background: #f8f9fa;
      padding: 12px;
      text-align: left;
      font-weight: 600;
      color: #495057;
      border-bottom: 2px solid #dee2e6;
    }

    td {
      padding: 12px;
      border-bottom: 1px solid #dee2e6;
    }

    tr:hover {
      background: #f8f9fa;
    }

    footer {
      margin-top: 30px;
      padding: 20px;
      text-align: center;
      color: #6c757d;
      font-size: 0.9em;
    }

    .total-findings {
      font-size: 3em;
      font-weight: bold;
      color: #667eea;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>AWS Security Scanner Report</h1>
      <p>Comprehensive security and compliance analysis</p>
      <div class="info-grid">
        <div class="info-item">
          <div class="info-label">Account ID</div>
          <div class="info-value">${report.account}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Scan Date</div>
          <div class="info-value">${report.timestamp.toLocaleDateString()}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Regions</div>
          <div class="info-value">${report.regions.length}</div>
        </div>
        <div class="info-item">
          <div class="info-label">Services</div>
          <div class="info-value">${report.services.length}</div>
        </div>
      </div>
    </header>

    <section class="summary">
      <div class="summary-card critical">
        <h3>CRITICAL</h3>
        <div class="count">${report.summary.critical}</div>
        <p>Immediate action required</p>
      </div>
      <div class="summary-card high">
        <h3>HIGH</h3>
        <div class="count">${report.summary.high}</div>
        <p>Requires attention</p>
      </div>
      <div class="summary-card medium">
        <h3>MEDIUM</h3>
        <div class="count">${report.summary.medium}</div>
        <p>Should be addressed</p>
      </div>
      <div class="summary-card low">
        <h3>LOW</h3>
        <div class="count">${report.summary.low}</div>
        <p>Best practices</p>
      </div>
      <div class="summary-card info">
        <h3>INFO</h3>
        <div class="count">${report.summary.info}</div>
        <p>Informational</p>
      </div>
    </section>

    <div class="chart-container">
      <h2>Findings Distribution</h2>
      <div class="chart-wrapper">
        <canvas id="severityChart"></canvas>
      </div>
    </div>

    ${report.findings.length > 0 ? `
      <div class="findings-container">
        <h2>Detailed Findings (${report.findings.length} total)</h2>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Service</th>
              <th>Title</th>
              <th>Description</th>
              <th>Remediation</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            ${findingRows}
          </tbody>
        </table>
      </div>
    ` : `
      <div class="findings-container">
        <h2>Scan Results</h2>
        <p style="padding: 20px; text-align: center; color: #28a745;">
          No findings - your AWS environment is secure!
        </p>
      </div>
    `}

    <footer>
      <p>Generated by AWS Scanner on ${new Date().toISOString()}</p>
      <p>This report contains sensitive security information. Handle with care.</p>
    </footer>
  </div>

  <script>
    const ctx = document.getElementById('severityChart').getContext('2d');
    const chart = new Chart(ctx, {
      type: 'doughnut',
      data: ${chartData},
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom'
          }
        }
      }
    });
  </script>
</body>
</html>
    `;
  }
}

export default HTMLReporter;
