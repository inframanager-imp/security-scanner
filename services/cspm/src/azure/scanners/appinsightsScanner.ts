// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';
import type { AzureClient } from '../client';

export class AzureAppInsightsScanner extends AzureBaseScanner {
  constructor(client: AzureClient) {
    super(client, 'Azure-AppInsights');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const appInsightsClient = this.client.appInsights();

      // appinsights_ensure_is_configured: the subscription should have at
      // least one Application Insights component collecting telemetry.
      const components: any[] = [];
      const result: any = await appInsightsClient.components.list();
      if (Array.isArray(result)) {
        components.push(...result);
      } else if (Array.isArray(result?.value)) {
        components.push(...result.value);
      }

      if (components.length < 1) {
        findings.push(this.emit(
          'appinsights_ensure_is_configured',
          { subscriptionId: this.client.subscriptionId, componentCount: components.length },
          {
            message: `There are no Application Insights components configured in subscription ${this.client.subscriptionId}`,
          },
        ));
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Application Insights scan error',
        `Could not complete Application Insights scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Application Insights components.',
      ));
    }

    return findings;
  }
}

export default AzureAppInsightsScanner;
