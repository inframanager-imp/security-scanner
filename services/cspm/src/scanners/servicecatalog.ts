// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ServiceCatalogClient,
  ListPortfoliosCommand,
  DescribePortfolioSharesCommand,
} from '@aws-sdk/client-service-catalog';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class ServiceCatalogScanner extends BaseScanner {
  private catalog: ServiceCatalogClient;

  constructor(client: AWSClient) {
    super(client, 'ServiceCatalog');
    this.catalog = new ServiceCatalogClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Service Catalog security scan...');

      const portfolios = await this.listPortfolios();
      logger.info(`ServiceCatalog: scanning ${portfolios.length} portfolio(s)`);

      // servicecatalog_portfolio_shared_within_organization_only: portfolios
      // shared directly with external accounts bypass organization guardrails.
      for (const portfolio of portfolios) {
        try {
          const accountShares = await this.listShares(portfolio.Id, 'ACCOUNT');
          if (accountShares.length > 0) {
            findings.push(this.emit(
              'servicecatalog_portfolio_shared_within_organization_only',
              { portfolio: portfolio.DisplayName, portfolioId: portfolio.Id, accountShares: accountShares.length },
              {
                message: `Service Catalog portfolio "${portfolio.DisplayName}" is shared directly with ${accountShares.length} individual account(s) outside organization-managed sharing`,
                remediation: `Replace direct account shares of portfolio "${portfolio.DisplayName}" with organization or organizational-unit shares so access stays governed by the organization`,
              }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to scan portfolio ${portfolio.Id}`, { error: (error as Error).message });
        }
      }

      logger.info(`ServiceCatalog scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('ServiceCatalog scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listPortfolios(): Promise<any[]> {
    const portfolios: any[] = [];
    let pageToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.catalog.send(new ListPortfoliosCommand({ PageToken: pageToken }));
      });
      portfolios.push(...(result.PortfolioDetails ?? []));
      pageToken = result.NextPageToken;
    } while (pageToken);
    return portfolios;
  }

  private async listShares(portfolioId: string, type: 'ACCOUNT' | 'ORGANIZATION'): Promise<any[]> {
    const shares: any[] = [];
    let pageToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.catalog.send(new DescribePortfolioSharesCommand({
          PortfolioId: portfolioId,
          Type: type,
          PageToken: pageToken,
        }));
      });
      shares.push(...(result.PortfolioShareDetails ?? []));
      pageToken = result.NextPageToken;
    } while (pageToken);
    return shares;
  }
}

export default ServiceCatalogScanner;
