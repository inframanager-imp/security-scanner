import AzureClient, { AzureClientOptions } from './client';
import { AzureIAMScanner }        from './scanners/iamScanner';
import { AzureStorageScanner }    from './scanners/storageScanner';
import { AzureVMScanner }         from './scanners/vmScanner';
import { AzureSQLScanner }        from './scanners/sqlScanner';
import { AzureKeyVaultScanner }   from './scanners/keyVaultScanner';
import { AzureNSGScanner }        from './scanners/nsgScanner';
import { AzureAppServiceScanner } from './scanners/appServiceScanner';
import { AzureAKSScanner }        from './scanners/aksScanner';
import { AzureNetworkScanner }    from './scanners/networkScanner';
import { AzureCosmosScanner }     from './scanners/cosmosScanner';
import { AzureThreatScanner }     from './scanners/threatScanner';
import { AzureACRScanner }        from './scanners/acrScanner';
import { AzureEntraScanner }      from './scanners/entraScanner';
import { AzureRedisScanner }      from './scanners/redisScanner';
import { AzureServiceBusScanner } from './scanners/serviceBusScanner';
import { AzureEventHubScanner }   from './scanners/eventHubScanner';
import { AzurePostgresScanner }   from './scanners/postgresScanner';
import { AzureMySQLScanner }      from './scanners/mysqlScanner';
import { AzureCognitiveScanner }  from './scanners/cognitiveScanner';
import { AzureAPIMScanner }         from './scanners/apimScanner';
import { AzureFunctionsScanner }     from './scanners/functionsScanner';
import { AzureContainerAppsScanner } from './scanners/containerAppsScanner';
import { AzureAppGatewayScanner }    from './scanners/appGatewayScanner';
import { AzureMLScanner }            from './scanners/amlScanner';
import { AzureDataFactoryScanner }   from './scanners/adfScanner';
import { AzureSynapseScanner }       from './scanners/synapseScanner';
import { AzureBackupScanner }        from './scanners/backupScanner';
import { AzureLogAnalyticsScanner }  from './scanners/logAnalyticsScanner';
import { AzureEventGridScanner }     from './scanners/eventGridScanner';
import { AzureIoTHubScanner }        from './scanners/iotHubScanner';
import { AzureSearchScanner }        from './scanners/searchScanner';
import { AzureAutomationScanner }    from './scanners/automationScanner';
import { AzureDefenderScanner }      from './scanners/defenderScanner';
import { AzureMonitorScanner }       from './scanners/monitorScanner';
import { AzureDatabricksScanner }    from './scanners/databricksScanner';
import { AzureAppInsightsScanner }   from './scanners/appinsightsScanner';
import { AzurePolicyScanner }        from './scanners/policyScanner';
import { ScanningResult, ScanReport } from '../utils/types';

export interface AzureScanOptions {
  services?: string[];
  credentials: AzureClientOptions;
}

export const AZURE_SERVICES = [
  'iam',
  'storage',
  'vm',
  'sql',
  'keyvault',
  'nsg',
  'network',
  'appservice',
  'aks',
  'acr',
  'cosmos',
  'entra',
  'threat',
  'redis',
  'servicebus',
  'eventhub',
  'postgres',
  'mysql',
  'cognitive',
  'apim',
  'functions',
  'containerapps',
  'appgateway',
  'aml',
  'adf',
  'synapse',
  'backup',
  'loganalytics',
  'eventgrid',
  'iothub',
  'search',
  'automation',
  'defender',
  'monitor',
  'databricks',
  'appinsights',
  'policy',
];

export class AzureScanEngine {
  async executeScan(options: AzureScanOptions): Promise<ScanReport> {
    const startTime = Date.now();
    const findings: ScanningResult[] = [];
    const services  = options.services ?? AZURE_SERVICES;

    const client = new AzureClient(options.credentials);

    const scannerMap: Record<string, () => Promise<ScanningResult[]>> = {
      iam:        () => new AzureIAMScanner(client).scan(),
      storage:    () => new AzureStorageScanner(client).scan(),
      vm:         () => new AzureVMScanner(client).scan(),
      sql:        () => new AzureSQLScanner(client).scan(),
      keyvault:   () => new AzureKeyVaultScanner(client).scan(),
      nsg:        () => new AzureNSGScanner(client).scan(),
      appservice: () => new AzureAppServiceScanner(client).scan(),
      aks:        () => new AzureAKSScanner(client).scan(),
      network:    () => new AzureNetworkScanner(client).scan(),
      cosmos:     () => new AzureCosmosScanner(client).scan(),
      acr:        () => new AzureACRScanner(client).scan(),
      entra:      () => new AzureEntraScanner(client).scan(),
      threat:     () => new AzureThreatScanner(client).scan(),
      redis:      () => new AzureRedisScanner(client).scan(),
      servicebus: () => new AzureServiceBusScanner(client).scan(),
      eventhub:   () => new AzureEventHubScanner(client).scan(),
      postgres:   () => new AzurePostgresScanner(client).scan(),
      mysql:      () => new AzureMySQLScanner(client).scan(),
      cognitive:  () => new AzureCognitiveScanner(client).scan(),
      apim:         () => new AzureAPIMScanner(client).scan(),
      functions:    () => new AzureFunctionsScanner(client).scan(),
      containerapps:() => new AzureContainerAppsScanner(client).scan(),
      appgateway:   () => new AzureAppGatewayScanner(client).scan(),
      aml:          () => new AzureMLScanner(client).scan(),
      adf:          () => new AzureDataFactoryScanner(client).scan(),
      synapse:      () => new AzureSynapseScanner(client).scan(),
      backup:       () => new AzureBackupScanner(client).scan(),
      loganalytics: () => new AzureLogAnalyticsScanner(client).scan(),
      eventgrid:    () => new AzureEventGridScanner(client).scan(),
      iothub:       () => new AzureIoTHubScanner(client).scan(),
      search:       () => new AzureSearchScanner(client).scan(),
      automation:   () => new AzureAutomationScanner(client).scan(),
      defender:     () => new AzureDefenderScanner(client).scan(),
      monitor:      () => new AzureMonitorScanner(client).scan(),
      databricks:   () => new AzureDatabricksScanner(client).scan(),
      appinsights:  () => new AzureAppInsightsScanner(client).scan(),
      policy:       () => new AzurePolicyScanner(client).scan(),
    };

    for (const svc of services) {
      const runner = scannerMap[svc];
      if (!runner) continue;
      try {
        const results = await runner();
        findings.push(...results);
      } catch (err) {
        // Individual scanner failure — log and continue
        findings.push({
          id: `azure-${svc}-error-${Date.now()}`,
          timestamp: new Date(),
          service: `Azure-${svc}`,
          severity: 'INFO',
          title: `Scanner error — ${svc}`,
          description: `The ${svc} scanner encountered an unexpected error: ${(err as Error).message}`,
          evidence: { error: (err as Error).message },
          remediation: `Verify that the service principal has the required permissions for Azure ${svc}.`,
          status: 'OPEN',
          tags: ['scanner-error'],
        });
      }
    }

    const duration = Date.now() - startTime;

    return {
      id: `azure-${Date.now()}`,
      timestamp: new Date(),
      account: options.credentials.subscriptionId,
      regions: ['azure-global'],
      services,
      totalFindings: findings.length,
      findings,
      summary: {
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high:     findings.filter(f => f.severity === 'HIGH').length,
        medium:   findings.filter(f => f.severity === 'MEDIUM').length,
        low:      findings.filter(f => f.severity === 'LOW').length,
        info:     findings.filter(f => f.severity === 'INFO').length,
      },
      duration,
    };
  }
}

export default AzureScanEngine;
