// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';
import type { AzureClient } from '../client';

const SECURITY_CENTER_BUILT_IN_ASSIGNMENT = 'SecurityCenterBuiltIn';

export class AzurePolicyScanner extends AzureBaseScanner {
  constructor(client: AzureClient) {
    super(client, 'Azure-Policy');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const policyClient = this.client.policy();

      const assignments: any[] = [];
      for await (const a of policyClient.policyAssignments.list()) assignments.push(a);

      const builtIn = assignments.find((a) => a.name === SECURITY_CENTER_BUILT_IN_ASSIGNMENT);

      // policy_ensure_asc_enforcement_enabled: the Defender for Cloud
      // built-in policy assignment should have enforcement mode "Default",
      // not "DoNotEnforce".
      if (builtIn && builtIn.enforcementMode !== 'Default') {
        findings.push(this.emit(
          'policy_ensure_asc_enforcement_enabled',
          { policyAssignment: builtIn.name, id: builtIn.id, enforcementMode: builtIn.enforcementMode },
          {
            message: `Policy assignment "${builtIn.id}" is not configured with enforcement mode Default (current: ${builtIn.enforcementMode})`,
          },
        ));
      }
      // Note: when the SecurityCenterBuiltIn assignment is absent entirely,
      // Prowler's check emits no finding for that subscription (mirrored here).
    } catch (err) {
      findings.push(this.finding(
        'Azure Policy scan error',
        `Could not complete Policy assignment scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on policy assignments (Microsoft.Authorization/policyAssignments/read).',
      ));
    }

    return findings;
  }
}

export default AzurePolicyScanner;
