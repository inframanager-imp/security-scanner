// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

interface KeySpec {
  keyType?: string | null;
  algorithm?: string | null;
}

interface ManagedZone {
  name?: string | null;
  id?: string | null;
  dnsName?: string | null;
  dnssecConfig?: {
    state?: string | null;
    defaultKeySpecs?: KeySpec[] | null;
  } | null;
}

export class GcpDnsScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-DNS');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const zones = await this.listManagedZones(project);

      for (const zone of zones) {
        const zoneName = zone.name ?? zone.id ?? 'unnamed-zone';
        const dnssecEnabled = (zone.dnssecConfig?.state ?? '') === 'on';
        const keySpecs = zone.dnssecConfig?.defaultKeySpecs ?? [];

        // dns_dnssec_disabled
        if (!dnssecEnabled) {
          findings.push(this.emit(
            'dns_dnssec_disabled',
            { project, zone: zoneName, dnsName: zone.dnsName },
            { message: `Cloud DNS managed zone "${zoneName}" (${zone.dnsName ?? 'unknown domain'}) in project "${project}" does not have DNSSEC enabled.` },
          ));
          continue; // no KSK/ZSK algorithm to inspect when DNSSEC is off
        }

        // dns_rsasha1_in_use_to_key_sign_in_dnssec
        const kskRsasha1 = keySpecs.some(k => k.keyType === 'keySigning' && k.algorithm === 'rsasha1');
        if (kskRsasha1) {
          findings.push(this.emit(
            'dns_rsasha1_in_use_to_key_sign_in_dnssec',
            { project, zone: zoneName, dnsName: zone.dnsName },
            { message: `Cloud DNS managed zone "${zoneName}" in project "${project}" uses the RSASHA1 algorithm for its DNSSEC key-signing key.` },
          ));
        }

        // dns_rsasha1_in_use_to_zone_sign_in_dnssec
        const zskRsasha1 = keySpecs.some(k => k.keyType === 'zoneSigning' && k.algorithm === 'rsasha1');
        if (zskRsasha1) {
          findings.push(this.emit(
            'dns_rsasha1_in_use_to_zone_sign_in_dnssec',
            { project, zone: zoneName, dnsName: zone.dnsName },
            { message: `Cloud DNS managed zone "${zoneName}" in project "${project}" uses the RSASHA1 algorithm for its DNSSEC zone-signing key.` },
          ));
        }
      }
    } catch (err) {
      findings.push(this.emit(
        'dns_dnssec_disabled',
        { error: (err as Error).message },
        { severity: 'INFO', message: `GCP Cloud DNS scan error: ${(err as Error).message}`, remediation: 'Ensure the service account has the roles/dns.reader permission.' },
      ));
    }

    return findings;
  }

  private async listManagedZones(project: string): Promise<ManagedZone[]> {
    const dns = this.client.dns();
    const zones: ManagedZone[] = [];
    let pageToken: string | undefined;
    do {
      const res = await dns.managedZones.list({ project, pageToken });
      zones.push(...(res.data.managedZones ?? []));
      pageToken = res.data.nextPageToken ?? undefined;
    } while (pageToken);
    return zones;
  }
}

export default GcpDnsScanner;
