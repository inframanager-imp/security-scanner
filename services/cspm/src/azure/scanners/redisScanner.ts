import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureRedisScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Redis');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const redisClient = this.client.redis();

      const caches: any[] = [];
      for await (const c of redisClient.redis.listBySubscription()) caches.push(c);

      if (caches.length === 0) return findings;

      for (const cache of caches) {
        const name = cache.name ?? 'unknown';
        const rg   = cache.id?.split('/')[4] ?? 'unknown';
        const sku  = cache.sku?.name ?? 'Basic';
        const tier = cache.sku?.tier ?? 'Basic';

        // 1. Non-SSL port enabled (port 6379)
        if (cache.enableNonSslPort === true) {
          findings.push(this.finding(
            'Redis Cache has non-SSL port (6379) enabled',
            `Redis Cache "${name}" has the non-SSL port 6379 enabled. All traffic on this port is transmitted in plaintext, exposing data and authentication credentials to interception.`,
            'CRITICAL',
            { cache: name, resourceGroup: rg, sku },
            'Disable the non-SSL port immediately. All clients must connect exclusively on the TLS port (6380). Update application connection strings to use SSL=True.',
            ['redis', 'encryption-in-transit'],
          ));
        }

        // 2. Minimum TLS version
        const minTls = cache.minimumTlsVersion ?? '1.0';
        if (minTls !== '1.2') {
          findings.push(this.finding(
            'Redis Cache allows connections below TLS 1.2',
            `Redis Cache "${name}" has minimum TLS version set to "${minTls}". TLS 1.0/1.1 are deprecated and vulnerable to BEAST, POODLE, and related attacks.`,
            'HIGH',
            { cache: name, minimumTlsVersion: minTls, resourceGroup: rg },
            'Set minimumTlsVersion to "1.2" on the Redis Cache. Verify all application clients support TLS 1.2 before enforcing.',
            ['redis', 'tls'],
          ));
        }

        // 3. Public network access
        const publicAccess = cache.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Redis Cache has public network access enabled',
            `Redis Cache "${name}" is accessible from the public internet. Even with authentication required, public exposure significantly increases the attack surface.`,
            'HIGH',
            { cache: name, resourceGroup: rg, sku },
            'Set publicNetworkAccess to "Disabled" and create a Private Endpoint in the VNet used by your applications. Update connection strings to use the private endpoint FQDN.',
            ['redis', 'network', 'public-access'],
          ));
        }

        // 4. Basic/Standard SKU — no replication, no SLA, no zone redundancy
        if (tier === 'Basic') {
          findings.push(this.finding(
            'Redis Cache is using the Basic SKU',
            `Redis Cache "${name}" uses the Basic SKU (single node, no SLA, no replication). A single node failure results in full data loss and downtime. Not suitable for production workloads.`,
            'HIGH',
            { cache: name, resourceGroup: rg, sku, tier },
            'Upgrade to Standard SKU for primary/replica replication and a 99.9% SLA, or Premium for geo-replication, VNet injection, cluster mode, and zone redundancy.',
            ['redis', 'availability', 'sku'],
          ));
        }

        // 5. Geo-replication not configured (Premium only)
        if (tier === 'Premium') {
          try {
            const geoLinks: any[] = [];
            for await (const link of redisClient.linkedServer.list(rg, name)) geoLinks.push(link);
            if (geoLinks.length === 0) {
              findings.push(this.finding(
                'Redis Cache has no geo-replication linked server configured',
                `Redis Cache "${name}" (Premium SKU) has no geo-replication. A regional outage will cause cache unavailability and possible data loss for cross-region workloads.`,
                'MEDIUM',
                { cache: name, resourceGroup: rg },
                'Configure geo-replication by linking a secondary Redis Cache in a paired region. This enables read access during primary region outages.',
                ['redis', 'availability', 'geo-replication'],
              ));
            }
          } catch { /* geo-replication check optional */ }
        }

        // 6. Firewall rules — check if all IPs are allowed
        try {
          const firewallRules: any[] = [];
          for await (const rule of redisClient.firewallRules.list(rg, name)) firewallRules.push(rule);

          const openRule = firewallRules.find(r =>
            r.startIP === '0.0.0.0' && r.endIP === '255.255.255.255',
          );
          if (openRule) {
            findings.push(this.finding(
              'Redis Cache firewall allows access from all IP addresses',
              `Redis Cache "${name}" has a firewall rule allowing 0.0.0.0–255.255.255.255. This effectively disables the IP-based firewall, allowing any internet host to connect.`,
              'CRITICAL',
              { cache: name, resourceGroup: rg, rule: openRule.name },
              'Remove the open firewall rule. Restrict access to specific application server IP ranges or, preferably, disable public network access entirely and use Private Endpoint.',
              ['redis', 'firewall', 'network'],
            ));
          } else if (firewallRules.length === 0 && publicAccess === 'Enabled') {
            findings.push(this.finding(
              'Redis Cache has no firewall rules configured',
              `Redis Cache "${name}" has public network access enabled but no firewall rules. Access is controlled only by authentication (access key).`,
              'HIGH',
              { cache: name, resourceGroup: rg },
              'Add firewall rules restricting access to known application server IP ranges, or disable public network access and use Private Endpoint.',
              ['redis', 'firewall', 'network'],
            ));
          }
        } catch { /* firewall rules optional */ }

        // 7. Redis version — check for EOL versions
        const redisVersion = cache.redisVersion ?? '';
        if (redisVersion && redisVersion.startsWith('4.')) {
          findings.push(this.finding(
            'Redis Cache is running an end-of-life Redis version',
            `Redis Cache "${name}" runs Redis ${redisVersion}. Redis 4.x reached end-of-life in 2023 and no longer receives security patches.`,
            'HIGH',
            { cache: name, redisVersion, resourceGroup: rg },
            'Upgrade to Redis 6.x or later. Test application compatibility in a non-production environment before upgrading.',
            ['redis', 'eol-version'],
          ));
        }

        // 8. Microsoft Entra ID authentication — prefer over access keys
        const authConfig = (cache as any).redisConfiguration;
        const aadEnabled = (cache as any).redisVersion >= '6' &&
          (authConfig?.['aad-enabled'] === 'true' || (cache as any).authenticationConfig?.type === 'MicrosoftEntra');
        if (!aadEnabled && tier !== 'Basic') {
          findings.push(this.finding(
            'Redis Cache uses access key authentication instead of Microsoft Entra ID',
            `Redis Cache "${name}" relies on shared access keys for authentication. Access keys cannot be scoped per user, do not support MFA, and must be manually rotated.`,
            'MEDIUM',
            { cache: name, resourceGroup: rg, redisVersion },
            'Enable Microsoft Entra ID authentication for Redis Cache (requires Redis 6+) and migrate application clients to use token-based authentication. Disable access key authentication once migrated.',
            ['redis', 'authentication'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Redis Cache scan error',
        `Could not complete Redis Cache scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Redis Cache resources.',
      ));
    }

    return findings;
  }
}
