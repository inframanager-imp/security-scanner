// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DescribeLoadBalancersCommand,
  DescribeListenersCommand,
  DescribeLoadBalancerAttributesCommand,
  DescribeTargetGroupsCommand,
  type LoadBalancer,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import {
  ElasticLoadBalancingClient,
  DescribeLoadBalancersCommand as DescribeClassicLoadBalancersCommand,
  DescribeLoadBalancerAttributesCommand as DescribeClassicLoadBalancerAttributesCommand,
} from '@aws-sdk/client-elastic-load-balancing';
import { GetWebACLForResourceCommand } from '@aws-sdk/client-wafv2';
import { DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import { ListCertificatesCommand } from '@aws-sdk/client-acm';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Weak SSL policies that should be upgraded
const WEAK_SSL_POLICIES = new Set([
  'ELBSecurityPolicy-2016-08',
  'ELBSecurityPolicy-TLS-1-0-2015-04',
  'ELBSecurityPolicy-TLS-1-1-2017-01',
]);

// Minimum availability zones a load balancer should span (Prowler default)
const MIN_AZS = 2;

// The only Classic LB predefined policy Prowler treats as free of insecure SSL ciphers
const SECURE_CLASSIC_SSL_POLICY = 'ELBSecurityPolicy-TLS-1-2-2017-01';

// Classic LB listener protocols that encrypt client traffic
const SECURE_CLASSIC_PROTOCOLS = ['HTTPS', 'SSL'];

// Post-quantum TLS policies (hybrid ML-KEM 768 + ECDHE key exchange)
const PQ_TLS_POLICIES = new Set([
  'ELBSecurityPolicy-TLS13-1-2-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-3-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09',
  'ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09',
]);

export class ELBScanner extends BaseScanner {
  private elbClassic: ElasticLoadBalancingClient;

  constructor(client: AWSClient) {
    super(client, 'ELB');
    this.elbClassic = new ElasticLoadBalancingClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting ELB/ALB security scan...');

    try {
      const lbs = await this.listAllLoadBalancers();
      logger.info(`ELB: scanning ${lbs.length} load balancer(s)`);

      await Promise.allSettled(
        lbs.map(lb => this.scanLoadBalancer(lb).then(f => findings.push(...f)))
      );

      findings.push(...(await this.checkInsecureTargetGroups()));
      findings.push(...(await this.scanClassicLoadBalancers()));
    } catch (error) {
      logger.error('ELB scan failed', { error: (error as Error).message });
    }

    logger.info(`ELB scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async checkInsecureTargetGroups(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    let marker: string | undefined;
    const insecure: { name: string; arn: string; protocol: string }[] = [];

    try {
      do {
        const result = await retry(() =>
          this.client.elbv2.send(new DescribeTargetGroupsCommand({ Marker: marker, PageSize: 400 }))
        );
        for (const tg of result.TargetGroups ?? []) {
          const protocol = tg.Protocol ?? '';
          // Backend HTTP/TCP targets carry traffic between LB and instances unencrypted.
          if (protocol === 'HTTP' || protocol === 'TCP') {
            insecure.push({
              name: tg.TargetGroupName ?? 'Unknown',
              arn: tg.TargetGroupArn ?? '',
              protocol,
            });
          }
        }
        marker = result.NextMarker;
      } while (marker);
    } catch { return findings; }

    for (const tg of insecure) {
      findings.push(this.emit(
        'elb_target_group_insecure_backend_protocol',
        { resourceId: `${tg.arn}::insecure-backend`, targetGroupName: tg.name, targetGroupArn: tg.arn, protocol: tg.protocol },
        {
          message: `Target group "${tg.name}" forwards traffic to backends using ${tg.protocol}. ` +
            `Traffic between the load balancer and the targets is unencrypted, even if the listener uses TLS.`,
          remediation: `Switch the target group to HTTPS (or TLS) and configure the targets to terminate TLS, then update via: ` +
            `aws elbv2 modify-target-group --target-group-arn ${tg.arn} --protocol HTTPS`,
        }
      ));
    }
    return findings;
  }

  private async listAllLoadBalancers(): Promise<LoadBalancer[]> {
    const lbs: LoadBalancer[] = [];
    let marker: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.elbv2.send(new DescribeLoadBalancersCommand({ Marker: marker, PageSize: 400 }))
        );
        lbs.push(...(result.LoadBalancers ?? []));
        marker = result.NextMarker;
      } while (marker);
    } catch { /* no ELBs or no permission */ }
    return lbs;
  }

  private async scanLoadBalancer(lb: LoadBalancer): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const name  = lb.LoadBalancerName ?? 'Unknown';
    const arn   = lb.LoadBalancerArn  ?? '';
    const type  = lb.Type ?? 'application';
    const scheme = lb.Scheme ?? '';

    // Fetch listeners and attributes in parallel
    const [listenersResult, attrsResult] = await Promise.allSettled([
      retry(() => this.client.elbv2.send(new DescribeListenersCommand({ LoadBalancerArn: arn }))),
      retry(() => this.client.elbv2.send(new DescribeLoadBalancerAttributesCommand({ LoadBalancerArn: arn }))),
    ]);

    const listenersOk = listenersResult.status  === 'fulfilled';
    const attrsOk     = attrsResult.status === 'fulfilled';
    const listeners  = listenersResult.status  === 'fulfilled' ? (listenersResult.value.Listeners  ?? []) : [];
    const attributes = attrsResult.status === 'fulfilled' ? (attrsResult.value.Attributes ?? []) : [];

    const attrMap = Object.fromEntries(attributes.map(a => [a.Key, a.Value]));

    // 1. Access logging disabled
    if (attrMap['access_logs.s3.enabled'] !== 'true') {
      findings.push(this.emit(
        'elbv2_logging_enabled',
        { resourceId: `${arn}::access-logs`, lbName: name, lbArn: arn, lbType: type, scheme },
        {
          message: `${type.toUpperCase()} load balancer "${name}" does not have access logs enabled. ` +
            `Access logs are required for security analysis, compliance (PCI 10.2), and incident response.`,
          remediation: `Enable access logs: aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${arn} ` +
            `--attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<your-log-bucket>`,
        }
      ));
    }

    // 2. Deletion protection disabled
    if (attrMap['deletion_protection.enabled'] !== 'true') {
      findings.push(this.emit(
        'elbv2_deletion_protection',
        { resourceId: `${arn}::deletion-protection`, lbName: name, lbArn: arn, scheme },
        {
          message: `${type.toUpperCase()} load balancer "${name}" has deletion protection disabled. ` +
            `This allows accidental or malicious deletion of a production load balancer.`,
          remediation: `Enable deletion protection: aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${arn} ` +
            `--attributes Key=deletion_protection.enabled,Value=true`,
        }
      ));
    }

    // 3. HTTP listener without redirect to HTTPS (internet-facing only)
    if (scheme === 'internet-facing') {
      const httpListeners = listeners.filter(l => l.Protocol === 'HTTP');
      for (const listener of httpListeners) {
        const hasRedirect = (listener.DefaultActions ?? []).some(
          a => a.Type === 'redirect' && a.RedirectConfig?.Protocol === 'HTTPS'
        );
        if (!hasRedirect) {
          findings.push(this.emit(
            'elbv2_ssl_listeners',
            {
              resourceId:  `${arn}::http-no-redirect::${listener.Port}`,
              lbName:      name,
              lbArn:       arn,
              listenerArn: listener.ListenerArn,
              port:        listener.Port,
            },
            {
              message: `Internet-facing load balancer "${name}" has an HTTP listener on port ${listener.Port} ` +
                `that does not redirect traffic to HTTPS. Data in transit is unencrypted.`,
              remediation: `Add a redirect action to the HTTP listener: ` +
                `aws elbv2 modify-listener --listener-arn ${listener.ListenerArn} ` +
                `--default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'`,
            }
          ));
        }
      }

      // 4. Weak TLS policy on HTTPS listeners
      const httpsListeners = listeners.filter(l => l.Protocol === 'HTTPS');
      for (const listener of httpsListeners) {
        if (listener.SslPolicy && WEAK_SSL_POLICIES.has(listener.SslPolicy)) {
          findings.push(this.emit(
            'elbv2_insecure_ssl_ciphers',
            {
              resourceId:  `${arn}::weak-tls::${listener.Port}`,
              lbName:      name,
              lbArn:       arn,
              listenerArn: listener.ListenerArn,
              sslPolicy:   listener.SslPolicy,
            },
            {
              message: `HTTPS listener on "${name}" (port ${listener.Port}) uses SSL policy "${listener.SslPolicy}" ` +
                `which supports weak ciphers or TLS versions below 1.2.`,
              remediation: `Update to a modern TLS policy: aws elbv2 modify-listener --listener-arn ${listener.ListenerArn} ` +
                `--ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06`,
            }
          ));
        }
      }
    }

    // 5. Not enabled in enough availability zones
    const azs = (lb.AvailabilityZones ?? []).map(az => az.ZoneName ?? '').filter(z => z !== '');
    if (azs.length < MIN_AZS) {
      findings.push(this.emit(
        'elbv2_is_in_multiple_az',
        { resourceId: `${arn}::multi-az`, lbName: name, lbArn: arn, lbType: type, availabilityZones: azs },
        {
          message: `${type.toUpperCase()} load balancer "${name}" is enabled in only ${azs.length} availability zone(s)` +
            `${azs.length ? ` (${azs.join(', ')})` : ''}, below the recommended minimum of ${MIN_AZS}. ` +
            `An availability zone outage would take the load balancer offline.`,
          remediation: `Add a subnet in a second availability zone: aws elbv2 set-subnets --load-balancer-arn ${arn} ` +
            `--subnets <subnet-in-az-a> <subnet-in-az-b>`,
        }
      ));
    }

    // 6. Cross-zone load balancing disabled (NLB/GLB only; always on for ALB)
    if (type !== 'application' && attrsOk && attrMap['load_balancing.cross_zone.enabled'] !== 'true') {
      findings.push(this.emit(
        'elbv2_cross_zone_load_balancing_enabled',
        { resourceId: `${arn}::cross-zone`, lbName: name, lbArn: arn, lbType: type },
        {
          message: `${type.toUpperCase()} load balancer "${name}" does not have cross-zone load balancing enabled. ` +
            `Traffic can concentrate on targets in a single availability zone, causing hot spots and uneven failover.`,
          remediation: `Enable cross-zone load balancing: aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${arn} ` +
            `--attributes Key=load_balancing.cross_zone.enabled,Value=true`,
        }
      ));
    }

    // 7. No listeners configured (skip if listener discovery failed)
    if (listenersOk && listeners.length === 0) {
      findings.push(this.emit(
        'elbv2_listeners_underneath',
        { resourceId: `${arn}::no-listeners`, lbName: name, lbArn: arn, lbType: type },
        {
          message: `${type.toUpperCase()} load balancer "${name}" has no listeners configured. ` +
            `It cannot accept connections, so services behind its DNS endpoint are unreachable.`,
          remediation: `Add a listener (prefer HTTPS on 443): aws elbv2 create-listener --load-balancer-arn ${arn} ` +
            `--protocol HTTPS --port 443 --certificates CertificateArn=<acm-cert-arn> ` +
            `--default-actions Type=forward,TargetGroupArn=<target-group-arn>`,
        }
      ));
    }

    // 8. ALB-specific attribute checks: invalid header handling and desync mitigation
    if (type === 'application' && attrsOk) {
      const dropInvalidHeaders = attrMap['routing.http.drop_invalid_header_fields.enabled'];
      if (dropInvalidHeaders !== 'true') {
        findings.push(this.emit(
          'elbv2_alb_drop_invalid_header_fields_enabled',
          { resourceId: `${arn}::drop-invalid-headers`, lbName: name, lbArn: arn, scheme },
          {
            message: `ALB "${name}" is not configured to drop invalid HTTP header fields. ` +
              `Non-RFC-compliant headers are forwarded to targets, enabling HTTP desync (request smuggling) attacks.`,
            remediation: `Drop invalid header fields: aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${arn} ` +
              `--attributes Key=routing.http.drop_invalid_header_fields.enabled,Value=true`,
          }
        ));
      }

      const desyncMode = attrMap['routing.http.desync_mitigation_mode'] ?? '';
      if (desyncMode !== 'strictest' && desyncMode !== 'defensive' && dropInvalidHeaders === 'false') {
        findings.push(this.emit(
          'elbv2_desync_mitigation_mode',
          { resourceId: `${arn}::desync-mitigation`, lbName: name, lbArn: arn, desyncMitigationMode: desyncMode },
          {
            message: `ALB "${name}" has desync mitigation mode set to "${desyncMode}" instead of defensive/strictest, ` +
              `and does not drop invalid header fields. It is exposed to HTTP request smuggling.`,
            remediation: `Set a strict desync mitigation mode: aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${arn} ` +
              `--attributes Key=routing.http.desync_mitigation_mode,Value=strictest`,
          }
        ));
      }
    }

    // 9. ALB without a WAF web ACL
    if (type === 'application') {
      findings.push(...(await this.checkAlbWafAcl(name, arn, scheme)));
    }

    // 10. NLB without TLS termination (skip if listener discovery failed)
    if (type === 'network' && listenersOk && !listeners.some(l => l.Protocol === 'TLS')) {
      findings.push(this.emit(
        'elbv2_nlb_tls_termination_enabled',
        { resourceId: `${arn}::nlb-tls-termination`, lbName: name, lbArn: arn, scheme },
        {
          message: `NLB "${name}" has no TLS listener, so it does not terminate TLS connections. ` +
            `Encryption is left to backend targets, where it may be inconsistent or absent.`,
          remediation: `Add a TLS listener: aws elbv2 create-listener --load-balancer-arn ${arn} --protocol TLS --port 443 ` +
            `--ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 --certificates CertificateArn=<acm-cert-arn> ` +
            `--default-actions Type=forward,TargetGroupArn=<target-group-arn>`,
        }
      ));
    }

    // 11. HTTPS/TLS listeners without a post-quantum TLS policy (skip if listener discovery failed)
    if (listenersOk) {
      const tlsListeners = listeners.filter(l => l.Protocol === 'HTTPS' || l.Protocol === 'TLS');
      const nonPq = tlsListeners.filter(l => !PQ_TLS_POLICIES.has(l.SslPolicy ?? ''));
      if (tlsListeners.length > 0 && nonPq.length > 0) {
        const nonPqDesc = nonPq.map(l => `${l.Protocol}:${l.Port} (${l.SslPolicy ?? 'none'})`).join(', ');
        findings.push(this.emit(
          'elbv2_listener_pqc_tls_enabled',
          {
            resourceId: `${arn}::pqc-tls`,
            lbName: name,
            lbArn: arn,
            lbType: type,
            nonPqListeners: nonPq.map(l => ({ protocol: l.Protocol, port: l.Port, sslPolicy: l.SslPolicy ?? null })),
          },
          {
            message: `${type.toUpperCase()} load balancer "${name}" has HTTPS/TLS listener(s) without a post-quantum ` +
              `TLS policy: ${nonPqDesc}. Recorded traffic is exposed to harvest-now-decrypt-later attacks.`,
            remediation: `Switch listeners to a post-quantum TLS policy: aws elbv2 modify-listener ` +
              `--listener-arn <listener-arn> --ssl-policy ELBSecurityPolicy-TLS13-1-2-PQ-2025-09`,
          }
        ));
      }
    }

    // 12. Internet-facing with a security group open to the world
    if (scheme === 'internet-facing' && (lb.SecurityGroups ?? []).length > 0) {
      try {
        const publicSg = await this.getPublicSecurityGroup(lb.SecurityGroups ?? []);
        if (publicSg) {
          findings.push(this.emit(
            'elbv2_internet_facing',
            {
              resourceId: `${arn}::internet-facing`,
              lbName: name,
              lbArn: arn,
              lbType: type,
              dns: lb.DNSName ?? null,
              publicSecurityGroup: publicSg,
            },
            {
              message: `${type.toUpperCase()} load balancer "${name}" is internet-facing (${lb.DNSName ?? 'no DNS'}) and ` +
                `its security group ${publicSg} allows inbound TCP from 0.0.0.0/0 or ::/0, so it is reachable from anywhere.`,
              remediation: `Restrict inbound rules on security group ${publicSg} to trusted CIDRs, or recreate the ` +
                `load balancer with an internal scheme if public access is not required.`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to evaluate security groups for load balancer ${name}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  /** Returns the id of the first attached security group open to the world over TCP, or null. */
  private async getPublicSecurityGroup(groupIds: string[]): Promise<string | null> {
    const result: any = await retry(() =>
      this.client.ec2.send(new DescribeSecurityGroupsCommand({ GroupIds: groupIds }))
    );
    for (const sg of result.SecurityGroups ?? []) {
      for (const rule of sg.IpPermissions ?? []) {
        const protocol = rule.IpProtocol ?? '';
        if (protocol !== '-1' && protocol !== 'tcp') continue;
        const openV4 = (rule.IpRanges ?? []).some((r: any) => r.CidrIp === '0.0.0.0/0');
        const openV6 = (rule.Ipv6Ranges ?? []).some((r: any) => r.CidrIpv6 === '::/0');
        if (openV4 || openV6) return sg.GroupId ?? '';
      }
    }
    return null;
  }

  private async checkAlbWafAcl(name: string, arn: string, scheme: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result: any = await retry(() =>
        this.client.wafv2.send(new GetWebACLForResourceCommand({ ResourceArn: arn }))
      );
      if (!result.WebACL) {
        findings.push(this.emit(
          'elbv2_waf_acl_attached',
          { resourceId: `${arn}::waf-acl`, lbName: name, lbArn: arn, scheme },
          {
            message: `ALB "${name}" does not have an AWS WAF web ACL attached. ` +
              `Layer 7 traffic reaches the targets unfiltered, exposing them to injection, bots and credential stuffing.`,
            remediation: `Associate a WAFv2 web ACL: aws wafv2 associate-web-acl --web-acl-arn <web-acl-arn> --resource-arn ${arn}`,
          }
        ));
      }
    } catch (error) {
      // No wafv2 permission or transient error: skip rather than emit a false positive
      logger.debug(`Failed to check WAF web ACL for ALB ${name}`, { error: (error as Error).message });
    }
    return findings;
  }

  // ---------------------------------------------------------------------------
  // Classic (ELB v1) load balancers
  // ---------------------------------------------------------------------------

  private async scanClassicLoadBalancers(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const clbs = await this.listAllClassicLoadBalancers();
    logger.info(`ELB: scanning ${clbs.length} Classic load balancer(s)`);
    if (clbs.length === 0) return findings;

    let accountId = '';
    try {
      accountId = await this.client.getAccountId();
    } catch { /* ARN falls back to an empty account field */ }

    // ACM certificate types are only needed when a CLB terminates TLS with a certificate
    const needsAcm = clbs.some(clb =>
      (clb.ListenerDescriptions ?? []).some((ld: any) =>
        SECURE_CLASSIC_PROTOCOLS.includes(ld?.Listener?.Protocol ?? '') && ld?.Listener?.SSLCertificateId
      )
    );
    const acmCerts = needsAcm ? await this.getAcmCertificateTypes() : null;

    await Promise.allSettled(
      clbs.map(clb =>
        this.scanClassicLoadBalancer(clb, accountId, acmCerts).then(f => findings.push(...f))
      )
    );
    return findings;
  }

  private async listAllClassicLoadBalancers(): Promise<any[]> {
    const clbs: any[] = [];
    let marker: string | undefined;
    try {
      do {
        const result: any = await retry(() =>
          this.elbClassic.send(new DescribeClassicLoadBalancersCommand({ Marker: marker, PageSize: 400 }))
        );
        clbs.push(...(result.LoadBalancerDescriptions ?? []));
        marker = result.NextMarker;
      } while (marker);
    } catch { /* no Classic ELBs or no permission */ }
    return clbs;
  }

  private async scanClassicLoadBalancer(
    clb: any,
    accountId: string,
    acmCerts: Map<string, string> | null
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const name   = clb.LoadBalancerName ?? 'Unknown';
    const dns    = clb.DNSName ?? '';
    const scheme = clb.Scheme ?? '';
    const arn    = `arn:aws:elasticloadbalancing:${this.client.getRegion()}:${accountId}:loadbalancer/${name}`;
    const listeners: any[] = clb.ListenerDescriptions ?? [];

    // Attribute-based checks (connection draining, cross-zone, access logs, desync mode)
    let attrs: any = null;
    try {
      const result: any = await retry(() =>
        this.elbClassic.send(new DescribeClassicLoadBalancerAttributesCommand({ LoadBalancerName: name }))
      );
      attrs = result.LoadBalancerAttributes ?? null;
    } catch (error) {
      logger.debug(`Failed to describe attributes for Classic Load Balancer ${name}`, { error: (error as Error).message });
    }

    if (attrs) {
      // 1. Connection draining disabled
      if (!attrs.ConnectionDraining?.Enabled) {
        findings.push(this.emit(
          'elb_connection_draining_enabled',
          { resourceId: `${arn}::connection-draining`, lbName: name, lbType: 'classic', scheme },
          {
            message: `Classic Load Balancer "${name}" does not have connection draining enabled. ` +
              `Deregistering or unhealthy instances drop in-flight requests instead of completing them.`,
            remediation: `Enable connection draining: aws elb modify-load-balancer-attributes --load-balancer-name ${name} ` +
              `--load-balancer-attributes '{"ConnectionDraining":{"Enabled":true}}'`,
          }
        ));
      }

      // 2. Cross-zone load balancing disabled
      if (!attrs.CrossZoneLoadBalancing?.Enabled) {
        findings.push(this.emit(
          'elb_cross_zone_load_balancing_enabled',
          { resourceId: `${arn}::cross-zone`, lbName: name, lbType: 'classic', scheme },
          {
            message: `Classic Load Balancer "${name}" does not have cross-zone load balancing enabled. ` +
              `Traffic can concentrate on instances in a single availability zone, causing hot spots and uneven failover.`,
            remediation: `Enable cross-zone load balancing: aws elb modify-load-balancer-attributes --load-balancer-name ${name} ` +
              `--load-balancer-attributes '{"CrossZoneLoadBalancing":{"Enabled":true}}'`,
          }
        ));
      }

      // 3. Access logging disabled
      if (!attrs.AccessLog?.Enabled) {
        findings.push(this.emit(
          'elb_logging_enabled',
          { resourceId: `${arn}::access-logs`, lbName: name, lbType: 'classic', scheme },
          {
            message: `Classic Load Balancer "${name}" does not have access logs configured. ` +
              `Edge traffic is invisible to security analysis, forensics and incident response.`,
            remediation: `Enable access logs: aws elb modify-load-balancer-attributes --load-balancer-name ${name} ` +
              `--load-balancer-attributes AccessLog={Enabled=true,S3BucketName=<your-log-bucket>}`,
          }
        ));
      }

      // 4. Desync mitigation mode not defensive/strictest
      const desyncMode = ((attrs.AdditionalAttributes ?? [])
        .find((a: any) => a.Key === 'elb.http.desyncmitigationmode') ?? {}).Value ?? '';
      if (desyncMode !== 'defensive' && desyncMode !== 'strictest') {
        findings.push(this.emit(
          'elb_desync_mitigation_mode',
          { resourceId: `${arn}::desync-mitigation`, lbName: name, lbType: 'classic', desyncMitigationMode: desyncMode || null },
          {
            message: `Classic Load Balancer "${name}" has desync mitigation mode set to ` +
              `"${desyncMode || 'not configured'}" instead of defensive or strictest. ` +
              `It is exposed to HTTP request smuggling.`,
            remediation: `Set a strict desync mitigation mode: aws elb modify-load-balancer-attributes --load-balancer-name ${name} ` +
              `--load-balancer-attributes '{"AdditionalAttributes":[{"Key":"elb.http.desyncmitigationmode","Value":"defensive"}]}'`,
          }
        ));
      }
    }

    // 5. Internet-facing scheme
    if (scheme === 'internet-facing') {
      findings.push(this.emit(
        'elb_internet_facing',
        { resourceId: `${arn}::internet-facing`, lbName: name, lbType: 'classic', dns, scheme },
        {
          message: `Classic Load Balancer "${name}" is internet-facing (${dns || 'no DNS'}). ` +
            `Its backends are exposed to the internet through a public DNS name.`,
          remediation: `If public access is not required, recreate the load balancer with an internal scheme. ` +
            `Otherwise restrict its security groups to trusted CIDRs and enforce TLS.`,
        }
      ));
    }

    // 6. Not in enough availability zones
    const azs: string[] = clb.AvailabilityZones ?? [];
    if (azs.length < MIN_AZS) {
      findings.push(this.emit(
        'elb_is_in_multiple_az',
        { resourceId: `${arn}::multi-az`, lbName: name, lbType: 'classic', availabilityZones: azs },
        {
          message: `Classic Load Balancer "${name}" is enabled in only ${azs.length} availability zone(s)` +
            `${azs.length ? ` (${azs.join(', ')})` : ''}, below the recommended minimum of ${MIN_AZS}. ` +
            `An availability zone outage would take the load balancer offline.`,
          remediation: `Attach a subnet in a second availability zone: aws elb attach-load-balancer-to-subnets ` +
            `--load-balancer-name ${name} --subnets <subnet-in-another-az>`,
        }
      ));
    }

    // 7. Unencrypted (non-HTTPS/SSL) listeners
    const insecureListeners = listeners.filter(
      (ld: any) => !SECURE_CLASSIC_PROTOCOLS.includes(ld?.Listener?.Protocol ?? '')
    );
    if (listeners.length > 0 && insecureListeners.length > 0) {
      const desc = insecureListeners
        .map((ld: any) => `${ld?.Listener?.Protocol ?? 'UNKNOWN'}:${ld?.Listener?.LoadBalancerPort ?? '?'}`)
        .join(', ');
      findings.push(this.emit(
        'elb_ssl_listeners',
        {
          resourceId: `${arn}::unencrypted-listeners`,
          lbName: name,
          lbType: 'classic',
          insecureListeners: insecureListeners.map((ld: any) => ({
            protocol: ld?.Listener?.Protocol ?? null,
            port: ld?.Listener?.LoadBalancerPort ?? null,
          })),
        },
        {
          message: `Classic Load Balancer "${name}" has non-encrypted listener(s): ${desc}. ` +
            `Traffic between clients and the load balancer is in plaintext.`,
          remediation: `Replace plaintext listeners with HTTPS/SSL listeners backed by an ACM certificate, then remove ` +
            `the old ones: aws elb delete-load-balancer-listeners --load-balancer-name ${name} --load-balancer-ports <port>`,
        }
      ));
    }

    // 8. HTTPS listeners without the secure TLS 1.2 policy
    const weakHttpsListeners = listeners.filter(
      (ld: any) =>
        ld?.Listener?.Protocol === 'HTTPS' &&
        !(ld?.PolicyNames ?? []).includes(SECURE_CLASSIC_SSL_POLICY)
    );
    if (weakHttpsListeners.length > 0) {
      const ports = weakHttpsListeners.map((ld: any) => ld?.Listener?.LoadBalancerPort ?? '?').join(', ');
      findings.push(this.emit(
        'elb_insecure_ssl_ciphers',
        {
          resourceId: `${arn}::insecure-ssl-ciphers`,
          lbName: name,
          lbType: 'classic',
          ports: weakHttpsListeners.map((ld: any) => ld?.Listener?.LoadBalancerPort ?? null),
        },
        {
          message: `Classic Load Balancer "${name}" has HTTPS listener(s) on port(s) ${ports} that do not use the ` +
            `${SECURE_CLASSIC_SSL_POLICY} security policy, so legacy protocols or weak ciphers may be negotiated.`,
          remediation: `Apply the TLS 1.2-only policy: aws elb set-load-balancer-policies-of-listener ` +
            `--load-balancer-name ${name} --load-balancer-port <port> --policy-names ${SECURE_CLASSIC_SSL_POLICY}`,
        }
      ));
    }

    // 9. HTTPS/SSL listener certificates not issued by ACM (skipped when ACM inventory is unavailable)
    if (acmCerts) {
      const nonAcmListeners = listeners.filter((ld: any) => {
        const l = ld?.Listener ?? {};
        if (!SECURE_CLASSIC_PROTOCOLS.includes(l.Protocol ?? '') || !l.SSLCertificateId) return false;
        return acmCerts.get(l.SSLCertificateId) !== 'AMAZON_ISSUED';
      });
      if (nonAcmListeners.length > 0) {
        const ports = nonAcmListeners.map((ld: any) => ld?.Listener?.LoadBalancerPort ?? '?').join(', ');
        findings.push(this.emit(
          'elb_ssl_listeners_use_acm_certificate',
          {
            resourceId: `${arn}::non-acm-certificate`,
            lbName: name,
            lbType: 'classic',
            listeners: nonAcmListeners.map((ld: any) => ({
              port: ld?.Listener?.LoadBalancerPort ?? null,
              certificateArn: ld?.Listener?.SSLCertificateId ?? null,
            })),
          },
          {
            message: `Classic Load Balancer "${name}" has HTTPS/SSL listener(s) on port(s) ${ports} using certificates ` +
              `that are not Amazon-issued ACM certificates, so rotation and renewal are not managed by AWS.`,
            remediation: `Attach an Amazon-issued ACM certificate: aws elb set-load-balancer-listener-ssl-certificate ` +
              `--load-balancer-name ${name} --load-balancer-port <port> --ssl-certificate-id <acm-certificate-arn>`,
          }
        ));
      }
    }

    return findings;
  }

  /** Map of ACM certificate ARN -> certificate type (AMAZON_ISSUED | IMPORTED | PRIVATE), or null on failure. */
  private async getAcmCertificateTypes(): Promise<Map<string, string> | null> {
    const certTypes = new Map<string, string>();
    let nextToken: string | undefined;
    try {
      do {
        const result: any = await retry(() =>
          this.client.acm.send(new ListCertificatesCommand({
            NextToken: nextToken,
            // Without the keyTypes filter ACM only returns RSA_2048 certificates
            Includes: {
              keyTypes: [
                'RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096',
                'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1',
              ],
            },
          }))
        );
        for (const cert of result.CertificateSummaryList ?? []) {
          if (cert.CertificateArn) certTypes.set(cert.CertificateArn, cert.Type ?? '');
        }
        nextToken = result.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list ACM certificates for the ELB certificate check', { error: (error as Error).message });
      return null;
    }
    return certTypes;
  }
}

export default ELBScanner;
