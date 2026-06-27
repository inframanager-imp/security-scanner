import {
  DescribeLoadBalancersCommand,
  DescribeListenersCommand,
  DescribeLoadBalancerAttributesCommand,
  DescribeTargetGroupsCommand,
  type LoadBalancer,
} from '@aws-sdk/client-elastic-load-balancing-v2';
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

export class ELBScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'ELB');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting ELB/ALB security scan...');

    const lbs = await this.listAllLoadBalancers();
    logger.info(`ELB: scanning ${lbs.length} load balancer(s)`);

    await Promise.allSettled(
      lbs.map(lb => this.scanLoadBalancer(lb).then(f => findings.push(...f)))
    );

    findings.push(...(await this.checkInsecureTargetGroups()));

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
      findings.push(this.createFinding(
        'Target Group Uses Unencrypted Backend Protocol',
        `Target group "${tg.name}" forwards traffic to backends using ${tg.protocol}. ` +
        `Traffic between the load balancer and the targets is unencrypted, even if the listener uses TLS.`,
        'MEDIUM',
        { resourceId: `${tg.arn}::insecure-backend`, targetGroupName: tg.name, targetGroupArn: tg.arn, protocol: tg.protocol },
        `Switch the target group to HTTPS (or TLS) and configure the targets to terminate TLS, then update via: ` +
        `aws elbv2 modify-target-group --target-group-arn ${tg.arn} --protocol HTTPS`,
        ['elb', 'encryption', 'backend-tls'],
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

    const listeners  = listenersResult.status  === 'fulfilled' ? (listenersResult.value.Listeners  ?? []) : [];
    const attributes = attrsResult.status === 'fulfilled' ? (attrsResult.value.Attributes ?? []) : [];

    const attrMap = Object.fromEntries(attributes.map(a => [a.Key, a.Value]));

    // 1. Access logging disabled
    if (attrMap['access_logs.s3.enabled'] !== 'true') {
      findings.push(this.createFinding(
        'Load Balancer Access Logging Disabled',
        `${type.toUpperCase()} load balancer "${name}" does not have access logs enabled. ` +
        `Access logs are required for security analysis, compliance (PCI 10.2), and incident response.`,
        'HIGH',
        { resourceId: `${arn}::access-logs`, lbName: name, lbArn: arn, lbType: type, scheme },
        `Enable access logs: aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${arn} ` +
        `--attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<your-log-bucket>`,
        ['elb', 'logging'],
      ));
    }

    // 2. Deletion protection disabled
    if (attrMap['deletion_protection.enabled'] !== 'true') {
      findings.push(this.createFinding(
        'Load Balancer Deletion Protection Disabled',
        `${type.toUpperCase()} load balancer "${name}" has deletion protection disabled. ` +
        `This allows accidental or malicious deletion of a production load balancer.`,
        'MEDIUM',
        { resourceId: `${arn}::deletion-protection`, lbName: name, lbArn: arn, scheme },
        `Enable deletion protection: aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${arn} ` +
        `--attributes Key=deletion_protection.enabled,Value=true`,
        ['elb', 'availability'],
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
          findings.push(this.createFinding(
            'Load Balancer HTTP Listener Without HTTPS Redirect',
            `Internet-facing load balancer "${name}" has an HTTP listener on port ${listener.Port} ` +
            `that does not redirect traffic to HTTPS. Data in transit is unencrypted.`,
            'HIGH',
            {
              resourceId:  `${arn}::http-no-redirect::${listener.Port}`,
              lbName:      name,
              lbArn:       arn,
              listenerArn: listener.ListenerArn,
              port:        listener.Port,
            },
            `Add a redirect action to the HTTP listener: ` +
            `aws elbv2 modify-listener --listener-arn ${listener.ListenerArn} ` +
            `--default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'`,
            ['elb', 'encryption', 'https'],
          ));
        }
      }

      // 4. Weak TLS policy on HTTPS listeners
      const httpsListeners = listeners.filter(l => l.Protocol === 'HTTPS');
      for (const listener of httpsListeners) {
        if (listener.SslPolicy && WEAK_SSL_POLICIES.has(listener.SslPolicy)) {
          findings.push(this.createFinding(
            'Load Balancer Uses Weak TLS Policy',
            `HTTPS listener on "${name}" (port ${listener.Port}) uses SSL policy "${listener.SslPolicy}" ` +
            `which supports weak ciphers or TLS versions below 1.2.`,
            'HIGH',
            {
              resourceId:  `${arn}::weak-tls::${listener.Port}`,
              lbName:      name,
              lbArn:       arn,
              listenerArn: listener.ListenerArn,
              sslPolicy:   listener.SslPolicy,
            },
            `Update to a modern TLS policy: aws elbv2 modify-listener --listener-arn ${listener.ListenerArn} ` +
            `--ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06`,
            ['elb', 'tls', 'encryption'],
          ));
        }
      }
    }

    return findings;
  }
}

export default ELBScanner;
