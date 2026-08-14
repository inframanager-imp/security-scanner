import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeListenersCommand,
  DescribeLoadBalancerAttributesCommand,
  DescribeTargetGroupsCommand,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import {
  ElasticLoadBalancingClient,
  DescribeLoadBalancersCommand as DescribeClassicLoadBalancersCommand,
  DescribeLoadBalancerAttributesCommand as DescribeClassicLoadBalancerAttributesCommand,
} from '@aws-sdk/client-elastic-load-balancing';
import { WAFV2Client, GetWebACLForResourceCommand } from '@aws-sdk/client-wafv2';
import { EC2Client, DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import { ACMClient, ListCertificatesCommand } from '@aws-sdk/client-acm';

import { ELBScanner } from '../../../src/scanners/elb';

const elbv2Mock = mockClient(ElasticLoadBalancingV2Client);
const elbClassicMock = mockClient(ElasticLoadBalancingClient);
const wafv2Mock = mockClient(WAFV2Client);
const ec2Mock = mockClient(EC2Client);
const acmMock = mockClient(ACMClient);

function makeAwsClient() {
  return {
    elbv2: new ElasticLoadBalancingV2Client({ region: 'us-east-1', credentials: {} }),
    ec2: new EC2Client({ region: 'us-east-1', credentials: {} }),
    wafv2: new WAFV2Client({ region: 'us-east-1', credentials: {} }),
    acm: new ACMClient({ region: 'us-east-1', credentials: {} }),
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
    getAccountId: async () => '123456789012',
    getRegion: () => 'us-east-1',
  } as any;
}

/** Default happy-path stubs so scans that don't target a specific check don't throw. */
function stubDefaults() {
  elbv2Mock.on(DescribeLoadBalancersCommand).resolves({ LoadBalancers: [] });
  elbv2Mock.on(DescribeTargetGroupsCommand).resolves({ TargetGroups: [] });
  elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({ LoadBalancerDescriptions: [] });
}

describe('ELBScanner', () => {
  beforeEach(() => {
    elbv2Mock.reset();
    elbClassicMock.reset();
    wafv2Mock.reset();
    ec2Mock.reset();
    acmMock.reset();
  });

  describe('scan', () => {
    it('returns no findings when there are no ALBs/NLBs and no Classic ELBs', async () => {
      stubDefaults();
      const scanner = new ELBScanner(makeAwsClient());

      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });

    it('flags an internet-facing ALB missing access logs, deletion protection and a WAF ACL', async () => {
      const arn = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123';

      elbv2Mock.on(DescribeLoadBalancersCommand).resolves({
        LoadBalancers: [
          {
            LoadBalancerName: 'my-alb',
            LoadBalancerArn: arn,
            Type: 'application',
            Scheme: 'internet-facing',
            AvailabilityZones: [{ ZoneName: 'us-east-1a' }, { ZoneName: 'us-east-1b' }],
            SecurityGroups: [],
          },
        ],
      });
      elbv2Mock.on(DescribeListenersCommand).resolves({
        Listeners: [
          { ListenerArn: `${arn}/listener/https`, Protocol: 'HTTPS', Port: 443, SslPolicy: 'ELBSecurityPolicy-TLS13-1-2-2021-06' },
        ],
      });
      elbv2Mock.on(DescribeLoadBalancerAttributesCommand).resolves({
        Attributes: [
          { Key: 'access_logs.s3.enabled', Value: 'false' },
          { Key: 'deletion_protection.enabled', Value: 'false' },
          { Key: 'routing.http.drop_invalid_header_fields.enabled', Value: 'true' },
          { Key: 'routing.http.desync_mitigation_mode', Value: 'strictest' },
        ],
      });
      elbv2Mock.on(DescribeTargetGroupsCommand).resolves({ TargetGroups: [] });
      elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({ LoadBalancerDescriptions: [] });
      wafv2Mock.on(GetWebACLForResourceCommand).resolves({ WebACL: undefined });

      const scanner = new ELBScanner(makeAwsClient());
      const findings = await scanner.scan();

      const checkIds = findings.map(f => f.checkId);
      expect(checkIds).toContain('elbv2_logging_enabled');
      expect(checkIds).toContain('elbv2_deletion_protection');
      expect(checkIds).toContain('elbv2_waf_acl_attached');

      const loggingFinding = findings.find(f => f.checkId === 'elbv2_logging_enabled');
      expect(loggingFinding?.service).toBe('ELB');
      expect(loggingFinding?.evidence).toMatchObject({
        lbName: 'my-alb',
        lbArn: arn,
        lbType: 'application',
        scheme: 'internet-facing',
      });
    });

    it('flags an internet-facing ALB with an HTTP listener that does not redirect to HTTPS', async () => {
      const arn = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/http-alb/xyz789';

      elbv2Mock.on(DescribeLoadBalancersCommand).resolves({
        LoadBalancers: [
          {
            LoadBalancerName: 'http-alb',
            LoadBalancerArn: arn,
            Type: 'application',
            Scheme: 'internet-facing',
            AvailabilityZones: [{ ZoneName: 'us-east-1a' }, { ZoneName: 'us-east-1b' }],
            SecurityGroups: [],
          },
        ],
      });
      elbv2Mock.on(DescribeListenersCommand).resolves({
        Listeners: [
          {
            ListenerArn: `${arn}/listener/http`,
            Protocol: 'HTTP',
            Port: 80,
            DefaultActions: [{ Type: 'forward' }],
          },
        ],
      });
      elbv2Mock.on(DescribeLoadBalancerAttributesCommand).resolves({
        Attributes: [
          { Key: 'access_logs.s3.enabled', Value: 'true' },
          { Key: 'deletion_protection.enabled', Value: 'true' },
          { Key: 'routing.http.drop_invalid_header_fields.enabled', Value: 'true' },
          { Key: 'routing.http.desync_mitigation_mode', Value: 'strictest' },
        ],
      });
      elbv2Mock.on(DescribeTargetGroupsCommand).resolves({ TargetGroups: [] });
      elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({ LoadBalancerDescriptions: [] });
      wafv2Mock.on(GetWebACLForResourceCommand).resolves({ WebACL: { Name: 'my-acl' } });

      const scanner = new ELBScanner(makeAwsClient());
      const findings = await scanner.scan();

      const redirectFinding = findings.find(f => f.checkId === 'elbv2_ssl_listeners');
      expect(redirectFinding).toBeDefined();
      expect(redirectFinding?.evidence).toMatchObject({
        lbName: 'http-alb',
        port: 80,
      });
      // WAF ACL is attached, so that check must not fire
      expect(findings.map(f => f.checkId)).not.toContain('elbv2_waf_acl_attached');
    });

    it('flags target groups whose backend protocol is unencrypted (HTTP/TCP)', async () => {
      stubDefaults();
      elbv2Mock.on(DescribeTargetGroupsCommand).resolves({
        TargetGroups: [
          { TargetGroupName: 'tg-http', TargetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-http/1', Protocol: 'HTTP' },
          { TargetGroupName: 'tg-https', TargetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-https/2', Protocol: 'HTTPS' },
        ],
      });

      const scanner = new ELBScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe('elb_target_group_insecure_backend_protocol');
      expect(findings[0].evidence).toMatchObject({ targetGroupName: 'tg-http', protocol: 'HTTP' });
    });

    it('paginates DescribeTargetGroups across multiple pages via NextMarker', async () => {
      elbv2Mock.on(DescribeLoadBalancersCommand).resolves({ LoadBalancers: [] });
      elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({ LoadBalancerDescriptions: [] });

      elbv2Mock
        .on(DescribeTargetGroupsCommand)
        .resolvesOnce({
          TargetGroups: [
            { TargetGroupName: 'tg-page1', TargetGroupArn: 'arn:tg-page1', Protocol: 'TCP' },
          ],
          NextMarker: 'page2',
        })
        .resolvesOnce({
          TargetGroups: [
            { TargetGroupName: 'tg-page2', TargetGroupArn: 'arn:tg-page2', Protocol: 'HTTP' },
          ],
        });

      const scanner = new ELBScanner(makeAwsClient());
      const findings = await scanner.scan();

      const names = findings
        .filter(f => f.checkId === 'elb_target_group_insecure_backend_protocol')
        .map(f => f.evidence.targetGroupName)
        .sort();
      expect(names).toEqual(['tg-page1', 'tg-page2']);
      expect(elbv2Mock.commandCalls(DescribeTargetGroupsCommand)).toHaveLength(2);
    });

    it('paginates DescribeLoadBalancers across multiple pages via NextMarker', async () => {
      elbv2Mock
        .on(DescribeLoadBalancersCommand)
        .resolvesOnce({
          LoadBalancers: [
            {
              LoadBalancerName: 'lb-page1',
              LoadBalancerArn: 'arn:lb-page1',
              Type: 'network',
              Scheme: 'internal',
              AvailabilityZones: [{ ZoneName: 'us-east-1a' }, { ZoneName: 'us-east-1b' }],
            },
          ],
          NextMarker: 'page2',
        })
        .resolvesOnce({
          LoadBalancers: [
            {
              LoadBalancerName: 'lb-page2',
              LoadBalancerArn: 'arn:lb-page2',
              Type: 'network',
              Scheme: 'internal',
              AvailabilityZones: [{ ZoneName: 'us-east-1a' }, { ZoneName: 'us-east-1b' }],
            },
          ],
        });
      elbv2Mock.on(DescribeListenersCommand).resolves({ Listeners: [{ Protocol: 'TLS', Port: 443, SslPolicy: 'ELBSecurityPolicy-TLS13-1-2-PQ-2025-09' }] });
      elbv2Mock.on(DescribeLoadBalancerAttributesCommand).resolves({
        Attributes: [{ Key: 'load_balancing.cross_zone.enabled', Value: 'true' }],
      });
      elbv2Mock.on(DescribeTargetGroupsCommand).resolves({ TargetGroups: [] });
      elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({ LoadBalancerDescriptions: [] });

      const scanner = new ELBScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(elbv2Mock.commandCalls(DescribeLoadBalancersCommand)).toHaveLength(2);
      const scannedLbNames = new Set(findings.map(f => f.evidence.lbName));
      expect(scannedLbNames.has('lb-page1')).toBe(true);
      expect(scannedLbNames.has('lb-page2')).toBe(true);
    });

    it('does not throw and returns gracefully when DescribeLoadBalancers rejects', async () => {
      elbv2Mock.on(DescribeLoadBalancersCommand).rejects(new Error('AccessDenied'));
      elbv2Mock.on(DescribeTargetGroupsCommand).resolves({ TargetGroups: [] });
      elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({ LoadBalancerDescriptions: [] });

      const scanner = new ELBScanner(makeAwsClient());

      await expect(scanner.scan()).resolves.toEqual([]);
    }, 15000);

    it('flags a Classic ELB that is internet-facing with plaintext listeners and no attributes available', async () => {
      elbv2Mock.on(DescribeLoadBalancersCommand).resolves({ LoadBalancers: [] });
      elbv2Mock.on(DescribeTargetGroupsCommand).resolves({ TargetGroups: [] });

      elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({
        LoadBalancerDescriptions: [
          {
            LoadBalancerName: 'my-classic-lb',
            DNSName: 'my-classic-lb.us-east-1.elb.amazonaws.com',
            Scheme: 'internet-facing',
            AvailabilityZones: ['us-east-1a'],
            ListenerDescriptions: [
              { Listener: { Protocol: 'HTTP', LoadBalancerPort: 80 } },
            ],
          },
        ],
      });
      // Attribute lookup fails -> attribute-based checks (1-4) are skipped gracefully
      elbClassicMock.on(DescribeClassicLoadBalancerAttributesCommand).rejects(new Error('AccessDenied'));

      const scanner = new ELBScanner(makeAwsClient());
      const findings = await scanner.scan();

      const checkIds = findings.map(f => f.checkId);
      expect(checkIds).toContain('elb_internet_facing');
      expect(checkIds).toContain('elb_is_in_multiple_az');
      expect(checkIds).toContain('elb_ssl_listeners');

      // Attribute-based checks must not appear since attrs fetch failed
      expect(checkIds).not.toContain('elb_connection_draining_enabled');
      expect(checkIds).not.toContain('elb_cross_zone_load_balancing_enabled');

      const internetFacingFinding = findings.find(f => f.checkId === 'elb_internet_facing');
      expect(internetFacingFinding?.service).toBe('ELB');
      expect(internetFacingFinding?.evidence).toMatchObject({
        lbName: 'my-classic-lb',
        lbType: 'classic',
        dns: 'my-classic-lb.us-east-1.elb.amazonaws.com',
      });
    }, 15000);

    it('returns no Classic ELB findings when there are none and no ALB/NLB findings when compliant', async () => {
      const arn = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/clean-nlb/def456';

      elbv2Mock.on(DescribeLoadBalancersCommand).resolves({
        LoadBalancers: [
          {
            LoadBalancerName: 'clean-nlb',
            LoadBalancerArn: arn,
            Type: 'network',
            Scheme: 'internal',
            AvailabilityZones: [{ ZoneName: 'us-east-1a' }, { ZoneName: 'us-east-1b' }],
          },
        ],
      });
      elbv2Mock.on(DescribeListenersCommand).resolves({
        Listeners: [
          { Protocol: 'TLS', Port: 443, SslPolicy: 'ELBSecurityPolicy-TLS13-1-2-PQ-2025-09' },
        ],
      });
      elbv2Mock.on(DescribeLoadBalancerAttributesCommand).resolves({
        Attributes: [
          { Key: 'access_logs.s3.enabled', Value: 'true' },
          { Key: 'deletion_protection.enabled', Value: 'true' },
          { Key: 'load_balancing.cross_zone.enabled', Value: 'true' },
        ],
      });
      elbv2Mock.on(DescribeTargetGroupsCommand).resolves({ TargetGroups: [] });
      elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({ LoadBalancerDescriptions: [] });

      const scanner = new ELBScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });

    it('flags an internet-facing ALB whose security group allows inbound traffic from 0.0.0.0/0', async () => {
      const arn = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/open-alb/pub123';

      elbv2Mock.on(DescribeLoadBalancersCommand).resolves({
        LoadBalancers: [
          {
            LoadBalancerName: 'open-alb',
            LoadBalancerArn: arn,
            Type: 'application',
            Scheme: 'internet-facing',
            AvailabilityZones: [{ ZoneName: 'us-east-1a' }, { ZoneName: 'us-east-1b' }],
            SecurityGroups: ['sg-public123'],
            DNSName: 'open-alb-123.us-east-1.elb.amazonaws.com',
          },
        ],
      });
      elbv2Mock.on(DescribeListenersCommand).resolves({
        Listeners: [
          { ListenerArn: `${arn}/listener/https`, Protocol: 'HTTPS', Port: 443, SslPolicy: 'ELBSecurityPolicy-TLS13-1-2-PQ-2025-09' },
        ],
      });
      elbv2Mock.on(DescribeLoadBalancerAttributesCommand).resolves({
        Attributes: [
          { Key: 'access_logs.s3.enabled', Value: 'true' },
          { Key: 'deletion_protection.enabled', Value: 'true' },
          { Key: 'routing.http.drop_invalid_header_fields.enabled', Value: 'true' },
          { Key: 'routing.http.desync_mitigation_mode', Value: 'strictest' },
        ],
      });
      elbv2Mock.on(DescribeTargetGroupsCommand).resolves({ TargetGroups: [] });
      elbClassicMock.on(DescribeClassicLoadBalancersCommand).resolves({ LoadBalancerDescriptions: [] });
      wafv2Mock.on(GetWebACLForResourceCommand).resolves({ WebACL: { Name: 'my-acl' } });
      ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
        SecurityGroups: [
          {
            GroupId: 'sg-public123',
            IpPermissions: [
              { IpProtocol: 'tcp', IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
            ],
          },
        ],
      });

      const scanner = new ELBScanner(makeAwsClient());
      const findings = await scanner.scan();

      const openFinding = findings.find(f => f.checkId === 'elbv2_internet_facing');
      expect(openFinding).toBeDefined();
      expect(openFinding?.evidence).toMatchObject({
        lbName: 'open-alb',
        publicSecurityGroup: 'sg-public123',
      });
    });
  });
});
