import {
  DescribeParametersCommand,
  GetParameterCommand,
  DescribeInstancePatchStatesCommand,
  DescribeInstanceInformationCommand,
} from '@aws-sdk/client-ssm';
import {
  DescribeInstancesCommand,
} from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Parameter name patterns that suggest secrets stored as plaintext
const SECRET_PATTERNS = [
  /password/i, /passwd/i, /secret/i, /apikey/i, /api[_-]key/i,
  /token/i, /credential/i, /private[_-]key/i, /access[_-]key/i,
  /auth/i, /db[_-]pass/i, /database[_-]pass/i,
];

function looksLikeSecret(name: string): boolean {
  return SECRET_PATTERNS.some(p => p.test(name));
}

// Confirmed-credential value prefixes (case-sensitive). Matching one of these
// means the parameter value is definitely a real secret, not a placeholder.
const CREDENTIAL_VALUE_PREFIXES: { label: string; test: (v: string) => boolean }[] = [
  { label: 'AWS access key', test: v => /^AKIA[0-9A-Z]{16}$/.test(v) || /^ASIA[0-9A-Z]{16}$/.test(v) },
  { label: 'GitHub token',   test: v => /^gh[pousr]_[A-Za-z0-9]{30,}$/.test(v) },
  { label: 'Slack token',    test: v => /^xox[abprs]-[A-Za-z0-9-]{10,}$/.test(v) },
  { label: 'OpenAI key',     test: v => /^sk-[A-Za-z0-9]{20,}$/.test(v) },
  { label: 'private key',    test: v => v.startsWith('-----BEGIN ') && v.includes('PRIVATE KEY') },
];

// How many suspicious params we'll actually fetch values for, to bound API/IAM cost
const MAX_PARAMS_TO_FETCH = 5;

export class SSMScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'SSM');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting SSM security scan...');

    await Promise.allSettled([
      this.checkPlaintextSecrets().then(f => findings.push(...f)),
      this.checkPatchCompliance().then(f => findings.push(...f)),
      this.checkUnmanagedInstances().then(f => findings.push(...f)),
    ]);

    logger.info(`SSM scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async checkPlaintextSecrets(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const suspicious: any[] = [];
    let nextToken: string | undefined;

    try {
      do {
        const result = await retry(() =>
          this.client.ssm.send(new DescribeParametersCommand({
            NextToken: nextToken,
            MaxResults: 50,
          }))
        );
        for (const param of result.Parameters ?? []) {
          if (param.Type === 'String' && looksLikeSecret(param.Name ?? '')) {
            suspicious.push(param);
          }
        }
        nextToken = result.NextToken;
      } while (nextToken);
    } catch { return findings; }

    if (suspicious.length > 0) {
      findings.push(this.emit(
        'ssm_parameter_store_plaintext_secrets',
        {
          resourceId:  'ssm::plaintext-secrets',
          count:       suspicious.length,
          paramNames:  suspicious.slice(0, 10).map(p => p.Name),
        },
        {
          message: `${suspicious.length} SSM Parameter(s) with secret-like names are stored as plaintext "String" type ` +
            `instead of "SecureString": ${suspicious.slice(0, 5).map(p => p.Name).join(', ')}${suspicious.length > 5 ? '...' : ''}. ` +
            `Plaintext parameters are readable by anyone with ssm:GetParameter permission and appear in logs unredacted.`,
        }
      ));

      // Confirm by fetching a small sample and matching values against known credential prefixes.
      // We log only the prefix-match label, never the value itself.
      for (const param of suspicious.slice(0, MAX_PARAMS_TO_FETCH)) {
        const paramName = param.Name;
        if (!paramName) continue;
        try {
          const result = await retry(() =>
            this.client.ssm.send(new GetParameterCommand({ Name: paramName, WithDecryption: false }))
          );
          const value = result.Parameter?.Value ?? '';
          if (!value) continue;
          const matched = CREDENTIAL_VALUE_PREFIXES.find(p => p.test(value));
          if (matched) {
            findings.push(this.emit(
              'ssm_parameter_confirmed_credential',
              { resourceId: `ssm::credential::${paramName}`, paramName, credentialType: matched.label },
              {
                message: `SSM Parameter "${paramName}" is stored as plaintext "String" and its value matches the format of ${matched.label}. ` +
                  `This is a confirmed credential leak, not a heuristic match.`,
              }
            ));
          }
        } catch { /* no permission to read value — heuristic finding above still stands */ }
      }
    }
    return findings;
  }

  private async checkPatchCompliance(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const noncompliant: any[] = [];

    try {
      // First collect all managed instance IDs
      const instanceIds: string[] = [];
      let infoToken: string | undefined;
      do {
        const infoResult = await retry(() =>
          this.client.ssm.send(new DescribeInstanceInformationCommand({ NextToken: infoToken }))
        );
        for (const info of infoResult.InstanceInformationList ?? []) {
          if (info.InstanceId) instanceIds.push(info.InstanceId);
        }
        infoToken = infoResult.NextToken;
      } while (infoToken);

      if (instanceIds.length === 0) return findings;

      // Fetch patch states in batches of 50 (API limit)
      const BATCH = 50;
      for (let i = 0; i < instanceIds.length; i += BATCH) {
        const batch = instanceIds.slice(i, i + BATCH);
        const result = await retry(() =>
          this.client.ssm.send(new DescribeInstancePatchStatesCommand({ InstanceIds: batch }))
        );
        for (const state of result.InstancePatchStates ?? []) {
          if (
            (state.CriticalNonCompliantCount ?? 0) > 0 ||
            (state.SecurityNonCompliantCount ?? 0) > 0
          ) {
            noncompliant.push(state);
          }
        }
      }
    } catch { return findings; }

    if (noncompliant.length > 0) {
      const totalCritical = noncompliant.reduce((s, i) => s + (i.CriticalNonCompliantCount ?? 0), 0);
      const totalSecurity = noncompliant.reduce((s, i) => s + (i.SecurityNonCompliantCount ?? 0), 0);

      findings.push(this.emit(
        'ssm_managed_compliant_patching',
        {
          resourceId:       'ssm::patch-compliance',
          instanceCount:    noncompliant.length,
          criticalMissing:  totalCritical,
          securityMissing:  totalSecurity,
          instanceIds:      noncompliant.slice(0, 10).map(i => i.InstanceId),
        },
        {
          message: `${noncompliant.length} managed instance(s) have unresolved patch compliance issues: ` +
            `${totalCritical} critical missing patches, ${totalSecurity} security missing patches. ` +
            `Instances: ${noncompliant.slice(0, 5).map(i => i.InstanceId).join(', ')}`,
          severity: totalCritical > 0 ? 'CRITICAL' : 'HIGH',
        }
      ));
    }
    return findings;
  }

  private async checkUnmanagedInstances(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let allInstanceIds: string[] = [];
    let ssmInstanceIds: string[] = [];

    try {
      // Get all running EC2 instance IDs
      let nextToken: string | undefined;
      do {
        const result = await retry(() =>
          this.client.ec2.send(new DescribeInstancesCommand({
            Filters: [{ Name: 'instance-state-name', Values: ['running'] }],
            NextToken: nextToken,
            MaxResults: 1000,
          }))
        );
        for (const r of result.Reservations ?? []) {
          allInstanceIds.push(...(r.Instances ?? []).map(i => i.InstanceId!).filter(Boolean));
        }
        nextToken = result.NextToken;
      } while (nextToken);

      // Get SSM-managed instances
      let ssmToken: string | undefined;
      do {
        const result = await retry(() =>
          this.client.ssm.send(new DescribeInstanceInformationCommand({
            NextToken: ssmToken,
            MaxResults: 50,
          }))
        );
        ssmInstanceIds.push(...(result.InstanceInformationList ?? []).map(i => i.InstanceId!).filter(Boolean));
        ssmToken = result.NextToken;
      } while (ssmToken);
    } catch { return findings; }

    const ssmSet     = new Set(ssmInstanceIds);
    const unmanaged  = allInstanceIds.filter(id => !ssmSet.has(id));

    if (unmanaged.length > 0) {
      findings.push(this.emit(
        'ec2_instance_managed_by_ssm',
        {
          resourceId:    'ssm::unmanaged-instances',
          instanceCount: unmanaged.length,
          instanceIds:   unmanaged.slice(0, 10),
        },
        {
          message: `${unmanaged.length} running EC2 instance(s) are not registered with AWS Systems Manager. ` +
            `Unmanaged instances cannot use Session Manager (SSH-free access), patch management, or Run Command. ` +
            `Instances: ${unmanaged.slice(0, 5).join(', ')}${unmanaged.length > 5 ? '...' : ''}`,
        }
      ));
    }
    return findings;
  }
}

export default SSMScanner;
