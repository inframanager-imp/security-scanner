// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  CognitoIdentityProviderClient,
  ListUserPoolsCommand,
  DescribeUserPoolCommand,
  GetUserPoolMfaConfigCommand,
  DescribeRiskConfigurationCommand,
  ListUserPoolClientsCommand,
  DescribeUserPoolClientCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class CognitoScanner extends BaseScanner {
  private cognitoIdp: CognitoIdentityProviderClient;

  constructor(client: AWSClient) {
    super(client, 'Cognito');
    this.cognitoIdp = new CognitoIdentityProviderClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Cognito security scan...');

      const userPools = await this.listUserPools();
      for (const pool of userPools) {
        const poolId = pool.Id || 'Unknown';
        const poolName = pool.Name || poolId;
        logger.debug(`Scanning Cognito user pool: ${poolName} (${poolId})`);

        const poolFindings = await this.validateUserPool(poolId, poolName);
        findings.push(...poolFindings);
      }

      logger.info(`Cognito scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Cognito scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listUserPools(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching Cognito user pools...');
      const pools: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await this.cognitoIdp.send(
          new ListUserPoolsCommand({ MaxResults: 60, NextToken: nextToken })
        );
        pools.push(...(result.UserPools || []));
        nextToken = result.NextToken;
      } while (nextToken);
      return pools;
    });
  }

  private async validateUserPool(poolId: string, poolName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let details: any;
    try {
      const result: any = await retry(async () => {
        return await this.cognitoIdp.send(new DescribeUserPoolCommand({ UserPoolId: poolId }));
      });
      details = result.UserPool || {};
    } catch (error) {
      logger.debug(`Failed to describe user pool ${poolId}`, { error: (error as Error).message });
      return findings;
    }

    const evidence = { userPoolId: poolId, userPoolName: poolName };

    // cognito_user_pool_deletion_protection_enabled
    const deletionProtection = details.DeletionProtection || 'INACTIVE';
    if (deletionProtection !== 'ACTIVE') {
      findings.push(this.emit(
        'cognito_user_pool_deletion_protection_enabled',
        { ...evidence, deletionProtection },
        { message: `User pool "${poolName}" has deletion protection disabled` }
      ));
    }

    // cognito_user_pool_self_registration_disabled
    const allowAdminCreateUserOnly = details.AdminCreateUserConfig?.AllowAdminCreateUserOnly === true;
    if (!allowAdminCreateUserOnly) {
      findings.push(this.emit(
        'cognito_user_pool_self_registration_disabled',
        { ...evidence, allowAdminCreateUserOnly },
        { message: `User pool "${poolName}" has self registration (self-service sign-up) enabled` }
      ));
    }

    // Password policy checks: Cognito always returns policy defaults; missing values are treated as 0
    const passwordPolicy = details.Policies?.PasswordPolicy;
    const minimumLength = passwordPolicy?.MinimumLength ?? 0;
    if (minimumLength < 14) {
      findings.push(this.emit(
        'cognito_user_pool_password_policy_minimum_length_14',
        { ...evidence, minimumLength, hasPasswordPolicy: !!passwordPolicy },
        { message: `User pool "${poolName}" password policy minimum length is ${minimumLength}, below the recommended 14 characters` }
      ));
    }

    const temporaryPasswordValidityDays = passwordPolicy?.TemporaryPasswordValidityDays ?? 0;
    if (temporaryPasswordValidityDays > 7) {
      findings.push(this.emit(
        'cognito_user_pool_temporary_password_expiration',
        { ...evidence, temporaryPasswordValidityDays },
        { message: `User pool "${poolName}" temporary passwords stay valid for ${temporaryPasswordValidityDays} days, exceeding the recommended 7 days` }
      ));
    }

    // cognito_user_pool_advanced_security_enabled
    const advancedSecurityMode = details.UserPoolAddOns?.AdvancedSecurityMode || 'OFF';
    if (advancedSecurityMode !== 'ENFORCED') {
      findings.push(this.emit(
        'cognito_user_pool_advanced_security_enabled',
        { ...evidence, advancedSecurityMode },
        {
          message: advancedSecurityMode === 'AUDIT'
            ? `User pool "${poolName}" has advanced security enabled but only in audit mode`
            : `User pool "${poolName}" has advanced security (threat protection) disabled`,
        }
      ));
    }

    // cognito_user_pool_mfa_enabled
    const mfaFindings = await this.checkMfa(poolId, poolName, evidence);
    findings.push(...mfaFindings);

    // Risk configuration checks (only meaningful when advanced security is on)
    const riskFindings = await this.checkRiskConfiguration(poolId, poolName, advancedSecurityMode, evidence);
    findings.push(...riskFindings);

    // Per-app-client checks
    const clientFindings = await this.checkUserPoolClients(poolId, poolName, evidence);
    findings.push(...clientFindings);

    return findings;
  }

  private async checkMfa(poolId: string, poolName: string, evidence: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result: any = await retry(async () => {
        return await this.cognitoIdp.send(new GetUserPoolMfaConfigCommand({ UserPoolId: poolId }));
      });
      const mfaConfiguration = result.MfaConfiguration || 'OFF';
      if (mfaConfiguration !== 'ON') {
        findings.push(this.emit(
          'cognito_user_pool_mfa_enabled',
          { ...evidence, mfaConfiguration },
          { message: `User pool "${poolName}" does not require MFA (MFA configuration is ${mfaConfiguration})` }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to get MFA config for user pool ${poolId}`, { error: (error as Error).message });
    }
    return findings;
  }

  private async checkRiskConfiguration(
    poolId: string,
    poolName: string,
    advancedSecurityMode: string,
    evidence: any
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let riskConfig: any = undefined;
    if (advancedSecurityMode !== 'OFF') {
      try {
        const result: any = await retry(async () => {
          return await this.cognitoIdp.send(new DescribeRiskConfigurationCommand({ UserPoolId: poolId }));
        });
        riskConfig = result.RiskConfiguration;
      } catch (error) {
        logger.debug(`Failed to get risk configuration for user pool ${poolId}`, { error: (error as Error).message });
      }
    }

    // cognito_user_pool_blocks_compromised_credentials_sign_in_attempts:
    // pass only when ENFORCED + compromised-credentials filter covers SIGN_IN with BLOCK action
    const compromised = riskConfig?.CompromisedCredentialsRiskConfiguration;
    const blocksCompromisedSignIn =
      advancedSecurityMode === 'ENFORCED' &&
      (compromised?.EventFilter || []).includes('SIGN_IN') &&
      compromised?.Actions?.EventAction === 'BLOCK';
    if (!blocksCompromisedSignIn) {
      findings.push(this.emit(
        'cognito_user_pool_blocks_compromised_credentials_sign_in_attempts',
        {
          ...evidence,
          advancedSecurityMode,
          compromisedCredentialsEventFilter: compromised?.EventFilter || [],
          compromisedCredentialsAction: compromised?.Actions?.EventAction || 'NONE',
        },
        { message: `User pool "${poolName}" does not block sign-in attempts with suspected compromised credentials` }
      ));
    }

    // cognito_user_pool_blocks_potential_malicious_sign_in_attempts:
    // pass only when ENFORCED + adaptive authentication blocks low/medium/high risk
    const takeoverActions = riskConfig?.AccountTakeoverRiskConfiguration?.Actions;
    const blocksAllRiskLevels =
      advancedSecurityMode === 'ENFORCED' &&
      takeoverActions?.LowAction?.EventAction === 'BLOCK' &&
      takeoverActions?.MediumAction?.EventAction === 'BLOCK' &&
      takeoverActions?.HighAction?.EventAction === 'BLOCK';
    if (!blocksAllRiskLevels) {
      findings.push(this.emit(
        'cognito_user_pool_blocks_potential_malicious_sign_in_attempts',
        {
          ...evidence,
          advancedSecurityMode,
          accountTakeoverActions: {
            low: takeoverActions?.LowAction?.EventAction || 'NONE',
            medium: takeoverActions?.MediumAction?.EventAction || 'NONE',
            high: takeoverActions?.HighAction?.EventAction || 'NONE',
          },
        },
        { message: `User pool "${poolName}" does not block potentially malicious sign-in attempts at all risk levels` }
      ));
    }

    return findings;
  }

  private async checkUserPoolClients(poolId: string, poolName: string, evidence: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let clients: any[] = [];
    try {
      clients = await retry(async () => {
        const collected: any[] = [];
        let nextToken: string | undefined;
        do {
          const result: any = await this.cognitoIdp.send(
            new ListUserPoolClientsCommand({ UserPoolId: poolId, MaxResults: 60, NextToken: nextToken })
          );
          collected.push(...(result.UserPoolClients || []));
          nextToken = result.NextToken;
        } while (nextToken);
        return collected;
      });
    } catch (error) {
      logger.debug(`Failed to list clients for user pool ${poolId}`, { error: (error as Error).message });
      return findings;
    }

    for (const client of clients) {
      const clientId = client.ClientId;
      const clientName = client.ClientName || clientId;
      if (!clientId) continue;

      try {
        const result: any = await retry(async () => {
          return await this.cognitoIdp.send(
            new DescribeUserPoolClientCommand({ UserPoolId: poolId, ClientId: clientId })
          );
        });
        const clientDetails = result.UserPoolClient || {};
        const clientEvidence = { ...evidence, clientId, clientName };

        // cognito_user_pool_client_prevent_user_existence_errors
        if (clientDetails.PreventUserExistenceErrors !== 'ENABLED') {
          findings.push(this.emit(
            'cognito_user_pool_client_prevent_user_existence_errors',
            { ...clientEvidence, preventUserExistenceErrors: clientDetails.PreventUserExistenceErrors || 'LEGACY' },
            { message: `App client "${clientName}" of user pool "${poolName}" does not prevent user existence errors, revealing which usernames exist` }
          ));
        }

        // cognito_user_pool_client_token_revocation_enabled
        if (!clientDetails.EnableTokenRevocation) {
          findings.push(this.emit(
            'cognito_user_pool_client_token_revocation_enabled',
            { ...clientEvidence, enableTokenRevocation: false },
            { message: `App client "${clientName}" of user pool "${poolName}" has token revocation disabled` }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to describe user pool client ${clientId} of pool ${poolId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }
}

export default CognitoScanner;
