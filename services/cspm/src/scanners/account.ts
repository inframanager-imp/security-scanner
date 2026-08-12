// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  AccountClient,
  GetContactInformationCommand,
  GetAlternateContactCommand,
} from '@aws-sdk/client-account';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const ALTERNATE_CONTACT_TYPES = ['BILLING', 'SECURITY', 'OPERATIONS'] as const;

export class AccountScanner extends BaseScanner {
  private account: AccountClient;

  constructor(client: AWSClient) {
    super(client, 'Account');
    this.account = new AccountClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Account security scan...');

      // Primary contact information (global, account-level)
      let primaryContact: any;
      try {
        const result = await retry(async () => {
          return await this.account.send(new GetContactInformationCommand({}));
        });
        primaryContact = result.ContactInformation;
      } catch (error) {
        // AccessDenied or other failure: cannot evaluate account contact checks, emit nothing
        logger.debug('Unable to get account contact information', { error: (error as Error).message });
        return findings;
      }

      // account_maintain_current_contact_details: primary contact info must be complete.
      // (Prowler marks this check manual; completeness of the registered details is the
      // automatable portion — keeping them current still needs periodic review.)
      if (!primaryContact?.FullName || !primaryContact?.PhoneNumber) {
        findings.push(this.emit(
          'account_maintain_current_contact_details',
          {
            fullNameRegistered: !!primaryContact?.FullName,
            phoneNumberRegistered: !!primaryContact?.PhoneNumber,
          },
          {
            message: 'Primary account contact information is missing a full name or phone number; register complete contact details and verify they are current',
          }
        ));
      }

      // Alternate contacts (BILLING / SECURITY / OPERATIONS)
      const alternateContacts: Record<string, any> = {};
      let alternateLookupFailed = false;
      for (const contactType of ALTERNATE_CONTACT_TYPES) {
        try {
          const result = await retry(async () => {
            return await this.account.send(new GetAlternateContactCommand({ AlternateContactType: contactType as any }));
          });
          alternateContacts[contactType] = result.AlternateContact ?? null;
        } catch (error) {
          const err = error as any;
          if (err?.name === 'ResourceNotFoundException') {
            // Contact of this type is not registered
            alternateContacts[contactType] = null;
          } else {
            // AccessDenied or other failure: cannot determine alternate contacts
            alternateLookupFailed = true;
            logger.debug(`Unable to get ${contactType} alternate contact`, { error: (error as Error).message });
          }
        }
      }

      if (!alternateLookupFailed) {
        // account_security_contact_information_is_registered: SECURITY contact must exist
        if (!alternateContacts['SECURITY']) {
          findings.push(this.emit(
            'account_security_contact_information_is_registered',
            { securityContactRegistered: false },
            { message: 'No SECURITY alternate contact is registered for this AWS account' }
          ));
        }

        // account_maintain_different_contact_details_to_security_billing_and_operations:
        // all four contacts registered and mutually distinct (4 unique phone numbers,
        // 4 unique names, 3 unique alternate-contact emails — primary has no email field)
        const contacts = ALTERNATE_CONTACT_TYPES.map((t) => alternateContacts[t]);
        const phoneNumbers = new Set<string | undefined>([
          primaryContact?.PhoneNumber,
          ...contacts.map((c) => c?.PhoneNumber),
        ]);
        const names = new Set<string | undefined>([
          primaryContact?.FullName,
          ...contacts.map((c) => c?.Name),
        ]);
        const emails = new Set<string | undefined>(contacts.map((c) => c?.EmailAddress));

        if (phoneNumbers.size !== 4 || names.size !== 4 || emails.size !== 3) {
          findings.push(this.emit(
            'account_maintain_different_contact_details_to_security_billing_and_operations',
            {
              billingContactRegistered: !!alternateContacts['BILLING'],
              securityContactRegistered: !!alternateContacts['SECURITY'],
              operationsContactRegistered: !!alternateContacts['OPERATIONS'],
              uniquePhoneNumbers: phoneNumbers.size,
              uniqueNames: names.size,
              uniqueEmails: emails.size,
            },
            {
              message: 'SECURITY, BILLING and OPERATIONS alternate contacts are missing or are not distinct from each other and from the primary (root) contact',
            }
          ));
        }
      }

      logger.info(`Account scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Account scan failed', { error: (error as Error).message });
    }

    return findings;
  }
}

export default AccountScanner;
