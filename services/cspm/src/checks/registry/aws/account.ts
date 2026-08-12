// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const accountChecks: CheckMetadata[] = [
  {
    checkId: 'account_maintain_current_contact_details',
    provider: 'aws',
    service: 'account',
    title: 'Primary Account Contact Details Incomplete',
    severity: 'MEDIUM',
    description: 'Checks that the primary account contact information is registered and complete (full name and phone number) so AWS can reach the account owner; keeping details current also requires periodic manual review.',
    remediation: 'Update the primary contact details in the AWS console under Account settings (or with aws account put-contact-information) and review them periodically to keep them current.',
    tags: ['account', 'contact-information'],
  },
  {
    checkId: 'account_maintain_different_contact_details_to_security_billing_and_operations',
    provider: 'aws',
    service: 'account',
    title: 'Alternate Account Contacts Missing or Not Distinct',
    severity: 'MEDIUM',
    description: 'Checks that SECURITY, BILLING and OPERATIONS alternate contacts are all registered and are distinct from each other and from the primary (root) contact.',
    remediation: 'Register dedicated SECURITY, BILLING and OPERATIONS alternate contacts (aws account put-alternate-contact) with distinct names, email addresses and phone numbers, preferably team distribution lists.',
    tags: ['account', 'contact-information'],
  },
  {
    checkId: 'account_security_contact_information_is_registered',
    provider: 'aws',
    service: 'account',
    title: 'Security Contact Not Registered',
    severity: 'MEDIUM',
    description: 'Checks that a SECURITY alternate contact is registered for the account so AWS can notify the security team about incidents, vulnerabilities and abuse reports.',
    remediation: 'Register a SECURITY alternate contact with a monitored email address and phone number: aws account put-alternate-contact --alternate-contact-type SECURITY.',
    tags: ['account', 'contact-information', 'incident-response'],
  },
];
