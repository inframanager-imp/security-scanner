// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const transferChecks: CheckMetadata[] = [
  {
    checkId: 'transfer_server_in_transit_encryption_enabled',
    provider: 'aws',
    service: 'transfer',
    title: 'Transfer Server Allows Unencrypted FTP',
    severity: 'HIGH',
    description: 'Checks that Transfer Family servers do not offer the plain FTP protocol, which sends credentials and file data unencrypted over the network.',
    remediation: 'Remove FTP from the server protocol list and use SFTP, FTPS or AS2 so credentials and file transfers are encrypted in transit.',
    tags: ['transfer', 'encryption-in-transit', 'ftp'],
  },
  {
    checkId: 'transfer_server_pqc_ssh_kex_enabled',
    provider: 'aws',
    service: 'transfer',
    title: 'Transfer Server Without Post-Quantum SSH Policy',
    severity: 'LOW',
    description: 'Checks that Transfer Family servers use a security policy that enables post-quantum hybrid SSH key exchange (ML-KEM), protecting captured traffic against future quantum decryption.',
    remediation: 'Attach a post-quantum security policy (for example TransferSecurityPolicy-2025-03 or TransferSecurityPolicy-FIPS-2025-03) to the server.',
    tags: ['transfer', 'post-quantum', 'ssh'],
  },
];
