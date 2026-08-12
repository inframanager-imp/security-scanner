// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const fsxChecks: CheckMetadata[] = [
  {
    checkId: 'fsx_file_system_copy_tags_to_backups_enabled',
    provider: 'aws',
    service: 'fsx',
    title: 'FSx Copy Tags to Backups Disabled',
    severity: 'LOW',
    description: 'Checks that FSx file systems (Lustre, Windows, OpenZFS) copy resource tags to backups, preserving ownership, cost-allocation and data-classification context on backup copies.',
    remediation: 'Enable CopyTagsToBackups on the file system configuration so backups inherit the tags used for access governance, retention and cost tracking.',
    tags: ['fsx', 'tagging', 'backup'],
  },
  {
    checkId: 'fsx_file_system_copy_tags_to_volumes_enabled',
    provider: 'aws',
    service: 'fsx',
    title: 'FSx Copy Tags to Volumes Disabled',
    severity: 'LOW',
    description: 'Checks that FSx for OpenZFS file systems copy resource tags to their volumes so volume-level resources retain governance and cost-allocation metadata.',
    remediation: 'Enable CopyTagsToVolumes on the OpenZFS file system configuration so newly created volumes inherit the file system tags.',
    tags: ['fsx', 'tagging', 'openzfs'],
  },
  {
    checkId: 'fsx_windows_file_system_multi_az_enabled',
    provider: 'aws',
    service: 'fsx',
    title: 'FSx Windows File System Not Multi-AZ',
    severity: 'LOW',
    description: 'Checks that FSx for Windows File Server file systems span more than one subnet, indicating a Multi-AZ deployment that survives the loss of a single Availability Zone.',
    remediation: 'Recreate or migrate the file system as a Multi-AZ deployment (subnets in two Availability Zones) for workloads that need high availability; FSx deployment type cannot be changed in place.',
    tags: ['fsx', 'multi-az', 'resilience'],
  },
];
