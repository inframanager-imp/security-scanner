/**
 * GCP Resource State Fetcher
 *
 * Given a GCP client + audit log method name + resource name, fetches the
 * CURRENT full resource configuration from the appropriate GCP API.
 *
 * Used to populate ConfigChange.newValue with the real post-change resource
 * state (instead of just the raw protoPayload.request from Audit Logs).
 */

import GcpClient from '../../../src/gcp/client';
import { logger } from '../config/logger';

// ─── Method prefix → fetch function ──────────────────────────────────────────

type FetchFn = (gcpClient: GcpClient, resourceName: string, projectId: string) => Promise<Record<string, unknown> | null>;

const METHOD_FETCHERS: { prefix: string; fn: FetchFn }[] = [
  { prefix: 'compute.firewalls.',         fn: fetchFirewall },
  { prefix: 'compute.instances.',         fn: fetchInstance },
  { prefix: 'compute.networks.',          fn: fetchNetwork },
  { prefix: 'compute.subnetworks.',       fn: fetchSubnetwork },
  { prefix: 'compute.routers.',           fn: fetchRouter },
  { prefix: 'storage.buckets.',           fn: fetchStorageBucket },
  { prefix: 'sqladmin.instances.',        fn: fetchSqlInstance },
  { prefix: 'cloudkms.cryptoKeyVersions.',fn: fetchKmsCryptoKey },
  { prefix: 'cloudkms.cryptokeys.',       fn: fetchKmsCryptoKey },
  { prefix: 'cloudkms.keyrings.',         fn: fetchKmsKeyRing },
  { prefix: 'iam.serviceaccounts.',       fn: fetchServiceAccount },
  { prefix: 'run.services.',              fn: fetchCloudRunService },
  { prefix: 'logging.sinks.',             fn: fetchLoggingSink },
  { prefix: 'pubsub.topics.',             fn: fetchPubSubTopic },
  { prefix: 'pubsub.subscriptions.',      fn: fetchPubSubSubscription },
];

// ─── Public API ───────────────────────────────────────────────────────────────

export async function fetchGcpResourceState(
  gcpClient: GcpClient,
  methodName: string,
  resourceName: string | null,
  projectId: string,
): Promise<Record<string, unknown> | null> {
  if (!resourceName) return null;

  // Don't fetch for delete events — resource is gone
  const lower = methodName.toLowerCase();
  if (lower.includes('delete') || lower.includes('destroy')) return null;

  const methodLower = lower;
  const entry = METHOD_FETCHERS.find((e) => methodLower.includes(e.prefix));
  if (!entry) return null;

  try {
    return await entry.fn(gcpClient, resourceName, projectId);
  } catch (err) {
    logger.debug(`[gcp-fetch] Could not fetch ${resourceName}: ${(err as Error).message}`);
    return null;
  }
}

// ─── Resource name parsing helpers ───────────────────────────────────────────

/** Parse GCP resource name: projects/my-proj/global/firewalls/my-rule → { project, zone, name } */
function parseResourceName(resourceName: string): { project: string; zone?: string; region?: string; name: string } {
  const parts = resourceName.split('/');
  const name = parts[parts.length - 1] ?? resourceName;
  const projectIdx = parts.indexOf('projects');
  const project = projectIdx >= 0 ? (parts[projectIdx + 1] ?? '') : '';
  const zoneIdx = parts.indexOf('zones');
  const zone = zoneIdx >= 0 ? parts[zoneIdx + 1] : undefined;
  const regionIdx = parts.indexOf('regions');
  const region = regionIdx >= 0 ? parts[regionIdx + 1] : undefined;
  return { project, zone, region, name };
}

// ─── Compute fetchers ─────────────────────────────────────────────────────────

async function fetchFirewall(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, project } = parseResourceName(resourceName);
  const compute = gcpClient.compute();
  const resp = await compute.firewalls.get({ project: project || projectId, firewall: name });
  const fw = resp.data;
  return {
    name:             fw.name,
    description:      fw.description,
    network:          fw.network,
    priority:         fw.priority,
    direction:        fw.direction,
    disabled:         fw.disabled,
    allowed:          fw.allowed,
    denied:           fw.denied,
    sourceRanges:     fw.sourceRanges,
    destinationRanges: fw.destinationRanges,
    sourceTags:       fw.sourceTags,
    targetTags:       fw.targetTags,
    sourceServiceAccounts: fw.sourceServiceAccounts,
    targetServiceAccounts: fw.targetServiceAccounts,
    logConfig:        fw.logConfig,
  };
}

async function fetchInstance(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, zone, project } = parseResourceName(resourceName);
  if (!zone) return null;
  const compute = gcpClient.compute();
  const resp = await compute.instances.get({ project: project || projectId, zone, instance: name });
  const inst = resp.data;
  return {
    name:              inst.name,
    machineType:       inst.machineType?.split('/').pop(),
    status:            inst.status,
    zone:              inst.zone?.split('/').pop(),
    networkInterfaces: inst.networkInterfaces,
    disks:             inst.disks,
    serviceAccounts:   inst.serviceAccounts,
    tags:              inst.tags,
    labels:            inst.labels,
    shieldedInstanceConfig: inst.shieldedInstanceConfig,
    confidentialInstanceConfig: inst.confidentialInstanceConfig,
    deletionProtection: inst.deletionProtection,
    metadata:          inst.metadata,
  };
}

async function fetchNetwork(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, project } = parseResourceName(resourceName);
  const compute = gcpClient.compute();
  const resp = await compute.networks.get({ project: project || projectId, network: name });
  const net = resp.data;
  return {
    name:              net.name,
    description:       net.description,
    autoCreateSubnetworks: net.autoCreateSubnetworks,
    routingConfig:     net.routingConfig,
    mtu:               net.mtu,
    subnetworks:       net.subnetworks,
  };
}

async function fetchSubnetwork(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, region, project } = parseResourceName(resourceName);
  if (!region) return null;
  const compute = gcpClient.compute();
  const resp = await compute.subnetworks.get({ project: project || projectId, region, subnetwork: name });
  const sub = resp.data;
  return {
    name:              sub.name,
    description:       sub.description,
    network:           sub.network?.split('/').pop(),
    region:            sub.region?.split('/').pop(),
    ipCidrRange:       sub.ipCidrRange,
    secondaryIpRanges: sub.secondaryIpRanges,
    privateIpGoogleAccess: sub.privateIpGoogleAccess,
    logConfig:         sub.logConfig,
    purpose:           sub.purpose,
    role:              sub.role,
  };
}

async function fetchRouter(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, region, project } = parseResourceName(resourceName);
  if (!region) return null;
  const compute = gcpClient.compute();
  const resp = await compute.routers.get({ project: project || projectId, region, router: name });
  const router = resp.data;
  return {
    name:       router.name,
    network:    router.network?.split('/').pop(),
    region:     router.region?.split('/').pop(),
    bgp:        router.bgp,
    bgpPeers:   router.bgpPeers,
    nats:       router.nats,
    interfaces: router.interfaces,
  };
}

// ─── Storage fetcher ─────────────────────────────────────────────────────────

async function fetchStorageBucket(gcpClient: GcpClient, resourceName: string, _projectId: string): Promise<Record<string, unknown> | null> {
  // resourceName may be "projects/_/buckets/my-bucket" or just "my-bucket"
  const bucketName = resourceName.includes('/buckets/')
    ? resourceName.split('/buckets/')[1]
    : resourceName.split('/').pop() ?? resourceName;

  const storage = gcpClient.storage();
  const [bucketResp, iamResp] = await Promise.all([
    storage.buckets.get({ bucket: bucketName }),
    storage.buckets.getIamPolicy({ bucket: bucketName }).catch(() => null),
  ]);
  const b = bucketResp.data;
  return {
    name:               b.name,
    location:           b.location,
    locationType:       b.locationType,
    storageClass:       b.storageClass,
    versioning:         b.versioning,
    lifecycle:          b.lifecycle,
    cors:               b.cors,
    logging:            b.logging,
    website:            b.website,
    iamConfiguration:   b.iamConfiguration,
    encryption:         b.encryption,
    retentionPolicy:    b.retentionPolicy,
    labels:             b.labels,
    iamPolicy:          iamResp?.data?.bindings,
  };
}

// ─── Cloud SQL fetcher ────────────────────────────────────────────────────────

async function fetchSqlInstance(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, project } = parseResourceName(resourceName);
  const sqladmin = gcpClient.sqladmin();
  const resp = await sqladmin.instances.get({ project: project || projectId, instance: name });
  const inst = resp.data;
  return {
    name:              inst.name,
    databaseVersion:   inst.databaseVersion,
    region:            inst.region,
    state:             inst.state,
    settings:          {
      tier:              inst.settings?.tier,
      activationPolicy:  inst.settings?.activationPolicy,
      backupConfiguration: inst.settings?.backupConfiguration,
      ipConfiguration:   inst.settings?.ipConfiguration,
      locationPreference: inst.settings?.locationPreference,
      maintenanceWindow: inst.settings?.maintenanceWindow,
      dataDiskSizeGb:    inst.settings?.dataDiskSizeGb,
      dataDiskType:      inst.settings?.dataDiskType,
      storageAutoResize: inst.settings?.storageAutoResize,
      availabilityType:  inst.settings?.availabilityType,
      databaseFlags:     inst.settings?.databaseFlags,
      denyMaintenancePeriods: inst.settings?.denyMaintenancePeriods,
      insightsConfig:    inst.settings?.insightsConfig,
    },
  };
}

// ─── KMS fetchers ─────────────────────────────────────────────────────────────

async function fetchKmsCryptoKey(gcpClient: GcpClient, resourceName: string, _projectId: string): Promise<Record<string, unknown> | null> {
  // resourceName: projects/p/locations/l/keyRings/r/cryptoKeys/k
  const kms = gcpClient.cloudkms();
  const [keyResp, iamResp] = await Promise.all([
    kms.projects.locations.keyRings.cryptoKeys.get({ name: resourceName }),
    kms.projects.locations.keyRings.cryptoKeys.getIamPolicy({ resource: resourceName }).catch(() => null),
  ]);
  const key = keyResp.data;
  return {
    name:                   key.name?.split('/').pop(),
    fullName:               key.name,
    purpose:                key.purpose,
    rotationPeriod:         key.rotationPeriod,
    nextRotationTime:       key.nextRotationTime,
    versionTemplate:        key.versionTemplate,
    importOnly:             key.importOnly,
    destroyScheduledDuration: key.destroyScheduledDuration,
    labels:                 key.labels,
    iamPolicy:              iamResp?.data?.bindings,
  };
}

async function fetchKmsKeyRing(gcpClient: GcpClient, resourceName: string, _projectId: string): Promise<Record<string, unknown> | null> {
  const kms = gcpClient.cloudkms();
  const resp = await kms.projects.locations.keyRings.get({ name: resourceName });
  const kr = resp.data;
  return {
    name:       kr.name?.split('/').pop(),
    fullName:   kr.name,
    createTime: kr.createTime,
  };
}

// ─── IAM: Service Account ─────────────────────────────────────────────────────

async function fetchServiceAccount(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, project } = parseResourceName(resourceName);
  const iam = gcpClient.iam();
  // Service account name in IAM API: projects/{project}/serviceAccounts/{email}
  const saName = resourceName.includes('@') || resourceName.includes('serviceAccounts/')
    ? resourceName
    : `projects/${project || projectId}/serviceAccounts/${name}`;

  const [saResp, iamResp] = await Promise.all([
    iam.projects.serviceAccounts.get({ name: saName }),
    iam.projects.serviceAccounts.getIamPolicy({ resource: saName }).catch(() => null),
  ]);
  const sa = saResp.data;
  return {
    name:          sa.name,
    email:         sa.email,
    displayName:   sa.displayName,
    description:   sa.description,
    disabled:      sa.disabled,
    projectId:     sa.projectId,
    oauth2ClientId: sa.oauth2ClientId,
    iamPolicy:     iamResp?.data?.bindings,
  };
}

// ─── Cloud Run ────────────────────────────────────────────────────────────────
async function fetchCloudRunService(_gcpClient: GcpClient, _resourceName: string, _projectId: string): Promise<Record<string, unknown> | null> {
  return null;
}

// ─── Logging Sink ─────────────────────────────────────────────────────────────

async function fetchLoggingSink(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, project } = parseResourceName(resourceName);
  const logging = gcpClient.logging();
  const sinkName = resourceName.includes('sinks/')
    ? resourceName
    : `projects/${project || projectId}/sinks/${name}`;

  const resp = await logging.projects.sinks.get({ sinkName });
  const sink = resp.data;
  return {
    name:               sink.name,
    destination:        sink.destination,
    filter:             sink.filter,
    description:        sink.description,
    disabled:           sink.disabled,
    includeChildren:    sink.includeChildren,
    bigqueryOptions:    sink.bigqueryOptions,
    exclusions:         sink.exclusions,
    createTime:         sink.createTime,
    updateTime:         sink.updateTime,
  };
}

// ─── Pub/Sub ─────────────────────────────────────────────────────────────────

async function fetchPubSubTopic(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, project } = parseResourceName(resourceName);
  const pubsub = gcpClient.pubsub();
  const topicName = resourceName.includes('topics/')
    ? resourceName
    : `projects/${project || projectId}/topics/${name}`;

  const [topicResp, iamResp] = await Promise.all([
    pubsub.projects.topics.get({ topic: topicName }),
    pubsub.projects.topics.getIamPolicy({ resource: topicName }).catch(() => null),
  ]);
  const topic = topicResp.data;
  return {
    name:                topic.name,
    labels:              topic.labels,
    messageStoragePolicy: topic.messageStoragePolicy,
    kmsKeyName:          topic.kmsKeyName,
    schemaSettings:      topic.schemaSettings,
    messageRetentionDuration: topic.messageRetentionDuration,
    iamPolicy:           iamResp?.data?.bindings,
  };
}

async function fetchPubSubSubscription(gcpClient: GcpClient, resourceName: string, projectId: string): Promise<Record<string, unknown> | null> {
  const { name, project } = parseResourceName(resourceName);
  const pubsub = gcpClient.pubsub();
  const subName = resourceName.includes('subscriptions/')
    ? resourceName
    : `projects/${project || projectId}/subscriptions/${name}`;

  const resp = await pubsub.projects.subscriptions.get({ subscription: subName });
  const sub = resp.data;
  return {
    name:                sub.name,
    topic:               sub.topic,
    pushConfig:          sub.pushConfig,
    bigqueryConfig:      sub.bigqueryConfig,
    cloudStorageConfig:  sub.cloudStorageConfig,
    ackDeadlineSeconds:  sub.ackDeadlineSeconds,
    retainAckedMessages: sub.retainAckedMessages,
    messageRetentionDuration: sub.messageRetentionDuration,
    filter:              sub.filter,
    deadLetterPolicy:    sub.deadLetterPolicy,
    retryPolicy:         sub.retryPolicy,
    enableExactlyOnceDelivery: sub.enableExactlyOnceDelivery,
    labels:              sub.labels,
  };
}
