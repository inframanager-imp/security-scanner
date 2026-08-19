/**
 * Approval Workflow Service
 *
 * Enterprise gate for three high-impact baseline actions:
 *   CAPTURE  — capture a new baseline snapshot
 *   REFRESH  — replace an existing baseline with current inventory state
 *   REVERT   — push baseline config back onto a drifted cloud resource
 *
 * Flow:
 *   1. requestApproval()   — creates ApprovalRequest (PENDING), dispatches notifications
 *   2. approveRequest()    — moves to APPROVED, executes the action immediately
 *   3. rejectRequest()     — moves to REJECTED, no action taken
 *   4. expireStaleRequests() — called on a timer, marks PENDING requests past expiresAt as EXPIRED
 *
 * Notifications use the existing IntegrationService webhook channel so no extra
 * config is required. Alert emails are sent if any SMTP alert config is active.
 */

import { prisma }            from '../config/database';
import { logger }            from '../config/logger';
import { captureBaseline, refreshBaseline } from './baselineService';
import { executeRevert }     from './revertService';

export type ApprovalAction = 'CAPTURE' | 'REFRESH' | 'REVERT';
export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED' | 'EXECUTING' | 'COMPLETED' | 'FAILED';

export interface ApprovalMetadata {
  // CAPTURE
  provider?:      string;
  targetId?:      string;
  name?:          string;
  description?:   string;
  resourceTypes?: string[];
  nameSearch?:    string;
  region?:        string;
  // REFRESH — just needs baselineId (top-level field)
  // REVERT
  driftId?:       string;
}

const EXPIRY_HOURS = 24;

// ─── Create approval request ──────────────────────────────────────────────────

export async function requestApproval(params: {
  action:          ApprovalAction;
  baselineId?:     string;
  driftId?:        string;
  requestedBy:     string;
  requestedByName?: string;
  notes?:          string;
  metadata?:       ApprovalMetadata;
}) {
  const expiresAt = new Date(Date.now() + EXPIRY_HOURS * 60 * 60 * 1000);

  const req = await prisma.approvalRequest.create({
    data: {
      action:          params.action,
      baselineId:      params.baselineId ?? null,
      driftId:         params.driftId    ?? null,
      requestedBy:     params.requestedBy,
      requestedByName: params.requestedByName ?? null,
      notes:           params.notes ?? null,
      expiresAt,
      metadata:        params.metadata as object ?? null,
    },
  });

  logger.info(`[approval] Created ${params.action} request ${req.id} by ${params.requestedBy}`);

  // Dispatch webhook notification (fire-and-forget)
  void dispatchApprovalNotification(req.id, 'PENDING_REVIEW', params.action, params.requestedBy, params.notes);

  return req;
}

// ─── Approve request ──────────────────────────────────────────────────────────

export async function approveRequest(params: {
  requestId:      string;
  reviewedBy:     string;
  reviewedByName?: string;
  reviewNotes?:   string;
}) {
  const req = await prisma.approvalRequest.findUnique({ where: { id: params.requestId } });
  if (!req) throw new Error('Approval request not found');
  if (req.status !== 'PENDING') throw new Error(`Cannot approve — request is ${req.status}`);
  if (new Date() > req.expiresAt) {
    await prisma.approvalRequest.update({ where: { id: req.id }, data: { status: 'EXPIRED' } });
    throw new Error('Approval request has expired');
  }

  // Move to EXECUTING
  await prisma.approvalRequest.update({
    where: { id: req.id },
    data: {
      status:        'EXECUTING',
      reviewedBy:    params.reviewedBy,
      reviewedByName: params.reviewedByName ?? null,
      reviewNotes:   params.reviewNotes ?? null,
      reviewedAt:    new Date(),
    },
  });

  const meta = (req.metadata ?? {}) as ApprovalMetadata;

  try {
    if (req.action === 'CAPTURE') {
      if (!meta.provider || !meta.targetId || !meta.name) {
        throw new Error('CAPTURE metadata incomplete — missing provider, targetId, or name');
      }
      await captureBaseline(
        meta.provider, meta.targetId, meta.name,
        meta.description, meta.resourceTypes, meta.nameSearch,
        req.requestedBy, meta.region,
      );

    } else if (req.action === 'REFRESH') {
      if (!req.baselineId) throw new Error('REFRESH approval missing baselineId');
      await refreshBaseline(req.baselineId, req.requestedBy);

    } else if (req.action === 'REVERT') {
      if (!req.baselineId || !meta.driftId) throw new Error('REVERT approval missing baselineId or driftId');
      await executeRevert(req.baselineId, meta.driftId, params.reviewedBy);
    }

    await prisma.approvalRequest.update({
      where: { id: req.id },
      data:  { status: 'COMPLETED', executedAt: new Date() },
    });

    logger.info(`[approval] ${req.action} ${req.id} COMPLETED by ${params.reviewedBy}`);
    void dispatchApprovalNotification(req.id, 'COMPLETED', req.action, params.reviewedBy, params.reviewNotes);

  } catch (err) {
    const msg = (err as Error).message;
    await prisma.approvalRequest.update({
      where: { id: req.id },
      data:  { status: 'FAILED', executedAt: new Date(), executionError: msg },
    });
    logger.error(`[approval] ${req.action} ${req.id} FAILED: ${msg}`);
    void dispatchApprovalNotification(req.id, 'FAILED', req.action, params.reviewedBy, msg);
    throw err;
  }

  return prisma.approvalRequest.findUnique({ where: { id: req.id } });
}

// ─── Reject request ───────────────────────────────────────────────────────────

export async function rejectRequest(params: {
  requestId:      string;
  reviewedBy:     string;
  reviewedByName?: string;
  reviewNotes?:   string;
}) {
  const req = await prisma.approvalRequest.findUnique({ where: { id: params.requestId } });
  if (!req) throw new Error('Approval request not found');
  if (req.status !== 'PENDING') throw new Error(`Cannot reject — request is ${req.status}`);

  const updated = await prisma.approvalRequest.update({
    where: { id: params.requestId },
    data: {
      status:        'REJECTED',
      reviewedBy:    params.reviewedBy,
      reviewedByName: params.reviewedByName ?? null,
      reviewNotes:   params.reviewNotes ?? null,
      reviewedAt:    new Date(),
    },
  });

  logger.info(`[approval] ${req.action} ${req.id} REJECTED by ${params.reviewedBy}`);
  void dispatchApprovalNotification(req.id, 'REJECTED', req.action, params.reviewedBy, params.reviewNotes);
  return updated;
}

// ─── Cancel own request ───────────────────────────────────────────────────────

export async function cancelRequest(requestId: string, cancelledBy: string) {
  const req = await prisma.approvalRequest.findUnique({ where: { id: requestId } });
  if (!req) throw new Error('Approval request not found');
  if (req.status !== 'PENDING') throw new Error(`Cannot cancel — request is ${req.status}`);

  return prisma.approvalRequest.update({
    where: { id: requestId },
    data:  { status: 'CANCELLED', reviewedAt: new Date(), reviewedBy: cancelledBy },
  });
}

// ─── Expire stale requests ────────────────────────────────────────────────────

export async function expireStaleApprovals(): Promise<number> {
  const result = await prisma.approvalRequest.updateMany({
    where: { status: 'PENDING', expiresAt: { lt: new Date() } },
    data:  { status: 'EXPIRED' },
  });
  if (result.count > 0) {
    logger.info(`[approval] Expired ${result.count} stale approval requests`);
  }
  return result.count;
}

// ─── Notification dispatcher ──────────────────────────────────────────────────

async function dispatchApprovalNotification(
  requestId: string,
  event: string,
  action: string,
  actor: string,
  notes?: string | null,
) {
  try {
    // Send to all active webhook integrations
    const integrations = await prisma.integrationConfig.findMany({
      where:  { isActive: true, integrationType: 'WEBHOOK' },
      select: { id: true, encryptedConfig: true },
    });

    const payload = {
      type:      'APPROVAL_REQUEST',
      event,
      requestId,
      action,
      actor,
      notes:     notes ?? null,
      timestamp: new Date().toISOString(),
      reviewUrl: `/baselines?approvalId=${requestId}`,
    };

    await Promise.allSettled(
      integrations.map(async (integration: { id: string; encryptedConfig: string }) => {
        let cfg: Record<string, string> = {};
        try { cfg = JSON.parse(integration.encryptedConfig) as Record<string, string>; } catch { return; }
        const url = cfg.webhookUrl;
        if (!url) return;
        await fetch(url, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', ...(cfg.secret ? { 'X-Webhook-Secret': cfg.secret } : {}) },
          body:    JSON.stringify(payload),
          signal:  AbortSignal.timeout(10_000),
        });
      }),
    );
  } catch (err) {
    logger.warn(`[approval] Notification dispatch failed: ${(err as Error).message}`);
  }
}
