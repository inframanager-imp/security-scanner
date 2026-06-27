/**
 * Freeze Window Service
 *
 * Checks whether a given provider+targetId is currently inside a freeze window.
 * Called during every real-time sync tick — if a change is detected and the
 * subscription is frozen, the change is flagged as a freeze violation.
 */

import { prisma } from '../config/database';
import type { FreezeWindow } from '@prisma/client';

// ─── Time helpers ─────────────────────────────────────────────────────────────

/**
 * Returns the current HH:MM in a given IANA timezone.
 */
function currentTimeInZone(timezone: string): { day: number; hhmm: string } {
  const now  = new Date();
  const opts: Intl.DateTimeFormatOptions = {
    timeZone: timezone,
    weekday:  'short',
    hour:     '2-digit',
    minute:   '2-digit',
    hour12:   false,
  };
  const parts = new Intl.DateTimeFormat('en-US', opts).formatToParts(now);
  const day   = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].indexOf(
    parts.find((p) => p.type === 'weekday')?.value ?? 'Sun',
  );
  const hour  = parts.find((p) => p.type === 'hour')?.value   ?? '00';
  const min   = parts.find((p) => p.type === 'minute')?.value ?? '00';
  return { day, hhmm: `${hour}:${min}` };
}

/**
 * Compare two "HH:MM" strings. Returns -1, 0, +1.
 */
function cmpTime(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Is the current moment inside this freeze window for the given provider+targetId?
 */
function isFrozen(win: FreezeWindow, provider: string, targetId: string): boolean {
  // Scope check
  if (win.providers.length > 0 && !win.providers.includes(provider)) return false;
  if (win.targetIds.length  > 0 && !win.targetIds.includes(targetId))  return false;

  const now = new Date();

  // One-time fixed window takes priority
  if (win.fixedStart && win.fixedEnd) {
    return now >= win.fixedStart && now <= win.fixedEnd;
  }

  // Recurring weekly window
  const { day, hhmm } = currentTimeInZone(win.timezone);

  // Day-of-week check (empty = every day)
  if (win.daysOfWeek.length > 0 && !win.daysOfWeek.includes(day)) return false;

  // Overnight window: startTime > endTime (e.g. 22:00–06:00)
  if (cmpTime(win.startTime, win.endTime) > 0) {
    return cmpTime(hhmm, win.startTime) >= 0 || cmpTime(hhmm, win.endTime) < 0;
  }

  // Same-day window
  return cmpTime(hhmm, win.startTime) >= 0 && cmpTime(hhmm, win.endTime) <= 0;
}

// ─── Public API ───────────────────────────────────────────────────────────────

let _cachedWindows: FreezeWindow[] = [];
let _cacheExpiry   = 0;

/**
 * Returns true if the given provider+targetId is currently in any active freeze window.
 * Windows are cached for 60 seconds to avoid per-change DB queries.
 */
export async function isInFreezeWindow(provider: string, targetId: string): Promise<boolean> {
  const now = Date.now();
  if (now > _cacheExpiry) {
    _cachedWindows = await prisma.freezeWindow.findMany({ where: { isActive: true } });
    _cacheExpiry   = now + 60_000; // refresh every 60s
  }

  return _cachedWindows.some((w) => isFrozen(w, provider, targetId));
}
