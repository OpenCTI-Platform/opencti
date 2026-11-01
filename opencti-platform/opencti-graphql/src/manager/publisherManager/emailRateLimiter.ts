import { logApp } from '../../config/conf';

const HOUR_IN_MS = 60 * 60 * 1000;

export interface EmailRateLimiterOptions {
  maxPerHour: number;
  maxPerTriggerRecipientPerHour: number;
}

export interface EmailRateLimitRequest {
  nowInMs: number;
  userId: string;
  triggerKeys: string[];
  isPerRecipientLimited: boolean;
}

export interface EmailRateLimiter {
  filterAllowedTriggerKeys: (request: EmailRateLimitRequest) => string[];
}

// Caps notification email attempts per clock hour, for the platform and per (trigger, recipient), 0 means unlimited.
export const createEmailRateLimiter = (options: EmailRateLimiterOptions): EmailRateLimiter => {
  const { maxPerHour, maxPerTriggerRecipientPerHour } = options;
  const pairAttempts = new Map<string, number>();
  const warnedTriggerKeys = new Set<string>();
  const droppedRecipients = new Set<string>();
  let windowStart = 0;
  let instanceAttempts = 0;
  let droppedAttempts = 0;
  let isInstanceCapWarned = false;

  const startWindow = (nowWindowStart: number) => {
    if (droppedAttempts > 0) {
      const meta = { droppedAttempts, distinctRecipients: droppedRecipients.size, maxPerHour, maxPerTriggerRecipientPerHour };
      logApp.warn('[OPENCTI-MODULE] Publisher manager notification emails dropped over the hourly rate limit', meta);
    }
    windowStart = nowWindowStart;
    instanceAttempts = 0;
    droppedAttempts = 0;
    isInstanceCapWarned = false;
    pairAttempts.clear();
    warnedTriggerKeys.clear();
    droppedRecipients.clear();
  };

  const recordDrops = (userId: string, count: number) => {
    droppedAttempts += count;
    droppedRecipients.add(userId);
  };

  const dropOverInstanceCap = (request: EmailRateLimitRequest): string[] => {
    if (!isInstanceCapWarned) {
      logApp.warn('[OPENCTI-MODULE] Publisher manager notification email rate limit reached, emails dropped until the next hour', { maxPerHour });
      isInstanceCapWarned = true;
    }
    recordDrops(request.userId, request.triggerKeys.length);
    return [];
  };

  const dropOverPairCap = (request: EmailRateLimitRequest, triggerKey: string) => {
    if (!warnedTriggerKeys.has(triggerKey)) {
      logApp.warn('[OPENCTI-MODULE] Publisher manager trigger email cap reached for a recipient, emails dropped until the next hour', { triggerKey, maxPerTriggerRecipientPerHour });
      warnedTriggerKeys.add(triggerKey);
    }
    recordDrops(request.userId, 1);
  };

  const consumePairs = (request: EmailRateLimitRequest): string[] => {
    const allowedKeys: string[] = [];
    for (let i = 0; i < request.triggerKeys.length; i += 1) {
      const triggerKey = request.triggerKeys[i];
      const pairKey = `${triggerKey}|${request.userId}`;
      const attempts = pairAttempts.get(pairKey) ?? 0;
      if (attempts < maxPerTriggerRecipientPerHour) {
        pairAttempts.set(pairKey, attempts + 1);
        allowedKeys.push(triggerKey);
      } else {
        dropOverPairCap(request, triggerKey);
      }
    }
    return allowedKeys;
  };

  const filterAllowedTriggerKeys = (request: EmailRateLimitRequest): string[] => {
    const nowWindowStart = Math.floor(request.nowInMs / HOUR_IN_MS) * HOUR_IN_MS;
    if (nowWindowStart !== windowStart) {
      startWindow(nowWindowStart);
    }
    const isInstanceFull = maxPerHour > 0 && instanceAttempts >= maxPerHour;
    if (isInstanceFull) {
      return dropOverInstanceCap(request);
    }
    const isRecipientLimitActive = request.isPerRecipientLimited && maxPerTriggerRecipientPerHour > 0;
    const allowedKeys = isRecipientLimitActive ? consumePairs(request) : request.triggerKeys;
    if (allowedKeys.length > 0) {
      instanceAttempts += 1;
    }
    return allowedKeys;
  };

  return { filterAllowedTriggerKeys };
};
