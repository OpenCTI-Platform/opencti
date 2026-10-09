import { LRUCache } from 'lru-cache';
import type { AuthContext } from '../types/user';
import type { BaseEvent, StreamDataEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../schema/general';
import { redisAddWorkTouchedElement, redisGetWorkEventType } from './redis';
import { logApp } from '../config/conf';

// A work type never changes, so the cache needs no invalidation
const NO_EVENT_TYPE = 'none';

// Cache used to avoid making a read inside Redis for each element of a work to know
// if the weork is from an enrichment connector or not.
const workEventTypeCache = new LRUCache<string, string>({ max: 5000, ttl: 60 * 60 * 1000 });

/**
 * Empty the work event type cache. Tests only.
 */
export const resetWorkEventTypeCache = () => workEventTypeCache.clear();

/**
 * Resolve the connector event type of a work, reading redis once per work.
 */
const resolveWorkEventType = async (workId: string) => {
  const cached = workEventTypeCache.get(workId);
  if (cached) {
    return cached;
  }
  const eventType = (await redisGetWorkEventType(workId)) ?? NO_EVENT_TYPE;
  workEventTypeCache.set(workId, eventType);
  return eventType;
};

/**
 * Record the element of a create / update stream event into the touched elements of the current enrichment work.
 * Never throws: tracking must not make a knowledge write fail.
 */
export const trackWorkTouchedElement = async (context: AuthContext, event: BaseEvent) => {
  const { workId } = context;
  if (!workId || (event.type !== 'create' && event.type !== 'update')) {
    return;
  }
  try {
    const eventType = await resolveWorkEventType(workId);
    if (eventType !== CONNECTOR_INTERNAL_ENRICHMENT) {
      return;
    }
    const elementId = (event as StreamDataEvent).data?.extensions?.[STIX_EXT_OCTI]?.id;
    if (!elementId) {
      return;
    }
    await redisAddWorkTouchedElement(workId, elementId);
  } catch (err) {
    logApp.warn('[WORK] Unable to track touched element', { workId, cause: err });
  }
};
