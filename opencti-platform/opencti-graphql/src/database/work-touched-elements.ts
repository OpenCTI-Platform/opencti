import { LRUCache } from 'lru-cache';
import type { AuthContext } from '../types/user';
import type { BaseEvent, StreamDataEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../schema/general';
import { redisAddWorkTouchedElement, redisDeleteWorkTouchedElements, redisGetWorkEventType, redisGetWorkTouchedElements, WORK_TOUCHED_CAP } from './redis';
import { logApp } from '../config/conf';
import { WORK_INVESTIGATION_STATUS_TO_REVIEW } from '../modules/workspace/workspace-types';

// Cache used to avoid making a read inside Redis for each element of a work to know
// if the work is from an enrichment connector or not.
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
  // A work type never changes, so the cache needs no invalidation
  const eventType = (await redisGetWorkEventType(workId)) ?? 'none';
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

// Written in the same update that marks the work complete. Completion can be processed more than once
// (worker and connector, in any order, or a forced close while the connector still writes), and the
// Redis set is deleted after each one. The ids are therefore merged as a capped union:
// - a later completion reading an empty set is a no-op, it never wipes the persisted ids;
// - a later completion reading new ids (written after an early completion) adds them, up to the cap.
const TOUCHED_IDS_COMPLETION_SCRIPT = `
  if (ctx._source.touched_ids == null) {
    ctx._source.touched_ids = [];
  }
  for (def touchedId : params.touched_ids) {
    if (ctx._source.touched_ids.size() >= params.touched_ids_cap) {
      break;
    }
    if (!ctx._source.touched_ids.contains(touchedId)) {
      ctx._source.touched_ids.add(touchedId);
    }
  }`;

// Written in the same update, after the touched ids. A work of an investigation is put to review at its first
// completion, and again at any later completion bringing new touched ids: new results reopen a work already reviewed
// (DONE), while a repeated completion with nothing new (an empty read) leaves the review status as it is.
const INVESTIGATION_STATUS_COMPLETION_SCRIPT = `
  if (ctx._source.investigation_id != null
    && (ctx._source.investigation_status == null || params.touched_ids.size() > 0)) {
    ctx._source.investigation_status = params.investigation_status_to_review;
  }`;

/**
 * Tell whether a work is an enrichment work, the only kind whose touched elements are tracked.
 */
const isEnrichmentWork = (work: { event_type?: string }) => work.event_type === CONNECTOR_INTERNAL_ENRICHMENT;

/**
 * Build the painless fragment and params to append to the update that completes an enrichment work.
 * The fragment merges the ids read from Redis into the ids already persisted (capped union, see
 * TOUCHED_IDS_COMPLETION_SCRIPT), so a work completed more than once keeps every id, and an empty read
 * never erases them. For a work of an investigation, it also sets the investigation status to TO_REVIEW
 * (see INVESTIGATION_STATUS_COMPLETION_SCRIPT). Empty for any other kind of work.
 */
export const buildEnrichmentCompletion = async (work: { id?: string; internal_id?: string; event_type?: string }) => {
  const workId = work.internal_id ?? work.id;
  if (!workId || !isEnrichmentWork(work)) {
    return { source: '', params: {} };
  }
  const touched = await redisGetWorkTouchedElements(workId);
  return {
    source: TOUCHED_IDS_COMPLETION_SCRIPT + INVESTIGATION_STATUS_COMPLETION_SCRIPT,
    params: {
      ...touched,
      touched_ids_cap: WORK_TOUCHED_CAP,
      investigation_status_to_review: WORK_INVESTIGATION_STATUS_TO_REVIEW,
    },
  };
};

/**
 * Delete the Redis set of an enrichment work once its completion update has persisted the ids.
 * Does nothing for any other kind of work. Never throws: a failed cleanup is only logged, the set
 * then expires through its TTL.
 */
export const clearCompletedWorkTouchedElements = async (work: { id?: string; internal_id?: string; event_type?: string }) => {
  const workId = work.internal_id ?? work.id;
  if (!workId || !isEnrichmentWork(work)) {
    return;
  }
  try {
    await redisDeleteWorkTouchedElements([workId]);
  } catch (err) {
    logApp.warn('[WORK] Unable to clean the touched elements of a completed work', { workId, cause: err });
  }
};
