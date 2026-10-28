import { LRUCache } from 'lru-cache';
import type { AuthContext } from '../types/user';
import type { BaseEvent, StreamDataEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../schema/general';
import { redisAddWorkTouchedElement, redisDeleteWorkTouchedElements, redisGetWorkTouchedElements, redisGetWorkTrackingInfo, WORK_TOUCHED_CAP } from './redis';
import { logApp } from '../config/conf';
import { WORK_INVESTIGATION_STATUS_TO_REVIEW } from '../modules/workspace/workspace-types';

// Cache used to avoid making a read inside Redis for each element of a work to know
// if the work is an enrichment triggered from an investigation or not.
const workTrackedCache = new LRUCache<string, boolean>({ max: 5000, ttl: 60 * 60 * 1000 });

/**
 * Empty the work tracked cache. Tests only.
 */
export const resetWorkTrackedCache = () => workTrackedCache.clear();

/**
 * Tell whether the touched elements of a work are tracked, reading redis once per work.
 * Only enrichment works triggered from an investigation are tracked.
 */
const resolveIsWorkTracked = async (workId: string) => {
  const cached = workTrackedCache.get(workId);
  if (cached !== undefined) {
    return cached;
  }
  // A work type and investigation never change, so the cache needs no invalidation
  const { eventType, investigationId } = await redisGetWorkTrackingInfo(workId);
  const isTracked = eventType === CONNECTOR_INTERNAL_ENRICHMENT && !!investigationId;
  workTrackedCache.set(workId, isTracked);
  return isTracked;
};

/**
 * Record the element of a create / update stream event into the touched elements of the current work,
 * when it is an enrichment triggered from an investigation.
 * Never throws: tracking must not make a knowledge write fail.
 */
export const trackWorkTouchedElement = async (context: AuthContext, event: BaseEvent) => {
  const { workId } = context;
  if (!workId || (event.type !== 'create' && event.type !== 'update')) {
    return;
  }
  try {
    const isTracked = await resolveIsWorkTracked(workId);
    if (!isTracked) {
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
    if (ctx._source.touched_ids.size() >= ${WORK_TOUCHED_CAP}) {
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
    ctx._source.investigation_status = ${WORK_INVESTIGATION_STATUS_TO_REVIEW};
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
    params: { ...touched },
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
