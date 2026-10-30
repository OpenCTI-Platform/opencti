import { LRUCache } from 'lru-cache';
import type { AuthContext } from '../types/user';
import type { BaseEvent, CreatedRef, StreamDataEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../schema/general';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { redisAddWorkTouchedElements, redisGetWorkTouchedElements, redisGetWorkTrackingInfo } from './redis';
import { logApp } from '../config/conf';
import { WORK_INVESTIGATION_STATUS_TO_REVIEW } from '../modules/workspace/workspace-types';

// How the touched elements of a work are tracked. enrichedEntityId is the internal id of the
// enriched entity, used to keep only the refs concerning it; null when the work has none.
type WorkTracking = {
  isTracked: boolean;
  enrichedEntityId: string | null;
};

// Cache used to avoid making a read inside Redis for each element of a work to know
// if the work is an enrichment triggered from an investigation or not.
const workTrackedCache = new LRUCache<string, WorkTracking>({ max: 5000, ttl: 60 * 60 * 1000 });

/**
 * Empty the work tracked cache. Tests only.
 */
export const resetWorkTrackedCache = () => workTrackedCache.clear();

/**
 * Tell whether and how the touched elements of a work are tracked, reading redis once per work.
 * Only enrichment works triggered from an investigation are tracked.
 */
const resolveWorkTracking = async (workId: string) => {
  const cached = workTrackedCache.get(workId);
  if (cached !== undefined) {
    return cached;
  }
  // A work type, investigation and enriched entity never change, so the cache needs no invalidation
  const { eventType, investigationId, enrichedEntityId } = await redisGetWorkTrackingInfo(workId);
  const tracking = {
    isTracked: eventType === CONNECTOR_INTERNAL_ENRICHMENT && !!investigationId,
    enrichedEntityId,
  };
  workTrackedCache.set(workId, tracking);
  return tracking;
};

/**
 * Tell whether a created ref is to record: it must start or end on the enriched entity, and not point
 * to a user, as the investigation expand leaves the refs to users out.
 */
const isTrackedRef = (ref: CreatedRef, enrichedEntityId: string | null) => {
  return !!enrichedEntityId
    && (ref.fromId === enrichedEntityId || ref.toId === enrichedEntityId)
    && ref.toType !== ENTITY_TYPE_USER;
};

/**
 * Record the element of a create / update stream event into the touched elements of the current work,
 * when it is an enrichment triggered from an investigation, together with the refs created with it
 * that concern the enriched entity (see isTrackedRef). Refs have no stream event of their own.
 * Never throws: tracking must not make a knowledge write fail.
 * @param createdRefs the ref relationships created with the event element
 */
export const trackWorkTouchedElement = async (context: AuthContext, event: BaseEvent, createdRefs: CreatedRef[] = []) => {
  const { workId } = context;
  if (!workId || (event.type !== 'create' && event.type !== 'update')) {
    return;
  }
  try {
    const { isTracked, enrichedEntityId } = await resolveWorkTracking(workId);
    if (!isTracked) {
      return;
    }
    const elementId = (event as StreamDataEvent).data?.extensions?.[STIX_EXT_OCTI]?.id;
    if (!elementId) {
      return;
    }
    const refIds = createdRefs
      .filter((ref) => isTrackedRef(ref, enrichedEntityId))
      .map((ref) => ref.internal_id);
    await redisAddWorkTouchedElements(workId, [elementId, ...refIds]);
  } catch (err) {
    logApp.warn('[WORK] Unable to track touched element', { workId, cause: err });
  }
};

// Written in the same update that marks the work complete. The Redis set keeps every id touched since the
// work started (it is only deleted with the work), so each completion replaces the persisted ids with it.
const TOUCHED_IDS_COMPLETION_SCRIPT = `
  ctx._source.touched_ids = params.touched_ids;`;

// Written in the same update, when isWorkToReview tells so.
const INVESTIGATION_STATUS_COMPLETION_SCRIPT = `
  ctx._source.investigation_status = "${WORK_INVESTIGATION_STATUS_TO_REVIEW}";`;

type CompletedWork = {
  id?: string;
  internal_id?: string;
  event_type?: string;
  investigation_id?: string;
  investigation_status?: string;
  touched_ids?: string[];
};

/**
 * Tell whether a work is an enrichment work, the only kind whose touched elements are tracked.
 */
const isEnrichmentWork = (work: CompletedWork) => work.event_type === CONNECTOR_INTERNAL_ENRICHMENT;

/**
 * Tell whether a completion puts a work of an investigation to review: at its first completion, and again at
 * any later completion bringing new touched ids. The Redis set only grows, so new ids make it bigger than the
 * persisted list, and new results reopen a work already reviewed (DONE). A repeated completion with nothing
 * new leaves the review status as it is.
 * Decided on the work loaded before the update: a concurrent change can only lead to an extra review.
 */
const isWorkToReview = (work: CompletedWork, touchedIds: string[]) => {
  return !!work.investigation_id && (!work.investigation_status || touchedIds.length > (work.touched_ids?.length ?? 0));
};

/**
 * Build the painless fragment and params to append to the update that completes an enrichment work.
 * The fragment replaces the persisted ids with the ids read from Redis (see TOUCHED_IDS_COMPLETION_SCRIPT)
 * and, when isWorkToReview tells so, sets the investigation status to TO_REVIEW.
 * Empty for any other kind of work.
 * @param work the work as loaded before the update, with its investigation fields and persisted touched ids
 */
export const buildEnrichmentCompletion = async (work: CompletedWork) => {
  const workId = work.internal_id ?? work.id;
  if (!workId || !isEnrichmentWork(work)) {
    return { source: '', params: {} };
  }
  const touched = await redisGetWorkTouchedElements(workId);
  const statusSource = isWorkToReview(work, touched.touched_ids) ? INVESTIGATION_STATUS_COMPLETION_SCRIPT : '';
  return {
    source: TOUCHED_IDS_COMPLETION_SCRIPT + statusSource,
    params: { ...touched },
  };
};
