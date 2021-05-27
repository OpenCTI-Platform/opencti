/* eslint-disable camelcase */
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../../database/rabbitmq';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { INDEX_MARKINGS_FIELD } from '../../schema/general';
import { createInferredRelation, internalLoadById, listAllRelations } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { UnsupportedError } from '../../config/errors';
import { extractFieldsOfPatch } from '../../graphql/sseMiddleware';
import { commonRuleDeletionHandler, commonRuleRelationMergeHandler } from './CommonRuleHandler';

const listenedFields = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
const buildRelationToRelationRule = (name, description, relationType, scopeFields, scopeFilters) => {
  const applyUpsert = async (markings, data) => {
    const events = [];
    const { x_opencti_id: createdId } = data;
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    // Need to discover on the from and the to if attributed-to also exists
    // IN CREATION: (A) -> attributed-to -> (B)
    // (P) -> FIND_RELS (attributed-to) -> (A) -> attributed-to -> (B)
    // (P) -> attributed-to -> (B)
    const listFromCallback = async (relationships) => {
      for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
        const { id: foundRelationId, fromId, confidence, start_time, stop_time } = relationships[sIndex];
        const existingRange = buildPeriodFromDates(start_time, stop_time);
        const range = computeRangeIntersection(creationRange, existingRange);
        const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
        // We do not need to propagate the creation here.
        // Because created relation have the same type.
        const input = {
          fromId,
          toId: targetRef,
          relationship_type: relationType,
          objectMarking: [...(markings || []), ...(relInternalMarkings || [])],
          confidence: createdConfidence < confidence ? createdConfidence : confidence,
          start_time: range.start,
          stop_time: range.end,
          inferenceRule: {
            name,
            explanation: [foundRelationId, createdId], // Free form, depending of the rules
            dependencies: [fromId, foundRelationId, sourceRef, createdId, targetRef], // Must contains all participants ids
          },
        };
        const event = await createInferredRelation(input);
        if (event) {
          events.push(event);
        }
      }
    };
    const listFromArgs = { toId: sourceRef, callback: listFromCallback };
    await listAllRelations(SYSTEM_USER, relationType, listFromArgs);
    // Need to discover on the from and the to if attributed-to also exists
    // (A) -> attributed-to -> (B)
    // (A) -> attributed-to -> (B) -> FIND_RELS -> (P)
    // (A) -> attributed-to -> (P)
    const listToCallback = async (relationships) => {
      for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
        const { id: foundRelationId, confidence, toId, start_time, stop_time } = relationships[sIndex];
        const existingRange = buildPeriodFromDates(start_time, stop_time);
        const range = computeRangeIntersection(creationRange, existingRange);
        const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
        // We do not need to propagate the creation here.
        // Because created relation have the same type.
        const input = {
          fromId: sourceRef,
          toId,
          relationship_type: relationType,
          objectMarking: [...(markings || []), ...(relInternalMarkings || [])],
          confidence: createdConfidence < confidence ? createdConfidence : confidence,
          start_time: range.start,
          stop_time: range.end,
          inferenceRule: {
            name,
            explanation: [createdId, foundRelationId], // Free form, depending of the rules
            dependencies: [sourceRef, createdId, toId, foundRelationId, targetRef], // Must contains all participants ids
          },
        };
        const event = await createInferredRelation(input);
        if (event) {
          events.push(event);
        }
      }
    };
    const listToArgs = { fromId: targetRef, callback: listToCallback };
    await listAllRelations(SYSTEM_USER, relationType, listToArgs);
    return events;
  };
  const applyDelete = async (event) => commonRuleDeletionHandler(event);
  const applyMerge = async (data) => commonRuleRelationMergeHandler(relationType, data);
  const clean = async (event) => applyDelete(event);
  const apply = async (event) => {
    const { type, markings, data } = event;
    const isImpactedRelation = data.relationship_type === relationType;
    switch (type) {
      case EVENT_TYPE_UPDATE: {
        const patchedFields = extractFieldsOfPatch(data.x_opencti_patch);
        const isImpactedFields = listenedFields.some((f) => patchedFields.includes(f));
        if (isImpactedRelation && isImpactedFields) {
          const rel = await internalLoadById(SYSTEM_USER, data.x_opencti_id);
          return applyUpsert(markings, { ...data, ...rel });
        }
        return [];
      }
      case EVENT_TYPE_CREATE: {
        if (isImpactedRelation) {
          return applyUpsert(markings, data);
        }
        return [];
      }
      case EVENT_TYPE_DELETE: {
        return applyDelete(event);
      }
      case EVENT_TYPE_MERGE: {
        return applyMerge(data);
      }
      default:
        throw UnsupportedError(`Event ${type} not supported`);
    }
  };
  return { name, description, apply, clean, scopeFields, scopeFilters };
};

export default buildRelationToRelationRule;
