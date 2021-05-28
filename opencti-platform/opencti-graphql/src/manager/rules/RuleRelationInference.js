/* eslint-disable camelcase */
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import {INDEX_MARKINGS_FIELD, RULE_PREFIX} from '../../schema/general';
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalLoadById,
  listAllRelations,
} from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { extractFieldsOfPatch } from '../../graphql/sseMiddleware';

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
          [`${RULE_PREFIX}${name}`]: {
            explanation: [foundRelationId, createdId], // Free form, depending of the rules
            dependencies: [fromId, foundRelationId, sourceRef, createdId, targetRef], // Must contains all participants ids
          },
        };
        const event = await createInferredRelation(name, input);
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
          [`${RULE_PREFIX}${name}`]: {
            explanation: [createdId, foundRelationId], // Free form, depending of the rules
            dependencies: [sourceRef, createdId, toId, foundRelationId, targetRef], // Must contains all participants ids
          },
        };
        const event = await createInferredRelation(name, input);
        if (event) {
          events.push(event);
        }
      }
    };
    const listToArgs = { fromId: targetRef, callback: listToCallback };
    await listAllRelations(SYSTEM_USER, relationType, listToArgs);
    return events;
  };
  const clean = async (element) => deleteInferredRuleElement(name, element);
  const insert = async (element) => {
    const { object_marking_refs: markings } = element;
    const isImpactedRelation = element.relationship_type === relationType;
    if (isImpactedRelation) {
      return applyUpsert(markings, element);
    }
    return [];
  };
  const update = async (element) => {
    const { object_marking_refs: markings } = element;
    const isImpactedRelation = element.relationship_type === relationType;
    const patchedFields = extractFieldsOfPatch(element.x_opencti_patch);
    const isImpactedFields = listenedFields.some((f) => patchedFields.includes(f));
    if (isImpactedRelation && isImpactedFields) {
      const rel = await internalLoadById(SYSTEM_USER, element.x_opencti_id);
      return applyUpsert(markings, { ...element, ...rel });
    }
    return [];
  };
  return { name, description, insert, update, clean, scopeFields, scopeFilters };
};

export default buildRelationToRelationRule;
