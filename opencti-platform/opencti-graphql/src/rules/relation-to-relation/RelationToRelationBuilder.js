/* eslint-disable camelcase */
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { INDEX_MARKINGS_FIELD } from '../../schema/general';
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalLoadById,
  listAllRelations,
} from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { extractFieldsOfPatch } from '../../graphql/sseMiddleware';
import { createRulePatch } from '../RuleUtils';

const listenedFields = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
const buildRelationToRelationRule = (id, name, description, relationTypes, scopeFields, scopeFilters) => {
  const { leftType, rightType, creationType } = relationTypes;
  const resolveTypes = [leftType, rightType];
  const applyUpsert = async (markings, data) => {
    const events = [];
    const { x_opencti_id: createdId, relationship_type } = data;
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    // Need to discover on the from and the to if attributed-to also exists
    // IN CREATION: (A) -> RightType -> (B)
    // (P) -> FIND_RELS (leftType) -> (A) -> RightType -> (B)
    // (P) -> creationType -> (B)
    if (relationship_type === rightType) {
      const listFromCallback = async (relationships) => {
        for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
          const { id: foundRelationId, fromId, confidence, start_time, stop_time } = relationships[sIndex];
          const existingRange = buildPeriodFromDates(start_time, stop_time);
          const range = computeRangeIntersection(creationRange, existingRange);
          const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
          // We do not need to propagate the creation here.
          // Because created relation have the same type.
          const explanation = [foundRelationId, createdId];
          const dependencies = [fromId, foundRelationId, sourceRef, createdId, targetRef];
          const input = {
            fromId,
            toId: targetRef,
            relationship_type: creationType,
            objectMarking: [...(markings || []), ...(relInternalMarkings || [])],
            confidence: createdConfidence < confidence ? createdConfidence : confidence,
            start_time: range.start,
            stop_time: range.end,
            ...createRulePatch(id, dependencies, explanation),
          };
          const event = await createInferredRelation(id, input);
          if (event) {
            events.push(event);
          }
        }
      };
      const listFromArgs = { toId: sourceRef, callback: listFromCallback };
      await listAllRelations(SYSTEM_USER, leftType, listFromArgs);
    }
    // Need to discover on the from and the to if attributed-to also exists
    // (A) -> leftType -> (B)
    // (A) -> leftType -> (B) -> FIND_RELS (RightType) -> (P)
    // (A) -> creationType -> (P)
    if (relationship_type === leftType) {
      const listToCallback = async (relationships) => {
        for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
          const { id: foundRelationId, confidence, toId, start_time, stop_time } = relationships[sIndex];
          const existingRange = buildPeriodFromDates(start_time, stop_time);
          const range = computeRangeIntersection(creationRange, existingRange);
          const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
          // We do not need to propagate the creation here.
          // Because created relation have the same type.
          const explanation = [createdId, foundRelationId];
          const dependencies = [sourceRef, createdId, toId, foundRelationId, targetRef];
          const input = {
            fromId: sourceRef,
            toId,
            relationship_type: creationType,
            objectMarking: [...(markings || []), ...(relInternalMarkings || [])],
            confidence: createdConfidence < confidence ? createdConfidence : confidence,
            start_time: range.start,
            stop_time: range.end,
            ...createRulePatch(id, dependencies, explanation),
          };
          const event = await createInferredRelation(id, input);
          if (event) {
            events.push(event);
          }
        }
      };
      const listToArgs = { fromId: targetRef, callback: listToCallback };
      await listAllRelations(SYSTEM_USER, rightType, listToArgs);
    }
    return events;
  };
  const clean = async (element) => deleteInferredRuleElement(id, element);
  const insert = async (element) => {
    const { object_marking_refs: markings } = element;
    const isImpactedRelation = resolveTypes.includes(element.relationship_type);
    if (isImpactedRelation) {
      return applyUpsert(markings, element);
    }
    return [];
  };
  const update = async (element) => {
    const { object_marking_refs: markings } = element;
    const isImpactedRelation = resolveTypes.includes(element.relationship_type);
    const patchedFields = extractFieldsOfPatch(element.x_opencti_patch);
    const isImpactedFields = listenedFields.some((f) => patchedFields.includes(f));
    if (isImpactedRelation && isImpactedFields) {
      const rel = await internalLoadById(SYSTEM_USER, element.x_opencti_id);
      return applyUpsert(markings, { ...element, ...rel });
    }
    return [];
  };
  return { id, name, description, scopeFields, scopeFilters, insert, update, clean };
};

export default buildRelationToRelationRule;
