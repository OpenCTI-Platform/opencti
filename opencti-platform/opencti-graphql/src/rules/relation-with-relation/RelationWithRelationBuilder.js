/* eslint-disable camelcase */
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalLoadById,
  listAllRelations,
} from '../../database/middleware';
import { extractFieldsOfPatch } from '../../graphql/sseMiddleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { createRulePatch, RULE_MANAGER_USER } from '../RuleUtils';

const buildRelationWithRelationRule = (id, name, description, relationTypes, scopeFields, scopeFilters) => {
  const { leftType, rightType, creationType } = relationTypes;
  const resolveTypes = { [leftType]: rightType, [rightType]: leftType };
  const listenedFields = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
  // execution
  const applyUpsert = async (markings, data) => {
    const events = [];
    const { x_opencti_id: createdId, relationship_type } = data;
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    const relationTypeToFind = resolveTypes[relationship_type];
    // Need to find every other relations
    const listFromCallback = async (relationships) => {
      const rels = relationships.filter((r) => r.internal_id !== createdId);
      for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
        const { id: foundRelationId, toId, confidence } = rels[relIndex];
        const { start_time, stop_time, object_marking_refs } = rels[relIndex];
        // If we looking for left side relation, relation toId of found rel will be the to of the creation
        // If we looking for right side, relation toId of found rel will be the from of the creation
        const inferenceFromId = relationTypeToFind === leftType ? targetRef : toId;
        const inferenceToId = relationTypeToFind === leftType ? toId : targetRef;
        const existingRange = buildPeriodFromDates(start_time, stop_time);
        const range = computeRangeIntersection(creationRange, existingRange);
        // We do not need to propagate the creation here.
        // Because created relation have the same type.
        const dependencies = [sourceRef, createdId, targetRef, foundRelationId, toId];
        const explanation = [foundRelationId, createdId];
        const input = {
          fromId: inferenceFromId,
          toId: inferenceToId,
          relationship_type: creationType,
          objectMarking: [...(markings || []), ...(object_marking_refs || [])],
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
    const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
    await listAllRelations(RULE_MANAGER_USER, relationTypeToFind, listFromArgs);
    return events;
  };
  const clean = async (element) => deleteInferredRuleElement(id, element);
  const insert = async (element) => {
    const types = Object.keys(resolveTypes);
    const isImpactedEvent = types.includes(element.relationship_type);
    const { object_marking_refs: markings } = element;
    if (isImpactedEvent) {
      return applyUpsert(markings, element);
    }
    return [];
  };
  const update = async (element) => {
    const types = Object.keys(resolveTypes);
    const isImpactedEvent = types.includes(element.relationship_type);
    const { object_marking_refs: markings } = element;
    const patchedFields = extractFieldsOfPatch(element.x_opencti_patch);
    // When updating, only some fields have impacts
    const isImpactedFields = listenedFields.some((f) => patchedFields.includes(f));
    if (isImpactedEvent && isImpactedFields) {
      const rel = await internalLoadById(RULE_MANAGER_USER, element.x_opencti_id);
      return applyUpsert(markings, { ...element, ...rel });
    }
    return [];
  };
  return { id, name, description, scopeFields, scopeFilters, insert, update, clean };
};

export default buildRelationWithRelationRule;
