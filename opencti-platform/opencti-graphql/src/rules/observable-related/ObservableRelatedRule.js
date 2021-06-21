/* eslint-disable camelcase */
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalLoadById,
  listAllRelations,
} from '../../database/middleware';
import { extractFieldsOfPatch } from '../../graphql/sseMiddleware';
import { getTypeFromStixId } from '../../schema/schemaUtils';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import def from './ObservableRelatedDefinition';
import { createRulePatch, RULE_MANAGER_USER } from '../RuleUtils';

const ruleRelatedObservableBuilder = () => {
  // config
  const relationType = RELATION_RELATED_TO;
  const listenedFields = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
  // execution
  const applyUpsert = async (markings, data) => {
    const events = [];
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef, x_opencti_id: createdId } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    // Need to find every other relations
    const listFromCallback = async (relationships) => {
      const rels = relationships.filter((r) => r.internal_id !== createdId);
      for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
        const { id: foundRelationId, toId, confidence, start_time, stop_time, object_marking_refs } = rels[relIndex];
        const existingRange = buildPeriodFromDates(start_time, stop_time);
        const range = computeRangeIntersection(creationRange, existingRange);
        // We do not need to propagate the creation here.
        // Because created relation have the same type.
        const dependencies = [sourceRef, createdId, targetRef, foundRelationId, toId];
        const explanation = [foundRelationId, createdId];
        const input = {
          fromId: targetRef,
          toId,
          relationship_type: relationType,
          objectMarking: [...(markings || []), ...(object_marking_refs || [])],
          confidence: createdConfidence < confidence ? createdConfidence : confidence,
          start_time: range.start,
          stop_time: range.end,
          ...createRulePatch(def.id, dependencies, explanation),
        };
        const event = await createInferredRelation(def.id, input);
        if (event) {
          events.push(event);
        }
      }
    };
    const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
    await listAllRelations(RULE_MANAGER_USER, relationType, listFromArgs);
    return events;
  };
  const clean = async (element) => deleteInferredRuleElement(def.id, element);
  const insert = async (element) => {
    const isCorrectType = element.relationship_type === relationType;
    const { source_ref: sourceRef, object_marking_refs: markings } = element;
    const sourceType = sourceRef ? getTypeFromStixId(sourceRef) : null;
    const isImpactedEvent = isCorrectType && sourceType && isStixCyberObservable(sourceType);
    if (isImpactedEvent) {
      return applyUpsert(markings, element);
    }
    return [];
  };
  const update = async (element) => {
    const isCorrectType = element.relationship_type === relationType;
    const { source_ref: sourceRef, object_marking_refs: markings } = element;
    const sourceType = sourceRef ? getTypeFromStixId(sourceRef) : null;
    const isImpactedEvent = isCorrectType && sourceType && isStixCyberObservable(sourceType);
    const patchedFields = extractFieldsOfPatch(element.x_opencti_patch);
    const isImpactedFields = listenedFields.some((f) => patchedFields.includes(f));
    if (isImpactedEvent && isImpactedFields) {
      const rel = await internalLoadById(RULE_MANAGER_USER, element.x_opencti_id);
      return applyUpsert(markings, { ...element, ...rel });
    }
    return [];
  };
  return { ...def, insert, update, clean };
};
const RuleObservableRelatedObservable = ruleRelatedObservableBuilder();
export default RuleObservableRelatedObservable;
