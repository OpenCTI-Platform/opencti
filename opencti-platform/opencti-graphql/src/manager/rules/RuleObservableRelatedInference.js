/* eslint-disable camelcase */
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalLoadById,
  listAllRelations,
} from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { extractFieldsOfPatch } from '../../graphql/sseMiddleware';
import { getTypeFromStixId } from '../../schema/schemaUtils';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import {INDEX_MARKINGS_FIELD, RULE_PREFIX} from '../../schema/general';

const name = 'observable_related';
const description =
  'This rule will infer the following fact: if an Observable A is related to an entity B and the Observable' +
  ' A is related to an entity C, the entity B is also related to the entity C.';
// const type = RELATION_RELATED_TO;
const listenedFields = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
const scopeFilters = { types: [RELATION_RELATED_TO] };
const relationType = RELATION_RELATED_TO;
const ruleRelatedObservableBuilder = () => {
  const applyUpsert = async (markings, data) => {
    const events = [];
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef, x_opencti_id: createdId } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    // Need to find every other relations
    const listFromCallback = async (relationships) => {
      const rels = relationships.filter((r) => r.internal_id !== createdId);
      for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
        const { id: foundRelationId, toId, confidence, start_time, stop_time } = rels[relIndex];
        const existingRange = buildPeriodFromDates(start_time, stop_time);
        const range = computeRangeIntersection(creationRange, existingRange);
        const relInternalMarkings = relationships[relIndex][INDEX_MARKINGS_FIELD];
        // We do not need to propagate the creation here.
        // Because created relation have the same type.
        const input = {
          fromId: targetRef,
          toId,
          relationship_type: relationType,
          objectMarking: [...(markings || []), ...(relInternalMarkings || [])],
          confidence: createdConfidence < confidence ? createdConfidence : confidence,
          start_time: range.start,
          stop_time: range.end,
          [`${RULE_PREFIX}${name}`]: {
            explanation: [foundRelationId, createdId],
            dependencies: [sourceRef, createdId, targetRef, foundRelationId, toId],
          },
        };
        const event = await createInferredRelation(name, input);
        if (event) {
          events.push(event);
        }
      }
    };
    const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
    await listAllRelations(SYSTEM_USER, relationType, listFromArgs);
    return events;
  };
  const clean = async (element) => deleteInferredRuleElement(name, element);
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
      const rel = await internalLoadById(SYSTEM_USER, element.x_opencti_id);
      return applyUpsert(markings, { ...element, ...rel });
    }
    return [];
  };
  return { name, description, insert, update, clean, scopeFields: '*', scopeFilters };
};
const RuleObservableRelatedObservable = ruleRelatedObservableBuilder();
export default RuleObservableRelatedObservable;
