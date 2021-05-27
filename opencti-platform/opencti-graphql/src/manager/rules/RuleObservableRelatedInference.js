/* eslint-disable camelcase */
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { createInferredRelation, internalLoadById, listAllRelations } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../../database/rabbitmq';
import { extractFieldsOfPatch } from '../../graphql/sseMiddleware';
import { UnsupportedError } from '../../config/errors';
import { getTypeFromStixId } from '../../schema/schemaUtils';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { INDEX_MARKINGS_FIELD } from '../../schema/general';
import { commonRuleDeletionHandler, commonRuleRelationMergeHandler } from './CommonRuleHandler';

const name = 'rule_related';
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
          inferenceRule: {
            name,
            explanation: [foundRelationId, createdId],
            dependencies: [sourceRef, createdId, targetRef, foundRelationId, toId],
          },
        };
        const event = await createInferredRelation(input);
        if (event) {
          events.push(event);
        }
      }
    };
    const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
    await listAllRelations(SYSTEM_USER, relationType, listFromArgs);
    return events;
  };
  const applyDelete = async (event) => commonRuleDeletionHandler(event);
  const applyMerge = async (data) => commonRuleRelationMergeHandler(relationType, data);
  const clean = async (event) => applyDelete(event);
  const apply = async (event) => {
    const { type, markings, data } = event;
    const isCorrectType = data.relationship_type === relationType;
    const { source_ref: sourceRef } = data;
    const sourceType = sourceRef ? getTypeFromStixId(sourceRef) : null;
    const isImpactedRelation = isCorrectType && sourceType && isStixCyberObservable(sourceType);
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
  return { name, description, apply, clean, scopeFields: '*', scopeFilters };
};
const RuleRelatedObservable = ruleRelatedObservableBuilder();
export default RuleRelatedObservable;
