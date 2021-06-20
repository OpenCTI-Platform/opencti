/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement, internalLoadById } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { extractFieldsOfPatch } from '../../graphql/sseMiddleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { INDEX_MARKINGS_FIELD } from '../../schema/general';
import { RELATION_LOCATED_AT, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './LocalizationOfTargetsDefinition';
import { createRulePatch } from '../RuleUtils';

const ruleLocalizationOfTargetsBuilder = () => {
  // config
  const relationType = RELATION_LOCATED_AT;
  const listenedFields = ['start_time', 'stop_time', 'confidence', 'object_marking_refs'];
  // execution
  const applyUpsert = async (markings, data) => {
    const events = [];
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef, x_opencti_id: createdId } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    const resolvedSource = await internalLoadById(SYSTEM_USER, sourceRef);
    if (resolvedSource.entity_type === RELATION_TARGETS) {
      const { id: foundRelationId, fromId: foundFrom, toId: foundTo } = resolvedSource;
      const { confidence, start_time, stop_time } = resolvedSource;
      const existingRange = buildPeriodFromDates(start_time, stop_time);
      const range = computeRangeIntersection(creationRange, existingRange);
      const relInternalMarkings = resolvedSource[INDEX_MARKINGS_FIELD];
      const dependencies = [foundFrom, foundTo, foundRelationId, createdId];
      const explanation = [foundRelationId, createdId];
      const input = {
        fromId: foundFrom,
        toId: targetRef,
        relationship_type: RELATION_TARGETS,
        objectMarking: [...(markings || []), ...(relInternalMarkings || [])],
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
    return events;
  };
  const clean = async (element) => deleteInferredRuleElement(def.id, element);
  const insert = async (element) => {
    const isImpactedEvent = element.relationship_type === relationType;
    const { object_marking_refs: markings } = element;
    if (isImpactedEvent) {
      return applyUpsert(markings, element);
    }
    return [];
  };
  const update = async (element) => {
    const isImpactedEvent = element.relationship_type === relationType;
    const { object_marking_refs: markings } = element;
    const patchedFields = extractFieldsOfPatch(element.x_opencti_patch);
    const isImpactedFields = listenedFields.some((f) => patchedFields.includes(f));
    if (isImpactedEvent && isImpactedFields) {
      const rel = await internalLoadById(SYSTEM_USER, element.x_opencti_id);
      return applyUpsert(markings, { ...element, ...rel });
    }
    return [];
  };
  return { ...def, insert, update, clean };
};
const RuleLocalizationOfTargets = ruleLocalizationOfTargetsBuilder();
export default RuleLocalizationOfTargets;
