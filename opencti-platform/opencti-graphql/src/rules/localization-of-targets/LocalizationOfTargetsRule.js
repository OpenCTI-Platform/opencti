/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement, internalLoadById } from '../../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './LocalizationOfTargetsDefinition';
import { createRuleContent, RULE_MANAGER_USER } from '../rules';
import { computeAverage } from '../../database/utils';

const ruleLocalizationOfTargetsBuilder = () => {
  // Execution
  const applyUpsert = async (data) => {
    const events = [];
    const { x_opencti_id: createdId, object_marking_refs: markings } = data;
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    const resolvedSource = await internalLoadById(RULE_MANAGER_USER, sourceRef);
    if (resolvedSource.entity_type === RELATION_TARGETS) {
      const { id: foundRelationId, fromId: foundFrom, toId: foundTo, object_marking_refs } = resolvedSource;
      const { confidence, start_time, stop_time } = resolvedSource;
      const existingRange = buildPeriodFromDates(start_time, stop_time);
      const range = computeRangeIntersection(creationRange, existingRange);
      const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
      const computedConfidence = computeAverage([createdConfidence, confidence]);
      // Rule content
      const dependencies = [foundFrom, foundTo, foundRelationId, createdId];
      const explanation = [foundRelationId, createdId];
      // Create the inferred relation
      const input = { fromId: foundFrom, toId: targetRef, relationship_type: RELATION_TARGETS };
      const ruleContent = createRuleContent(def.id, dependencies, explanation, {
        confidence: computedConfidence,
        start_time: range.start,
        stop_time: range.end,
        objectMarking: elementMarkings,
      });
      const event = await createInferredRelation(input, ruleContent);
      // Re inject event if needed
      if (event) {
        events.push(event);
      }
    }
    return events;
  };
  // Contract
  const clean = async (element, deletedDependencies) => deleteInferredRuleElement(def.id, element, deletedDependencies);
  const insert = async (element) => applyUpsert(element);
  const update = async (element) => applyUpsert(element);
  return { ...def, insert, update, clean };
};
const RuleLocalizationOfTargets = ruleLocalizationOfTargetsBuilder();

export default RuleLocalizationOfTargets;
