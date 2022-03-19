/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement, listAllRelations } from '../../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import def from './ObservableRelatedDefinition';
import { createRuleContent, RULE_MANAGER_USER } from '../rules';
import { computeAverage } from '../../database/utils';

const ruleRelatedObservableBuilder = () => {
  // Execution
  const applyUpsert = async (data) => {
    const events = [];
    const { x_opencti_id: createdId, object_marking_refs: markings } = data;
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    // Need to find every other relations
    const listFromCallback = async (relationships) => {
      const rels = relationships.filter((r) => r.internal_id !== createdId);
      for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
        const { id: foundRelationId, toId, confidence, start_time, stop_time, object_marking_refs } = rels[relIndex];
        const existingRange = buildPeriodFromDates(start_time, stop_time);
        const range = computeRangeIntersection(creationRange, existingRange);
        const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
        const computedConfidence = computeAverage([createdConfidence, confidence]);
        // -----------------------------------------------------------------------------------------------------------
        // Because of related-to exists both side, we need to force the both directions
        // -----------------------------------------------------------------------------------------------------------
        // Create relation FROM = TO
        const dependencies = [sourceRef, createdId, targetRef, foundRelationId, toId];
        // Create the inferred relation
        const ruleContent = createRuleContent(def.id, dependencies, [foundRelationId, createdId], {
          confidence: computedConfidence,
          start_time: range.start,
          stop_time: range.end,
          objectMarking: elementMarkings,
        });
        const input = { fromId: targetRef, toId, relationship_type: RELATION_RELATED_TO };
        const event = await createInferredRelation(input, ruleContent);
        if (event) {
          events.push(event);
        }
        // -----------------------------------------------------------------------------------------------------------
        // Create relation TO = FROM
        // Create the inferred relation
        const reverseRuleContent = createRuleContent(def.id, dependencies, [createdId, foundRelationId], {
          confidence: computedConfidence,
          start_time: range.start,
          stop_time: range.end,
          objectMarking: elementMarkings,
        });
        const reverseInput = { fromId: toId, toId: targetRef, relationship_type: RELATION_RELATED_TO };
        const reverseEvent = await createInferredRelation(reverseInput, reverseRuleContent);
        if (reverseEvent) {
          events.push(reverseEvent);
        }
      }
    };
    const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
    await listAllRelations(RULE_MANAGER_USER, RELATION_RELATED_TO, listFromArgs);
    return events;
  };
  // Contract
  const clean = async (element, deletedDependencies) => deleteInferredRuleElement(def.id, element, deletedDependencies);
  const insert = async (element) => applyUpsert(element);
  const update = async (element) => applyUpsert(element);
  return { ...def, insert, update, clean };
};
const RuleObservableRelatedObservable = ruleRelatedObservableBuilder();

export default RuleObservableRelatedObservable;
