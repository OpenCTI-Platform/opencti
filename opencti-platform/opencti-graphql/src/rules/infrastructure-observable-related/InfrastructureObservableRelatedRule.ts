/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement } from '../../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_CONSISTS_OF, RELATION_RELATED_TO, RELATION_USES } from '../../schema/stixCoreRelationship';
import def from './InfrastructureObservableRelatedDefinition';
import { createRuleContent } from '../rules-utils';
import { computeAverage } from '../../database/utils';
import { fullRelationsList } from '../../database/middleware-loader';
import type { StixRelation } from '../../types/stix-2-1-sro';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreRelation, StoreObject } from '../../types/store';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';

/**
 * Rule: If Entity A uses Infrastructure B, If Infrastructure B consists of Observable C,
 * Then Observable C related to Entity A
 *
 * Pattern:
 * - A uses B (A -> B)
 * - B consists-of C (B -> C)
 * - Result: C related-to A (C -> A)
 */
const ruleInfrastructureObservableRelatedBuilder = () => {
  // Execution
  const applyUpsert = async (data: StixRelation): Promise<void> => {
    const context = executionContext(def.name, RULE_MANAGER_USER);
    const { extensions } = data;
    const createdId = extensions[STIX_EXT_OCTI].id;
    const sourceRef = extensions[STIX_EXT_OCTI].source_ref;
    const targetRef = extensions[STIX_EXT_OCTI].target_ref;
    const { object_marking_refs: markings, relationship_type } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);

    // Case 1: When "B consists-of C" is created
    // Look for "uses" relations TO B (sourceRef), find A, then create "C related-to A"
    if (relationship_type === RELATION_CONSISTS_OF) {
      const listToCallback = async (relationships: Array<BasicStoreRelation>) => {
        const rels = relationships.filter((r) => r.internal_id !== createdId);
        for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
          const { internal_id: foundRelationId, fromId, confidence, start_time, stop_time } = rels[relIndex];
          const { [RELATION_OBJECT_MARKING]: object_marking_refs } = rels[relIndex];
          const existingRange = buildPeriodFromDates(start_time, stop_time);
          const range = computeRangeIntersection(creationRange, existingRange);
          const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
          const computedConfidence = computeAverage([createdConfidence, confidence]);
          // Rule content
          // Dependencies: Entity A (fromId), uses relation (foundRelationId), Infrastructure B (sourceRef),
          // consists-of relation (createdId), Observable C (targetRef)
          const dependencies = [fromId, foundRelationId, sourceRef, createdId, targetRef];
          const explanation = [foundRelationId, createdId];
          // Create the inferred relation: C related-to A
          const ruleContent = createRuleContent(def.id, dependencies, explanation, {
            confidence: computedConfidence,
            start_time: range.start,
            stop_time: range.end,
            objectMarking: elementMarkings,
          });
          const input = { fromId: targetRef, toId: fromId, relationship_type: RELATION_RELATED_TO };
          await createInferredRelation(context, input, ruleContent);
        }
      };
      // Look for "uses" relations TO sourceRef (Infrastructure B)
      const listToArgs = { toId: sourceRef, callback: listToCallback };
      await fullRelationsList(context, RULE_MANAGER_USER, RELATION_USES, listToArgs);
    }

    // Case 2: When "A uses B" is created
    // Look for "consists-of" relations FROM B (targetRef), find C, then create "C related-to A"
    if (relationship_type === RELATION_USES) {
      const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
        const rels = relationships.filter((r) => r.internal_id !== createdId);
        for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
          const { internal_id: foundRelationId, toId, confidence, start_time, stop_time } = rels[relIndex];
          const { [RELATION_OBJECT_MARKING]: object_marking_refs } = rels[relIndex];
          const existingRange = buildPeriodFromDates(start_time, stop_time);
          const range = computeRangeIntersection(creationRange, existingRange);
          const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
          const computedConfidence = computeAverage([createdConfidence, confidence]);
          // Rule content
          // Dependencies: Entity A (sourceRef), uses relation (createdId), Infrastructure B (targetRef),
          // consists-of relation (foundRelationId), Observable C (toId)
          const dependencies = [sourceRef, createdId, targetRef, foundRelationId, toId];
          const explanation = [createdId, foundRelationId];
          // Create the inferred relation: C related-to A
          const ruleContent = createRuleContent(def.id, dependencies, explanation, {
            confidence: computedConfidence,
            start_time: range.start,
            stop_time: range.end,
            objectMarking: elementMarkings,
          });
          const input = { fromId: toId, toId: sourceRef, relationship_type: RELATION_RELATED_TO };
          await createInferredRelation(context, input, ruleContent);
        }
      };
      // Look for "consists-of" relations FROM targetRef (Infrastructure B)
      const listFromArgs = { fromId: targetRef, callback: listFromCallback };
      await fullRelationsList(context, RULE_MANAGER_USER, RELATION_CONSISTS_OF, listFromArgs);
    }
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<void> => {
    await deleteInferredRuleElement(def.id, element, deletedDependencies);
  };
  const insert = async (element: StixRelation): Promise<void> => {
    return applyUpsert(element);
  };
  const update = async (element: StixRelation): Promise<void> => {
    return applyUpsert(element);
  };
  return { ...def, insert, update, clean };
};
const RuleInfrastructureObservableRelated = ruleInfrastructureObservableRelatedBuilder();

export default RuleInfrastructureObservableRelated;
