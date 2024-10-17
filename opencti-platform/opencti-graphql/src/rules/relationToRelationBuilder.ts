/* eslint-disable camelcase */
import { buildPeriodFromDates, computeRangeIntersection } from '../utils/format';
import { createInferredRelation, deleteInferredRuleElement } from '../database/middleware';
import { createRuleContent } from './rules-utils';
import { computeAverage } from '../database/utils';
import { listAllRelations } from '../database/middleware-loader';
import type { RelationTypes, RuleDefinition, RuleRuntime } from '../types/rules';
import type { BasicStoreRelation, StoreObject } from '../types/store';
import type { StixRelation } from '../types/stix-sro';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';
import type { DataEvent, UpdateEvent } from '../types/event';

const buildRelationToRelationRule = (ruleDefinition: RuleDefinition, relationTypes: RelationTypes): RuleRuntime => {
  const { id } = ruleDefinition;
  const { leftType, rightType, creationType } = relationTypes;
  // Execution
  const applyUpsert = async (data: StixRelation, event: DataEvent): Promise<void> => {
    const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER, event.draftContext);
    const { extensions } = data;
    const createdId = extensions[STIX_EXT_OCTI].id;
    const sourceRef = extensions[STIX_EXT_OCTI].source_ref;
    const targetRef = extensions[STIX_EXT_OCTI].target_ref;
    const { object_marking_refs: markings, relationship_type } = data;
    const { confidence: createdConfidence = 0, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    // Need to discover on the from and the to if attributed-to also exists
    // IN CREATION: (A) -> RightType -> (B)
    // (P) -> FIND_RELS (leftType) -> (A) -> RightType -> (B)
    // (P) -> creationType -> (B)
    if (relationship_type === rightType) {
      const listFromCallback = async (relationships: Array<BasicStoreRelation>): Promise<void> => {
        for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
          const { internal_id: foundRelationId, fromId, confidence = 0 } = relationships[sIndex];
          const { start_time, stop_time, [RELATION_OBJECT_MARKING]: object_marking_refs } = relationships[sIndex];
          const existingRange = buildPeriodFromDates(start_time, stop_time);
          const range = computeRangeIntersection(creationRange, existingRange);
          const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
          const computedConfidence = computeAverage([createdConfidence, confidence]);
          // We do not need to propagate the creation here.
          // Because created relation have the same type.
          const explanation = [foundRelationId, createdId];
          const dependencies = [fromId, foundRelationId, sourceRef, createdId, targetRef];
          // Create the inferred relation
          const input = { fromId, toId: targetRef, relationship_type: creationType };
          const ruleContent = createRuleContent(id, dependencies, explanation, {
            confidence: computedConfidence,
            start_time: range.start,
            stop_time: range.end,
            objectMarking: elementMarkings,
          });
          await createInferredRelation(context, input, ruleContent);
        }
      };
      const listFromArgs = { toId: sourceRef, callback: listFromCallback };
      await listAllRelations(context, RULE_MANAGER_USER, leftType, listFromArgs);
    }
    // Need to discover on the from and the to if attributed-to also exists
    // (A) -> leftType -> (B)
    // (A) -> leftType -> (B) -> FIND_RELS (RightType) -> (P)
    // (A) -> creationType -> (P)
    if (relationship_type === leftType) {
      const listToCallback = async (relationships: Array<BasicStoreRelation>): Promise<void> => {
        for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
          const { internal_id: foundRelationId, toId, confidence = 0 } = relationships[sIndex];
          const { start_time, stop_time, [RELATION_OBJECT_MARKING]: object_marking_refs } = relationships[sIndex];
          const existingRange = buildPeriodFromDates(start_time, stop_time);
          const range = computeRangeIntersection(creationRange, existingRange);
          const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
          const computedConfidence = computeAverage([createdConfidence, confidence]);
          // Rule content
          const explanation = [createdId, foundRelationId];
          const dependencies = [sourceRef, createdId, toId, foundRelationId, targetRef];
          // Create the inferred relation
          const input = { fromId: sourceRef, toId, relationship_type: creationType };
          const ruleContent = createRuleContent(id, dependencies, explanation, {
            confidence: computedConfidence,
            start_time: range.start,
            stop_time: range.end,
            objectMarking: elementMarkings,
          });
          await createInferredRelation(context, input, ruleContent);
        }
      };
      const listToArgs = { fromId: targetRef, callback: listToCallback };
      await listAllRelations(context, RULE_MANAGER_USER, rightType, listToArgs);
    }
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>, event: DataEvent): Promise<void> => {
    await deleteInferredRuleElement(id, element, deletedDependencies, { draftContext: event.draftContext });
  };
  const insert = async (element: StixRelation, event: DataEvent): Promise<void> => {
    return applyUpsert(element, event);
  };
  const update = async (element: StixRelation, event: UpdateEvent): Promise<void> => {
    return applyUpsert(element, event);
  };
  return { ...ruleDefinition, insert, update, clean };
};

export default buildRelationToRelationRule;
