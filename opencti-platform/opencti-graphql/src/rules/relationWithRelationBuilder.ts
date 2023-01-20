/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement } from '../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../utils/format';
import { createRuleContent } from './rules';
import { computeAverage } from '../database/utils';
import { listAllRelations } from '../database/middleware-loader';
import type { RelationTypes, RuleDefinition, RuleRuntime } from '../types/rules';
import type { StixRelation } from '../types/stix-sro';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { BasicStoreRelation, StoreObject } from '../types/store';
import { RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';

const buildRelationWithRelationRule = (ruleDefinition: RuleDefinition, relationTypes: RelationTypes): RuleRuntime => {
  const { id } = ruleDefinition;
  const { leftType, rightType, creationType } = relationTypes;
  const resolveTypes = { [leftType]: rightType, [rightType]: leftType };
  // Execution
  const applyUpsert = async (data: StixRelation): Promise<void> => {
    const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);
    const { extensions } = data;
    const createdId = extensions[STIX_EXT_OCTI].id;
    const sourceRef = extensions[STIX_EXT_OCTI].source_ref;
    const targetRef = extensions[STIX_EXT_OCTI].target_ref;
    const { object_marking_refs: markings, relationship_type } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    const relationTypeToFind = resolveTypes[relationship_type];
    // Need to find every other relations
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      const rels = relationships.filter((r) => r.internal_id !== createdId);
      for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
        const { internal_id: foundRelationId, toId, confidence } = rels[relIndex];
        const { start_time, stop_time, [RELATION_OBJECT_MARKING]: object_marking_refs } = rels[relIndex];
        // If we looking for left side relation, relation toId of found rel will be the to of the creation
        // If we looking for right side, relation toId of found rel will be the from of the creation
        const inferenceFromId = relationTypeToFind === leftType ? targetRef : toId;
        const inferenceToId = relationTypeToFind === leftType ? toId : targetRef;
        const existingRange = buildPeriodFromDates(start_time, stop_time);
        const range = computeRangeIntersection(creationRange, existingRange);
        const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
        const computedConfidence = computeAverage([createdConfidence, confidence]);
        // Rule content
        const dependencies = [sourceRef, createdId, targetRef, foundRelationId, toId];
        const explanation = [foundRelationId, createdId];
        // Create the inferred relation
        const input = { fromId: inferenceFromId, toId: inferenceToId, relationship_type: creationType };
        const ruleContent = createRuleContent(id, dependencies, explanation, {
          confidence: computedConfidence,
          start_time: range.start,
          stop_time: range.end,
          objectMarking: elementMarkings,
        });
        await createInferredRelation(context, input, ruleContent);
      }
    };
    const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
    await listAllRelations(context, RULE_MANAGER_USER, relationTypeToFind, listFromArgs);
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<void> => {
    await deleteInferredRuleElement(id, element, deletedDependencies);
  };
  const insert = async (element: StixRelation): Promise<void> => {
    return applyUpsert(element);
  };
  const update = async (element: StixRelation): Promise<void> => {
    return applyUpsert(element);
  };
  return { ...ruleDefinition, insert, update, clean };
};

export default buildRelationWithRelationRule;
