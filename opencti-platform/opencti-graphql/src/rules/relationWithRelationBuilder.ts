/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement } from '../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../utils/format';
import { createRuleContent, RULE_MANAGER_USER } from './rules';
import { computeAverage } from '../database/utils';
import { listAllRelations } from '../database/middleware-loader';
import type { RelationTypes, RuleRuntime, RuleDefinition } from '../types/rules';
import type { StixRelation } from '../types/stix-sro';
import type { Event } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { StoreObject, BasicStoreRelation } from '../types/store';
import { RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';

const buildRelationWithRelationRule = (ruleDefinition: RuleDefinition, relationTypes: RelationTypes): RuleRuntime => {
  const { id } = ruleDefinition;
  const { leftType, rightType, creationType } = relationTypes;
  const resolveTypes = { [leftType]: rightType, [rightType]: leftType };
  // Execution
  const applyUpsert = async (data: StixRelation): Promise<Array<Event>> => {
    const events: Array<Event> = [];
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
        const event = await createInferredRelation(input, ruleContent);
        // Re inject event if needed
        if (event) {
          events.push(event);
        }
      }
    };
    const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
    await listAllRelations(RULE_MANAGER_USER, relationTypeToFind, listFromArgs);
    return events;
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<Array<Event>> => {
    return deleteInferredRuleElement(id, element, deletedDependencies) as Promise<Array<Event>>;
  };
  const insert = async (element: StixRelation): Promise<Array<Event>> => {
    return applyUpsert(element);
  };
  const update = async (element: StixRelation): Promise<Array<Event>> => {
    return applyUpsert(element);
  };
  return { ...ruleDefinition, insert, update, clean };
};

export default buildRelationWithRelationRule;
