/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement } from '../../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import def from './ObservableRelatedDefinition';
import { createRuleContent } from '../rules';
import { computeAverage } from '../../database/utils';
import { listAllRelations } from '../../database/middleware-loader';
import type { StixRelation } from '../../types/stix-sro';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreRelation, StoreObject } from '../../types/store';
import { RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';

const ruleRelatedObservableBuilder = () => {
  // Execution
  const applyUpsert = async (data: StixRelation): Promise<void> => {
    const context = executionContext(def.name, RULE_MANAGER_USER);
    const { extensions } = data;
    const createdId = extensions[STIX_EXT_OCTI].id;
    const sourceRef = extensions[STIX_EXT_OCTI].source_ref;
    const targetRef = extensions[STIX_EXT_OCTI].target_ref;
    const { object_marking_refs: markings } = data;
    const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
    const creationRange = buildPeriodFromDates(startTime, stopTime);
    // Need to find every other relations
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      const rels = relationships.filter((r) => r.internal_id !== createdId);
      for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
        const { internal_id: foundRelationId, toId, confidence, start_time, stop_time } = rels[relIndex];
        const { [RELATION_OBJECT_MARKING]: object_marking_refs } = rels[relIndex];
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
        await createInferredRelation(context, input, ruleContent);
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
        await createInferredRelation(context, reverseInput, reverseRuleContent);
      }
    };
    const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
    await listAllRelations(context, RULE_MANAGER_USER, RELATION_RELATED_TO, listFromArgs);
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
const RuleObservableRelatedObservable = ruleRelatedObservableBuilder();

export default RuleObservableRelatedObservable;
