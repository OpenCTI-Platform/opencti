/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement } from '../../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './LocalizationOfTargetsDefinition';
import { createRuleContent } from '../rules';
import { computeAverage } from '../../database/utils';
import type { StixRelation } from '../../types/stix-sro';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreObject, BasicStoreRelation, StoreObject } from '../../types/store';
import { RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import { internalLoadById } from '../../database/middleware-loader';

const ruleLocalizationOfTargetsBuilder = () => {
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
    const internalSource = await internalLoadById(context, RULE_MANAGER_USER, sourceRef) as unknown as BasicStoreObject;
    if (internalSource.entity_type === RELATION_TARGETS) {
      const resolvedSource = internalSource as BasicStoreRelation;
      const { internal_id: foundRelationId, fromId: foundFrom, toId: foundTo, [RELATION_OBJECT_MARKING]: object_marking_refs } = resolvedSource;
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
      await createInferredRelation(context, input, ruleContent);
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
const RuleLocalizationOfTargets = ruleLocalizationOfTargetsBuilder();

export default RuleLocalizationOfTargets;
