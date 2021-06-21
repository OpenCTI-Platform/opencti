/* eslint-disable camelcase */
import { generateInternalType } from '../../../schema/schemaUtils';
import {
  deleteInferredRuleElement,
  internalLoadById,
  listAllThings,
  patchAttribute,
} from '../../../database/middleware';
import { READ_DATA_INDICES_WITHOUT_INFERRED } from '../../../database/utils';
import { isStixDomainObject } from '../../../schema/stixDomainObject';
import { isStixCoreRelationship } from '../../../schema/stixCoreRelationship';
import { extractFieldsOfPatch, rebuildInstanceWithPatch } from '../../../graphql/sseMiddleware';
import def from './ConfidenceLevelDefinition';
import { createRulePatch, RULE_MANAGER_USER } from '../../RuleUtils';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_CREATED_BY } from '../../../schema/stixMetaRelationship';

const ruleConfidenceLevelBuilder = () => {
  // config
  const reliabilityMapping = { A: 80, B: 60, C: 40, D: 20, E: 0, F: 0 };
  // utils
  const applyUpsert = async (element) => {
    const { created_by_ref, x_opencti_id } = element;
    const entityType = generateInternalType(element);
    if (created_by_ref) {
      const creator = await internalLoadById(RULE_MANAGER_USER, created_by_ref);
      const { x_opencti_reliability: reliability } = creator;
      const confidence = reliabilityMapping[reliability] || 0;
      const patch = createRulePatch(def.id, [creator.id], [creator.id], { confidence });
      await patchAttribute(RULE_MANAGER_USER, x_opencti_id, entityType, patch);
    }
  };
  const applyCreatorUpdate = async (markings, data) => {
    const { x_opencti_id, x_opencti_reliability: reliability } = data;
    const elementsCallback = async (elements) => {
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        const confidence = reliabilityMapping[reliability] || 0;
        const patch = createRulePatch(def.id, [x_opencti_id], [x_opencti_id], { confidence });
        await patchAttribute(RULE_MANAGER_USER, element.id, element.entity_type, patch);
      }
    };
    const types = ['Stix-Core-Object', 'stix-core-relationship'];
    const filters = [{ key: buildRefRelationKey(RELATION_CREATED_BY), values: [data.x_opencti_id] }];
    await listAllThings(RULE_MANAGER_USER, types, {
      indices: READ_DATA_INDICES_WITHOUT_INFERRED, // No need to compute on inferences
      filters,
      callback: elementsCallback,
    });
  };
  // basics
  const insert = async (element) => {
    const entityType = generateInternalType(element);
    if (isStixDomainObject(entityType) || isStixCoreRelationship(entityType)) {
      return applyUpsert(element);
    }
    return [];
  };
  const update = async (element) => {
    const { object_marking_refs: markings } = element;
    // If update is related to created_by_ref
    // Element confidence must be recomputed
    const patchedFields = extractFieldsOfPatch(element.x_opencti_patch);
    const instance = rebuildInstanceWithPatch(element, element.x_opencti_patch);
    if (patchedFields.includes('created_by_ref')) {
      await applyUpsert(instance);
    }
    // or related to x_opencti_reliability
    // Elements related to this creator must be recomputed
    if (patchedFields.includes('x_opencti_reliability')) {
      await applyCreatorUpdate(markings, instance);
    }
    return [];
  };
  const clean = async (element) => deleteInferredRuleElement(def.id, element);
  return { ...def, insert, update, clean };
};
const ConfidenceLevel = ruleConfidenceLevelBuilder();
export default ConfidenceLevel;
