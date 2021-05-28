/* eslint-disable camelcase */
import { isStixObject } from '../../schema/stixCoreObject';
import { generateInternalType } from '../../schema/schemaUtils';
import { internalLoadById, listAllThings, patchAttribute } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { extractFieldsOfPatch, rebuildInstanceWithPatch } from '../../graphql/sseMiddleware';
import { READ_DATA_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { RULE_PREFIX } from '../../schema/general';

const name = 'label';
const description =
  'This rule will compute the confidence level of any entity or relation. ' +
  'It will translate the reliability of the creator to a confidence ';
const scopeFields = ['confidence'];
const scopeFilters = { types: ['Stix-Core-Object', 'stix-core-relationship'] };
const reliabilityMapping = { A: 80, B: 60, C: 40, D: 20, E: 0, F: 0 };
const ruleConfidenceLevelBuilder = () => {
  // utils
  const applyUpsert = async (element) => {
    const { created_by_ref, x_opencti_id } = element;
    const entityType = generateInternalType(element);
    let confidenceLevel = 0;
    let ruleExplanation = null;
    if (created_by_ref) {
      const creator = await internalLoadById(SYSTEM_USER, created_by_ref);
      const { x_opencti_reliability: reliability } = creator;
      confidenceLevel = reliabilityMapping[reliability] || 0;
      ruleExplanation = { explanation: [created_by_ref], dependencies: [created_by_ref] };
    }
    const patch = { confidence: confidenceLevel, [`${RULE_PREFIX}${name}`]: ruleExplanation };
    await patchAttribute(SYSTEM_USER, x_opencti_id, entityType, patch);
  };
  const applyCreatorUpdate = async (markings, data) => {
    const { x_opencti_id, x_opencti_reliability: reliability } = data;
    const elementsCallback = async (elements) => {
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        const confidenceLevel = reliabilityMapping[reliability] || 0;
        const patch = {
          confidence: confidenceLevel,
          [`${RULE_PREFIX}${name}`]: { name, explanation: [x_opencti_id], dependencies: [x_opencti_id] },
        };
        await patchAttribute(SYSTEM_USER, element.id, element.entity_type, patch);
      }
    };
    const types = ['Stix-Core-Object', 'stix-core-relationship'];
    const filters = [{ key: 'rel_created-by.internal_id', values: [data.x_opencti_id] }];
    await listAllThings(SYSTEM_USER, types, {
      indices: READ_DATA_INDICES_WITHOUT_INFERRED, // No need to compute on inferences
      filters,
      callback: elementsCallback,
    });
  };
  // basics
  const insert = async (element) => {
    const entityType = generateInternalType(element);
    if (isStixObject(entityType)) {
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
  const clean = async (element) => {
    const { x_opencti_id } = element;
    const entityType = generateInternalType(element);
    const patch = { confidence: 0, [`${RULE_PREFIX}${name}`]: null };
    await patchAttribute(SYSTEM_USER, x_opencti_id, entityType, patch);
  };
  return { name, description, insert, update, clean, scopeFields, scopeFilters };
};
const RuleConfidenceLevel = ruleConfidenceLevelBuilder();
export default RuleConfidenceLevel;
