/* eslint-disable camelcase */
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../../database/rabbitmq';
import { UnsupportedError } from '../../config/errors';
import { isStixObject } from '../../schema/stixCoreObject';
import { generateInternalType } from '../../schema/schemaUtils';
import { internalLoadById, listAllThings, patchAttribute } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { extractFieldsOfPatch, rebuildInstanceWithPatch } from '../../graphql/sseMiddleware';
import { READ_DATA_INDICES_WITHOUT_INFERRED } from '../../database/utils';

const name = 'rule_label';
const description =
  'This rule will compute the confidence level of any entity or relation. ' +
  'It will translate the reliability of the creator to a confidence ';
const scopeFields = ['confidence'];
const scopeFilters = { types: ['Stix-Core-Object', 'stix-core-relationship'] };
const reliabilityMapping = { A: 80, B: 60, C: 40, D: 20, E: 0, F: 0 };
const ruleConfidenceLevelBuilder = () => {
  const applyUpsert = async (markings, data) => {
    const { created_by_ref, x_opencti_id } = data;
    const entityType = generateInternalType(data);
    let confidenceLevel = 0;
    if (created_by_ref) {
      const creator = await internalLoadById(SYSTEM_USER, created_by_ref);
      const { x_opencti_reliability: reliability } = creator;
      confidenceLevel = reliabilityMapping[reliability] || 0;
    }
    const patch = { confidence: confidenceLevel };
    await patchAttribute(SYSTEM_USER, x_opencti_id, entityType, patch);
  };
  const applyCreatorUpdate = async (markings, data) => {
    const { x_opencti_reliability: reliability } = data;
    const elementsCallback = async (elements) => {
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        const confidenceLevel = reliabilityMapping[reliability] || 0;
        const patch = { confidence: confidenceLevel };
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
  // eslint-disable-next-line no-unused-vars
  const clean = async (event) => {};
  const apply = async (event) => {
    const { type, markings, data } = event;
    switch (type) {
      case EVENT_TYPE_UPDATE: {
        // If update is related to created_by_ref
        // Element confidence must be recomputed
        const patchedFields = extractFieldsOfPatch(data.x_opencti_patch);
        const instance = rebuildInstanceWithPatch(data, data.x_opencti_patch);
        if (patchedFields.includes('created_by_ref')) {
          await applyUpsert(markings, instance);
        }
        // or related to x_opencti_reliability
        // Elements related to this creator must be recomputed
        if (patchedFields.includes('x_opencti_reliability')) {
          await applyCreatorUpdate(markings, instance);
        }
        return [];
      }
      case EVENT_TYPE_MERGE:
      case EVENT_TYPE_CREATE: {
        const entityType = generateInternalType(data);
        if (isStixObject(entityType)) {
          return applyUpsert(markings, data);
        }
        return [];
      }
      case EVENT_TYPE_DELETE:
        // Nothing to update on deletion, field will be deleted too
        return [];
      default:
        throw UnsupportedError(`Event ${type} not supported`);
    }
  };
  return { name, description, apply, clean, scopeFields, scopeFilters };
};
const RuleConfidenceLevel = ruleConfidenceLevelBuilder();
export default RuleConfidenceLevel;
