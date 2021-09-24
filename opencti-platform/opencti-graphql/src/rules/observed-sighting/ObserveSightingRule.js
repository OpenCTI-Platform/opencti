/* eslint-disable camelcase */
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalLoadById,
  listAllRelations,
  stixDataById,
} from '../../database/middleware';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import def from './ObserveSightingDefinition';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { RELATION_OBJECT } from '../../schema/stixMetaRelationship';
import { createRuleContent, RULE_MANAGER_USER, RULES_ATTRIBUTES_BEHAVIOR, RULES_DECLARATION } from '../rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';

// 'If **observed-data A** (`created-by` **identity X**) have `object` **observable B** and **indicator C** ' +
// 'is `based-on` **observable B**, then **indicator C** is `sighted` in **identity X**.';

const ruleObserveSightingBuilder = () => {
  const { id } = def;
  // Execution
  const generateDependencies = (observedDataId, objectId, observableId, organizationId, baseOnId, indicatorId) => {
    return [
      // Observed data dependencies
      observedDataId,
      `${observedDataId}_created_by_ref:${organizationId}`,
      // Entities dependencies
      observableId,
      organizationId,
      // Relations dependencies
      objectId,
      baseOnId,
      // Indicator dependencies
      indicatorId,
    ];
  };
  const handleIndicatorUpsert = async (indicator) => {
    const events = [];
    const { x_opencti_id: indicatorId } = indicator;
    const baseOnArgs = { toType: ABSTRACT_STIX_CYBER_OBSERVABLE, fromId: indicatorId };
    const baseOnRelations = await listAllRelations(RULE_MANAGER_USER, RELATION_BASED_ON, baseOnArgs);
    for (let index = 0; index < baseOnRelations.length; index += 1) {
      const { internal_id: baseOnId, toId: observableId } = baseOnRelations[index];
      // Get the observed-data
      const objectsArgs = { fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], toId: observableId };
      const objectsRelations = await listAllRelations(RULE_MANAGER_USER, RELATION_OBJECT, objectsArgs);
      for (let objectIndex = 0; objectIndex < objectsRelations.length; objectIndex += 1) {
        const { internal_id: objectId, fromId: observedDataId } = objectsRelations[objectIndex];
        const observedData = await internalLoadById(RULE_MANAGER_USER, observedDataId);
        const { created_by_ref: organizationId, confidence, object_marking_refs } = observedData;
        const { number_observed, first_observed, last_observed } = observedData;
        if (organizationId) {
          const explanation = [observedDataId, objectId, observableId, baseOnId, indicatorId];
          // eslint-disable-next-line prettier/prettier
            const dependencies = generateDependencies(
            observedDataId,
            objectId,
            observableId,
            organizationId,
            baseOnId,
            indicatorId
          );
          // Create the sighting between the indicator and the organization
          const input = { fromId: indicatorId, toId: organizationId, relationship_type: STIX_SIGHTING_RELATIONSHIP };
          const ruleContent = createRuleContent(id, dependencies, explanation, {
            first_seen: first_observed,
            last_seen: last_observed,
            attribute_count: number_observed,
            confidence,
            objectMarking: object_marking_refs,
          });
          const event = await createInferredRelation(input, ruleContent);
          // Re inject event if needed
          if (event) {
            events.push(event);
          }
        }
      }
    }
    return events;
  };
  const handleObservedDataUpsert = async (observedData) => {
    const events = [];
    // eslint-disable-next-line prettier/prettier
    const { x_opencti_id: observedDataId, created_by_ref: organizationId } = observedData;
    const { number_observed, first_observed, last_observed } = observedData;
    const { confidence, object_marking_refs } = observedData;
    const organization = await internalLoadById(RULE_MANAGER_USER, organizationId);
    if (organization) {
      // Get all observable of this observed-data
      const listFromArgs = { fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], fromId: observedDataId };
      const objectsRelations = await listAllRelations(RULE_MANAGER_USER, RELATION_OBJECT, listFromArgs);
      for (let objectIndex = 0; objectIndex < objectsRelations.length; objectIndex += 1) {
        const { internal_id: objectId, toId: observableId } = objectsRelations[objectIndex];
        // Get all base-on indicators of this observable
        const baseOnArgs = { fromTypes: [ENTITY_TYPE_INDICATOR], toId: observableId };
        const baseOnRelations = await listAllRelations(RULE_MANAGER_USER, RELATION_BASED_ON, baseOnArgs);
        for (let index = 0; index < baseOnRelations.length; index += 1) {
          const { internal_id: baseOnId, fromId: indicatorId } = baseOnRelations[index];
          const explanation = [observedDataId, objectId, observableId, baseOnId, indicatorId];
          // eslint-disable-next-line prettier/prettier
            const dependencies = generateDependencies(
            observedDataId,
            objectId,
            observableId,
            organization.internal_id,
            baseOnId,
            indicatorId
          );
          // Create the sighting between the indicator and the organization
          const input = { fromId: indicatorId, toId: organizationId, relationship_type: STIX_SIGHTING_RELATIONSHIP };
          const ruleContent = createRuleContent(id, dependencies, explanation, {
            first_seen: first_observed,
            last_seen: last_observed,
            attribute_count: number_observed,
            confidence,
            objectMarking: object_marking_refs,
          });
          const event = await createInferredRelation(input, ruleContent);
          // Re inject event if needed
          if (event) {
            events.push(event);
          }
        }
      }
    }
    return events;
  };
  const handleObservedDataRelationUpsert = async (objectRelation) => {
    const { x_opencti_source_ref: observedDataId } = objectRelation;
    const observedData = await stixDataById(RULE_MANAGER_USER, observedDataId);
    return handleObservedDataUpsert(observedData);
  };
  const handleObservableRelationUpsert = async (baseOnRelation) => {
    const { x_opencti_source_ref: indicatorId } = baseOnRelation;
    const baseOnIndicator = await stixDataById(RULE_MANAGER_USER, indicatorId);
    return handleIndicatorUpsert(baseOnIndicator);
  };
  const applyUpsert = async (data) => {
    const events = [];
    const { relationship_type: relationType } = data;
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_INDICATOR) {
      return handleIndicatorUpsert(data);
    }
    if (entityType === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
      return handleObservedDataUpsert(data);
    }
    if (relationType === RELATION_BASED_ON) {
      return handleObservableRelationUpsert(data);
    }
    if (relationType === RELATION_OBJECT) {
      return handleObservedDataRelationUpsert(data);
    }
    return events;
  };
  // Contract
  const clean = async (element, deletedDependencies) => deleteInferredRuleElement(def.id, element, deletedDependencies);
  const insert = async (element) => applyUpsert(element);
  const update = async (element) => applyUpsert(element);
  return { ...def, insert, update, clean };
};
const RuleObserveSighting = ruleObserveSightingBuilder();

// Add the merging attribute rule
RULES_ATTRIBUTES_BEHAVIOR.register(def.id, 'attribute_count', RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.SUM);
// Declare the rule
RULES_DECLARATION.push(RuleObserveSighting);
export default RuleObserveSighting;
