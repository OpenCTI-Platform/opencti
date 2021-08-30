/* eslint-disable camelcase */
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalLoadById,
  listAllRelations,
} from '../../database/middleware';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import def from './ObserveSightingDefinition';

import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { RELATION_OBJECT } from '../../schema/stixMetaRelationship';
import { isEmptyField } from '../../database/utils';
import { createRuleContent, RULE_MANAGER_USER, RULES_ATTRIBUTES_BEHAVIOR, RULES_DECLARATION } from '../rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';

// 'If **observed-data A (created-by Organization X)** have `object` **observable B** and **indicator C** ' +
// 'is `based-on` **observable B**, and `revoked` = **false** and `x_opencti_detection` = **false**' +
// 'then **indicator C** is `sighted` in **organization X**.';

const ruleObserveSightingBuilder = () => {
  const { id } = def;
  // Execution
  const handleIndicatorUpsert = async (data) => {
    const events = [];
    const { x_opencti_id: indicatorId, revoked, x_opencti_detection } = data;
    if (revoked === false && x_opencti_detection === false) {
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
            const dependencies = [observedDataId, objectId, observableId, organizationId, baseOnId, indicatorId];
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
    }
    return events;
  };
  const handleObservedDataObjectUpsert = async (data) => {
    const events = [];
    const { x_opencti_id: objectId } = data;
    const { x_opencti_source_ref: observedDataId, x_opencti_target_ref: observableId } = data;
    const { created_by_ref: organizationId, number_observed, first_observed, last_observed } = data;
    const { confidence, object_marking_refs } = data;
    // Get the observed-data organization. If not organization, do nothing
    if (isEmptyField(organizationId)) return events;
    // Get all indicators of this observable
    const listFromArgs = { fromTypes: [ENTITY_TYPE_INDICATOR], toId: observableId };
    const baseOnRelations = await listAllRelations(RULE_MANAGER_USER, RELATION_BASED_ON, listFromArgs);
    if (baseOnRelations.length > 0) {
      // Check for each observable if indicator is based on and have correct attributes
      for (let baseOnIndex = 0; baseOnIndex < baseOnRelations.length; baseOnIndex += 1) {
        const { internal_id: baseOnId, fromId: fromIndicatorId } = baseOnRelations[baseOnIndex];
        const baseOnIndicator = await internalLoadById(RULE_MANAGER_USER, fromIndicatorId);
        const { internal_id: indicatorId, revoked, x_opencti_detection } = baseOnIndicator;
        if (revoked === false && x_opencti_detection === false) {
          const explanation = [observedDataId, objectId, observableId, baseOnId, indicatorId];
          const dependencies = [observedDataId, objectId, observableId, organizationId, baseOnId, indicatorId];
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
  const handleObservedDataUpsert = async (data) => {
    const events = [];
    // eslint-disable-next-line prettier/prettier
    const { x_opencti_id: observedDataId, created_by_ref: organizationId } = data;
    const { number_observed, first_observed, last_observed } = data;
    const { confidence, object_marking_refs } = data;
    if (organizationId) {
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
          const indicator = await internalLoadById(RULE_MANAGER_USER, indicatorId);
          const { revoked, x_opencti_detection } = indicator;
          if (revoked === false && x_opencti_detection === false) {
            const explanation = [observedDataId, objectId, observableId, baseOnId, indicatorId];
            const dependencies = [observedDataId, objectId, observableId, organizationId, baseOnId, indicatorId];
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
    }
    return events;
  };
  const handleObservableUpsert = async (data) => {
    const events = [];
    const { x_opencti_id: baseOnId } = data;
    const { x_opencti_source_ref: indicatorId, x_opencti_target_ref: observableId } = data;
    // Check if indicator is compatible
    const baseOnIndicator = await internalLoadById(RULE_MANAGER_USER, indicatorId);
    const { revoked, x_opencti_detection } = baseOnIndicator;
    if (revoked === false && x_opencti_detection === false) {
      // Get observed-data through object relation
      const listFromArgs = { fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], toId: observableId };
      const objectsRelations = await listAllRelations(RULE_MANAGER_USER, RELATION_OBJECT, listFromArgs);
      for (let index = 0; index < objectsRelations.length; index += 1) {
        const { internal_id: objectId, fromId: observedDataId } = objectsRelations[index];
        const observedData = await internalLoadById(RULE_MANAGER_USER, observedDataId);
        const { created_by_ref: organizationId, confidence, object_marking_refs } = observedData;
        const { number_observed, first_observed, last_observed } = observedData;
        if (organizationId) {
          const explanation = [observedDataId, objectId, observableId, baseOnId, indicatorId];
          const dependencies = [observedDataId, objectId, observableId, organizationId, baseOnId, indicatorId];
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
      return handleObservableUpsert(data);
    }
    if (relationType === RELATION_OBJECT) {
      return handleObservedDataObjectUpsert(data);
    }
    return events;
  };
  // Contract
  const clean = async (element, dependencyId) => deleteInferredRuleElement(def.id, element, dependencyId);
  const insert = async (element) => applyUpsert(element);
  const update = async (element) => applyUpsert(element);
  return { ...def, insert, update, clean };
};
const RuleObserveSighting = ruleObserveSightingBuilder();

// Add the merging attribute rule
RULES_ATTRIBUTES_BEHAVIOR.register(def.id, 'attribute_count', RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.SUM);
// Declare the rule
RULES_DECLARATION.push(RuleObserveSighting);
