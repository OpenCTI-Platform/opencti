/* eslint-disable camelcase */
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalLoadById,
  listAllRelations,
  loadStixById,
} from '../../database/middleware';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import def from './ObserveSightingDefinition';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { RELATION_OBJECT } from '../../schema/stixMetaRelationship';
import { createRuleContent, RULE_MANAGER_USER } from '../rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import type { Event } from '../../types/event';
import type { Rule } from '../../types/rules';

// 'If **observed-data A** (`created-by` **identity X**) have `object` **observable B** and **indicator C** ' +
// 'is `based-on` **observable B**, then **indicator C** is `sighted` in **identity X**.';
const ruleObserveSightingBuilder = (): Rule => {
  const { id } = def;
  // Execution
  const generateDependencies = (
    observedDataId: string,
    objectId: string,
    observableId: string,
    organizationId: string,
    baseOnId: string,
    indicatorId: string
  ) => {
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
  const handleIndicatorUpsert = async (indicator: StixObject) => {
    const events: Array<Event> = [];
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
        const observedData = (await internalLoadById(RULE_MANAGER_USER, observedDataId)) as unknown as StoreObservedData;
        const { created_by_ref: organizationId, confidence, object_marking_refs } = observedData;
        const { number_observed, first_observed, last_observed } = observedData;
        if (organizationId) {
          const explanation = [observedDataId, objectId, observableId, baseOnId, indicatorId];
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
  const handleObservedDataUpsert = async (observedData: StoreObservedData) => {
    const events = [];
    const { x_opencti_id: observedDataId, created_by_ref: organizationId } = observedData;
    const { number_observed, first_observed, last_observed } = observedData;
    const { confidence, object_marking_refs } = observedData;
    const organization = (await internalLoadById(RULE_MANAGER_USER, organizationId)) as unknown as StoreBasicObject;
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
  const handleObservedDataRelationUpsert = async (objectRelation: StoreStixRelation) => {
    const { x_opencti_source_ref: observedDataId } = objectRelation;
    const observedData = (await loadStixById(RULE_MANAGER_USER, observedDataId)) as unknown as StoreObservedData;
    return handleObservedDataUpsert(observedData);
  };
  const handleObservableRelationUpsert = async (baseOnRelation: StoreStixRelation) => {
    const { x_opencti_source_ref: indicatorId } = baseOnRelation;
    const baseOnIndicator = (await loadStixById(RULE_MANAGER_USER, indicatorId)) as unknown as StixObject;
    return handleIndicatorUpsert(baseOnIndicator);
  };
  const applyUpsert = async (data: StixEntities | StoreStixRelation): Promise<Array<Event>> => {
    const events: Array<Event> = [];
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_INDICATOR) {
      return handleIndicatorUpsert(data);
    }
    if (entityType === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
      return handleObservedDataUpsert(data as StoreObservedData);
    }
    const upsertRelation = data as StoreStixRelation;
    const { relationship_type: relationType } = upsertRelation;
    if (relationType === RELATION_BASED_ON) {
      return handleObservableRelationUpsert(upsertRelation);
    }
    if (relationType === RELATION_OBJECT) {
      return handleObservedDataRelationUpsert(upsertRelation);
    }
    return events;
  };
  // Contract
  const clean = async (element: StixObject, deletedDependencies: Array<string>): Promise<Array<Event>> => {
    const cleanPromiseEvents = deleteInferredRuleElement(def.id, element, deletedDependencies);
    return cleanPromiseEvents as unknown as Promise<Array<Event>>;
  };
  const insert = async (element: StixEntities | StoreStixRelation): Promise<Array<Event>> => applyUpsert(element);
  const update = async (element: StixEntities | StoreStixRelation): Promise<Array<Event>> => applyUpsert(element);
  return { ...def, insert, update, clean };
};
const RuleObserveSighting = ruleObserveSightingBuilder();

export default RuleObserveSighting;
