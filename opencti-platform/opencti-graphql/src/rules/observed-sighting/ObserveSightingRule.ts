/* eslint-disable camelcase */
import {
  createInferredRelation,
  deleteInferredRuleElement,
  stixLoadById,
} from '../../database/middleware';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import def from './ObserveSightingDefinition';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import { createRuleContent } from '../rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import type { RuleRuntime } from '../../types/rules';
import type { StixObject, StixDomainObject } from '../../types/stix-common';
import type { StixIndicator, StixObservedData } from '../../types/stix-sdo';
import type { StixRelation } from '../../types/stix-sro';
import type { BasicStoreEntity, BasicStoreRelation, StoreObject } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { internalLoadById, listAllRelations } from '../../database/middleware-loader';
import type { Event, RelationCreation } from '../../types/event';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';

// 'If **observed-data A** (`created-by` **identity X**) have `object` **observable B** and **indicator C** ' +
// 'is `based-on` **observable B**, then **indicator C** is `sighted` in **identity X**.';
const ruleObserveSightingBuilder = (): RuleRuntime => {
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
  const handleIndicatorUpsert = async (context: AuthContext, indicator: StixDomainObject) => {
    const events: Array<Event> = [];
    const { id: indicatorId } = indicator.extensions[STIX_EXT_OCTI];
    const { object_marking_refs: indicatorMarkings } = indicator;
    const baseOnArgs = { toType: ABSTRACT_STIX_CYBER_OBSERVABLE, fromId: indicatorId };
    const baseOnRelations = await listAllRelations<BasicStoreRelation>(context, RULE_MANAGER_USER, RELATION_BASED_ON, baseOnArgs);
    for (let index = 0; index < baseOnRelations.length; index += 1) {
      const { internal_id: baseOnId, toId: observableId } = baseOnRelations[index];
      // Get the observed-data
      const objectsArgs = { fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], toId: observableId };
      const objectsRelations = await listAllRelations<BasicStoreRelation>(context, RULE_MANAGER_USER, RELATION_OBJECT, objectsArgs);
      for (let objectIndex = 0; objectIndex < objectsRelations.length; objectIndex += 1) {
        const { internal_id: objectId, fromId: observedDataId } = objectsRelations[objectIndex];
        const observedData = (await internalLoadById(context, RULE_MANAGER_USER, observedDataId)) as unknown as BasicStoreEntity;
        const { [RELATION_CREATED_BY]: organizationId, confidence } = observedData;
        const { number_observed, first_observed, last_observed } = observedData;
        if (organizationId) {
          const organization = (await internalLoadById(context, RULE_MANAGER_USER, organizationId)) as unknown as BasicStoreEntity;
          const { [RELATION_OBJECT_MARKING]: organizationMarkings } = organization;
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
          const elementMarkings = [...(organizationMarkings || []), ...(indicatorMarkings || [])];
          const ruleContent = createRuleContent(id, dependencies, explanation, {
            first_seen: first_observed,
            last_seen: last_observed,
            attribute_count: number_observed,
            confidence,
            objectMarking: elementMarkings,
          });
          const inferredRelation = await createInferredRelation(context, input, ruleContent) as RelationCreation;
          // Re inject event if needed
          if (inferredRelation.event) {
            events.push(inferredRelation.event);
          }
        }
      }
    }
    return events;
  };
  const handleObservedDataUpsert = async (context: AuthContext, observedData: StixObservedData) => {
    const events: Array<Event> = [];
    const { created_by_ref: organizationId } = observedData;
    const { id: observedDataId } = observedData.extensions[STIX_EXT_OCTI];
    const { number_observed, first_observed, last_observed, confidence } = observedData;
    const organization = (await internalLoadById(context, RULE_MANAGER_USER, organizationId)) as unknown as BasicStoreEntity;
    if (organization) {
      const { [RELATION_OBJECT_MARKING]: organizationMarkings } = organization;
      // Get all observable of this observed-data
      const listFromArgs = { fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], fromId: observedDataId };
      const objectsRelations = await listAllRelations<BasicStoreRelation>(context, RULE_MANAGER_USER, RELATION_OBJECT, listFromArgs);
      for (let objectIndex = 0; objectIndex < objectsRelations.length; objectIndex += 1) {
        const { internal_id: objectId, toId: observableId } = objectsRelations[objectIndex];
        // Get all base-on indicators of this observable
        const baseOnArgs = { fromTypes: [ENTITY_TYPE_INDICATOR], toId: observableId };
        const baseOnRelations = await listAllRelations<BasicStoreRelation>(context, RULE_MANAGER_USER, RELATION_BASED_ON, baseOnArgs);
        for (let index = 0; index < baseOnRelations.length; index += 1) {
          const { internal_id: baseOnId, fromId: indicatorId } = baseOnRelations[index];
          const indicator = (await internalLoadById(context, RULE_MANAGER_USER, indicatorId)) as unknown as BasicStoreEntity;
          const { [RELATION_OBJECT_MARKING]: indicatorMarkings } = indicator;
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
          const elementMarkings = [...(organizationMarkings || []), ...(indicatorMarkings || [])];
          const ruleContent = createRuleContent(id, dependencies, explanation, {
            first_seen: first_observed,
            last_seen: last_observed,
            attribute_count: number_observed,
            confidence,
            objectMarking: elementMarkings,
          });
          const inferredRelation = await createInferredRelation(context, input, ruleContent) as RelationCreation;
          // Re inject event if needed
          if (inferredRelation.event) {
            events.push(inferredRelation.event);
          }
        }
      }
    }
    return events;
  };
  const handleObservedDataRelationUpsert = async (context: AuthContext, objectRelation: StixRelation) => {
    const { source_ref: observedDataId } = objectRelation.extensions[STIX_EXT_OCTI];
    const observedData = (await stixLoadById(context, RULE_MANAGER_USER, observedDataId)) as unknown as StixObservedData;
    return handleObservedDataUpsert(context, observedData);
  };
  const handleObservableRelationUpsert = async (context: AuthContext, baseOnRelation: StixRelation) => {
    const { source_ref: indicatorId } = baseOnRelation.extensions[STIX_EXT_OCTI];
    const baseOnIndicator = (await stixLoadById(context, RULE_MANAGER_USER, indicatorId)) as unknown as StixIndicator;
    return handleIndicatorUpsert(context, baseOnIndicator);
  };
  const applyUpsert = async (data: StixObject): Promise<Array<Event>> => {
    const context = executionContext(def.name, RULE_MANAGER_USER);
    const events: Array<Event> = [];
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_INDICATOR) {
      return handleIndicatorUpsert(context, data as StixDomainObject);
    }
    if (entityType === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
      return handleObservedDataUpsert(context, data as StixObservedData);
    }
    const upsertRelation = data as StixRelation;
    const { relationship_type: relationType } = upsertRelation;
    if (relationType === RELATION_BASED_ON) {
      return handleObservableRelationUpsert(context, upsertRelation);
    }
    if (relationType === RELATION_OBJECT) {
      return handleObservedDataRelationUpsert(context, upsertRelation);
    }
    return events;
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<Array<Event>> => {
    const cleanPromiseEvents = deleteInferredRuleElement(def.id, element, deletedDependencies);
    return cleanPromiseEvents as unknown as Promise<Array<Event>>;
  };
  const insert = async (element: StixObject): Promise<Array<Event>> => applyUpsert(element);
  const update = async (element: StixObject): Promise<Array<Event>> => applyUpsert(element);
  return { ...def, insert, update, clean };
};
const RuleObserveSighting = ruleObserveSightingBuilder();

export default RuleObserveSighting;
