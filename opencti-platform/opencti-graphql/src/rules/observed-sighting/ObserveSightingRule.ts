/* eslint-disable camelcase */
import { createInferredRelation, deleteInferredRuleElement, stixLoadById, } from '../../database/middleware';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import def from './ObserveSightingDefinition';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import { createRuleContent } from '../rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import type { RuleRuntime } from '../../types/rules';
import type { StixDomainObject, StixObject } from '../../types/stix-common';
import type { StixIndicator, StixObservedData } from '../../types/stix-sdo';
import type { StixRelation } from '../../types/stix-sro';
import type { BasicStoreEntity, BasicStoreRelation, StoreObject } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { internalLoadById, listAllRelations } from '../../database/middleware-loader';
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
  const handleIndicatorUpsert = async (context: AuthContext, indicator: StixDomainObject): Promise<void> => {
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
          await createInferredRelation(context, input, ruleContent);
        }
      }
    }
  };
  const handleObservedDataUpsert = async (context: AuthContext, observedData: StixObservedData): Promise<void> => {
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
          await createInferredRelation(context, input, ruleContent);
        }
      }
    }
  };
  const handleObservableRelationUpsert = async (context: AuthContext, baseOnRelation: StixRelation) => {
    const { source_ref: indicatorId } = baseOnRelation.extensions[STIX_EXT_OCTI];
    const baseOnIndicator = (await stixLoadById(context, RULE_MANAGER_USER, indicatorId)) as unknown as StixIndicator;
    return handleIndicatorUpsert(context, baseOnIndicator);
  };
  const applyUpsert = async (data: StixObject): Promise<void> => {
    const context = executionContext(def.name, RULE_MANAGER_USER);
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_INDICATOR) {
      await handleIndicatorUpsert(context, data as StixDomainObject);
    }
    if (entityType === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
      await handleObservedDataUpsert(context, data as StixObservedData);
    }
    const upsertRelation = data as StixRelation;
    const { relationship_type: relationType } = upsertRelation;
    if (relationType === RELATION_BASED_ON) {
      await handleObservableRelationUpsert(context, upsertRelation);
    }
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<void> => {
    await deleteInferredRuleElement(def.id, element, deletedDependencies);
  };
  const insert = async (element: StixObject): Promise<void> => applyUpsert(element);
  const update = async (element: StixObject): Promise<void> => applyUpsert(element);
  return { ...def, insert, update, clean };
};
const RuleObserveSighting = ruleObserveSightingBuilder();

export default RuleObserveSighting;
