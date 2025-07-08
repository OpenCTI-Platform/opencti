/* eslint-disable camelcase */
import { createInferredEntity, createInferredRelation, deleteInferredRuleElement, stixLoadById } from '../../database/middleware';
import def from './SightingIncidentDefinition';
import { ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { createRuleContent } from '../rules-utils';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import { RELATION_RELATED_TO, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import { fullRelationsList } from '../../database/middleware-loader';
import type { StixSighting } from '../../types/stix-2-1-sro';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreRelation, StoreObject } from '../../types/store';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import type { StixIndicator } from '../../modules/indicator/indicator-types';
import { ENTITY_TYPE_INDICATOR } from '../../modules/indicator/indicator-types';
import type { CreateInferredEntityCallbackFunction, CreateInferredRelationCallbackFunction, RuleRuntime } from '../../types/rules';
import { idGenFromData } from '../../schema/identifier';

// 'If **indicator A** has `revoked` **false** and **indicator A** is `sighted` in ' +
// '**identity B**, then create **Incident C** `related-to` **indicator A** and ' +
// '`targets` **identity B**.';

const ruleSightingIncidentBuilder = () => {
  const { id } = def;
  // Execution
  const generateDependencies = (indicatorId: string, stixSightingId: string, identityId: string) => {
    return [
      // Entities dependencies
      indicatorId,
      `${indicatorId}_revoked:${false}`,
      identityId,
      // Relations dependencies
      stixSightingId,
    ];
  };
  const handleIndicatorUpsert = async (
    context: AuthContext,
    indicator: StixIndicator,
    createInferredEntityCallback: CreateInferredEntityCallbackFunction,
    createInferredRelationCallback: CreateInferredRelationCallbackFunction
  ): Promise<void> => {
    const { extensions } = indicator;
    const indicatorId = extensions[STIX_EXT_OCTI].id;
    const { name, pattern, revoked, object_marking_refs, confidence } = indicator;
    if (!revoked) {
      const sightingsArgs = { toType: ENTITY_TYPE_IDENTITY, fromId: indicatorId };
      const sightingsRelations = await fullRelationsList<BasicStoreRelation>(context, RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, sightingsArgs);
      for (let index = 0; index < sightingsRelations.length; index += 1) {
        const { internal_id: sightingId, toId: identityId, first_seen, last_seen } = sightingsRelations[index];
        const dependencies = generateDependencies(indicatorId, identityId, sightingId);
        // Create the incident with everything
        const explanation = [indicatorId, identityId, sightingId];
        const input = {
          name: `Sighting on valid indicator ${name}`,
          description: `Automatically generated incident based on indicator pattern: ${pattern}`,
        };
        const ruleBaseContent = { confidence, objectMarking: object_marking_refs };
        const ruleContentData = { ...ruleBaseContent, first_seen, last_seen };
        const ruleContent = createRuleContent(id, dependencies, explanation, ruleContentData);
        const inferredEntityStandardId = idGenFromData(ENTITY_TYPE_INCIDENT, ruleContent.content.dependencies.sort());
        await createInferredEntityCallback(context, input, ruleContent, ENTITY_TYPE_INCIDENT);
        const ruleRelContent = createRuleContent(id, dependencies, explanation, ruleBaseContent);
        // Create **Incident C** `related-to` **indicator A**
        const incidentToIndicator = { fromId: inferredEntityStandardId, toId: indicatorId, relationship_type: RELATION_RELATED_TO };
        await createInferredRelationCallback(context, incidentToIndicator, ruleRelContent);
        // Create **Incident C** `targets` **identity B**
        const incidentToIdentity = { fromId: inferredEntityStandardId, toId: identityId, relationship_type: RELATION_TARGETS };
        await createInferredRelationCallback(context, incidentToIdentity, ruleRelContent);
      }
    }
  };
  const handleIndicatorRelationUpsert = async (
    context: AuthContext,
    sightingRelation: StixSighting,
    createInferredEntityCallback: CreateInferredEntityCallbackFunction,
    createInferredRelationCallback: CreateInferredRelationCallbackFunction
  ) => {
    const indicatorId = sightingRelation.extensions[STIX_EXT_OCTI].sighting_of_ref;
    const sightingIndicator = await stixLoadById(context, RULE_MANAGER_USER, indicatorId);
    return handleIndicatorUpsert(context, sightingIndicator as StixIndicator, createInferredEntityCallback, createInferredRelationCallback);
  };
  const applyUpsert = async (
    data: StixIndicator | StixSighting,
    createInferredEntityCallback: CreateInferredEntityCallbackFunction,
    createInferredRelationCallback: CreateInferredRelationCallbackFunction
  ): Promise<void> => {
    const context = executionContext(def.name, RULE_MANAGER_USER);
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_INDICATOR) {
      await handleIndicatorUpsert(context, data as StixIndicator, createInferredEntityCallback, createInferredRelationCallback);
    }
    if (entityType === STIX_SIGHTING_RELATIONSHIP) {
      await handleIndicatorRelationUpsert(context, data as StixSighting, createInferredEntityCallback, createInferredRelationCallback);
    }
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<void> => {
    await deleteInferredRuleElement(def.id, element, deletedDependencies);
  };
  const insert: RuleRuntime['insert'] = async (
    element,
    createInferredEntityCallback,
    createInferredRelationCallback
  ) => {
    return applyUpsert(element, createInferredEntityCallback, createInferredRelationCallback);
  };
  const update = async (element: StixIndicator | StixSighting): Promise<void> => {
    return applyUpsert(element, createInferredEntity, createInferredRelation);
  };
  return { ...def, insert, update, clean };
};
const RuleSightingIncident = ruleSightingIncidentBuilder();

export default RuleSightingIncident;
