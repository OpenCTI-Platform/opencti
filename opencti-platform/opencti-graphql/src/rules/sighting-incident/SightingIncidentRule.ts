/* eslint-disable camelcase */
import {
  createInferredEntity,
  createInferredRelation,
  deleteInferredRuleElement,
  stixLoadById,
} from '../../database/middleware';
import def from './SightingIncidentDefinition';
import { ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { createRuleContent } from '../rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import { RELATION_RELATED_TO, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import { listAllRelations } from '../../database/middleware-loader';
import type { StixIndicator } from '../../types/stix-sdo';
import type { StixSighting } from '../../types/stix-sro';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreRelation, StoreObject } from '../../types/store';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';

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
  const handleIndicatorUpsert = async (context: AuthContext, indicator: StixIndicator): Promise<void> => {
    const { extensions } = indicator;
    const indicatorId = extensions[STIX_EXT_OCTI].id;
    const { name, pattern, revoked, object_marking_refs, confidence } = indicator;
    if (!revoked) {
      const sightingsArgs = { toType: ENTITY_TYPE_IDENTITY, fromId: indicatorId };
      const sightingsRelations = await listAllRelations<BasicStoreRelation>(context, RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, sightingsArgs);
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
        const inferredEntity = await createInferredEntity(context, input, ruleContent, ENTITY_TYPE_INCIDENT);
        const ruleRelContent = createRuleContent(id, dependencies, explanation, ruleBaseContent);
        // Create **Incident C** `related-to` **indicator A**
        const created = inferredEntity.element as StoreObject;
        const incidentToIndicator = { fromId: created.internal_id, toId: indicatorId, relationship_type: RELATION_RELATED_TO };
        await createInferredRelation(context, incidentToIndicator, ruleRelContent);
        // Create **Incident C** `targets` **identity B**
        const incidentToIdentity = { fromId: created.internal_id, toId: identityId, relationship_type: RELATION_TARGETS };
        await createInferredRelation(context, incidentToIdentity, ruleRelContent);
      }
    }
  };
  const handleIndicatorRelationUpsert = async (context: AuthContext, sightingRelation: StixSighting) => {
    const indicatorId = sightingRelation.extensions[STIX_EXT_OCTI].sighting_of_ref;
    const sightingIndicator = await stixLoadById(context, RULE_MANAGER_USER, indicatorId);
    return handleIndicatorUpsert(context, sightingIndicator as StixIndicator);
  };
  const applyUpsert = async (data: StixIndicator | StixSighting): Promise<void> => {
    const context = executionContext(def.name, RULE_MANAGER_USER);
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_INDICATOR) {
      await handleIndicatorUpsert(context, data as StixIndicator);
    }
    if (entityType === STIX_SIGHTING_RELATIONSHIP) {
      await handleIndicatorRelationUpsert(context, data as StixSighting);
    }
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<void> => {
    await deleteInferredRuleElement(def.id, element, deletedDependencies);
  };
  const insert = async (element: StixIndicator | StixSighting): Promise<void> => {
    return applyUpsert(element);
  };
  const update = async (element: StixIndicator | StixSighting): Promise<void> => {
    return applyUpsert(element);
  };
  return { ...def, insert, update, clean };
};
const RuleSightingIncident = ruleSightingIncidentBuilder();

export default RuleSightingIncident;
