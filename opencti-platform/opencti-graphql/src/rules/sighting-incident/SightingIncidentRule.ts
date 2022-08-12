/* eslint-disable camelcase */
import {
  createInferredEntity,
  createInferredRelation,
  deleteInferredRuleElement,
  stixLoadById,
} from '../../database/middleware';
import def from './SightingIncidentDefinition';
import { ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { createRuleContent, RULE_MANAGER_USER } from '../rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import { RELATION_RELATED_TO, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import { listAllRelations } from '../../database/middleware-loader';
import type { StixIndicator } from '../../types/stix-sdo';
import type { StixSighting } from '../../types/stix-sro';
import type { Event } from '../../types/event';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreRelation, StoreObject } from '../../types/store';

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
  const handleIndicatorUpsert = async (indicator: StixIndicator): Promise<Array<Event>> => {
    const events: Array<Event> = [];
    const { extensions } = indicator;
    const indicatorId = extensions[STIX_EXT_OCTI].id;
    const { name, pattern, revoked, object_marking_refs, confidence } = indicator;
    if (!revoked) {
      const sightingsArgs = { toType: ENTITY_TYPE_IDENTITY, fromId: indicatorId };
      const sightingsRelations = await listAllRelations<BasicStoreRelation>(RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, sightingsArgs);
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
        const inferredEntity = await createInferredEntity(input, ruleContent, ENTITY_TYPE_INCIDENT);
        if (inferredEntity.event) {
          events.push(inferredEntity.event as Event);
        }
        const ruleRelContent = createRuleContent(id, dependencies, explanation, ruleBaseContent);
        // Create **Incident C** `related-to` **indicator A**
        const created = inferredEntity.element as StoreObject;
        const incidentToIndicator = {
          fromId: created.internal_id,
          toId: indicatorId,
          relationship_type: RELATION_RELATED_TO,
        };
        const incidentToIndicatorEvent = await createInferredRelation(incidentToIndicator, ruleRelContent) as Event;
        if (incidentToIndicatorEvent) {
          events.push(incidentToIndicatorEvent);
        }
        // Create **Incident C** `targets` **identity B**

        const incidentToIdentity = {
          fromId: created.internal_id,
          toId: identityId,
          relationship_type: RELATION_TARGETS,
        };
        const incidentToIdentityEvent = await createInferredRelation(incidentToIdentity, ruleRelContent) as Event;
        if (incidentToIdentityEvent) {
          events.push(incidentToIdentityEvent);
        }
      }
    }
    return events;
  };
  const handleIndicatorRelationUpsert = async (sightingRelation: StixSighting) => {
    const indicatorId = sightingRelation.extensions[STIX_EXT_OCTI].sighting_of_ref;
    const sightingIndicator = await stixLoadById(RULE_MANAGER_USER, indicatorId);
    return handleIndicatorUpsert(sightingIndicator as StixIndicator);
  };
  const applyUpsert = async (data: StixIndicator | StixSighting): Promise<Array<Event>> => {
    const events: Array<Event> = [];
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_INDICATOR) {
      return handleIndicatorUpsert(data as StixIndicator);
    }
    if (entityType === STIX_SIGHTING_RELATIONSHIP) {
      return handleIndicatorRelationUpsert(data as StixSighting);
    }
    return events;
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<Array<Event>> => {
    return deleteInferredRuleElement(def.id, element, deletedDependencies) as Promise<Array<Event>>;
  };
  const insert = async (element: StixIndicator | StixSighting): Promise<Array<Event>> => {
    return applyUpsert(element);
  };
  const update = async (element: StixIndicator | StixSighting): Promise<Array<Event>> => {
    return applyUpsert(element);
  };
  return { ...def, insert, update, clean };
};
const RuleSightingIncident = ruleSightingIncidentBuilder();

export default RuleSightingIncident;
