/* eslint-disable camelcase */
import {
  createInferredEntity,
  deleteInferredRuleElement,
  listAllRelations,
  stixDataById,
} from '../../database/middleware';
import def from './SightingIncidentDefinition';
import { ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { createRuleContent, RULE_MANAGER_USER, RULES_DECLARATION } from '../rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';

// 'If **indicator A** has `revoked` **false** and **indicator A** is `sighted` in ' +
// '**identity B**, then create **Incident C** `related-to` **indicator A** and ' +
// '`targets` **identity B**.';

const ruleSightingIncidentBuilder = () => {
  const { id } = def;
  // Execution
  const generateDependencies = (indicatorId, stixSightingId, identityId) => {
    return [
      // Entities dependencies
      indicatorId,
      identityId,
      // Relations dependencies
      stixSightingId,
    ];
  };
  const handleIndicatorUpsert = async (indicator) => {
    const events = [];
    const { x_opencti_id: indicatorId, name, revoked, object_marking_refs, confidence } = indicator;
    if (revoked === false) {
      const sightingsArgs = { toType: ENTITY_TYPE_IDENTITY, fromId: indicatorId };
      const sightingsRelations = await listAllRelations(RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, sightingsArgs);
      for (let index = 0; index < sightingsRelations.length; index += 1) {
        const { internal_id: sightingId, toId: identityId } = sightingsRelations[index];
        const dependencies = generateDependencies(indicatorId, identityId, sightingId);
        // Create the incident with everything
        const explanation = [indicatorId, identityId, sightingId];
        const input = { name: `Sighting on valid indicator ${name}`, description: 'Automatically generated incident' };
        const ruleContent = createRuleContent(id, dependencies, explanation, {
          confidence,
          objectMarking: object_marking_refs,
        });
        const event = await createInferredEntity(input, ruleContent, ENTITY_TYPE_INCIDENT);
        // Re inject event if needed
        if (event) {
          events.push(event);
        }
      }
    }
    return events;
  };
  const handleIndicatorRelationUpsert = async (sightingRelation) => {
    const { x_opencti_source_ref: indicatorId } = sightingRelation;
    const sightingIndicator = await stixDataById(RULE_MANAGER_USER, indicatorId);
    return handleIndicatorUpsert(sightingIndicator);
  };
  const applyUpsert = async (data) => {
    const events = [];
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_INDICATOR) {
      return handleIndicatorUpsert(data);
    }
    if (entityType === STIX_SIGHTING_RELATIONSHIP) {
      return handleIndicatorRelationUpsert(data);
    }
    return events;
  };
  // Contract
  const clean = async (element, deletedDependencies) => deleteInferredRuleElement(def.id, element, deletedDependencies);
  const insert = async (element) => applyUpsert(element);
  const update = async (element) => applyUpsert(element);
  return { ...def, insert, update, clean };
};
const RuleSightingIncident = ruleSightingIncidentBuilder();

// Declare the rule
RULES_DECLARATION.push(RuleSightingIncident);
export default RuleSightingIncident;
