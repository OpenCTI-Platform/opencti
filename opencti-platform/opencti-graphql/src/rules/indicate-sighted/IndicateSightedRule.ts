/* eslint-disable camelcase */
import * as R from 'ramda';
import def from './IndicateSightedDefinition';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { StixRelation, StixSighting } from '../../types/stix-sro';
import type { Event } from '../../types/event';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import type { BasicStoreRelation } from '../../types/store';
import { RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import { computeAverage } from '../../database/utils';
import { createRuleContent, RULE_MANAGER_USER } from '../rules';
import { createInferredRelation, deleteInferredRuleElement } from '../../database/middleware';
import { listAllRelations, RelationOptions } from '../../database/middleware-loader';
import type { StixObject } from '../../types/stix-common';
import { RELATION_INDICATES, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_MALWARE } from '../../schema/stixDomainObject';
import type { RuleRuntime } from '../../types/rules';

const indicateSightedRuleBuilder = (): RuleRuntime => {
  // Execution
  const applyFromStixRelation = async (data: StixRelation): Promise<Array<Event>> => {
    // **indicator A** `indicates` **Malware C**
    const events: Array<Event> = [];
    const createdId = data.extensions[STIX_EXT_OCTI].id;
    const fromIndicator = data.extensions[STIX_EXT_OCTI].source_ref;
    const toMalware = data.extensions[STIX_EXT_OCTI].target_ref;
    const { object_marking_refs: markings, confidence: createdConfidence } = data;
    const creationRange = buildPeriodFromDates(data.start_time, data.stop_time);
    // Need to find **indicator A** `sighted` **organization B**
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      const rels = relationships.filter((r) => r.internal_id !== createdId);
      for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
        const basicSighting = rels[relIndex];
        const { internal_id: foundRelationId, toId: organizationId, confidence } = basicSighting;
        const { [RELATION_OBJECT_MARKING]: object_marking_refs } = basicSighting;
        // We can have sighting or relationship depending on the first scanned relation
        const existingRange = buildPeriodFromDates(basicSighting.first_seen, basicSighting.last_seen);
        const range = computeRangeIntersection(creationRange, existingRange);
        const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
        const computedConfidence = computeAverage([createdConfidence, confidence]);
        // Rule content
        const dependencies = [fromIndicator, createdId, toMalware, foundRelationId, organizationId];
        const explanation = [foundRelationId, createdId];
        // Create the inferred sighting
        const input = { fromId: fromIndicator, toId: organizationId, relationship_type: STIX_SIGHTING_RELATIONSHIP };
        const ruleContent = createRuleContent(def.id, dependencies, explanation, {
          confidence: computedConfidence,
          first_seen: range.start,
          last_seen: range.end,
          objectMarking: elementMarkings
        });
        const event = await createInferredRelation(input, ruleContent);
        // Re inject event if needed
        if (event) {
          events.push(event);
        }
      }
    };
    const listFromArgs: RelationOptions<BasicStoreRelation> = {
      fromId: fromIndicator,
      toTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION],
      callback: listFromCallback
    };
    await listAllRelations(RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, listFromArgs);
    return events;
  };
  const applyFromStixSighting = async (data: StixSighting): Promise<Array<Event>> => {
    // **indicator A** `sighted` **organization B**
    const events: Array<Event> = [];
    const createdId = data.extensions[STIX_EXT_OCTI].id;
    const fromSightingIndicator = data.extensions[STIX_EXT_OCTI].sighting_of_ref;
    const toSightingOrganization = R.head(data.extensions[STIX_EXT_OCTI].where_sighted_refs);
    const { object_marking_refs: markings } = data;
    const { confidence: createdConfidence } = data;
    const creationRange = buildPeriodFromDates(data.first_seen, data.last_seen);
    // Need to find **indicator A** `indicates` **Malware C**
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      const rels = relationships.filter((r) => r.internal_id !== createdId);
      for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
        const basicStoreRelation = rels[relIndex];
        const { internal_id: foundRelationId, toId: malwareId, confidence } = basicStoreRelation;
        const { [RELATION_OBJECT_MARKING]: object_marking_refs } = basicStoreRelation;
        // We can have sighting or relationship depending on the first scanned relation
        const compareFromDate = basicStoreRelation.start_time;
        const compareToDate = basicStoreRelation.stop_time;
        const existingRange = buildPeriodFromDates(compareFromDate, compareToDate);
        const range = computeRangeIntersection(creationRange, existingRange);
        const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
        const computedConfidence = computeAverage([createdConfidence, confidence]);
        // Rule content
        const dependencies = [fromSightingIndicator, createdId, toSightingOrganization, foundRelationId, malwareId];
        const explanation = [foundRelationId, createdId];
        // Create the inferred relation
        const input = { fromId: malwareId, toId: toSightingOrganization, relationship_type: RELATION_TARGETS };
        const ruleContent = createRuleContent(def.id, dependencies, explanation, {
          confidence: computedConfidence,
          start_time: range.start,
          stop_time: range.end,
          objectMarking: elementMarkings
        });
        const event = await createInferredRelation(input, ruleContent);
        // Re inject event if needed
        if (event) {
          events.push(event);
        }
      }
    };
    const listFromArgs: RelationOptions<BasicStoreRelation> = {
      fromId: fromSightingIndicator,
      toTypes: [ENTITY_TYPE_MALWARE],
      callback: listFromCallback
    };
    await listAllRelations(RULE_MANAGER_USER, RELATION_INDICATES, listFromArgs);
    return events;
  };
  const applyUpsert = async (data: StixRelation | StixSighting): Promise<Array<Event>> => {
    if (data.extensions[STIX_EXT_OCTI].type === STIX_SIGHTING_RELATIONSHIP) {
      const sighting: StixSighting = data as StixSighting;
      return applyFromStixSighting(sighting);
    }
    const rel: StixRelation = data as StixRelation;
    return applyFromStixRelation(rel);
  };
  // Contract
  const clean = async (element: StixObject, deletedDependencies: Array<string>): Promise<Array<Event>> => {
    return deleteInferredRuleElement(def.id, element, deletedDependencies) as Promise<Array<Event>>;
  };
  const insert = async (element: StixRelation): Promise<Array<Event>> => {
    return applyUpsert(element);
  };
  const update = async (element: StixRelation): Promise<Array<Event>> => {
    return applyUpsert(element);
  };
  return { ...def, insert, update, clean };
};
const IndicateSightedRule = indicateSightedRuleBuilder();

export default IndicateSightedRule;
