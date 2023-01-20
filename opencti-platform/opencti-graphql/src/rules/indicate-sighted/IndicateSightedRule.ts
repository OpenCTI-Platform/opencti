/* eslint-disable camelcase */
import * as R from 'ramda';
import def from './IndicateSightedDefinition';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { StixRelation, StixSighting } from '../../types/stix-sro';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import type { BasicStoreRelation, StoreObject } from '../../types/store';
import { RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import { computeAverage } from '../../database/utils';
import { createRuleContent } from '../rules';
import { createInferredRelation, deleteInferredRuleElement } from '../../database/middleware';
import { listAllRelations, RelationOptions } from '../../database/middleware-loader';
import { RELATION_INDICATES, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR
} from '../../schema/stixDomainObject';
import type { RuleRuntime } from '../../types/rules';
import { ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../../schema/general';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';

const indicateSightedRuleBuilder = (): RuleRuntime => {
  // Execution
  const applyFromStixRelation = async (context: AuthContext, data: StixRelation): Promise<void> => {
    // **indicator A** `indicates` **Malware C**
    const createdId = data.extensions[STIX_EXT_OCTI].id;
    const fromIndicator = data.extensions[STIX_EXT_OCTI].source_ref;
    const toMalware = data.extensions[STIX_EXT_OCTI].target_ref;
    const { object_marking_refs: markings, confidence: createdConfidence } = data;
    const creationRange = buildPeriodFromDates(data.start_time, data.stop_time);
    // Need to find **indicator A** `sighted` **identity/location B**
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
        // Create the inferred targets relation
        const input = { fromId: toMalware, toId: organizationId, relationship_type: RELATION_TARGETS };
        const ruleContent = createRuleContent(def.id, dependencies, explanation, {
          confidence: computedConfidence,
          start_time: range.start,
          stop_time: range.end,
          objectMarking: elementMarkings
        });
        await createInferredRelation(context, input, ruleContent);
      }
    };
    const listFromArgs: RelationOptions<BasicStoreRelation> = {
      fromId: fromIndicator,
      toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION],
      callback: listFromCallback
    };
    await listAllRelations(context, RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, listFromArgs);
  };
  const applyFromStixSighting = async (context: AuthContext, data: StixSighting): Promise<void> => {
    // **indicator A** `sighted` **identity/location B**
    const createdId = data.extensions[STIX_EXT_OCTI].id;
    const fromSightingIndicator = data.extensions[STIX_EXT_OCTI].sighting_of_ref;
    const toSightingOrganization = R.head(data.extensions[STIX_EXT_OCTI].where_sighted_refs);
    const { object_marking_refs: markings } = data;
    const { confidence: createdConfidence } = data;
    const creationRange = buildPeriodFromDates(data.first_seen, data.last_seen);
    // Need to find **indicator A** `indicates` **malware/threat actor/intrusion set/campaign/incident C**
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
        // Create the inferred targets relation
        const input = { fromId: malwareId, toId: toSightingOrganization, relationship_type: RELATION_TARGETS };
        const ruleContent = createRuleContent(def.id, dependencies, explanation, {
          confidence: computedConfidence,
          start_time: range.start,
          stop_time: range.end,
          objectMarking: elementMarkings
        });
        await createInferredRelation(context, input, ruleContent);
      }
    };
    const listFromArgs: RelationOptions<BasicStoreRelation> = {
      fromId: fromSightingIndicator,
      toTypes: [ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT],
      callback: listFromCallback
    };
    await listAllRelations(context, RULE_MANAGER_USER, RELATION_INDICATES, listFromArgs);
  };
  const applyUpsert = async (data: StixRelation | StixSighting): Promise<void> => {
    const context = executionContext(def.name, RULE_MANAGER_USER);
    if (data.extensions[STIX_EXT_OCTI].type === STIX_SIGHTING_RELATIONSHIP) {
      const sighting: StixSighting = data as StixSighting;
      return applyFromStixSighting(context, sighting);
    }
    const rel: StixRelation = data as StixRelation;
    return applyFromStixRelation(context, rel);
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<void> => {
    await deleteInferredRuleElement(def.id, element, deletedDependencies);
  };
  const insert = async (element: StixRelation): Promise<void> => {
    return applyUpsert(element);
  };
  const update = async (element: StixRelation): Promise<void> => {
    return applyUpsert(element);
  };
  return { ...def, insert, update, clean };
};
const IndicateSightedRule = indicateSightedRuleBuilder();

export default IndicateSightedRule;
