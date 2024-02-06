var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/* eslint-disable camelcase */
import * as R from 'ramda';
import def from './IndicateSightedDefinition';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { computeAverage } from '../../database/utils';
import { createRuleContent } from '../rules-utils';
import { createInferredRelation, deleteInferredRuleElement } from '../../database/middleware';
import { listAllRelations } from '../../database/middleware-loader';
import { RELATION_INDICATES, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../../schema/general';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
const indicateSightedRuleBuilder = () => {
    // Execution
    const applyFromStixRelation = (context, data) => __awaiter(void 0, void 0, void 0, function* () {
        // **indicator A** `indicates` **Malware C**
        const createdId = data.extensions[STIX_EXT_OCTI].id;
        const fromIndicator = data.extensions[STIX_EXT_OCTI].source_ref;
        const toMalware = data.extensions[STIX_EXT_OCTI].target_ref;
        const { object_marking_refs: markings, confidence: createdConfidence } = data;
        const creationRange = buildPeriodFromDates(data.start_time, data.stop_time);
        // Need to find **indicator A** `sighted` **identity/location B**
        const listFromCallback = (relationships) => __awaiter(void 0, void 0, void 0, function* () {
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
                yield createInferredRelation(context, input, ruleContent);
            }
        });
        const listFromArgs = {
            fromId: fromIndicator,
            toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION],
            callback: listFromCallback
        };
        yield listAllRelations(context, RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, listFromArgs);
    });
    const applyFromStixSighting = (context, data) => __awaiter(void 0, void 0, void 0, function* () {
        // **indicator A** `sighted` **identity/location B**
        const createdId = data.extensions[STIX_EXT_OCTI].id;
        const fromSightingIndicator = data.extensions[STIX_EXT_OCTI].sighting_of_ref;
        const toSightingOrganization = R.head(data.extensions[STIX_EXT_OCTI].where_sighted_refs);
        const { object_marking_refs: markings } = data;
        const { confidence: createdConfidence } = data;
        const creationRange = buildPeriodFromDates(data.first_seen, data.last_seen);
        // Need to find **indicator A** `indicates` **malware/threat actor/intrusion set/campaign/incident C**
        const listFromCallback = (relationships) => __awaiter(void 0, void 0, void 0, function* () {
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
                yield createInferredRelation(context, input, ruleContent);
            }
        });
        const listFromArgs = {
            fromId: fromSightingIndicator,
            toTypes: [ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT],
            callback: listFromCallback
        };
        yield listAllRelations(context, RULE_MANAGER_USER, RELATION_INDICATES, listFromArgs);
    });
    const applyUpsert = (data) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext(def.name, RULE_MANAGER_USER);
        if (data.extensions[STIX_EXT_OCTI].type === STIX_SIGHTING_RELATIONSHIP) {
            const sighting = data;
            return applyFromStixSighting(context, sighting);
        }
        const rel = data;
        return applyFromStixRelation(context, rel);
    });
    // Contract
    const clean = (element, deletedDependencies) => __awaiter(void 0, void 0, void 0, function* () {
        yield deleteInferredRuleElement(def.id, element, deletedDependencies);
    });
    const insert = (element) => __awaiter(void 0, void 0, void 0, function* () {
        return applyUpsert(element);
    });
    const update = (element) => __awaiter(void 0, void 0, void 0, function* () {
        return applyUpsert(element);
    });
    return Object.assign(Object.assign({}, def), { insert, update, clean });
};
const IndicateSightedRule = indicateSightedRuleBuilder();
export default IndicateSightedRule;
