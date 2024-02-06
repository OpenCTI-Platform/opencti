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
import def from './SightingObservableDefinition';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { computeAverage } from '../../database/utils';
import { createRuleContent } from '../rules-utils';
import { createInferredRelation, deleteInferredRuleElement } from '../../database/middleware';
import { listAllRelations } from '../../database/middleware-loader';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../../schema/general';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import { ENTITY_TYPE_INDICATOR } from '../../modules/indicator/indicator-types';
/*
'If **observable A** is `sighted` in **identity/location B** and '
 '**indicator C** `based on` **observable A**, '
 'then create **indicator C** `sighted` in **identity/location B**.';
 */
const sightingObservableRuleBuilder = () => {
    // Execution
    const applyFromStixRelation = (context, data) => __awaiter(void 0, void 0, void 0, function* () {
        // **indicator C** `based on` **observable A**
        const createdId = data.extensions[STIX_EXT_OCTI].id;
        const fromIndicator = data.extensions[STIX_EXT_OCTI].source_ref;
        const toObservable = data.extensions[STIX_EXT_OCTI].target_ref;
        const { object_marking_refs: markings, confidence: createdConfidence } = data;
        const creationRange = buildPeriodFromDates(data.start_time, data.stop_time);
        // Need to find **observable A** is `sighted` in **identity/location B*
        const listFromCallback = (relationships) => __awaiter(void 0, void 0, void 0, function* () {
            const rels = relationships.filter((r) => r.internal_id !== createdId);
            for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
                const basicSighting = rels[relIndex];
                const { internal_id: foundRelationId, toId: toSightingIdentityOrLocation, confidence } = basicSighting;
                const { [RELATION_OBJECT_MARKING]: object_marking_refs } = basicSighting;
                // We can have sighting or relationship depending on the first scanned relation
                const existingRange = buildPeriodFromDates(basicSighting.first_seen, basicSighting.last_seen);
                const range = computeRangeIntersection(creationRange, existingRange);
                const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
                const computedConfidence = computeAverage([createdConfidence, confidence]);
                // Rule content
                const dependencies = [fromIndicator, createdId, toObservable, foundRelationId, toSightingIdentityOrLocation];
                const explanation = [foundRelationId, createdId];
                // create **indicator C** `sighted` in **identity/location B**
                const input = { fromId: fromIndicator, toId: toSightingIdentityOrLocation, relationship_type: STIX_SIGHTING_RELATIONSHIP };
                const ruleContent = createRuleContent(def.id, dependencies, explanation, {
                    confidence: computedConfidence,
                    first_seen: range.start,
                    last_seen: range.end,
                    objectMarking: elementMarkings
                });
                yield createInferredRelation(context, input, ruleContent);
            }
        });
        const listFromArgs = {
            fromId: toObservable,
            toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION],
            callback: listFromCallback
        };
        yield listAllRelations(context, RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, listFromArgs);
    });
    const applyFromStixSighting = (context, data) => __awaiter(void 0, void 0, void 0, function* () {
        // **observable A** is `sighted` in **identity/location B**
        const createdId = data.extensions[STIX_EXT_OCTI].id;
        const fromObservable = data.extensions[STIX_EXT_OCTI].sighting_of_ref;
        const toSightingIdentityOrLocation = R.head(data.extensions[STIX_EXT_OCTI].where_sighted_refs);
        const { object_marking_refs: markings } = data;
        const { confidence: createdConfidence } = data;
        const creationRange = buildPeriodFromDates(data.first_seen, data.last_seen);
        // Need to find **indicator C** `based on` **observable A**
        const listFromCallback = (relationships) => __awaiter(void 0, void 0, void 0, function* () {
            const rels = relationships.filter((r) => r.internal_id !== createdId);
            for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
                const basicStoreRelation = rels[relIndex];
                const { internal_id: foundRelationId, fromId: indicatorId, confidence } = basicStoreRelation;
                const { [RELATION_OBJECT_MARKING]: object_marking_refs } = basicStoreRelation;
                // We can have sighting or relationship depending on the first scanned relation
                const existingRange = buildPeriodFromDates(basicStoreRelation.start_time, basicStoreRelation.stop_time);
                const range = computeRangeIntersection(creationRange, existingRange);
                const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
                const computedConfidence = computeAverage([createdConfidence, confidence]);
                // Rule content
                const dependencies = [fromObservable, createdId, toSightingIdentityOrLocation, foundRelationId, indicatorId];
                const explanation = [foundRelationId, createdId];
                // create **indicator C** `sighted` in **identity/location B**
                const input = { fromId: indicatorId, toId: toSightingIdentityOrLocation, relationship_type: STIX_SIGHTING_RELATIONSHIP };
                const ruleContent = createRuleContent(def.id, dependencies, explanation, {
                    confidence: computedConfidence,
                    first_seen: range.start,
                    last_seen: range.end,
                    objectMarking: elementMarkings
                });
                yield createInferredRelation(context, input, ruleContent);
            }
        });
        const listFromArgs = {
            toId: fromObservable,
            fromTypes: [ENTITY_TYPE_INDICATOR],
            callback: listFromCallback
        };
        yield listAllRelations(context, RULE_MANAGER_USER, RELATION_BASED_ON, listFromArgs);
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
const SightingObservableRule = sightingObservableRuleBuilder();
export default SightingObservableRule;
