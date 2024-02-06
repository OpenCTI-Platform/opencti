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
import { buildPeriodFromDates, computeRangeIntersection } from '../utils/format';
import { createInferredRelation, deleteInferredRuleElement } from '../database/middleware';
import { createRuleContent } from './rules-utils';
import { computeAverage } from '../database/utils';
import { listAllRelations } from '../database/middleware-loader';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';
const buildRelationToRelationRule = (ruleDefinition, relationTypes) => {
    const { id } = ruleDefinition;
    const { leftType, rightType, creationType } = relationTypes;
    // Execution
    const applyUpsert = (data) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);
        const { extensions } = data;
        const createdId = extensions[STIX_EXT_OCTI].id;
        const sourceRef = extensions[STIX_EXT_OCTI].source_ref;
        const targetRef = extensions[STIX_EXT_OCTI].target_ref;
        const { object_marking_refs: markings, relationship_type } = data;
        const { confidence: createdConfidence = 0, start_time: startTime, stop_time: stopTime } = data;
        const creationRange = buildPeriodFromDates(startTime, stopTime);
        // Need to discover on the from and the to if attributed-to also exists
        // IN CREATION: (A) -> RightType -> (B)
        // (P) -> FIND_RELS (leftType) -> (A) -> RightType -> (B)
        // (P) -> creationType -> (B)
        if (relationship_type === rightType) {
            const listFromCallback = (relationships) => __awaiter(void 0, void 0, void 0, function* () {
                for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
                    const { internal_id: foundRelationId, fromId, confidence = 0 } = relationships[sIndex];
                    const { start_time, stop_time, [RELATION_OBJECT_MARKING]: object_marking_refs } = relationships[sIndex];
                    const existingRange = buildPeriodFromDates(start_time, stop_time);
                    const range = computeRangeIntersection(creationRange, existingRange);
                    const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
                    const computedConfidence = computeAverage([createdConfidence, confidence]);
                    // We do not need to propagate the creation here.
                    // Because created relation have the same type.
                    const explanation = [foundRelationId, createdId];
                    const dependencies = [fromId, foundRelationId, sourceRef, createdId, targetRef];
                    // Create the inferred relation
                    const input = { fromId, toId: targetRef, relationship_type: creationType };
                    const ruleContent = createRuleContent(id, dependencies, explanation, {
                        confidence: computedConfidence,
                        start_time: range.start,
                        stop_time: range.end,
                        objectMarking: elementMarkings,
                    });
                    yield createInferredRelation(context, input, ruleContent);
                }
            });
            const listFromArgs = { toId: sourceRef, callback: listFromCallback };
            yield listAllRelations(context, RULE_MANAGER_USER, leftType, listFromArgs);
        }
        // Need to discover on the from and the to if attributed-to also exists
        // (A) -> leftType -> (B)
        // (A) -> leftType -> (B) -> FIND_RELS (RightType) -> (P)
        // (A) -> creationType -> (P)
        if (relationship_type === leftType) {
            const listToCallback = (relationships) => __awaiter(void 0, void 0, void 0, function* () {
                for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
                    const { internal_id: foundRelationId, toId, confidence = 0 } = relationships[sIndex];
                    const { start_time, stop_time, [RELATION_OBJECT_MARKING]: object_marking_refs } = relationships[sIndex];
                    const existingRange = buildPeriodFromDates(start_time, stop_time);
                    const range = computeRangeIntersection(creationRange, existingRange);
                    const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
                    const computedConfidence = computeAverage([createdConfidence, confidence]);
                    // Rule content
                    const explanation = [createdId, foundRelationId];
                    const dependencies = [sourceRef, createdId, toId, foundRelationId, targetRef];
                    // Create the inferred relation
                    const input = { fromId: sourceRef, toId, relationship_type: creationType };
                    const ruleContent = createRuleContent(id, dependencies, explanation, {
                        confidence: computedConfidence,
                        start_time: range.start,
                        stop_time: range.end,
                        objectMarking: elementMarkings,
                    });
                    yield createInferredRelation(context, input, ruleContent);
                }
            });
            const listToArgs = { fromId: targetRef, callback: listToCallback };
            yield listAllRelations(context, RULE_MANAGER_USER, rightType, listToArgs);
        }
    });
    // Contract
    const clean = (element, deletedDependencies) => __awaiter(void 0, void 0, void 0, function* () {
        yield deleteInferredRuleElement(id, element, deletedDependencies);
    });
    const insert = (element) => __awaiter(void 0, void 0, void 0, function* () {
        return applyUpsert(element);
    });
    const update = (element) => __awaiter(void 0, void 0, void 0, function* () {
        return applyUpsert(element);
    });
    return Object.assign(Object.assign({}, ruleDefinition), { insert, update, clean });
};
export default buildRelationToRelationRule;
