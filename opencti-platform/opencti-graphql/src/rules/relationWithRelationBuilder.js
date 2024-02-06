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
import { createInferredRelation, deleteInferredRuleElement } from '../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../utils/format';
import { createRuleContent } from './rules-utils';
import { computeAverage } from '../database/utils';
import { listAllRelations } from '../database/middleware-loader';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';
const buildRelationWithRelationRule = (ruleDefinition, relationTypes) => {
    const { id } = ruleDefinition;
    const { leftType, rightType, creationType } = relationTypes;
    const resolveTypes = { [leftType]: rightType, [rightType]: leftType };
    // Execution
    const applyUpsert = (data) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);
        const { extensions } = data;
        const createdId = extensions[STIX_EXT_OCTI].id;
        const sourceRef = extensions[STIX_EXT_OCTI].source_ref;
        const targetRef = extensions[STIX_EXT_OCTI].target_ref;
        const { object_marking_refs: markings, relationship_type } = data;
        const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
        const creationRange = buildPeriodFromDates(startTime, stopTime);
        const relationTypeToFind = resolveTypes[relationship_type];
        // Need to find every other relations
        const listFromCallback = (relationships) => __awaiter(void 0, void 0, void 0, function* () {
            const rels = relationships.filter((r) => r.internal_id !== createdId);
            for (let relIndex = 0; relIndex < rels.length; relIndex += 1) {
                const { internal_id: foundRelationId, toId, confidence } = rels[relIndex];
                const { start_time, stop_time, [RELATION_OBJECT_MARKING]: object_marking_refs } = rels[relIndex];
                // If we looking for left side relation, relation toId of found rel will be the to of the creation
                // If we looking for right side, relation toId of found rel will be the from of the creation
                const inferenceFromId = relationTypeToFind === leftType ? targetRef : toId;
                const inferenceToId = relationTypeToFind === leftType ? toId : targetRef;
                const existingRange = buildPeriodFromDates(start_time, stop_time);
                const range = computeRangeIntersection(creationRange, existingRange);
                const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
                const computedConfidence = computeAverage([createdConfidence, confidence]);
                // Rule content
                const dependencies = [sourceRef, createdId, targetRef, foundRelationId, toId];
                const explanation = [foundRelationId, createdId];
                // Create the inferred relation
                const input = { fromId: inferenceFromId, toId: inferenceToId, relationship_type: creationType };
                const ruleContent = createRuleContent(id, dependencies, explanation, {
                    confidence: computedConfidence,
                    start_time: range.start,
                    stop_time: range.end,
                    objectMarking: elementMarkings,
                });
                yield createInferredRelation(context, input, ruleContent);
            }
        });
        const listFromArgs = { fromId: sourceRef, callback: listFromCallback };
        yield listAllRelations(context, RULE_MANAGER_USER, relationTypeToFind, listFromArgs);
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
export default buildRelationWithRelationRule;
