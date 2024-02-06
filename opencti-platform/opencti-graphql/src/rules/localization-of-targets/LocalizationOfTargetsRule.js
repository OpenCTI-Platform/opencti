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
import { createInferredRelation, deleteInferredRuleElement } from '../../database/middleware';
import { buildPeriodFromDates, computeRangeIntersection } from '../../utils/format';
import { RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './LocalizationOfTargetsDefinition';
import { createRuleContent } from '../rules-utils';
import { computeAverage } from '../../database/utils';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import { internalLoadById } from '../../database/middleware-loader';
const ruleLocalizationOfTargetsBuilder = () => {
    // Execution
    const applyUpsert = (data) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext(def.name, RULE_MANAGER_USER);
        const { extensions } = data;
        const createdId = extensions[STIX_EXT_OCTI].id;
        const sourceRef = extensions[STIX_EXT_OCTI].source_ref;
        const targetRef = extensions[STIX_EXT_OCTI].target_ref;
        const { object_marking_refs: markings } = data;
        const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
        const creationRange = buildPeriodFromDates(startTime, stopTime);
        const internalSource = yield internalLoadById(context, RULE_MANAGER_USER, sourceRef);
        if (internalSource.entity_type === RELATION_TARGETS) {
            const resolvedSource = internalSource;
            const { internal_id: foundRelationId, fromId: foundFrom, toId: foundTo, [RELATION_OBJECT_MARKING]: object_marking_refs } = resolvedSource;
            const { confidence, start_time, stop_time } = resolvedSource;
            const existingRange = buildPeriodFromDates(start_time, stop_time);
            const range = computeRangeIntersection(creationRange, existingRange);
            const elementMarkings = [...(markings || []), ...(object_marking_refs || [])];
            const computedConfidence = computeAverage([createdConfidence, confidence]);
            // Rule content
            const dependencies = [foundFrom, foundTo, foundRelationId, createdId];
            const explanation = [foundRelationId, createdId];
            // Create the inferred relation
            const input = { fromId: foundFrom, toId: targetRef, relationship_type: RELATION_TARGETS };
            const ruleContent = createRuleContent(def.id, dependencies, explanation, {
                confidence: computedConfidence,
                start_time: range.start,
                stop_time: range.end,
                objectMarking: elementMarkings,
            });
            yield createInferredRelation(context, input, ruleContent);
        }
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
const RuleLocalizationOfTargets = ruleLocalizationOfTargetsBuilder();
export default RuleLocalizationOfTargets;
