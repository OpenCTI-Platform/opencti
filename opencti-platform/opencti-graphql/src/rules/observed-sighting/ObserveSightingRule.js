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
import { createInferredRelation, deleteInferredRuleElement, stixLoadById, } from '../../database/middleware';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import def from './ObserveSightingDefinition';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { createRuleContent } from '../rules-utils';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { internalLoadById, listAllRelations } from '../../database/middleware-loader';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import { ENTITY_TYPE_INDICATOR } from '../../modules/indicator/indicator-types';
// 'If **observed-data A** (`created-by` **identity X**) have `object` **observable B** and **indicator C** ' +
// 'is `based-on` **observable B**, then **indicator C** is `sighted` in **identity X**.';
const ruleObserveSightingBuilder = () => {
    const { id } = def;
    // Execution
    const generateDependencies = (observedDataId, objectId, observableId, organizationId, baseOnId, indicatorId) => {
        return [
            // Observed data dependencies
            observedDataId,
            // Entities dependencies
            observableId,
            organizationId,
            // Relations dependencies
            objectId,
            baseOnId,
            // Indicator dependencies
            indicatorId,
        ];
    };
    const handleIndicatorUpsert = (context, indicator) => __awaiter(void 0, void 0, void 0, function* () {
        const { id: indicatorId } = indicator.extensions[STIX_EXT_OCTI];
        const { object_marking_refs: indicatorMarkings } = indicator;
        const baseOnArgs = { toType: ABSTRACT_STIX_CYBER_OBSERVABLE, fromId: indicatorId };
        const baseOnRelations = yield listAllRelations(context, RULE_MANAGER_USER, RELATION_BASED_ON, baseOnArgs);
        for (let index = 0; index < baseOnRelations.length; index += 1) {
            const { internal_id: baseOnId, toId: observableId } = baseOnRelations[index];
            // Get the observed-data
            const objectsArgs = { fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], toId: observableId };
            const objectsRelations = yield listAllRelations(context, RULE_MANAGER_USER, RELATION_OBJECT, objectsArgs);
            for (let objectIndex = 0; objectIndex < objectsRelations.length; objectIndex += 1) {
                const { internal_id: objectId, fromId: observedDataId } = objectsRelations[objectIndex];
                const observedData = (yield internalLoadById(context, RULE_MANAGER_USER, observedDataId));
                const { [RELATION_CREATED_BY]: organizationId, confidence } = observedData;
                const { number_observed, first_observed, last_observed } = observedData;
                if (organizationId) {
                    const organization = (yield internalLoadById(context, RULE_MANAGER_USER, organizationId));
                    const { [RELATION_OBJECT_MARKING]: organizationMarkings } = organization;
                    const explanation = [observedDataId, objectId, observableId, baseOnId, indicatorId];
                    const dependencies = generateDependencies(observedDataId, objectId, observableId, organizationId, baseOnId, indicatorId);
                    // Create the sighting between the indicator and the organization
                    const input = { fromId: indicatorId, toId: organizationId, relationship_type: STIX_SIGHTING_RELATIONSHIP };
                    const elementMarkings = [...(organizationMarkings || []), ...(indicatorMarkings || [])];
                    const ruleContent = createRuleContent(id, dependencies, explanation, {
                        first_seen: first_observed,
                        last_seen: last_observed,
                        attribute_count: number_observed,
                        confidence,
                        objectMarking: elementMarkings,
                    });
                    yield createInferredRelation(context, input, ruleContent);
                }
            }
        }
    });
    const handleObservedDataUpsert = (context, observedData) => __awaiter(void 0, void 0, void 0, function* () {
        const { created_by_ref: organizationId } = observedData;
        const { id: observedDataId } = observedData.extensions[STIX_EXT_OCTI];
        const { number_observed, first_observed, last_observed, confidence } = observedData;
        const organization = (yield internalLoadById(context, RULE_MANAGER_USER, organizationId));
        if (organization) {
            const { [RELATION_OBJECT_MARKING]: organizationMarkings } = organization;
            // Get all observable of this observed-data
            const listFromArgs = { fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], fromId: observedDataId };
            const objectsRelations = yield listAllRelations(context, RULE_MANAGER_USER, RELATION_OBJECT, listFromArgs);
            for (let objectIndex = 0; objectIndex < objectsRelations.length; objectIndex += 1) {
                const { internal_id: objectId, toId: observableId } = objectsRelations[objectIndex];
                // Get all base-on indicators of this observable
                const baseOnArgs = { fromTypes: [ENTITY_TYPE_INDICATOR], toId: observableId };
                const baseOnRelations = yield listAllRelations(context, RULE_MANAGER_USER, RELATION_BASED_ON, baseOnArgs);
                for (let index = 0; index < baseOnRelations.length; index += 1) {
                    const { internal_id: baseOnId, fromId: indicatorId } = baseOnRelations[index];
                    const indicator = (yield internalLoadById(context, RULE_MANAGER_USER, indicatorId));
                    const { [RELATION_OBJECT_MARKING]: indicatorMarkings } = indicator;
                    const explanation = [observedDataId, objectId, observableId, baseOnId, indicatorId];
                    const dependencies = generateDependencies(observedDataId, objectId, observableId, organization.internal_id, baseOnId, indicatorId);
                    // Create the sighting between the indicator and the organization
                    const input = { fromId: indicatorId, toId: organizationId, relationship_type: STIX_SIGHTING_RELATIONSHIP };
                    const elementMarkings = [...(organizationMarkings || []), ...(indicatorMarkings || [])];
                    const ruleContent = createRuleContent(id, dependencies, explanation, {
                        first_seen: first_observed,
                        last_seen: last_observed,
                        attribute_count: number_observed,
                        confidence,
                        objectMarking: elementMarkings,
                    });
                    yield createInferredRelation(context, input, ruleContent);
                }
            }
        }
    });
    const handleObservableRelationUpsert = (context, baseOnRelation) => __awaiter(void 0, void 0, void 0, function* () {
        const { source_ref: indicatorId } = baseOnRelation.extensions[STIX_EXT_OCTI];
        const baseOnIndicator = (yield stixLoadById(context, RULE_MANAGER_USER, indicatorId));
        return handleIndicatorUpsert(context, baseOnIndicator);
    });
    const applyUpsert = (data) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext(def.name, RULE_MANAGER_USER);
        const entityType = generateInternalType(data);
        if (entityType === ENTITY_TYPE_INDICATOR) {
            yield handleIndicatorUpsert(context, data);
        }
        if (entityType === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
            yield handleObservedDataUpsert(context, data);
        }
        const upsertRelation = data;
        const { relationship_type: relationType } = upsertRelation;
        if (relationType === RELATION_BASED_ON) {
            yield handleObservableRelationUpsert(context, upsertRelation);
        }
    });
    // Contract
    const clean = (element, deletedDependencies) => __awaiter(void 0, void 0, void 0, function* () {
        yield deleteInferredRuleElement(def.id, element, deletedDependencies);
    });
    const insert = (element) => __awaiter(void 0, void 0, void 0, function* () { return applyUpsert(element); });
    const update = (element) => __awaiter(void 0, void 0, void 0, function* () { return applyUpsert(element); });
    return Object.assign(Object.assign({}, def), { insert, update, clean });
};
const RuleObserveSighting = ruleObserveSightingBuilder();
export default RuleObserveSighting;
