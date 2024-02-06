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
import * as jsonpatch from 'fast-json-patch';
import * as R from 'ramda';
import { createInferredRelation, deleteInferredRuleElement, stixLoadById, } from '../database/middleware';
import { RELATION_OBJECT } from '../schema/stixRefRelationship';
import { createRuleContent } from './rules-utils';
import { convertStixToInternalTypes, generateInternalType } from '../schema/schemaUtils';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { internalFindByIds, internalLoadById, listAllRelations } from '../database/middleware-loader';
import { READ_DATA_INDICES, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';
import { buildStixUpdateEvent, publishStixToStream } from '../database/redis';
import { INPUT_DOMAIN_TO, INPUT_OBJECTS, RULE_PREFIX } from '../schema/general';
import { generateUpdateMessage } from '../database/generate-message';
import { FilterMode, FilterOperator } from '../generated/graphql';
const buildContainerRefsRule = (ruleDefinition, containerType, relationTypes) => {
    const { id } = ruleDefinition;
    const { isSource = true } = relationTypes;
    const typeRefFilter = (ref) => {
        const [type] = ref.split('--');
        const internalTypes = convertStixToInternalTypes(type);
        return isSource ? internalTypes.includes(relationTypes.leftType) : internalTypes.includes(relationTypes.rightType);
    };
    const generateDependencies = (reportId, partOfFromId, partOfId, partOfTargetId) => {
        return [
            reportId,
            partOfFromId,
            partOfId,
            partOfTargetId,
        ];
    };
    // eslint-disable-next-line max-len
    const createObjectRefsInferences = (context, report, addedTargets, deletedTargets) => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        if (addedTargets.length === 0 && deletedTargets.length === 0) {
            return;
        }
        const opts = { publishStreamEvent: false };
        const createdTargets = [];
        const { id: reportId, object_refs_inferred } = report.extensions[STIX_EXT_OCTI];
        const reportObjectRefIds = [...((_a = report.object_refs) !== null && _a !== void 0 ? _a : []), ...(object_refs_inferred !== null && object_refs_inferred !== void 0 ? object_refs_inferred : [])];
        // region handle creation
        for (let index = 0; index < addedTargets.length; index += 1) {
            const { partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId } = addedTargets[index];
            // When generating inferences, no need to listen internal generated events
            // relationships are internal meta so creation will be in the stream directly
            const dependencies = generateDependencies(reportId, partOfFromId, partOfId, partOfTargetId);
            if (!reportObjectRefIds.includes(partOfStandardId)) {
                const ruleRelationContent = createRuleContent(id, dependencies, [reportId, partOfId], {});
                const inputForRelation = { fromId: reportId, toId: partOfId, relationship_type: RELATION_OBJECT };
                const inferredRelation = yield createInferredRelation(context, inputForRelation, ruleRelationContent, opts);
                if (inferredRelation.isCreation) {
                    createdTargets.push(inferredRelation.element[INPUT_DOMAIN_TO]);
                }
            }
            // -----------------------------------------------------------------------------------------------------------
            if (!reportObjectRefIds.includes(partOfTargetStandardId)) {
                const ruleIdentityContent = createRuleContent(id, dependencies, isSource ? [reportId, partOfTargetId] : [reportId, partOfFromId], {});
                const inputForIdentity = { fromId: reportId, toId: isSource ? partOfTargetId : partOfFromId, relationship_type: RELATION_OBJECT };
                const inferredTarget = yield createInferredRelation(context, inputForIdentity, ruleIdentityContent, opts);
                if (inferredTarget.isCreation) {
                    createdTargets.push(inferredTarget.element[INPUT_DOMAIN_TO]);
                }
            }
        }
        // endregion
        // region handle deletion
        const deletedTargetRefs = [];
        for (let indexDeletion = 0; indexDeletion < deletedTargets.length; indexDeletion += 1) {
            const inferenceToDelete = deletedTargets[indexDeletion];
            const isDeletion = yield deleteInferredRuleElement(id, inferenceToDelete, [], opts);
            if (isDeletion) {
                // if delete really occurs (not simple upsert removing an explanation)
                const deletedTarget = yield internalLoadById(context, RULE_MANAGER_USER, inferenceToDelete.toId);
                deletedTargetRefs.push(deletedTarget);
            }
        }
        // endregion
        if (createdTargets.length > 0 || deletedTargetRefs.length > 0) {
            const updatedReport = structuredClone(report);
            const deletedTargetIds = deletedTargetRefs.map((d) => d.standard_id);
            const refsWithoutDeletion = (object_refs_inferred !== null && object_refs_inferred !== void 0 ? object_refs_inferred : []).filter((o) => !deletedTargetIds.includes(o));
            const createdTargetIds = createdTargets.map((c) => c.standard_id);
            const objectRefsInferred = [...refsWithoutDeletion, ...createdTargetIds];
            if (objectRefsInferred.length > 0) {
                updatedReport.extensions[STIX_EXT_OCTI].object_refs_inferred = objectRefsInferred;
            }
            else {
                delete updatedReport.extensions[STIX_EXT_OCTI].object_refs_inferred;
            }
            const inputs = [];
            if (createdTargets.length > 0) {
                inputs.push({ key: INPUT_OBJECTS, value: createdTargets, operation: UPDATE_OPERATION_ADD });
            }
            if (deletedTargetRefs.length > 0) {
                inputs.push({ key: INPUT_OBJECTS, value: deletedTargetRefs, operation: UPDATE_OPERATION_REMOVE });
            }
            const message = yield generateUpdateMessage(context, report.extensions[STIX_EXT_OCTI].type, inputs);
            const updateEvent = buildStixUpdateEvent(RULE_MANAGER_USER, report, updatedReport, message);
            yield publishStixToStream(context, RULE_MANAGER_USER, updateEvent);
        }
    });
    const handleReportCreation = (context, report, addedRefs, removedRefs) => __awaiter(void 0, void 0, void 0, function* () {
        const addedTargets = [];
        const relations = [];
        if (addedRefs.length > 0) {
            const identities = yield internalFindByIds(context, RULE_MANAGER_USER, addedRefs);
            const originIds = identities.map((i) => i.internal_id);
            // Find all identities part of current identities
            const listArgs = isSource ? { fromId: originIds, toTypes: [relationTypes.rightType] } : { toId: originIds, fromTypes: [relationTypes.leftType] };
            const fromRelations = yield listAllRelations(context, RULE_MANAGER_USER, relationTypes.creationType, listArgs);
            relations.push(...fromRelations);
        }
        if (relations.length > 0) {
            const targets = yield internalFindByIds(context, RULE_MANAGER_USER, R.uniq(relations.map((r) => (isSource ? r.toId : r.fromId))));
            const targetIdsMap = new Map(targets.map((i) => [i.internal_id, i.standard_id]));
            for (let relIndex = 0; relIndex < relations.length; relIndex += 1) {
                const { internal_id: partOfId, standard_id: partOfStandardId, fromId: partOfFromId, toId: partOfTargetId } = relations[relIndex];
                if (isSource) {
                    const partOfTargetStandardId = targetIdsMap.get(partOfTargetId);
                    if (partOfStandardId && partOfTargetStandardId) {
                        addedTargets.push({ partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId });
                    }
                }
                else {
                    const partOfTargetStandardId = targetIdsMap.get(partOfFromId);
                    if (partOfStandardId && partOfTargetStandardId) {
                        addedTargets.push({ partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId });
                    }
                }
            }
        }
        // Find all current inferences that need to be deleted
        const deletedTargets = [];
        if (removedRefs.length > 0) {
            const removedRefIdentities = yield internalFindByIds(context, RULE_MANAGER_USER, removedRefs);
            const removedIds = removedRefIdentities.map((i) => i.internal_id);
            const filters = {
                mode: FilterMode.And,
                filters: [{ key: [`${RULE_PREFIX}*.dependencies`], values: removedIds, operator: FilterOperator.Wildcard }],
                filterGroups: [],
            };
            const args = { fromId: report.extensions[STIX_EXT_OCTI].id, filters, noFiltersChecking: true, indices: READ_DATA_INDICES };
            const targets = yield listAllRelations(context, RULE_MANAGER_USER, RELATION_OBJECT, args);
            deletedTargets.push(...targets);
        }
        // update the report
        return createObjectRefsInferences(context, report, addedTargets, deletedTargets);
    });
    const handlePartOfRelationCreation = (context, partOfRelation) => __awaiter(void 0, void 0, void 0, function* () {
        let partOfTargetStandardId;
        const { id: partOfStandardId } = partOfRelation;
        if (isSource) {
            partOfTargetStandardId = partOfRelation.target_ref;
        }
        else {
            partOfTargetStandardId = partOfRelation.source_ref;
        }
        const { id: partOfId, source_ref: partOfFromId, target_ref: partOfTargetId } = partOfRelation.extensions[STIX_EXT_OCTI];
        const listFromCallback = (relationships) => __awaiter(void 0, void 0, void 0, function* () {
            for (let objectRefIndex = 0; objectRefIndex < relationships.length; objectRefIndex += 1) {
                const { fromId: reportId } = relationships[objectRefIndex];
                const report = yield stixLoadById(context, RULE_MANAGER_USER, reportId);
                const addedRefs = [{ partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId }];
                yield createObjectRefsInferences(context, report, addedRefs, []);
            }
        });
        const listReportArgs = { fromTypes: [containerType], toId: isSource ? partOfFromId : partOfTargetId, callback: listFromCallback };
        yield listAllRelations(context, RULE_MANAGER_USER, RELATION_OBJECT, listReportArgs);
    });
    // eslint-disable-next-line consistent-return
    const applyInsert = (data) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);
        const entityType = generateInternalType(data);
        if (entityType === containerType) {
            const report = data;
            const { object_refs: reportObjectRefs } = report;
            // Get all identities from the report refs
            const leftRefs = (reportObjectRefs !== null && reportObjectRefs !== void 0 ? reportObjectRefs : []).filter(typeRefFilter);
            if (leftRefs.length > 0) {
                return handleReportCreation(context, report, leftRefs, []);
            }
        }
        const upsertRelation = data;
        const { relationship_type: relationType } = upsertRelation;
        if (relationType === relationTypes.creationType) {
            return handlePartOfRelationCreation(context, upsertRelation);
        }
    });
    const applyUpdate = (data, event) => __awaiter(void 0, void 0, void 0, function* () {
        var _b, _c, _d, _e;
        const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);
        const entityType = generateInternalType(data);
        if (entityType === containerType) {
            const report = data;
            const previousPatch = event.context.reverse_patch;
            const previousData = jsonpatch.applyPatch(structuredClone(report), previousPatch).newDocument;
            const previousRefIds = [...((_b = previousData.extensions[STIX_EXT_OCTI].object_refs_inferred) !== null && _b !== void 0 ? _b : []), ...((_c = previousData.object_refs) !== null && _c !== void 0 ? _c : [])];
            const newRefIds = [...((_d = report.extensions[STIX_EXT_OCTI].object_refs_inferred) !== null && _d !== void 0 ? _d : []), ...((_e = report.object_refs) !== null && _e !== void 0 ? _e : [])];
            // AddedRefs are ids not includes in previous data
            const addedRefs = newRefIds.filter((newId) => !previousRefIds.includes(newId));
            // RemovedRefs are ids not includes in current data
            const removedRefs = previousRefIds.filter((newId) => !newRefIds.includes(newId));
            // Apply operations
            // For added identities
            const leftAddedRefs = addedRefs.filter(typeRefFilter);
            const removedLeftRefs = removedRefs.filter(typeRefFilter);
            if (leftAddedRefs.length > 0 || removedLeftRefs.length > 0) {
                yield handleReportCreation(context, report, leftAddedRefs, removedLeftRefs);
            }
        }
    });
    // Contract
    const clean = (element, deletedDependencies) => __awaiter(void 0, void 0, void 0, function* () {
        yield deleteInferredRuleElement(id, element, deletedDependencies);
    });
    const insert = (element) => __awaiter(void 0, void 0, void 0, function* () { return applyInsert(element); });
    const update = (element, event) => __awaiter(void 0, void 0, void 0, function* () { return applyUpdate(element, event); });
    return Object.assign(Object.assign({}, ruleDefinition), { insert, update, clean });
};
export default buildContainerRefsRule;
