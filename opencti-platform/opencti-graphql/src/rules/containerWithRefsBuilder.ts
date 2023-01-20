/* eslint-disable camelcase */
import type { AddOperation, Operation, ReplaceOperation } from 'fast-json-patch';
import * as jsonpatch from 'fast-json-patch';
import * as R from 'ramda';
import { createInferredRelation, deleteInferredRuleElement, stixLoadById, } from '../database/middleware';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { createRuleContent } from './rules';
import { generateInternalType } from '../schema/schemaUtils';
import type { RelationTypes, RuleDefinition, RuleRuntime } from '../types/rules';
import type { StixId, StixObject } from '../types/stix-common';
import type { StixReport } from '../types/stix-sdo';
import type { StixRelation } from '../types/stix-sro';
import type { BasicStoreRelation, StoreObject } from '../types/store';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { internalFindByIds, internalLoadById, listAllRelations } from '../database/middleware-loader';
import type { RelationCreation, UpdateEvent } from '../types/event';
import {
  EVENT_TYPE_DELETE,
  READ_DATA_INDICES,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
  UPDATE_OPERATION_REPLACE
} from '../database/utils';
import type { AuthContext } from '../types/user';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';
import { buildStixUpdateEvent, publishStixToStream } from '../database/redis';
import { RULE_PREFIX } from '../schema/general';

const INFERRED_OBJECT_REF_PATH = `/extensions/${STIX_EXT_OCTI}/object_refs_inferred`;

const buildContainerRefsRule = (ruleDefinition: RuleDefinition, containerType: string, relationTypes: RelationTypes): RuleRuntime => {
  const { id } = ruleDefinition;
  const leftTypeRefFilter = (ref: string) => {
    const [type] = ref.split('--');
    return type === relationTypes.leftType.toLowerCase();
  };
  const generateDependencies = (reportId: string, partOfFromId: string, partOfId: string, partOfTargetId: string) => {
    return [
      reportId,
      partOfFromId,
      partOfId,
      partOfTargetId,
    ];
  };
  type ArrayRefs = Array<{ partOfFromId: string, partOfId: string, partOfStandardId: StixId; partOfTargetId: string; partOfTargetStandardId: StixId }>;
  // eslint-disable-next-line max-len
  const createObjectRefsInferences = async (context: AuthContext, report: StixReport, addedTargets: ArrayRefs, deletedTargets: Array<BasicStoreRelation>): Promise<void> => {
    if (addedTargets.length === 0 && deletedTargets.length === 0) {
      return;
    }
    const opts = { publishStreamEvent: false };
    const createdTargets: Array<StixId> = [];
    const { id: reportId, object_refs_inferred } = report.extensions[STIX_EXT_OCTI];
    const reportObjectRefIds = [...(report.object_refs ?? []), ...(object_refs_inferred ?? [])];
    // region handle creation
    for (let index = 0; index < addedTargets.length; index += 1) {
      const { partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId } = addedTargets[index];
      // When generating inferences, no need to listen internal generated events
      // relationships are internal meta so creation will be in the stream directly
      const dependencies = generateDependencies(reportId, partOfFromId, partOfId, partOfTargetId);
      if (!reportObjectRefIds.includes(partOfStandardId)) {
        const ruleRelationContent = createRuleContent(id, dependencies, [reportId, partOfId], {});
        const inputForRelation = { fromId: reportId, toId: partOfId, relationship_type: RELATION_OBJECT };
        const inferredRelation = await createInferredRelation(context, inputForRelation, ruleRelationContent, opts) as RelationCreation;
        if (inferredRelation.isCreation) {
          createdTargets.push(partOfStandardId);
        }
      }
      // -----------------------------------------------------------------------------------------------------------
      if (!reportObjectRefIds.includes(partOfTargetStandardId)) {
        const ruleIdentityContent = createRuleContent(id, dependencies, [reportId, partOfTargetId], {});
        const inputForIdentity = { fromId: reportId, toId: partOfTargetId, relationship_type: RELATION_OBJECT };
        const inferredTarget = await createInferredRelation(context, inputForIdentity, ruleIdentityContent, opts) as RelationCreation;
        if (inferredTarget.isCreation) {
          createdTargets.push(partOfTargetStandardId);
        }
      }
    }
    // endregion
    // region handle deletion
    const deletedTargetRefs: Array<StixId> = [];
    for (let indexDeletion = 0; indexDeletion < deletedTargets.length; indexDeletion += 1) {
      const inferenceToDelete = deletedTargets[indexDeletion];
      const event = await deleteInferredRuleElement(id, inferenceToDelete, [], opts);
      if (event?.type === EVENT_TYPE_DELETE) {
        // if delete really occurs (not simple upsert removing an explanation)
        const deletedTarget = await internalLoadById(context, RULE_MANAGER_USER, inferenceToDelete.toId) as unknown as StoreObject;
        deletedTargetRefs.push(deletedTarget.standard_id);
      }
    }
    // endregion
    if (createdTargets.length > 0 || deletedTargetRefs.length > 0) {
      const updatedReport = R.clone(report);
      const refsWithoutDeletion = (object_refs_inferred ?? []).filter((o) => !deletedTargetRefs.includes(o));
      updatedReport.extensions[STIX_EXT_OCTI].object_refs_inferred = [...refsWithoutDeletion, ...createdTargets];
      const updateEvent = buildStixUpdateEvent(RULE_MANAGER_USER, report, updatedReport, '');
      await publishStixToStream(context, RULE_MANAGER_USER, updateEvent);
    }
  };
  const handleReportCreation = async (context: AuthContext, report: StixReport, addedRefs: Array<string>, removedRefs: Array<string>): Promise<void> => {
    const addedTargets: ArrayRefs = [];
    const relations = [];
    if (addedRefs.length > 0) {
      const identities = await internalFindByIds(context, RULE_MANAGER_USER, addedRefs) as Array<StoreObject>;
      const fromIds = identities.map((i) => i.internal_id);
      // Find all identities part of current identities
      const listFromArgs = { fromId: fromIds, toTypes: [relationTypes.rightType] };
      const fromRelations = await listAllRelations<BasicStoreRelation>(context, RULE_MANAGER_USER, relationTypes.creationType, listFromArgs);
      relations.push(...fromRelations);
    }
    if (relations.length > 0) {
      const targets = await internalFindByIds(context, RULE_MANAGER_USER, R.uniq(relations.map((r) => r.toId))) as Array<StoreObject>;
      const toIdsMap = new Map(targets.map((i) => [i.internal_id, i.standard_id]));
      for (let relIndex = 0; relIndex < relations.length; relIndex += 1) {
        const { internal_id: partOfId, standard_id: partOfStandardId, fromId: partOfFromId, toId: partOfTargetId } = relations[relIndex];
        const partOfTargetStandardId = toIdsMap.get(partOfTargetId);
        if (partOfStandardId && partOfTargetStandardId) {
          addedTargets.push({ partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId });
        }
      }
    }
    // Find all current inferences that need to be deleted
    const deletedTargets: Array<BasicStoreRelation> = [];
    if (removedRefs.length > 0) {
      const removedRefIdentities = await internalFindByIds(context, RULE_MANAGER_USER, removedRefs) as Array<StoreObject>;
      const removedIds = removedRefIdentities.map((i) => i.internal_id);
      const filters = [{ key: `${RULE_PREFIX}*.dependencies`, values: removedIds, operator: 'wildcard' }];
      const args = { filters, indices: READ_DATA_INDICES };
      const targets = await listAllRelations<BasicStoreRelation>(context, RULE_MANAGER_USER, RELATION_OBJECT, args);
      deletedTargets.push(...targets);
    }
    // update the report
    return createObjectRefsInferences(context, report, addedTargets, deletedTargets);
  };
  const handlePartOfRelationCreation = async (context: AuthContext, partOfRelation: StixRelation): Promise<void> => {
    const { id: partOfStandardId, target_ref: partOfTargetStandardId } = partOfRelation;
    const { id: partOfId, source_ref: partOfFromId, target_ref: partOfTargetId } = partOfRelation.extensions[STIX_EXT_OCTI];
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      for (let objectRefIndex = 0; objectRefIndex < relationships.length; objectRefIndex += 1) {
        const { fromId: reportId } = relationships[objectRefIndex];
        const report = await stixLoadById(context, RULE_MANAGER_USER, reportId) as StixReport;
        const addedRefs = [{ partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId }];
        await createObjectRefsInferences(context, report, addedRefs, []);
      }
    };
    const listReportArgs = { fromTypes: [containerType], toId: partOfFromId, callback: listFromCallback };
    await listAllRelations(context, RULE_MANAGER_USER, RELATION_OBJECT, listReportArgs);
  };
  // eslint-disable-next-line consistent-return
  const applyInsert = async (data: StixObject): Promise<void> => {
    const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);
    const entityType = generateInternalType(data);
    if (entityType === containerType) {
      const report = data as StixReport;
      const { object_refs: reportObjectRefs } = report;
      // Get all identities from the report refs
      const leftRefs = (reportObjectRefs ?? []).filter(leftTypeRefFilter);
      if (leftRefs.length > 0) {
        return handleReportCreation(context, report, leftRefs, []);
      }
    }
    const upsertRelation = data as StixRelation;
    const { relationship_type: relationType } = upsertRelation;
    if (relationType === relationTypes.creationType) {
      return handlePartOfRelationCreation(context, upsertRelation);
    }
  };
  const applyUpdate = async (data: StixObject, event: UpdateEvent): Promise<void> => {
    const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);
    const entityType = generateInternalType(data);
    if (entityType === containerType) {
      const report = data as StixReport;
      const operations: Array<Operation> = event.context.patch;
      const previousPatch = event.context.reverse_patch;
      const previousData = jsonpatch.applyPatch<StixReport>(R.clone(report), previousPatch).newDocument;
      const refOperations = operations.filter((o) => o.path.startsWith('/object_refs')
          || o.path.startsWith(INFERRED_OBJECT_REF_PATH));
      const addedRefs: Array<StixId> = [];
      const removedRefs: Array<StixId> = [];
      // Replace operations behavior
      const replaceOperations = refOperations.filter((o) => o.op === UPDATE_OPERATION_REPLACE) as Array<ReplaceOperation<string>>;
      for (let replaceIndex = 0; replaceIndex < replaceOperations.length; replaceIndex += 1) {
        const replaceOperation = replaceOperations[replaceIndex];
        addedRefs.push(replaceOperation.value as StixId);
        // For replace we need to look into the previous data, the deleted element
        const opPath = replaceOperation.path.substring(replaceOperation.path.indexOf('/object_refs'));
        const removeObjectIndex = R.last(opPath.split('/'));
        if (removeObjectIndex) {
          const replaceObjectRefIndex = parseInt(removeObjectIndex, 10);
          const isExtension = replaceOperation.path.startsWith(INFERRED_OBJECT_REF_PATH);
          const baseData = isExtension ? previousData.extensions[STIX_EXT_OCTI].object_refs_inferred : previousData.object_refs;
          const removeRefId = baseData[replaceObjectRefIndex];
          removedRefs.push(removeRefId);
        }
      }
      // Add operations behavior
      const addOperations = refOperations.filter((o) => o.op === UPDATE_OPERATION_ADD) as Array<AddOperation<string>>;
      for (let addIndex = 0; addIndex < addOperations.length; addIndex += 1) {
        const addOperation = addOperations[addIndex];
        const addedValues = Array.isArray(addOperation.value) ? addOperation.value : [addOperation.value];
        addedRefs.push(...addedValues);
      }
      // Remove operations behavior
      const removeOperations = refOperations.filter((o) => o.op === UPDATE_OPERATION_REMOVE);
      for (let removeIndex = 0; removeIndex < removeOperations.length; removeIndex += 1) {
        const removeOperation = removeOperations[removeIndex];
        // For remove op we need to look into the previous data, the deleted element
        const isExtension = removeOperation.path.startsWith(INFERRED_OBJECT_REF_PATH);
        const baseData = isExtension ? previousData.extensions[STIX_EXT_OCTI].object_refs_inferred : previousData.object_refs;
        const opPath = removeOperation.path.substring(removeOperation.path.indexOf('/object_refs'));
        const [,, index] = opPath.split('/');
        if (index) {
          const replaceObjectRefIndex = parseInt(index, 10);
          const removeRefId = baseData[replaceObjectRefIndex];
          removedRefs.push(removeRefId);
        } else {
          const removeRefIds = baseData ?? [];
          removedRefs.push(...removeRefIds);
        }
      }
      // Apply operations
      // For added identities
      const leftAddedRefs = addedRefs.filter(leftTypeRefFilter);
      const removedLeftRefs = removedRefs.filter(leftTypeRefFilter);
      if (leftAddedRefs.length > 0 || removedLeftRefs.length > 0) {
        await handleReportCreation(context, report, leftAddedRefs, removedLeftRefs);
      }
    }
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<void> => {
    await deleteInferredRuleElement(id, element, deletedDependencies);
  };
  const insert = async (element: StixObject): Promise<void> => applyInsert(element);
  const update = async (element: StixObject, event: UpdateEvent): Promise<void> => applyUpdate(element, event);
  return { ...ruleDefinition, insert, update, clean };
};

export default buildContainerRefsRule;
