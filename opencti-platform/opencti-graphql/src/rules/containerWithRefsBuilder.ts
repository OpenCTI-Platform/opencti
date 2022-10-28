/* eslint-disable camelcase */
import type { AddOperation, Operation, ReplaceOperation } from 'fast-json-patch';
import * as jsonpatch from 'fast-json-patch';
import * as R from 'ramda';
import {
  createInferredRelation,
  deleteInferredRuleElement,
  internalFindByIds,
  storeLoadByIdWithRefs,
} from '../database/middleware';

import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { createRuleContent, RULE_MANAGER_USER } from './rules';
import { INPUT_OBJECTS } from '../schema/general';
import { generateInternalType } from '../schema/schemaUtils';
import type { RuleDefinition, RelationTypes, RuleRuntime } from '../types/rules';
import type { StixId, StixObject } from '../types/stix-common';
import type { StixReport } from '../types/stix-sdo';
import type { StixRelation } from '../types/stix-sro';
import type { BasicStoreRelation, StoreEntity, StoreObject } from '../types/store';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { listAllRelations } from '../database/middleware-loader';
import type { DependenciesDeleteEvent, Event, RelationCreation, RuleEvent, UpdateEvent } from '../types/event';
import {
  generateUpdateMessage,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
  UPDATE_OPERATION_REPLACE
} from '../database/utils';
import { storeUpdateEvent } from '../database/redis';
import type { AuthContext } from '../types/user';
import { executionContext } from '../utils/access';

const INFERRED_OBJECT_REF_PATH = `/extensions/${STIX_EXT_OCTI}/object_refs_inferred`;
const buildContainerRefsRule = (ruleDefinition: RuleDefinition, containerType: string, relationTypes: RelationTypes): RuleRuntime => {
  const { id } = ruleDefinition;
  const identityRefFilter = (ref: string) => {
    const [type] = ref.split('--');
    return type === relationTypes.leftType.toLowerCase();
  };
  const generateDependencies = (reportId: string, partOfFromId: string, partOfId: string, partOfTargetId: string) => {
    return [
      reportId,
      `${partOfFromId}_ref`,
      partOfFromId,
      partOfId,
      partOfTargetId,
    ];
  };
  type ArrayRefs = Array<{ partOfFromId: string, partOfId: string, partOfTargetId: string }>;
  const createObjectRefsInferences = async (context: AuthContext, reportId: string, refs: ArrayRefs) => {
    const report = await storeLoadByIdWithRefs(context, RULE_MANAGER_USER, reportId) as StoreEntity;
    const reportObjectRefIds = report[INPUT_OBJECTS].map((r) => r.internal_id);
    const opts = { publishStreamEvent: false };
    const targetIds = refs.map((r) => [r.partOfId, r.partOfTargetId]).flat();
    const targetsMap = await internalFindByIds(context, RULE_MANAGER_USER, targetIds, { toMap: true }) as any;
    const createdTargets: Array<StoreEntity> = [];
    for (let index = 0; index < refs.length; index += 1) {
      const { partOfFromId, partOfId, partOfTargetId } = refs[index];
      // When generating inferences, no need to listen internal generated events
      // relationships are internal meta so creation will be in the stream directly
      const dependencies = generateDependencies(reportId, partOfFromId, partOfId, partOfTargetId);
      if (!reportObjectRefIds.includes(partOfId)) {
        const ruleRelationContent = createRuleContent(id, dependencies, [reportId, partOfId], {});
        const inputForRelation = { fromId: reportId, toId: partOfId, relationship_type: RELATION_OBJECT };
        const inferredRelation = await createInferredRelation(context, inputForRelation, ruleRelationContent, opts) as RelationCreation;
        if (inferredRelation.isCreation) {
          const target = targetsMap[partOfId];
          target.i_relation = inferredRelation.element;
          createdTargets.push(target);
        }
      }
      // -----------------------------------------------------------------------------------------------------------
      if (!reportObjectRefIds.includes(partOfTargetId)) {
        const ruleIdentityContent = createRuleContent(id, dependencies, [reportId, partOfTargetId], {});
        const inputForIdentity = { fromId: reportId, toId: partOfTargetId, relationship_type: RELATION_OBJECT };
        const inferredTarget = await createInferredRelation(context, inputForIdentity, ruleIdentityContent, opts) as RelationCreation;
        if (inferredTarget.isCreation) {
          const target = targetsMap[partOfTargetId];
          target.i_relation = inferredTarget.element;
          createdTargets.push(target);
        }
      }
    }
    if (createdTargets.length > 0) {
      const updatedReport = { ...report };
      const inputs = [{ key: INPUT_OBJECTS, value: createdTargets, operation: UPDATE_OPERATION_ADD }];
      const message = generateUpdateMessage(inputs);
      updatedReport[INPUT_OBJECTS] = [...(updatedReport[INPUT_OBJECTS] ?? []), ...createdTargets];
      await storeUpdateEvent(context, RULE_MANAGER_USER, report, updatedReport, message);
    }
  };
  const handleReportCreation = async (context: AuthContext, report: StixReport, addedIdentityRefs: Array<string>) => {
    const objectRefsToCreate: ArrayRefs = [];
    const { id: reportId } = report.extensions[STIX_EXT_OCTI];
    const identities = await internalFindByIds(context, RULE_MANAGER_USER, addedIdentityRefs) as Array<StoreObject>;
    const fromIds = identities.map((i) => i.internal_id);
    // Find all identities part of current identities
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      for (let relIndex = 0; relIndex < relationships.length; relIndex += 1) {
        const { internal_id: partOfId, fromId: partOfFromId, toId: partOfTargetId } = relationships[relIndex];
        objectRefsToCreate.push({ partOfFromId, partOfId, partOfTargetId });
      }
    };
    const listFromArgs = { fromId: fromIds, toTypes: [relationTypes.rightType], callback: listFromCallback };
    await listAllRelations(context, RULE_MANAGER_USER, relationTypes.creationType, listFromArgs);
    // update the report
    await createObjectRefsInferences(context, reportId, objectRefsToCreate);
    return [];
  };
  const handlePartOfRelationCreation = async (context: AuthContext, partOfRelation: StixRelation) => {
    const { id: partOfId, source_ref: partOfFromId, target_ref: partOfTargetId } = partOfRelation.extensions[STIX_EXT_OCTI];
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      for (let objectRefIndex = 0; objectRefIndex < relationships.length; objectRefIndex += 1) {
        const { fromId: reportId } = relationships[objectRefIndex];
        await createObjectRefsInferences(context, reportId, [{ partOfFromId, partOfId, partOfTargetId }]);
      }
    };
    const listReportArgs = { fromTypes: [containerType], toId: partOfFromId, callback: listFromCallback };
    await listAllRelations(context, RULE_MANAGER_USER, RELATION_OBJECT, listReportArgs);
    return [];
  };
  const applyInsert = async (data: StixObject): Promise<Array<Event>> => {
    const context = executionContext(ruleDefinition.name);
    const events: Array<Event> = [];
    const entityType = generateInternalType(data);
    if (entityType === containerType) {
      const report = data as StixReport;
      const { object_refs: reportObjectRefs } = report;
      // Get all identities from the report refs
      const identityRefs = (reportObjectRefs ?? []).filter(identityRefFilter);
      if (identityRefs.length > 0) {
        return handleReportCreation(context, report, identityRefs);
      }
    }
    const upsertRelation = data as StixRelation;
    const { relationship_type: relationType } = upsertRelation;
    if (relationType === relationTypes.creationType) {
      return handlePartOfRelationCreation(context, upsertRelation);
    }
    return events;
  };
  const applyUpdate = async (data: StixObject, event: UpdateEvent): Promise<Array<RuleEvent>> => {
    const context = executionContext(ruleDefinition.name);
    const events: Array<RuleEvent> = [];
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
      const addedIdentityRefs = addedRefs.filter(identityRefFilter);
      if (addedIdentityRefs.length > 0) {
        const createEvents = await handleReportCreation(context, report, addedIdentityRefs);
        events.push(...createEvents);
      }
      // For removed identities
      const removedIdentityRefs = removedRefs.filter(identityRefFilter);
      if (removedIdentityRefs.length > 0) {
        // For meta deletion, generate deletion events
        const removedRefIdentities = await internalFindByIds(context, RULE_MANAGER_USER, removedIdentityRefs) as Array<StoreObject>;
        const removedIds = removedRefIdentities.map((i) => i.internal_id);
        const deleteEvent: DependenciesDeleteEvent = { type: 'delete-dependencies', ids: removedIds.map((ref) => `${ref}_ref`) };
        events.push(deleteEvent);
      }
      return events;
    }
    // We don't care about the relation update
    // We have nothing to complete inside an internal meta.
    return events;
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<Array<RuleEvent>> => {
    const cleanPromiseEvents = deleteInferredRuleElement(id, element, deletedDependencies);
    return cleanPromiseEvents as unknown as Promise<Array<RuleEvent>>;
  };
  const insert = async (element: StixObject): Promise<Array<RuleEvent>> => applyInsert(element);
  const update = async (element: StixObject, event: UpdateEvent): Promise<Array<RuleEvent>> => applyUpdate(element, event);
  return { ...ruleDefinition, insert, update, clean };
};

export default buildContainerRefsRule;
