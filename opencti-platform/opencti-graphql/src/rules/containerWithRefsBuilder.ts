import * as jsonpatch from 'fast-json-patch';
import * as R from 'ramda';
import { createInferredRelation, deleteInferredRuleElement, generateUpdateMessage, stixLoadById } from '../database/middleware';
import { RELATION_OBJECT } from '../schema/stixRefRelationship';
import { createRuleContent } from './rules-utils';
import { convertStixToInternalTypes, generateInternalType } from '../schema/schemaUtils';
import type { RelationTypes, RuleDefinition, RuleRuntime } from '../types/rules';
import type { StixId, StixObject } from '../types/stix-2-1-common';
import type { StixReport } from '../types/stix-2-1-sdo';
import type { StixRelation } from '../types/stix-2-1-sro';
import type { BasicStoreObject, BasicStoreRelation, StoreObject } from '../types/store';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { fullRelationsList, internalFindByIds, internalLoadById } from '../database/middleware-loader';
import type { RelationCreation, UpdateEvent } from '../types/event';
import { READ_DATA_INDICES } from '../database/utils';
import type { AuthContext } from '../types/user';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';
import { publishStixToStream } from '../database/stream/stream-handler';
import { INPUT_DOMAIN_TO, INPUT_OBJECTS, RULE_PREFIX } from '../schema/general';
import { type EditInput, EditOperation, FilterMode, FilterOperator } from '../generated/graphql';
import { asyncFilter } from '../utils/data-processing';
import { buildStixUpdateEvent } from '../database/stream/stream-utils';

const buildContainerRefsRule = (ruleDefinition: RuleDefinition, containerType: string, relationTypes: RelationTypes): RuleRuntime => {
  const { id } = ruleDefinition;
  const { isSource = true } = relationTypes;
  const typeRefFilter = (ref: string) => {
    const [type] = ref.split('--');
    const internalTypes = convertStixToInternalTypes(type);
    return isSource ? internalTypes.includes(relationTypes.leftType) : internalTypes.includes(relationTypes.rightType);
  };
  const generateDependencies = (reportId: string, partOfFromId: string, partOfId: string, partOfTargetId: string) => {
    return [
      reportId,
      partOfFromId,
      `${partOfFromId}_ref`,
      partOfId,
      partOfTargetId,
      `${partOfTargetId}_ref`,
    ];
  };
  type ArrayRefs = Array<{ partOfFromId: string; partOfId: string; partOfStandardId: StixId; partOfTargetId: string; partOfTargetStandardId: StixId }>;

  const createObjectRefsInferences = async (context: AuthContext, data: StixReport, addedTargets: ArrayRefs, deletedTargets: Array<BasicStoreRelation>): Promise<void> => {
    if (addedTargets.length === 0 && deletedTargets.length === 0) {
      return;
    }
    const opts = { publishStreamEvent: false };
    const createdTargets: Array<BasicStoreObject> = [];
    const report = await stixLoadById(context, RULE_MANAGER_USER, data.id) as StixReport;
    if (!report) {
      return;
    }
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
          createdTargets.push(inferredRelation.element[INPUT_DOMAIN_TO] as BasicStoreObject);
        }
      }
      // -----------------------------------------------------------------------------------------------------------
      if (!reportObjectRefIds.includes(partOfTargetStandardId)) {
        const ruleIdentityContent = createRuleContent(id, dependencies, isSource ? [reportId, partOfTargetId] : [reportId, partOfFromId], {});
        const inputForIdentity = { fromId: reportId, toId: isSource ? partOfTargetId : partOfFromId, relationship_type: RELATION_OBJECT };
        const inferredTarget = await createInferredRelation(context, inputForIdentity, ruleIdentityContent, opts) as RelationCreation;
        if (inferredTarget.isCreation) {
          createdTargets.push(inferredTarget.element[INPUT_DOMAIN_TO] as BasicStoreObject);
        }
      }
    }
    // endregion
    // region handle deletion
    const deletedTargetRefs: Array<StoreObject> = [];
    for (let indexDeletion = 0; indexDeletion < deletedTargets.length; indexDeletion += 1) {
      const inferenceToDelete = deletedTargets[indexDeletion];
      const isDeletion = await deleteInferredRuleElement(id, inferenceToDelete, [], opts);
      if (isDeletion) {
        // if delete really occurs (not simple upsert removing an explanation)
        const deletedTarget = await internalLoadById(context, RULE_MANAGER_USER, inferenceToDelete.toId) as unknown as StoreObject;
        deletedTargetRefs.push(deletedTarget);
      }
    }
    // endregion
    if (createdTargets.length > 0 || deletedTargetRefs.length > 0) {
      const updatedReport = structuredClone(report);
      const deletedTargetIds = deletedTargetRefs.map((d) => d.standard_id);
      const refsWithoutDeletion = (object_refs_inferred ?? []).filter((o) => !deletedTargetIds.includes(o));
      const createdTargetIds = createdTargets.map((c) => c.standard_id);
      const objectRefsInferred = [...refsWithoutDeletion, ...createdTargetIds];
      if (objectRefsInferred.length > 0) {
        updatedReport.extensions[STIX_EXT_OCTI].object_refs_inferred = objectRefsInferred;
      } else {
        delete updatedReport.extensions[STIX_EXT_OCTI].object_refs_inferred;
      }
      const inputs: EditInput[] = [];
      if (createdTargets.length > 0) {
        inputs.push({ key: INPUT_OBJECTS, value: createdTargets, operation: EditOperation.Add });
      }
      if (deletedTargetRefs.length > 0) {
        inputs.push({ key: INPUT_OBJECTS, value: deletedTargetRefs, operation: EditOperation.Remove });
      }
      const message = await generateUpdateMessage(context, RULE_MANAGER_USER, report.extensions[STIX_EXT_OCTI].type, inputs);
      const updateEvent = buildStixUpdateEvent(RULE_MANAGER_USER, report, updatedReport, message, []);
      await publishStixToStream(context, RULE_MANAGER_USER, updateEvent);
    }
  };
  const handleReportCreation = async (context: AuthContext, report: StixReport, addedRefs: Array<string>, removedRefs: Array<string>): Promise<void> => {
    if (addedRefs.length > 0) {
      const identities = await internalFindByIds(context, RULE_MANAGER_USER, addedRefs) as Array<StoreObject>;
      const originIds = identities.map((i) => i.internal_id);
      // Find all identities part of current identities
      const listAddedRefsCallback = async (relationships: Array<BasicStoreRelation>) => {
        if (relationships.length > 0) {
          const addedTargets: ArrayRefs = [];
          const targets = await internalFindByIds(context, RULE_MANAGER_USER, R.uniq(relationships.map((r) => (isSource ? r.toId : r.fromId)))) as Array<StoreObject>;
          const targetIdsMap = new Map(targets.map((i) => [i.internal_id, i.standard_id]));
          for (let relIndex = 0; relIndex < relationships.length; relIndex += 1) {
            const { internal_id: partOfId, standard_id: partOfStandardId, fromId: partOfFromId, toId: partOfTargetId } = relationships[relIndex];
            if (isSource) {
              const partOfTargetStandardId = targetIdsMap.get(partOfTargetId);
              if (partOfStandardId && partOfTargetStandardId) {
                addedTargets.push({ partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId });
              }
            } else {
              const partOfTargetStandardId = targetIdsMap.get(partOfFromId);
              if (partOfStandardId && partOfTargetStandardId) {
                addedTargets.push({ partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId });
              }
            }
          }
          // update the report
          await createObjectRefsInferences(context, report, addedTargets, []);
        }
      };
      // If originIds could no longer be found, we don't try to list relations since the fromId filter will not be applied
      if (originIds.length > 0) {
        const listArgs = isSource ? { fromId: originIds, toTypes: [relationTypes.rightType] } : { toId: originIds, fromTypes: [relationTypes.leftType] };
        const fullListArgs = { ...listArgs, callback: listAddedRefsCallback };
        await fullRelationsList<BasicStoreRelation>(context, RULE_MANAGER_USER, relationTypes.creationType, fullListArgs);
      }
    }

    // Find all current inferences that need to be deleted
    if (removedRefs.length > 0) {
      const removedRefIdentities = await internalFindByIds(context, RULE_MANAGER_USER, removedRefs) as Array<StoreObject>;
      const removedIds = removedRefIdentities.map((i) => `${i.internal_id}_ref`);
      const filters = {
        mode: FilterMode.And,
        filters: [{ key: [`${RULE_PREFIX}*.dependencies`], values: removedIds, operator: FilterOperator.Wildcard }],
        filterGroups: [],
      };
      const listRemovedRefsCallback = async (deletedTargets: Array<BasicStoreRelation>) => {
        if (deletedTargets.length > 0) {
          // update the report
          await createObjectRefsInferences(context, report, [], deletedTargets);
        }
      };
      const args = { fromId: report.extensions[STIX_EXT_OCTI].id, filters, noFiltersChecking: true, indices: READ_DATA_INDICES, callback: listRemovedRefsCallback };
      await fullRelationsList<BasicStoreRelation>(context, RULE_MANAGER_USER, RELATION_OBJECT, args);
    }
  };
  const handlePartOfRelationCreation = async (context: AuthContext, partOfRelation: StixRelation): Promise<void> => {
    let partOfTargetStandardId: StixId;
    const { id: partOfStandardId } = partOfRelation;
    if (isSource) {
      partOfTargetStandardId = partOfRelation.target_ref;
    } else {
      partOfTargetStandardId = partOfRelation.source_ref;
    }
    const { id: partOfId, source_ref: partOfFromId, target_ref: partOfTargetId } = partOfRelation.extensions[STIX_EXT_OCTI];
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      for (let objectRefIndex = 0; objectRefIndex < relationships.length; objectRefIndex += 1) {
        const { fromId: reportId } = relationships[objectRefIndex];
        const report = await stixLoadById(context, RULE_MANAGER_USER, reportId) as StixReport;
        if (report) {
          const addedRefs = [{ partOfFromId, partOfId, partOfStandardId, partOfTargetId, partOfTargetStandardId }];
          await createObjectRefsInferences(context, report, addedRefs, []);
        }
      }
    };
    const listReportArgs = { fromTypes: [containerType], toId: isSource ? partOfFromId : partOfTargetId, callback: listFromCallback };
    await fullRelationsList(context, RULE_MANAGER_USER, RELATION_OBJECT, listReportArgs);
  };

  const applyInsert = async (data: StixObject): Promise<void> => {
    const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);
    const entityType = generateInternalType(data);
    if (entityType === containerType) {
      const report = data as StixReport;
      const { object_refs: reportObjectRefs } = report;
      // Get all identities from the report refs
      const leftRefs = (reportObjectRefs ?? []).filter(typeRefFilter);
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
      const previousPatch = event.context.reverse_patch;
      const previousData = jsonpatch.applyPatch<StixReport>(structuredClone(report), previousPatch).newDocument;
      const previousRefIds = [...(previousData.extensions[STIX_EXT_OCTI].object_refs_inferred ?? []), ...(previousData.object_refs ?? [])];
      const previousRefIdsSet = new Set(previousRefIds);
      const newRefIds = [...(report.extensions[STIX_EXT_OCTI].object_refs_inferred ?? []), ...(report.object_refs ?? [])];
      const newRefIdsSet = new Set(newRefIds);
      // AddedRefs are ids not includes in previous data
      const addedRefs: Array<StixId> = await asyncFilter(newRefIds, (newId) => !previousRefIdsSet.has(newId));
      // RemovedRefs are ids not includes in current data
      const removedRefs: Array<StixId> = await asyncFilter(previousRefIds, (newId) => !newRefIdsSet.has(newId));
      // Apply operations
      // For added identities
      const leftAddedRefs = addedRefs.filter(typeRefFilter);
      const removedLeftRefs = removedRefs.filter(typeRefFilter);
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
