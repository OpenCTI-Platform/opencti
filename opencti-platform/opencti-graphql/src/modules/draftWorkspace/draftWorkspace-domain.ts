import { BUS_TOPICS, logApp } from '../../config/conf';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { elDeleteDraftContextFromUsers, elDeleteDraftContextFromWorks, elDeleteDraftElements, resolveDraftUpdateFiles } from '../../database/draft-engine';
import { buildUpdateFieldPatch } from '../../database/draft-utils';
import { elAggregationCount, elCount, elFindByIds, elList, elLoadById, loadDraftElement } from '../../database/engine';
import { createEntity, createRelation, deleteElementById, deleteRelationsByFromAndTo, stixLoadByIds, updateAttribute } from '../../database/middleware';
import { type EntityOptions, fullEntitiesList, fullRelationsList, pageEntitiesConnection, pageRelationsConnection, storeLoadById } from '../../database/middleware-loader';
import { pushToWorkerForConnector } from '../../database/rabbitmq';
import { notify, setEditContext } from '../../database/redis';
import { buildStixBundle } from '../../database/stix-2-1-converter';
import { computeSumOfList, isDraftIndex, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { createWork, updateExpectationsNumber } from '../../domain/work';
import {
  DraftChangeType,
  type DraftWorkspaceAddInput,
  type EditContext,
  type EditInput,
  FilterMode,
  FilterOperator,
  type MemberAccessInput,
  type QueryDraftWorkspaceEntitiesArgs,
  type QueryDraftWorkspaceRelationshipsArgs,
  type QueryDraftWorkspacesArgs,
  type QueryDraftWorkspaceSightingRelationshipsArgs,
  type StixRefRelationshipAddInput,
} from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { addDraftCreationCount, addDraftValidationCount } from '../../manager/telemetryManager';
import { authorizedMembers } from '../../schema/attribute-definition';
import { ABSTRACT_INTERNAL_RELATIONSHIP, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_INTERNAL_FILE, ENTITY_TYPE_USER, ENTITY_TYPE_WORK } from '../../schema/internalObject';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isStixRefRelationship, RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { isStixRelationshipExceptRef } from '../../schema/stixRelationship';
import { isStixDomainObject, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { deleteAllDraftFiles } from '../../database/file-storage';
import { resolveEmbeddedImagesInDescriptionFieldsForExport } from '../../database/middlewareEmbeddedImages';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreRelation, StoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { getUserAccessRight, KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS, SYSTEM_USER } from '../../utils/access';
import { editAuthorizedMembers } from '../../utils/authorizedMembers';
import { getDraftContext } from '../../utils/draftContext';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { now } from '../../utils/format';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_DELETE, DRAFT_OPERATION_UPDATE } from './draftOperations';
import { DRAFT_STATUS_OPEN, DRAFT_STATUS_VALIDATED } from './draftStatuses';
import { DRAFT_VALIDATION_CONNECTOR } from './draftWorkspace-connector';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE, type StoreEntityDraftWorkspace } from './draftWorkspace-types';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { extractEntityRepresentativeName } from '../../database/entity-representative';

export const checkAndReturnDraft = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const draft = await findById(context, user, draftId);
  if (!draft) {
    throw FunctionalError(`Draft ${draftId} cannot be found`);
  }
  return draft;
};

const bypassDraftContext = (context: AuthContext): AuthContext => {
  return {
    ...context,
    draft_context: undefined,
    user: context.user ? { ...context.user, draft_context: undefined } : undefined,
  };
};

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDraftWorkspace>(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);
};

export const findDraftWorkspacePaginated = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspacesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityDraftWorkspace>(context, user, [ENTITY_TYPE_DRAFT_WORKSPACE], args);
};

export const findDraftWorkspaceRestrictedPaginated = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspacesArgs) => {
  const filters = addFilter(args.filters, `${authorizedMembers.name}.id`, [], FilterOperator.NotNil);

  return pageEntitiesConnection<BasicStoreEntityDraftWorkspace>(context, user, [ENTITY_TYPE_DRAFT_WORKSPACE], {
    ...args,
    includeAuthorities: true,
    filters,
  });
};

export const getObjectsCount = async (context: AuthContext, user: AuthUser, draft: BasicStoreEntityDraftWorkspace) => {
  const opts = {
    // types: ['Stix-Object'],
    field: 'entity_type',
    includeDeletedInDraft: true,
    normalizeLabel: false,
    convertEntityTypeLabel: true,
  };
  const draftContext = { ...context, draft_context: draft.id };
  const distributionResult = await elAggregationCount(draftContext, user, READ_INDEX_DRAFT_OBJECTS, opts);

  // TODO fix total to include only stix domain objects & SCO & stix core relationships & sightings & stix domain objects
  const totalCount = computeSumOfList(distributionResult.map((r: { label: string; count: number }) => r.count));
  const entitiesCount = computeSumOfList(
    distributionResult.filter((r: { label: string }) => isStixDomainObject(r.label) && !isStixDomainObjectContainer(r.label)).map((r: { count: number }) => r.count),
  );
  const observablesCount = computeSumOfList(
    distributionResult.filter((r: { label: string }) => isStixCyberObservable(r.label)).map((r: { count: number }) => r.count),
  );
  const relationshipsCount = computeSumOfList(
    distributionResult.filter((r: { label: string }) => isStixCoreRelationship(r.label)).map((r: { count: number }) => r.count),
  );
  const sightingsCount = computeSumOfList(
    distributionResult.filter((r: { label: string }) => isStixSightingRelationship(r.label)).map((r: { count: number }) => r.count),
  );
  const containersCount = computeSumOfList(
    distributionResult.filter((r: { label: string }) => isStixDomainObjectContainer(r.label)).map((r: { count: number }) => r.count),
  );
  // reviewsCount = all stix core objects (entities + observables + containers), matching what the Review list displays
  const reviewsCount = entitiesCount + observablesCount + containersCount;
  return {
    totalCount,
    entitiesCount,
    observablesCount,
    relationshipsCount,
    sightingsCount,
    containersCount,
    reviewsCount,
  };
};

export const getProcessingCount = async (context: AuthContext, user: AuthUser, draft: BasicStoreEntityDraftWorkspace) => {
  const draftWorksFilter = {
    filterGroups: [],
    filters: [
      {
        key: 'draft_context',
        mode: 'or',
        operator: 'eq',
        values: [draft.internal_id],
      },
      {
        key: 'status',
        mode: 'or',
        operator: 'eq',
        values: ['wait', 'progress'],
      },
    ],
    mode: 'and',
  };
  const worksOpts = {
    types: [ENTITY_TYPE_WORK],
    filters: draftWorksFilter,
  };
  const draftIncompleteWorksCount = await elCount(context, user, READ_INDEX_HISTORY, worksOpts);
  const draftTasksFilter = {
    filterGroups: [],
    filters: [
      {
        key: 'draft_context',
        mode: 'or',
        operator: 'eq',
        values: [draft.internal_id],
      },
      {
        key: 'completed',
        mode: 'or',
        operator: 'eq',
        values: ['false'],
      },
    ],
    mode: 'and',
  };
  const tasksOpts = {
    types: [ENTITY_TYPE_BACKGROUND_TASK],
    filters: draftTasksFilter,
  };
  const draftIncompleteTasksCount = await elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, tasksOpts);
  return draftIncompleteTasksCount + draftIncompleteWorksCount;
};

export const getCurrentUserAccessRight = async (
  user: AuthUser,
  draft: BasicStoreEntityDraftWorkspace,
) => {
  return getUserAccessRight(user, draft);
};

export const listDraftObjects = async (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceEntitiesArgs) => {
  let types: string[] = [];
  const { draftId, draftOperation, ...listArgs } = args as QueryDraftWorkspaceEntitiesArgs & { draftOperation?: string };
  await checkAndReturnDraft(context, user, draftId);

  if (args.types) {
    types = args.types.filter((t) => t && isStixCoreObject(t)) as string[];
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  const draftContext = { ...context, draft_context: draftId };
  const draftOperationFilter = draftOperation
    ? addFilter(listArgs.filters, 'draft_change.draft_operation', draftOperation)
    : listArgs.filters;
  const newArgs: EntityOptions<BasicStoreEntity> = {
    ...listArgs,
    types,
    indices: [READ_INDEX_DRAFT_OBJECTS],
    includeDeletedInDraft: true,
    filters: draftOperationFilter,
    noFiltersChecking: draftOperation ? true : undefined,
  };
  return pageEntitiesConnection<BasicStoreEntity>(draftContext, user, types, newArgs);
};

export const listDraftRelations = async (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceRelationshipsArgs) => {
  let types: string[] = [];
  const { draftId, ...listArgs } = args;
  await checkAndReturnDraft(context, user, draftId);
  if (args.types) {
    types = args.types.filter((t) => t && isStixRelationshipExceptRef(t)) as string[];
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_RELATIONSHIP);
  }
  const newArgs: EntityOptions<BasicStoreRelation> = { ...listArgs, types, indices: [READ_INDEX_DRAFT_OBJECTS], includeDeletedInDraft: true };
  const draftContext = { ...context, draft_context: draftId };
  return pageRelationsConnection<BasicStoreRelation>(draftContext, user, types, newArgs);
};

export const listDraftSightingRelations = async (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceSightingRelationshipsArgs) => {
  let types: string[] = [];
  const { draftId, ...listArgs } = args;
  await checkAndReturnDraft(context, user, draftId);
  if (args.types) {
    types = args.types.filter((t) => t && isStixSightingRelationship(t)) as string[];
  }
  if (types.length === 0) {
    types.push(STIX_SIGHTING_RELATIONSHIP);
  }
  const newArgs: EntityOptions<BasicStoreRelation> = { ...listArgs, types, indices: [READ_INDEX_DRAFT_OBJECTS], includeDeletedInDraft: true };
  const draftContext = { ...context, draft_context: draftId };
  return pageRelationsConnection<BasicStoreRelation>(draftContext, user, types, newArgs);
};

export const addDraftWorkspace = async (context: AuthContext, user: AuthUser, input: DraftWorkspaceAddInput) => {
  const defaultOps = {
    created_at: now(),
    draft_status: DRAFT_STATUS_OPEN,
  };
  const draftWorkspaceInput = { ...input, ...defaultOps };
  const createdDraftWorkspace = await createEntity(context, user, draftWorkspaceInput, ENTITY_TYPE_DRAFT_WORKSPACE);
  if (createdDraftWorkspace && input.entity_id) {
    const contextInDraft = { ...context, draft_context: createdDraftWorkspace.id };
    const draftInEntity = await elLoadById(contextInDraft, user, input.entity_id);
    if (draftInEntity) {
      await loadDraftElement(contextInDraft, user, draftInEntity);
    }
  }
  await addDraftCreationCount();
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates draft workspace \`${createdDraftWorkspace.name}\``,
    context_data: {
      id: createdDraftWorkspace.id,
      entity_type: ENTITY_TYPE_DRAFT_WORKSPACE,
      input,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_DRAFT_WORKSPACE].ADDED_TOPIC, createdDraftWorkspace, user);
};

export const draftWorkspaceAddRelation = async (context: AuthContext, user: AuthUser, draftId: string, input: StixRefRelationshipAddInput) => {
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user ?? user;
  const draft = await checkAndReturnDraft(executionContext, executionUser, draftId);
  const finalInput = { ...input, fromId: draftId };
  const relationData = await createRelation(executionContext, executionUser, finalInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${relationData.toType} \`${extractEntityRepresentativeName(relationData.to)}\` for draft \`${draft.name}\``,
    context_data: { id: draft.id, entity_type: ENTITY_TYPE_DRAFT_WORKSPACE, input: finalInput },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_DRAFT_WORKSPACE].EDIT_TOPIC, draft, executionUser).then(() => relationData);
};

export const draftWorkspaceDeleteRelation = async (context: AuthContext, user: AuthUser, draftId: string, toId: string, relationshipType: string) => {
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user ?? user;
  const draft = await checkAndReturnDraft(executionContext, executionUser, draftId);
  const { to } = await deleteRelationsByFromAndTo(executionContext, executionUser, draft.id, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  const input = { relationship_type: relationshipType, toId };
  const draftUpdated = await findById(executionContext, executionUser, draftId);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${to.entity_type} \`${extractEntityRepresentativeName(to)}\` for draft \`${draft.name}\``,
    context_data: { id: draft.id, entity_type: ENTITY_TYPE_DRAFT_WORKSPACE, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_DRAFT_WORKSPACE].EDIT_TOPIC, draftUpdated, executionUser);
};

export const draftWorkspaceEditField = async (context: AuthContext, user: AuthUser, draftId: string, input: EditInput[]) => {
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user ?? user;
  await checkAndReturnDraft(executionContext, executionUser, draftId);

  const { element } = await updateAttribute<StoreEntity>(executionContext, executionUser, draftId, ENTITY_TYPE_DRAFT_WORKSPACE, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for draft \`${element.name}\``,
    context_data: { id: draftId, entity_type: ENTITY_TYPE_DRAFT_WORKSPACE, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_DRAFT_WORKSPACE].EDIT_TOPIC, element, executionUser);
};

export const draftWorkspaceEditAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: MemberAccessInput[] | undefined | null,
) => {
  const args = {
    entityId: workspaceId,
    input,
    requiredCapabilities: [KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS],
    entityType: ENTITY_TYPE_DRAFT_WORKSPACE,
    busTopicKey: ENTITY_TYPE_DRAFT_WORKSPACE,
  };
  // @ts-expect-error TODO improve busTopicKey types to avoid this
  return editAuthorizedMembers(context, user, args);
};

const findAllUsersWithDraftContext = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const listArgs = {
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['draft_context'], values: [draftId] }], filterGroups: [] },
  };
  return fullEntitiesList(context, user, [ENTITY_TYPE_USER], listArgs);
};

// When deleting a draft, we need to move all users that are still in the draft context back to the live context
const deleteDraftContextFromUsers = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const usersWithDraftContext = await findAllUsersWithDraftContext(context, user, draftId);
  if (usersWithDraftContext.length > 0) {
    await elDeleteDraftContextFromUsers(context, user, draftId);
    await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, usersWithDraftContext, user);
  }
};

const findAllWorksWithDraftContext = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const listArgs = {
    indices: [READ_INDEX_HISTORY],
    filters: { mode: FilterMode.And, filters: [{ key: ['draft_context'], values: [draftId] }], filterGroups: [] },
  };
  return fullEntitiesList(context, user, [ENTITY_TYPE_WORK], listArgs);
};

// When deleting a draft, we need to remove all draft_ids from works currently linked to this draft
const deleteDraftContextFromWorks = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const worksWithDraftContext = await findAllWorksWithDraftContext(context, user, draftId);
  if (worksWithDraftContext.length > 0) {
    await elDeleteDraftContextFromWorks(context, user, draftId);
  }
};

export const deleteDraftWorkspace = async (context: AuthContext, user: AuthUser, id: string) => {
  if (getDraftContext(context, user)) throw UnsupportedError('Cannot delete draft while in draft context');
  await checkAndReturnDraft(context, user, id);
  await deleteAllDraftFiles(context, user, id);
  await elDeleteDraftElements(context, user, id); // delete all draft elements from draft index
  await deleteDraftContextFromUsers(context, user, id);
  await deleteDraftContextFromWorks(context, user, id);
  const deleted = await deleteElementById<StoreEntityDraftWorkspace>(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'extended',
    message: `deletes draft workspace \`${deleted.name}\``,
    context_data: {
      id: deleted.id,
      entity_type: ENTITY_TYPE_DRAFT_WORKSPACE,
      input: deleted,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_DRAFT_WORKSPACE].DELETE_TOPIC, deleted, user).then(() => id);
};

export const buildDraftVersion = (object: BasicStoreCommon) => {
  if (!isDraftIndex(object._index)) {
    return null;
  }

  if (!object.draft_ids || object.draft_ids.length === 0) {
    logApp.warn('Draft entity without draft ids found', { id: object.id });
    return null;
  }

  return {
    draft_id: object.draft_ids[0],
    draft_operation: object.draft_change?.draft_operation,
    draft_updates_patch: object.draft_change?.draft_updates_patch ?? null,
  };
};

// Maximum number of IDs to load per stixLoadByIds call to prevent OOM on large drafts
const STIX_LOAD_BATCH_SIZE = 2000;
// Maximum number of STIX objects per RabbitMQ message to prevent message size overflow
const BUNDLE_SPLIT_THRESHOLD = 5000;

/**
 * Batch-load STIX objects by IDs in chunks to prevent memory exhaustion on large drafts.
 */
const stixLoadByIdsBatched = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  opts: Parameters<typeof stixLoadByIds>[3] = {},
): Promise<any[]> => {
  if (ids.length <= STIX_LOAD_BATCH_SIZE) {
    return stixLoadByIds(context, user, ids, opts);
  }
  const results: any[] = [];
  for (let i = 0; i < ids.length; i += STIX_LOAD_BATCH_SIZE) {
    const chunk = ids.slice(i, i + STIX_LOAD_BATCH_SIZE);
    const chunkResults = await stixLoadByIds(context, user, chunk, opts);
    results.push(...chunkResults);
  }
  return results;
};

export const buildDraftValidationBundle = async (context: AuthContext, user: AuthUser, draft_id: string) => {
  const contextInDraft = { ...context, draft_context: draft_id };
  const includeDeleteOption = { includeDeletedInDraft: true };
  // We start by listing all elements currently in this draft context
  const draftEntities = await elList(contextInDraft, user, READ_INDEX_DRAFT_OBJECTS, includeDeleteOption);

  const draftEntitiesMinusRefRel = draftEntities.filter((e) => !isStixRefRelationship(e.entity_type) && e.entity_type !== ENTITY_TYPE_INTERNAL_FILE);

  // We add all created elements as stix objects to the bundle
  const createEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_CREATE);
  const createEntitiesIds = createEntities.map((e) => e.internal_id);
  const createStixEntities = await stixLoadByIdsBatched(contextInDraft, user, createEntitiesIds, { resolveStixFiles: true });

  // We add all deleted elements as stix objects to the bundle, but we mark them as a delete operation
  const deletedEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_DELETE);
  const deleteEntitiesIds = deletedEntities.map((e) => e.internal_id);
  const deleteStixEntities = await stixLoadByIdsBatched(contextInDraft, user, deleteEntitiesIds, includeDeleteOption);
  const deleteStixEntitiesModified = deleteStixEntities.map((d: any) => {
    const stixWithOperation = { ...d };
    stixWithOperation.extensions[STIX_EXT_OCTI].opencti_operation = 'delete';
    return stixWithOperation;
  });

  // Send update with "field patch" info
  const updateEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_UPDATE && e.draft_change.draft_updates_patch);
  const updateEntitiesIds = updateEntities.map((e) => e.internal_id);
  const updateStixEntities = await stixLoadByIdsBatched(contextInDraft, user, updateEntitiesIds);

  const updateStixEntitiesWithPatchPromises = updateStixEntities.map(async (d: any) => {
    const draftEntity = updateEntities.find((e) => e.standard_id === d.id);
    let stixPayloadReadyForExport = d;
    if (draftEntity) {
      // Resolve embedded markdown image URLs in the object payload.
      stixPayloadReadyForExport = await resolveEmbeddedImagesInDescriptionFieldsForExport(contextInDraft, d, {
        entityType: draftEntity.entity_type,
        entityId: draftEntity.internal_id,
      });
    }
    // Build patch operations from the stored draft change payload.
    const updateFieldPatchFromDraftChange = buildUpdateFieldPatch(draftEntity?.draft_change?.draft_updates_patch as string);
    // Resolve patch values (files and markdown) so import can apply them out of draft.
    const updateFieldPatchReadyForImport = await resolveDraftUpdateFiles(contextInDraft, user, updateFieldPatchFromDraftChange, {
      entityType: draftEntity?.entity_type,
      entityId: draftEntity?.internal_id,
    });

    const stixWithPatch = { ...stixPayloadReadyForExport };
    stixWithPatch.extensions[STIX_EXT_OCTI].opencti_operation = 'patch';
    stixWithPatch.extensions[STIX_EXT_OCTI].opencti_field_patch = updateFieldPatchReadyForImport;
    return stixWithPatch;
  });
  const updateStixEntitiesWithPatch = await Promise.all(updateStixEntitiesWithPatchPromises);

  return [...createStixEntities, ...deleteStixEntitiesModified, ...updateStixEntitiesWithPatch];
};

/**
 * Encode a STIX bundle as a base64 string ready for RabbitMQ transmission.
 */
const encodeBundleContent = (stixObjects: any[]): string => {
  const bundle = buildStixBundle(stixObjects);
  const jsonBundle = JSON.stringify(bundle);
  return Buffer.from(jsonBundle, 'utf-8').toString('base64');
};

export const validateDraftWorkspace = async (context: AuthContext, user: AuthUser, draft_id: string) => {
  const draftWorkspace = await checkAndReturnDraft(context, user, draft_id);
  if (draftWorkspace.draft_status !== DRAFT_STATUS_OPEN) {
    throw FunctionalError('Draft workspace cannot be validated in this state', { draftId: draft_id, status: draftWorkspace.draft_status });
  }
  const stixObjects = await buildDraftValidationBundle(context, user, draft_id);
  const totalObjectsCount = stixObjects.length;
  const isLargeDraft = totalObjectsCount > BUNDLE_SPLIT_THRESHOLD;

  logApp.info('[DRAFT] Starting draft validation', { draftId: draft_id, objectsCount: totalObjectsCount, isLargeDraft });

  const contextOutOfDraft = { ...context, draft_context: '' };
  const work: any = await createWork(
    contextOutOfDraft,
    SYSTEM_USER,
    DRAFT_VALIDATION_CONNECTOR,
    `Draft validation ${draftWorkspace.name} (${draft_id})`,
    DRAFT_VALIDATION_CONNECTOR.internal_id,
    { receivedTime: now(), isMultiPartWork: isLargeDraft },
  );

  if (isLargeDraft) {
    // Split into multiple smaller bundles and send as separate messages
    for (let i = 0; i < totalObjectsCount; i += BUNDLE_SPLIT_THRESHOLD) {
      const chunk = stixObjects.slice(i, i + BUNDLE_SPLIT_THRESHOLD);
      const content = encodeBundleContent(chunk);
      await pushToWorkerForConnector(DRAFT_VALIDATION_CONNECTOR.id, {
        type: 'bundle',
        applicant_id: user.internal_id,
        content,
        update: true,
        work_id: work.id,
        draft_id: '',
      });
    }
    logApp.info('[DRAFT] Large draft bundle split and sent', { draftId: draft_id, chunks: Math.ceil(totalObjectsCount / BUNDLE_SPLIT_THRESHOLD) });
  } else {
    // Small draft: send as a single bundle message
    const content = encodeBundleContent(stixObjects);
    if (totalObjectsCount === 1) {
      // Only add explicit expectation if the worker will not split anything
      await updateExpectationsNumber(contextOutOfDraft, context.user, work.id, totalObjectsCount);
    }
    await pushToWorkerForConnector(DRAFT_VALIDATION_CONNECTOR.id, {
      type: 'bundle',
      applicant_id: user.internal_id,
      content,
      update: true,
      work_id: work.id,
      draft_id: '',
    });
  }

  const draftValidationInput = [{ key: 'draft_status', value: [DRAFT_STATUS_VALIDATED] }, { key: 'validation_work_id', value: [work.id] }];
  const { element } = await updateAttribute(context, user, draft_id, ENTITY_TYPE_DRAFT_WORKSPACE, draftValidationInput);
  await notify(BUS_TOPICS[ENTITY_TYPE_DRAFT_WORKSPACE].EDIT_TOPIC, element, user);
  await deleteDraftContextFromUsers(context, user, draft_id);

  await addDraftValidationCount();

  return work;
};

export const listDraftContainerObjects = async (context: AuthContext, user: AuthUser, args: { draftId: string; containerId: string }) => {
  const { draftId, containerId } = args;
  await checkAndReturnDraft(context, user, draftId);
  const draftContext = { ...context, draft_context: draftId };

  const relations = await fullRelationsList(draftContext, user, RELATION_OBJECT, {
    fromId: containerId,
    indices: [READ_INDEX_DRAFT_OBJECTS],
    includeDeletedInDraft: true,
  });

  const relevantRels = relations.filter((rel) => {
    const op = rel.draft_change?.draft_operation;
    return op === DRAFT_OPERATION_CREATE || op === DRAFT_OPERATION_DELETE;
  });
  if (relevantRels.length === 0) return [];

  const entityIds = relevantRels.map((rel) => rel.toId);
  const entitiesMap = await elFindByIds<BasicStoreCommon>(draftContext, user, entityIds, {
    includeDeletedInDraft: true,
    toMap: true,
  }) as Record<string, BasicStoreCommon>;

  const result = [];
  for (const rel of relevantRels) {
    const entity = entitiesMap[rel.toId];
    if (!entity) continue;
    const op = rel.draft_change!.draft_operation;
    result.push({
      entity_id: rel.toId,
      entity_type: entity.entity_type,
      representative_main: extractEntityRepresentativeName(entity as any),
      draft_operation: op === DRAFT_OPERATION_CREATE ? DraftChangeType.Add : DraftChangeType.Remove,
    });
  }
  return result;
};

export const draftWorkspaceEditContext = async (context: AuthContext, user: AuthUser, draftId: string, input?: EditContext) => {
  await checkEnterpriseEdition(context);
  await checkAndReturnDraft(context, user, draftId);
  if (input) {
    await setEditContext(user, draftId, input);
  }
  return storeLoadById(context, user, draftId, ENTITY_TYPE_DRAFT_WORKSPACE).then((draft) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_DRAFT_WORKSPACE].CONTEXT_TOPIC, draft, user);
  });
};

export const resolveIdRepresentatives = async (
  context: AuthContext,
  user: AuthUser,
  args: { draftId: string; ids: string[] },
): Promise<{ id: string; representative_main: string | null }[]> => {
  const { draftId, ids } = args;
  if (ids.length === 0) return [];
  const MAX_RESOLVE_IDS = 100;
  if (ids.length > MAX_RESOLVE_IDS) {
    throw FunctionalError(`Too many IDs to resolve (max ${MAX_RESOLVE_IDS})`, { count: ids.length });
  }
  await checkAndReturnDraft(context, user, draftId);
  const draftContext = { ...context, draft_context: draftId };
  const entities = await elFindByIds<BasicStoreCommon>(draftContext, user, ids) as BasicStoreCommon[];
  return ids.map((id) => {
    const entity = entities.find((e) => e.standard_id === id || e.internal_id === id);
    return {
      id,
      representative_main: entity ? extractEntityRepresentativeName(entity as any) : null,
    };
  });
};

type DraftEntityRelationResult = {
  relation_id: string; relationship_type: string;
  from_id: string; from_type: string; from_name: string;
  to_id: string; to_type: string; to_name: string;
  draft_operation: DraftChangeType;
};

export const getEntityRelations = async (
  context: AuthContext,
  user: AuthUser,
  args: { draftId: string; entityId: string },
): Promise<DraftEntityRelationResult[]> => {
  const { draftId, entityId } = args;
  await checkAndReturnDraft(context, user, draftId);
  const draftContext = { ...context, draft_context: draftId };

  // Part 1: direct relations where the entity is from or to
  const directRelations = await fullRelationsList<BasicStoreRelation>(draftContext, user, [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], {
    fromOrToId: entityId,
    indices: [READ_INDEX_DRAFT_OBJECTS],
    includeDeletedInDraft: true,
  });
  const filteredDirect = directRelations.filter((rel) => {
    const op = rel.draft_change?.draft_operation;
    return op === DRAFT_OPERATION_CREATE || op === DRAFT_OPERATION_DELETE;
  });

  // Part 2: for containers (e.g. Report), find core/sighting relations that are objects of this entity
  // via RELATION_OBJECT refs (report → uses), which are not direct endpoints of the relation
  const objectRefs = await fullRelationsList<BasicStoreRelation>(draftContext, user, RELATION_OBJECT, {
    fromId: entityId,
    indices: [READ_INDEX_DRAFT_OBJECTS],
    includeDeletedInDraft: true,
  });
  const directRelationIds = new Set(filteredDirect.map((r) => r.internal_id));
  const containerRelations: { rel: BasicStoreRelation; refOp: string }[] = [];
  const relevantRefs = objectRefs.filter((ref) => {
    const refOp = ref.draft_change?.draft_operation;
    return refOp === DRAFT_OPERATION_CREATE || refOp === DRAFT_OPERATION_DELETE;
  });
  if (relevantRefs.length > 0) {
    const targetIds = relevantRefs.map((ref) => ref.toId);
    const targetsMap = await elFindByIds<BasicStoreRelation>(draftContext, user, targetIds, {
      includeDeletedInDraft: true,
      toMap: true,
    }) as Record<string, BasicStoreRelation>;
    for (const ref of relevantRefs) {
      const target = targetsMap[ref.toId];
      if (!target) continue;
      if (!isStixCoreRelationship(target.entity_type) && !isStixSightingRelationship(target.entity_type)) continue;
      if (directRelationIds.has(target.internal_id)) continue;
      containerRelations.push({ rel: target, refOp: ref.draft_change!.draft_operation });
    }
  }

  const directResults = filteredDirect.map((rel) => ({
    relation_id: rel.internal_id,
    relationship_type: rel.relationship_type,
    from_id: rel.fromId,
    from_type: rel.fromType,
    from_name: rel.fromName,
    to_id: rel.toId,
    to_type: rel.toType,
    to_name: rel.toName,
    draft_operation: rel.draft_change!.draft_operation === DRAFT_OPERATION_CREATE ? DraftChangeType.Create : DraftChangeType.Delete,
  }));
  const containerResults = containerRelations.map(({ rel, refOp }) => ({
    relation_id: rel.internal_id,
    relationship_type: rel.relationship_type,
    from_id: rel.fromId,
    from_type: rel.fromType,
    from_name: rel.fromName,
    to_id: rel.toId,
    to_type: rel.toType,
    to_name: rel.toName,
    // The ref changed (added/removed from this container), not the relation itself
    draft_operation: refOp === DRAFT_OPERATION_CREATE ? DraftChangeType.Add : DraftChangeType.Remove,
  }));
  return [...directResults, ...containerResults];
};

type DraftEntityContainerRefResult = {
  container_id: string;
  container_type: string;
  container_name: string;
  draft_operation: DraftChangeType;
};

export const getEntityContainerRefs = async (
  context: AuthContext,
  user: AuthUser,
  args: { draftId: string; entityId: string },
): Promise<DraftEntityContainerRefResult[]> => {
  const { draftId, entityId } = args;
  await checkAndReturnDraft(context, user, draftId);
  const draftContext = { ...context, draft_context: draftId };

  // Find RELATION_OBJECT refs pointing TO this entity (container → entityId)
  const objectRefs = await fullRelationsList<BasicStoreRelation>(draftContext, user, RELATION_OBJECT, {
    toId: entityId,
    indices: [READ_INDEX_DRAFT_OBJECTS],
    includeDeletedInDraft: true,
  });

  const relevantRefs = objectRefs.filter((ref) => {
    const op = ref.draft_change?.draft_operation;
    return op === DRAFT_OPERATION_CREATE || op === DRAFT_OPERATION_DELETE;
  });
  if (relevantRefs.length === 0) return [];

  const containerIds = relevantRefs.map((ref) => ref.fromId);
  const containersMap = await elFindByIds<BasicStoreCommon>(draftContext, user, containerIds, {
    includeDeletedInDraft: true,
    toMap: true,
  }) as Record<string, BasicStoreCommon>;

  const results: DraftEntityContainerRefResult[] = [];
  for (const ref of relevantRefs) {
    const container = containersMap[ref.fromId];
    if (!container) continue;
    const op = ref.draft_change!.draft_operation;
    results.push({
      container_id: ref.fromId,
      container_type: container.entity_type,
      container_name: extractEntityRepresentativeName(container as any),
      draft_operation: op === DRAFT_OPERATION_CREATE ? DraftChangeType.Add : DraftChangeType.Remove,
    });
  }
  return results;
};

const EXCLUDED_ENTITY_FIELDS = new Set([
  '_index', '_score', 'internal_id', 'standard_id', 'id',
  'parent_types', 'base_type', 'entity_type', 'i_aliases_ids',
  'i_attributes_computed', 'sort', 'draft_ids', 'draft_change', 'draft_context',
  'hashes', 'created_at', 'updated_at', 'spec_version',
  'x_opencti_stix_ids', 'creator_id', 'x_opencti_id', 'x_opencti_workflow_id', 'x_opencti_organization_id', 'x_opencti_tags_ids',
]);

export const getEntityFields = async (
  context: AuthContext,
  user: AuthUser,
  args: { draftId: string; entityId: string },
): Promise<{ field: string; values: string[] }[]> => {
  const { draftId, entityId } = args;
  await checkAndReturnDraft(context, user, draftId);
  const draftContext = { ...context, draft_context: draftId };
  const entities = await elFindByIds<BasicStoreCommon>(draftContext, user, [entityId], { includeDeletedInDraft: true }) as BasicStoreCommon[];
  const entity = entities[0];
  if (!entity) return [];

  return Object.entries(entity)
    .filter(([key, value]) => {
      if (EXCLUDED_ENTITY_FIELDS.has(key)) return false;
      if (key.startsWith('_') || key.startsWith('i_')) return false;
      if (key.startsWith('rel_')) return false;
      if (value === null || value === undefined) return false;
      if (Array.isArray(value) && value.length === 0) return false;
      if (typeof value === 'object' && !Array.isArray(value)) return false;
      return true;
    })
    .map(([field, value]) => ({
      field,
      values: Array.isArray(value) ? value.map(String) : [String(value)],
    }));
};
