import { BUS_TOPICS, logApp } from '../../config/conf';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { elDeleteDraftContextFromUsers, elDeleteDraftContextFromWorks, elDeleteDraftElements, resolveDraftUpdateFiles } from '../../database/draft-engine';
import { buildUpdateFieldPatch } from '../../database/draft-utils';
import { elAggregationCount, elCount, elList, elLoadById, loadDraftElement } from '../../database/engine';
import { createEntity, deleteElementById, stixLoadByIds, updateAttribute } from '../../database/middleware';
import { type EntityOptions, fullEntitiesList, pageEntitiesConnection, pageRelationsConnection, storeLoadById } from '../../database/middleware-loader';
import { pushToWorkerForConnector } from '../../database/rabbitmq';
import { notify } from '../../database/redis';
import { buildStixBundle } from '../../database/stix-2-1-converter';
import { computeSumOfList, isDraftIndex, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { createWork, updateExpectationsNumber } from '../../domain/work';
import {
  type DraftWorkspaceAddInput,
  FilterMode,
  FilterOperator,
  type MemberAccessInput,
  type QueryDraftWorkspaceEntitiesArgs,
  type QueryDraftWorkspaceRelationshipsArgs,
  type QueryDraftWorkspacesArgs,
  type QueryDraftWorkspaceSightingRelationshipsArgs,
} from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { addDraftCreationCount, addDraftValidationCount } from '../../manager/telemetryManager';
import { authorizedMembers } from '../../schema/attribute-definition';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_INTERNAL_FILE, ENTITY_TYPE_USER, ENTITY_TYPE_WORK } from '../../schema/internalObject';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isStixRefRelationship } from '../../schema/stixRefRelationship';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { isStixRelationshipExceptRef } from '../../schema/stixRelationship';
import { isStixDomainObject, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { deleteAllDraftFiles } from '../../database/file-storage';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { getUserAccessRight, SYSTEM_USER } from '../../utils/access';
import { editAuthorizedMembers } from '../../utils/authorizedMembers';
import { getDraftContext } from '../../utils/draftContext';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { now } from '../../utils/format';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_DELETE, DRAFT_OPERATION_UPDATE } from './draftOperations';
import { DRAFT_STATUS_OPEN, DRAFT_STATUS_VALIDATED } from './draftStatuses';
import { DRAFT_VALIDATION_CONNECTOR } from './draftWorkspace-connector';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE, type StoreEntityDraftWorkspace } from './draftWorkspace-types';

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
  return {
    totalCount,
    entitiesCount,
    observablesCount,
    relationshipsCount,
    sightingsCount,
    containersCount,
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
  context: AuthContext,
  user: AuthUser,
  draft: BasicStoreEntityDraftWorkspace,
) => {
  return getUserAccessRight(user, draft);
};

export const listDraftObjects = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceEntitiesArgs) => {
  let types: string[] = [];
  const { draftId, ...listArgs } = args;
  if (args.types) {
    types = args.types.filter((t) => t && isStixCoreObject(t)) as string[];
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  const newArgs: EntityOptions<BasicStoreEntity> = { ...listArgs, types, indices: [READ_INDEX_DRAFT_OBJECTS], includeDeletedInDraft: true };
  const draftContext = { ...context, draft_context: draftId };
  return pageEntitiesConnection<BasicStoreEntity>(draftContext, user, types, newArgs);
};

export const listDraftRelations = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceRelationshipsArgs) => {
  let types: string[] = [];
  const { draftId, ...listArgs } = args;
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

export const listDraftSightingRelations = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceSightingRelationshipsArgs) => {
  let types: string[] = [];
  const { draftId, ...listArgs } = args;
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

export const draftWorkspaceEditAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: MemberAccessInput[] | undefined | null,
) => {
  const args = {
    entityId: workspaceId,
    input,
    requiredCapabilities: ['EXPLORE_EXUPDATE_EXDELETE'],
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
  const draftWorkspace = await findById(context, user, id);
  if (!draftWorkspace) {
    throw FunctionalError(`Draft workspace ${id} cannot be found`, id);
  }
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

  return { draft_id: object.draft_ids[0], draft_operation: object.draft_change?.draft_operation };
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
  const createStixEntities = await stixLoadByIds(contextInDraft, user, createEntitiesIds, { resolveStixFiles: true });

  // We add all deleted elements as stix objects to the bundle, but we mark them as a delete operation
  const deletedEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_DELETE);
  const deleteEntitiesIds = deletedEntities.map((e) => e.internal_id);
  const deleteStixEntities = await stixLoadByIds(contextInDraft, user, deleteEntitiesIds, includeDeleteOption);
  const deleteStixEntitiesModified = deleteStixEntities.map((d: any) => {
    const stixWithOperation = { ...d };
    stixWithOperation.extensions[STIX_EXT_OCTI].opencti_operation = 'delete';
    return stixWithOperation;
  });

  // Send update with "field patch" info
  const updateEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_UPDATE && e.draft_change.draft_updates_patch);
  const updateEntitiesIds = updateEntities.map((e) => e.internal_id);
  const updateStixEntities = await stixLoadByIds(contextInDraft, user, updateEntitiesIds);
  const updateStixEntitiesWithPatchPromises = updateStixEntities.map(async (d: any) => {
    const updateFieldPatchNonResolved = buildUpdateFieldPatch(updateEntities.find((e) => e.standard_id === d.id)?.draft_change?.draft_updates_patch as string);
    const updateFieldPatchResolved = await resolveDraftUpdateFiles(contextInDraft, user, updateFieldPatchNonResolved);
    const stixWithPatch = { ...d };
    stixWithPatch.extensions[STIX_EXT_OCTI].opencti_operation = 'patch';
    stixWithPatch.extensions[STIX_EXT_OCTI].opencti_field_patch = updateFieldPatchResolved;
    return stixWithPatch;
  });
  const updateStixEntitiesWithPatch = await Promise.all(updateStixEntitiesWithPatchPromises);

  return buildStixBundle([...createStixEntities, ...deleteStixEntitiesModified, ...updateStixEntitiesWithPatch]);
};

export const validateDraftWorkspace = async (context: AuthContext, user: AuthUser, draft_id: string) => {
  const draftWorkspace = await findById(context, user, draft_id);
  if (!draftWorkspace) {
    throw FunctionalError(`Draft workspace ${draft_id} cannot be found`, draft_id);
  }
  if (draftWorkspace.draft_status !== DRAFT_STATUS_OPEN) {
    throw FunctionalError('Draft workspace cannot be validated in this state', { draftId: draft_id, status: draftWorkspace.draft_status });
  }
  const stixBundle = await buildDraftValidationBundle(context, user, draft_id);
  const jsonBundle = JSON.stringify(stixBundle);
  const content = Buffer.from(jsonBundle, 'utf-8').toString('base64');

  const contextOutOfDraft = { ...context, draft_context: '' };
  const work: any = await createWork(contextOutOfDraft, SYSTEM_USER, DRAFT_VALIDATION_CONNECTOR, `Draft validation ${draftWorkspace.name} (${draft_id})`, DRAFT_VALIDATION_CONNECTOR.internal_id, { receivedTime: now() });
  if (stixBundle.objects.length === 1) {
    // Only add explicit expectation if the worker will not split anything
    await updateExpectationsNumber(contextOutOfDraft, context.user, work.id, stixBundle.objects.length);
  }
  await pushToWorkerForConnector(DRAFT_VALIDATION_CONNECTOR.id, { type: 'bundle', applicant_id: user.internal_id, content, update: true, work_id: work.id, draft_id: '' });
  const draftValidationInput = [{ key: 'draft_status', value: [DRAFT_STATUS_VALIDATED] }, { key: 'validation_work_id', value: [work.id] }];
  const { element } = await updateAttribute(context, user, draft_id, ENTITY_TYPE_DRAFT_WORKSPACE, draftValidationInput);
  await notify(BUS_TOPICS[ENTITY_TYPE_DRAFT_WORKSPACE].EDIT_TOPIC, element, user);
  await deleteDraftContextFromUsers(context, user, draft_id);

  await addDraftValidationCount();

  return work;
};
