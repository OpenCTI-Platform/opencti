import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listAllEntities, listEntitiesPaginated, listRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import {
  type DraftWorkspaceAddInput,
  FilterMode,
  type QueryDraftWorkspaceEntitiesArgs,
  type QueryDraftWorkspaceRelationshipsArgs,
  type QueryDraftWorkspacesArgs
} from '../../generated/graphql';
import { createInternalObject } from '../../domain/internalObject';
import { now } from '../../utils/format';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE, type StoreEntityDraftWorkspace } from './draftWorkspace-types';
import { elDeleteDraftContextFromUsers, elDeleteDraftElements } from '../../database/draft-engine';
import { isDraftIndex, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { deleteElementById, stixLoadByIds } from '../../database/middleware';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP } from '../../schema/general';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { BUS_TOPICS, isFeatureEnabled } from '../../config/conf';
import { getDraftContext } from '../../utils/draftContext';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { usersSessionRefresh } from '../../domain/user';
import { elList } from '../../database/engine';
import { buildStixBundle } from '../../database/stix-converter';
import { pushToWorkerForConnector } from '../../database/rabbitmq';
import { SYSTEM_USER } from '../../utils/access';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_DELETE, DRAFT_OPERATION_UPDATE } from '../../database/draft-utils';
import { createWork, updateExpectationsNumber } from '../../domain/work';
import { DRAFT_VALIDATION_CONNECTOR } from './draftWorkspace-connector';
import { isStixRefRelationship } from '../../schema/stixRefRelationship';
import { notify } from '../../database/redis';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { isStixRelationshipExceptRef } from '../../schema/stixRelationship';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDraftWorkspace>(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspacesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDraftWorkspace>(context, user, [ENTITY_TYPE_DRAFT_WORKSPACE], args);
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
  return listEntitiesPaginated<BasicStoreEntity>(draftContext, user, types, newArgs);
};

export const listDraftRelations = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceRelationshipsArgs) => {
  let types: string[] = [];
  const { draftId, ...listArgs } = args;
  if (args.types) {
    types = args.types.filter((t) => t && isStixRelationshipExceptRef(t)) as string[];
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_RELATIONSHIP);
    types.push(STIX_SIGHTING_RELATIONSHIP);
  }
  const newArgs: EntityOptions<BasicStoreRelation> = { ...listArgs, types, indices: [READ_INDEX_DRAFT_OBJECTS], includeDeletedInDraft: true };
  const draftContext = { ...context, draft_context: draftId };
  return listRelationsPaginated<BasicStoreRelation>(draftContext, user, types, newArgs);
};

export const addDraftWorkspace = async (context: AuthContext, user: AuthUser, input: DraftWorkspaceAddInput) => {
  if (!isFeatureEnabled('DRAFT_WORKSPACE')) throw new Error('Feature not yet available');
  const defaultOps = {
    created_at: now(),
  };
  const draftWorkspaceInput = { ...input, ...defaultOps };
  return createInternalObject<StoreEntityDraftWorkspace>(context, user, draftWorkspaceInput, ENTITY_TYPE_DRAFT_WORKSPACE);
};

const findAllUsersWithDraftContext = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const listArgs = {
    connectionFormat: false,
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['draft_context'], values: [draftId] }], filterGroups: [] }
  };
  return listAllEntities(context, user, [ENTITY_TYPE_USER], listArgs);
};

// When deleting a draft, we need to move all users that are still in the draft context back to the live context
const deleteDraftContextFromUsers = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const usersWithDraftContext = await findAllUsersWithDraftContext(context, user, draftId);
  if (usersWithDraftContext.length > 0) {
    await elDeleteDraftContextFromUsers(context, user, draftId);
    const usersIds = usersWithDraftContext.map((u) => u.id);
    await usersSessionRefresh(usersIds);
    await Promise.all(usersWithDraftContext.map((u) => notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, u, user)));
  }
};

export const deleteDraftWorkspace = async (context: AuthContext, user: AuthUser, id: string) => {
  if (getDraftContext(context, user)) throw UnsupportedError('Cannot delete draft while in draft context');
  const draftWorkspace = await findById(context, user, id);
  if (!draftWorkspace) {
    throw FunctionalError(`Draft workspace ${id} cannot be found`, id);
  }
  await elDeleteDraftElements(context, user, id); // delete all draft elements from draft index
  await deleteDraftContextFromUsers(context, user, id);
  await deleteElementById(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);

  return id;
};

export const buildDraftVersion = (object: BasicStoreCommon) => {
  if (!isDraftIndex(object._index)) {
    return null;
  }

  if (!object.draft_ids || object.draft_ids.length === 0) {
    throw FunctionalError('Cannot find draft ids on draft entity', { id: object.id });
  }

  return { draft_id: object.draft_ids[0], draft_operation: object.draft_change?.draft_operation };
};

export const buildDraftValidationBundle = async (context: AuthContext, user: AuthUser, draft_id: string) => {
  const contextInDraft = { ...context, draft_context: draft_id };
  const includeDeleteOption = { includeDeletedInDraft: true };
  // We start by listing all elements currently in this draft context
  const draftEntities = await elList(contextInDraft, user, READ_INDEX_DRAFT_OBJECTS, includeDeleteOption);

  const draftEntitiesMinusRefRel = draftEntities.filter((e) => !isStixRefRelationship(e.entity_type));

  // We add all created elements as stix objects to the bundle
  const createEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_CREATE);
  const createEntitiesIds = createEntities.map((e) => e.internal_id);
  const createStixEntities = await stixLoadByIds(contextInDraft, user, createEntitiesIds);

  // We add all deleted elements as stix objects to the bundle, but we mark them as a delete operation
  const deletedEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_DELETE);
  const deleteEntitiesIds = deletedEntities.map((e) => e.internal_id);
  const deleteStixEntities = await stixLoadByIds(contextInDraft, user, deleteEntitiesIds, includeDeleteOption);
  const deleteStixEntitiesModified = deleteStixEntities.map((d: any) => ({ ...d, opencti_operation: 'delete' }));

  // We add all deleted refs in the bundle, marking them as a delete operation
  const draftStixDeleteRefs = draftEntities.filter((e) => isStixRefRelationship(e.entity_type) && e.draft_change?.draft_operation === DRAFT_OPERATION_DELETE);
  const deletedRefsBundle = draftStixDeleteRefs.map((ref) => ({ id: ref.internal_id, type: ABSTRACT_STIX_REF_RELATIONSHIP, opencti_operation: 'delete' }));

  // TODO: for now, updated entities are fully sent in bundle. But once update metadata are OK, we will want to take the live element and only apply updates done in the draft
  const updateEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_UPDATE);
  const updateEntitiesIds = updateEntities.map((e) => e.internal_id);
  const updateStixEntities = await stixLoadByIds(contextInDraft, user, updateEntitiesIds);

  // const updatedEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === DRAFT_OPERATION_UPDATE
  //     && e.draft_change.draft_update_patch && e.draft_change.draft_update_patch.length > 0);
  // const convertUpdatedEntityToStix = async (updatedDraftEntity: any) => {
  //   const element = await elLoadById(contextOutOfDraft, user, updatedDraftEntity.internal_id, { withoutRels: true, connectionFormat: false }) as any;
  //   if (!element) return element;
  //
  //   for (let i = 0; i < updatedDraftEntity.draft_change.draft_update_patch.length; i += 1) {
  //     const { path, value } = updatedDraftEntity.draft_change.draft_update_patch[i];
  //     element[path] = value;
  //   }
  //   const elementsWithDeps = await loadElementsWithDependencies(contextInDraft, user, [element]);
  //   if (elementsWithDeps.length === 0) return null;
  //   const elementWithDep = elementsWithDeps[0];
  //   return convertStoreToStix(elementWithDep);
  // };
  // const updateStixEntities = await Promise.all(updatedEntities.map(async (e) => convertUpdatedEntityToStix(e)).filter((e) => e));

  return buildStixBundle([...createStixEntities, ...deleteStixEntitiesModified, ...deletedRefsBundle, ...updateStixEntities]);
};

export const validateDraftWorkspace = async (context: AuthContext, user: AuthUser, draft_id: string) => {
  const draftWorkspace = await findById(context, user, draft_id);
  if (!draftWorkspace) {
    throw FunctionalError(`Draft workspace ${draft_id} cannot be found`, draft_id);
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
  await pushToWorkerForConnector(DRAFT_VALIDATION_CONNECTOR.id, { type: 'bundle', applicant_id: user.internal_id, content, update: true, work_id: work.id });
  await deleteDraftWorkspace(contextOutOfDraft, user, draft_id);

  return work;
};
