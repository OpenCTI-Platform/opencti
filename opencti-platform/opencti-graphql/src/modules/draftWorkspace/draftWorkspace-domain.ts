import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type DraftWorkspaceAddInput, FilterMode, type QueryDraftWorkspaceEntitiesArgs, type QueryDraftWorkspacesArgs } from '../../generated/graphql';
import { createInternalObject } from '../../domain/internalObject';
import { now } from '../../utils/format';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE, type StoreEntityDraftWorkspace } from './draftWorkspace-types';
import { elDeleteDraftContextFromUsers, elDeleteDraftElements } from '../../database/draft-engine';
import { READ_INDEX_DRAFT_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { deleteElementById, stixLoadByIds } from '../../database/middleware';
import type { BasicStoreEntity } from '../../types/store';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isFeatureEnabled } from '../../config/conf';
import { getDraftContext } from '../../utils/draftContext';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { usersSessionRefresh } from '../../domain/user';
import { elList } from '../../database/engine';
import { isStixRefRelationship } from '../../schema/stixRefRelationship';
import { buildStixBundle } from '../../database/stix-converter';
import { pushToWorkerForDraft } from '../../database/rabbitmq';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDraftWorkspace>(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspacesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDraftWorkspace>(context, user, [ENTITY_TYPE_DRAFT_WORKSPACE], args);
};

export const listDraftObjects = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceEntitiesArgs) => {
  let types: string[] = [];
  if (args && args.types) {
    types = args.types.filter((t) => t && isStixCoreObject(t)) as string[];
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  const newArgs: EntityOptions<BasicStoreEntity> = { ...args, types, indices: [READ_INDEX_DRAFT_OBJECTS] };
  return listEntitiesPaginated<BasicStoreEntity>(context, user, types, newArgs);
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

const deleteDraftContextFromUsers = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const usersWithDraftContext = await findAllUsersWithDraftContext(context, user, draftId);
  if (usersWithDraftContext.length > 0) {
    await elDeleteDraftContextFromUsers(context, user, draftId);
    const usersIds = usersWithDraftContext.map((u) => u.id);
    await usersSessionRefresh(usersIds);
  }
};

export const deleteDraftWorkspace = async (context: AuthContext, user: AuthUser, id: string) => {
  if (getDraftContext(context, user)) throw UnsupportedError('Cannot delete draft while in draft context');
  const draftWorkspace = await findById(context, user, id);
  if (!draftWorkspace) {
    throw FunctionalError(`Draft workspace ${id} cannot be found`, id);
  }

  await elDeleteDraftElements(context, user, id);
  await deleteDraftContextFromUsers(context, user, id);
  await deleteElementById(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);

  return id;
};

export const validateDraftWorkspace = async (context: AuthContext, user: AuthUser, draft_id: string) => {
  context.draft_context = draft_id;
  const draftEntities = await elList(context, user, READ_INDEX_DRAFT_OBJECTS);

  const draftEntitiesMinusRefRel = draftEntities.filter((e) => !isStixRefRelationship(e.entity_type));

  const createEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === 'create');
  const createEntitiesIds = createEntities.map((e) => e.internal_id);
  const createStixEntities = await stixLoadByIds(context, user, createEntitiesIds, { draftID: user.draft_context });

  const deletedEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === 'delete');
  const deleteEntitiesIds = deletedEntities.map((e) => e.internal_id);
  const deleteStixEntities = await stixLoadByIds(context, user, deleteEntitiesIds);
  const deleteStixEntitiesModified = deleteStixEntities.map((d: any) => ({ ...d, opencti_operation: 'delete' }));

  // TODO handle updated entities
  // const updatedEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === 'update'
  //     && e.draft_change.draft_updates && e.draft_change.draft_updates.length > 0);
  // const convertUpdatedEntityToStix = async (updatedDraftEntity: any) => {
  //   const element = await elLoadById(context, SYSTEM_USER, updatedDraftEntity.internal_id, { withoutRels: true, connectionFormat: false });
  //   if (!element) return element;
  //
  //   for (let i = 0; i < updatedDraftEntity.draft_change.draft_updates.length; i += 1) {
  //     const draftUpdate = updatedDraftEntity.draft_change.draft_updates[i];
  //     element[draftUpdate.draft_update_field] = draftUpdate.draft_update_values;
  //   }
  //   const elementsWithDeps = await loadElementsWithDependencies(context, user, [element], { draftID: user.draft_context });
  //   if (elementsWithDeps.length === 0) return null;
  //   const elementWithDep = elementsWithDeps[0];
  //   return convertStoreToStix(elementWithDep);
  // };
  // const updateStixEntities = await Promise.all(updatedEntities.map(async (e) => convertUpdatedEntityToStix(e)).filter((e) => e));

  const stixBundle = buildStixBundle([...createStixEntities, ...deleteStixEntitiesModified]);
  const jsonBundle = JSON.stringify(stixBundle);
  const content = Buffer.from(jsonBundle, 'utf-8').toString('base64');
  await pushToWorkerForDraft({ type: 'bundle', applicant_id: user.internal_id, content, update: true });

  await deleteDraftWorkspace({ ...context, draft_context: '' }, user, draft_id);

  return jsonBundle;
};
