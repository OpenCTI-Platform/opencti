import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { DraftWorkspaceAddInput, QueryDraftWorkspaceEntitiesArgs, QueryDraftWorkspacesArgs } from '../../generated/graphql';
import { createInternalObject } from '../../domain/internalObject';
import { now } from '../../utils/format';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE, type StoreEntityDraftWorkspace } from './draftWorkspace-types';
import {
  elCreateIndex,
  elDeleteDraftElements,
  elDeleteIndices,
  elList,
  elLoadById,
  elPlatformIndices,
  engineMappingGenerator
} from '../../database/engine';
import {ES_INDEX_PREFIX, isNotEmptyField, READ_INDEX_DRAFT} from '../../database/utils';
import { FunctionalError } from '../../config/errors';
import { deleteElementById, loadElementsWithDependencies, stixLoadByIds } from '../../database/middleware';
import { buildStixBundle, convertStoreToStix } from '../../database/stix-converter';
import { isStixRefRelationship } from '../../schema/stixRefRelationship';
import { pushToWorkerForDraft } from '../../database/rabbitmq';
import { SYSTEM_USER } from '../../utils/access';
import type { BasicStoreEntity } from '../../types/store';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { isStixCoreObject } from '../../schema/stixCoreObject';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDraftWorkspace>(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspacesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDraftWorkspace>(context, user, [ENTITY_TYPE_DRAFT_WORKSPACE], args);
};

export const findAllEntities = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceEntitiesArgs) => {
  let types = [];
  if (isNotEmptyField(args.types)) {
    types = R.filter((type) => isStixCoreObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  return listEntitiesPaginated<BasicStoreEntity>(context, user, types, { ...args, indices: [READ_INDEX_DRAFT] });
};

export const addDraftWorkspace = async (context: AuthContext, user: AuthUser, input: DraftWorkspaceAddInput) => {
  const defaultOps = {
    created_at: now(),
  };

  const draftWorkspaceInput = { ...input, ...defaultOps };
  const createdDraftWorkspace = await createInternalObject<StoreEntityDraftWorkspace>(context, user, draftWorkspaceInput, ENTITY_TYPE_DRAFT_WORKSPACE);

  return createdDraftWorkspace;
};

export const deleteDraftWorkspace = async (context: AuthContext, user: AuthUser, id: string) => {
  const draftWorkspace = await findById(context, user, id);
  if (!draftWorkspace) {
    throw FunctionalError(`Draft workspace ${id} cannot be found`, id);
  }

  await elDeleteDraftElements(context, user, id);
  await deleteElementById(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);

  return id;
};

export const validateDraftWorkspace = async (context: AuthContext, user: AuthUser, id: string) => {
  const draftEntities = await elList(context, user, READ_INDEX_DRAFT);

  const draftEntitiesMinusRefRel = draftEntities.filter((e) => !isStixRefRelationship(e.entity_type));

  const createEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === 'create');
  const createEntitiesIds = createEntities.map((e) => e.internal_id);
  const createStixEntities = await stixLoadByIds(context, user, createEntitiesIds, { draftID: user.workspace_context });

  const deletedEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === 'delete');
  const deleteEntitiesIds = deletedEntities.map((e) => e.internal_id);
  const deleteStixEntities = await stixLoadByIds(context, user, deleteEntitiesIds);
  const deleteStixEntitiesModified = deleteStixEntities.map((d) => ({ ...d, opencti_operation: 'delete' }));

  const updatedEntities = draftEntitiesMinusRefRel.filter((e) => e.draft_change?.draft_operation === 'update'
      && e.draft_change.draft_updates && e.draft_change.draft_updates.length > 0);
  const convertUpdatedEntityToStix = async (updatedDraftEntity) => {
    const element = await elLoadById(context, SYSTEM_USER, updatedDraftEntity.internal_id, { withoutRels: true, connectionFormat: false });
    if (!element) return element;

    for (let i = 0; i < updatedDraftEntity.draft_change.draft_updates.length; i += 1) {
      const draftUpdate = updatedDraftEntity.draft_change.draft_updates[i];
      element[draftUpdate.draft_update_field] = draftUpdate.draft_update_values;
    }
    const elementsWithDeps = await loadElementsWithDependencies(context, user, [element], { draftID: user.workspace_context });
    if (elementsWithDeps.length === 0) return null;
    const elementWithDep = elementsWithDeps[0];
    return convertStoreToStix(elementWithDep);
  };
  const updateStixEntities = await Promise.all(updatedEntities.map(async (e) => convertUpdatedEntityToStix(e)).filter((e) => e));

  const stixBundle = buildStixBundle([...createStixEntities, ...deleteStixEntitiesModified, ...updateStixEntities]);
  const jsonBundle = JSON.stringify(stixBundle);
  const content = Buffer.from(jsonBundle, 'utf-8').toString('base64');
  await pushToWorkerForDraft({ type: 'bundle', applicant_id: user.internal_id, content, update: true });

  return jsonBundle;
};
