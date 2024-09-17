import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { DraftWorkspaceAddInput, QueryDraftWorkspaceEntitiesArgs, QueryDraftWorkspacesArgs } from '../../generated/graphql';
import { createInternalObject } from '../../domain/internalObject';
import { now } from '../../utils/format';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE, type StoreEntityDraftWorkspace } from './draftWorkspace-types';
import { elDeleteDraftElements } from '../../database/engine';
import { READ_INDEX_DRAFT } from '../../database/utils';
import { FunctionalError } from '../../config/errors';
import { deleteElementById } from '../../database/middleware';
import type { BasicStoreEntity } from '../../types/store';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isFeatureEnabled } from '../../config/conf';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDraftWorkspace>(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspacesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDraftWorkspace>(context, user, [ENTITY_TYPE_DRAFT_WORKSPACE], args);
};

export const findAllEntities = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceEntitiesArgs) => {
  let types: string[] = [];
  if (args && args.types) {
    types = args.types.filter((t) => t && isStixCoreObject(t)) as string[];
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  const newArgs: EntityOptions<BasicStoreEntity> = { ...args, types, indices: [READ_INDEX_DRAFT] };
  return listEntitiesPaginated<BasicStoreEntity>(context, user, types, newArgs);
};

export const addDraftWorkspace = async (context: AuthContext, user: AuthUser, input: DraftWorkspaceAddInput) => {
  const defaultOps = {
    created_at: now(),
  };

  if (!isFeatureEnabled('DRAFT_WORKSPACE')) throw new Error('Feature not yet available');

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
