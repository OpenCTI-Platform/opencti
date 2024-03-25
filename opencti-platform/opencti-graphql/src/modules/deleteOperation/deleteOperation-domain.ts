import { type BasicStoreEntityDeleteOperation, ENTITY_TYPE_DELETE_OPERATION } from './deleteOperation-types';
import { FunctionalError } from '../../config/errors';
import { elDeleteInstances, elFindByIds } from '../../database/engine';
import { deleteAllObjectFiles } from '../../database/file-storage';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { READ_INDEX_DELETED_OBJECTS } from '../../database/utils';
import type { QueryDeleteOperationsArgs } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';

export const findById = async (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDeleteOperation>(context, user, id, ENTITY_TYPE_DELETE_OPERATION);
};

export const findAll = async (context: AuthContext, user: AuthUser, args: QueryDeleteOperationsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDeleteOperation>(context, user, [ENTITY_TYPE_DELETE_OPERATION], args);
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const restoreDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  throw new Error('Restore delete not implemented');
};

export const completeDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const deleteOperation = await findById(context, user, id);
  if (!deleteOperation) {
    throw FunctionalError(`Delete operation ${id} cannot be found`);
  }
  // get all deleted elements & main deleted entity (from deleted_objects index)
  const mainEntityId = deleteOperation.main_entity_id;
  const deletedElementsIds = deleteOperation.deleted_elements.map((el) => el.id);
  const deletedElements: any[] = await elFindByIds(context, user, deletedElementsIds, { indices: READ_INDEX_DELETED_OBJECTS }) as any[];
  const mainDeletedEntity = deletedElements.find((el) => el.internal_id === mainEntityId);
  if (mainDeletedEntity) {
    // delete main entity files
    await deleteAllObjectFiles(context, user, mainDeletedEntity);
  }
  // delete elements
  await elDeleteInstances([...deletedElements]);
  // finally delete deleteOperation
  await elDeleteInstances([deleteOperation]);
  return id;
};
