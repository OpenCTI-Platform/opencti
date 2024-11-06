import { Readable } from 'stream';
import { type FileUploadData, uploadToStorage } from '../../database/file-storage-helper';
import { deleteFile } from '../../database/file-storage';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST, type StoreEntityExclusionList } from './exclusionList-types';
import type { ExclusionListContentAddInput, ExclusionListFileAddInput, QueryExclusionListsArgs } from '../../generated/graphql';

const filePath = 'exclusionLists';
export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityExclusionList>(context, user, id, ENTITY_TYPE_EXCLUSION_LIST);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryExclusionListsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityExclusionList>(context, user, [ENTITY_TYPE_EXCLUSION_LIST], args);
};

const storeAndCreateExclusionList = async (context: AuthContext, user: AuthUser, input: ExclusionListContentAddInput | ExclusionListFileAddInput, file: FileUploadData) => {
  const { upload } = await uploadToStorage(context, user, filePath, file, {});

  const exclusionListToCreate = {
    name: input.name,
    description: input.description,
    enabled: false,
    exclusion_list_entity_types: input.list_entity_types,
    file_id: upload.id
  };

  return createInternalObject<StoreEntityExclusionList>(context, user, exclusionListToCreate, ENTITY_TYPE_EXCLUSION_LIST);
};

export const addExclusionListContent = async (context: AuthContext, user: AuthUser, input: ExclusionListContentAddInput) => {
  const file = {
    createReadStream: () => Readable.from(Buffer.from(input.content, 'utf-8')),
    filename: `${input.name}.txt`,
    mimetype: 'text/plain',
  };

  return storeAndCreateExclusionList(context, user, input, file);
};
export const addExclusionListFile = async (context: AuthContext, user: AuthUser, input: ExclusionListFileAddInput) => {
  return storeAndCreateExclusionList(context, user, input, input.file);
};

export const deleteExclusionList = async (context: AuthContext, user: AuthUser, exclusionListId: string) => {
  const exclusionList = await findById(context, user, exclusionListId);
  await deleteFile(context, user, exclusionList.file_id);
  return deleteInternalObject(context, user, exclusionListId, ENTITY_TYPE_EXCLUSION_LIST);
};
