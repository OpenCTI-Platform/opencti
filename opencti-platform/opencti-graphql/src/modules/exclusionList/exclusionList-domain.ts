import { Readable } from 'stream';
import conf, { BUS_TOPICS, isFeatureEnabled } from '../../config/conf';
import { type FileUploadData, uploadToStorage } from '../../database/file-storage-helper';
import { deleteFile } from '../../database/file-storage';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST, type StoreEntityExclusionList } from './exclusionList-types';
import { type ExclusionListContentAddInput, type ExclusionListFileAddInput, type MutationExclusionListFieldPatchArgs, type QueryExclusionListsArgs } from '../../generated/graphql';
import { getClusterInstances, notify, redisGetExclusionListStatus, redisUpdateExclusionListStatus } from '../../database/redis';
import { FunctionalError } from '../../config/errors';
import { updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { generateInternalId } from '../../schema/identifier';

const filePath = 'exclusionLists';

const isExclusionListEnabled = isFeatureEnabled('EXCLUSION_LIST');
const MAX_FILE_SIZE = conf.get('app:exclusion_list:file_max_size') ?? 10000000;

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityExclusionList>(context, user, id, ENTITY_TYPE_EXCLUSION_LIST);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryExclusionListsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityExclusionList>(context, user, [ENTITY_TYPE_EXCLUSION_LIST], args);
};

export const getCacheStatus = async () => {
  const redisCacheStatus = await redisGetExclusionListStatus();
  const refreshVersion = redisCacheStatus.last_refresh_ask_date ?? '';
  const cacheVersion = redisCacheStatus.last_cache_date ?? '';
  const clusterConfig = await getClusterInstances();
  const allNodeIds = clusterConfig.map((c) => c.platform_id);
  let isCacheRebuildInProgress = refreshVersion !== cacheVersion;
  for (let i = 0; i < clusterConfig.length; i += 1) {
    const platformInstanceId = allNodeIds[i];
    isCacheRebuildInProgress = isCacheRebuildInProgress || refreshVersion !== redisCacheStatus[platformInstanceId];
  }

  return { refreshVersion, cacheVersion, isCacheRebuildInProgress };
};

const refreshExclusionListStatus = async () => {
  await redisUpdateExclusionListStatus({ last_refresh_ask_date: (new Date()).toString() });
};

export const checkFileSize = async (createReadStream: () => Readable) => {
  const uploadStream = createReadStream();
  let byteLength = 0;
  let fileTooHeavy = false;
  // eslint-disable-next-line no-restricted-syntax
  for await (const uploadChunk of uploadStream) {
    byteLength += (uploadChunk as Buffer).byteLength;

    if (byteLength > MAX_FILE_SIZE) {
      fileTooHeavy = true;
      break;
    }
  }
  uploadStream.destroy();

  if (fileTooHeavy) {
    throw FunctionalError('Exclusion list file too large', { maxFileSize: MAX_FILE_SIZE });
  }
};

const uploadExclusionListFile = async (context: AuthContext, user: AuthUser, exclusionListId: string, file: FileUploadData) => {
  const fullFile = await file;
  await checkFileSize(fullFile.createReadStream);
  const exclusionFile = { ...fullFile, filename: `${exclusionListId}.txt` };
  const { upload } = await uploadToStorage(context, user, filePath, exclusionFile, {});
  return upload;
};

const storeAndCreateExclusionList = async (context: AuthContext, user: AuthUser, input: ExclusionListContentAddInput | ExclusionListFileAddInput, file: FileUploadData) => {
  const exclusionListInternalId = generateInternalId();
  const upload = await uploadExclusionListFile(context, user, exclusionListInternalId, file);
  const exclusionListToCreate = {
    name: input.name,
    description: input.description,
    enabled: true,
    exclusion_list_entity_types: input.exclusion_list_entity_types,
    file_id: upload.id,
    internal_id: exclusionListInternalId
  };
  const createdExclusionList = createInternalObject<StoreEntityExclusionList>(context, user, exclusionListToCreate, ENTITY_TYPE_EXCLUSION_LIST);
  await refreshExclusionListStatus();
  return createdExclusionList;
};

export const addExclusionListContent = async (context: AuthContext, user: AuthUser, input: ExclusionListContentAddInput) => {
  if (!isExclusionListEnabled) throw new Error('Feature not yet available');
  const file = {
    createReadStream: () => Readable.from(Buffer.from(input.content, 'utf-8')),
    filename: `${input.name}.txt`,
    mimetype: 'text/plain',
  };

  return storeAndCreateExclusionList(context, user, input, file);
};
export const addExclusionListFile = async (context: AuthContext, user: AuthUser, input: ExclusionListFileAddInput) => {
  if (!isExclusionListEnabled) throw new Error('Feature not yet available');
  return storeAndCreateExclusionList(context, user, input, input.file);
};

export const fieldPatchExclusionList = async (context: AuthContext, user: AuthUser, args: MutationExclusionListFieldPatchArgs) => {
  const { id, file, input } = args;
  const exclusionList = await findById(context, user, id);
  if (!exclusionList) {
    throw FunctionalError(`Exclusion list ${id} cannot be found`);
  }

  if (file) {
    await uploadExclusionListFile(context, user, exclusionList.internal_id, file);
  }
  let element;
  if (input) {
    const { updatedElement } = await updateAttribute(context, user, id, ENTITY_TYPE_EXCLUSION_LIST, input);
    element = updatedElement;
  }

  if (file || (input && input.some((i) => i.key === 'enabled'))) {
    await refreshExclusionListStatus();
  }
  if (element) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `updates \`${input?.map((i) => i.key).join(', ')}\` for exclusion list \`${element.name}\``,
      context_data: { id, entity_type: ENTITY_TYPE_EXCLUSION_LIST, input }
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_EXCLUSION_LIST].EDIT_TOPIC, element, user);
  }
  return exclusionList;
};

export const deleteExclusionList = async (context: AuthContext, user: AuthUser, exclusionListId: string) => {
  if (!isExclusionListEnabled) throw new Error('Feature not yet available');
  const exclusionList = await findById(context, user, exclusionListId);
  await deleteFile(context, user, exclusionList.file_id);
  const deletedExclusionList = deleteInternalObject(context, user, exclusionListId, ENTITY_TYPE_EXCLUSION_LIST);
  await refreshExclusionListStatus();
  return deletedExclusionList;
};
