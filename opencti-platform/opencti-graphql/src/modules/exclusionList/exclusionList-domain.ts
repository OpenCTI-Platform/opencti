import { Readable } from 'stream';
import conf, { BUS_TOPICS } from '../../config/conf';
import { type FileUploadData, uploadToStorage } from '../../database/file-storage';
import { deleteFile, guessMimeType } from '../../database/file-storage';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST, type StoreEntityExclusionList } from './exclusionList-types';
import type { ExclusionListFileAddInput, MutationExclusionListFieldPatchArgs, QueryExclusionListsArgs } from '../../generated/graphql';
import { getClusterInstances, notify, redisGetExclusionListStatus, redisUpdateExclusionListStatus } from '../../database/redis';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { generateInternalId } from '../../schema/identifier';

const filePath = 'exclusionLists';

const MAX_FILE_SIZE = conf.get('app:exclusion_list:file_max_size') ?? 10000000;

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityExclusionList>(context, user, id, ENTITY_TYPE_EXCLUSION_LIST);
};

export const findExclusionListPaginated = (context: AuthContext, user: AuthUser, args: QueryExclusionListsArgs) => {
  return pageEntitiesConnection<BasicStoreEntityExclusionList>(context, user, [ENTITY_TYPE_EXCLUSION_LIST], args);
};

export const getCacheStatus = async () => {
  const redisCacheStatus = await redisGetExclusionListStatus();
  const refreshVersion = redisCacheStatus.last_refresh_ask_date ?? '';
  const cacheVersion = redisCacheStatus.last_cache_date ?? '';
  const clusterConfig = await getClusterInstances();
  const allNodeIds = clusterConfig.map((c) => c.platform_id);
  let isCacheRebuildInProgress = false;
  if (refreshVersion) {
    isCacheRebuildInProgress = refreshVersion !== cacheVersion;
    for (let i = 0; i < clusterConfig.length; i += 1) {
      const platformInstanceId = allNodeIds[i];
      isCacheRebuildInProgress = isCacheRebuildInProgress || refreshVersion !== redisCacheStatus[platformInstanceId];
    }
  }

  return { refreshVersion, cacheVersion, isCacheRebuildInProgress };
};

const refreshExclusionListStatus = async () => {
  await redisUpdateExclusionListStatus({ last_refresh_ask_date: (new Date()).toString() });
};

const checkFileSize = async (createReadStream: () => Readable) => {
  const uploadStream = createReadStream();
  let byteLength = 0;
  let linesNumber = 1;
  let fileTooHeavy = false;
  // eslint-disable-next-line no-restricted-syntax
  for await (const uploadChunk of uploadStream) {
    byteLength += (uploadChunk as Buffer).byteLength;
    const chunkAsString = (uploadChunk as Buffer).toString('utf-8');
    const newLinesNumber = chunkAsString.split(/\r\n|\n/).length - 1;
    linesNumber += newLinesNumber;

    if (byteLength > MAX_FILE_SIZE) {
      fileTooHeavy = true;
      break;
    }
  }
  uploadStream.destroy();

  if (fileTooHeavy) {
    throw FunctionalError('Exclusion list file too large', { maxFileSize: MAX_FILE_SIZE });
  }

  return { byteLength, linesNumber };
};

const uploadExclusionListFile = async (context: AuthContext, user: AuthUser, exclusionListId: string, file: FileUploadData) => {
  const fullFile = await file;
  const { byteLength, linesNumber } = await checkFileSize(fullFile.createReadStream);
  const mimeType = guessMimeType(fullFile.filename);
  if (mimeType !== 'text/plain') {
    throw UnsupportedError('Exclusion list file format must be text/plain', { mimeType });
  }
  const exclusionFile = { ...fullFile, filename: `${exclusionListId}.txt` };
  const { upload } = await uploadToStorage(context, user, filePath, exclusionFile, {});
  return { upload, byteLength, linesNumber };
};

const storeAndCreateExclusionList = async (context: AuthContext, user: AuthUser, input: ExclusionListFileAddInput, file: FileUploadData) => {
  const exclusionListInternalId = generateInternalId();
  const { upload, byteLength, linesNumber } = await uploadExclusionListFile(context, user, exclusionListInternalId, file);
  const exclusionListToCreate = {
    name: input.name,
    description: input.description,
    enabled: true,
    exclusion_list_entity_types: input.exclusion_list_entity_types,
    file_id: upload.id,
    internal_id: exclusionListInternalId,
    exclusion_list_file_size: byteLength,
    exclusion_list_values_count: linesNumber
  };
  const createdExclusionList = createInternalObject<StoreEntityExclusionList>(context, user, exclusionListToCreate, ENTITY_TYPE_EXCLUSION_LIST);
  await refreshExclusionListStatus();
  return createdExclusionList;
};

export const addExclusionListFile = async (context: AuthContext, user: AuthUser, input: ExclusionListFileAddInput) => {
  return storeAndCreateExclusionList(context, user, input, input.file);
};

export const fieldPatchExclusionList = async (context: AuthContext, user: AuthUser, args: MutationExclusionListFieldPatchArgs) => {
  const { id, file, input } = args;
  const exclusionList = await findById(context, user, id);
  if (!exclusionList) {
    throw FunctionalError(`Exclusion list ${id} cannot be found`);
  }

  let fileSize = exclusionList.exclusion_list_file_size;
  let exclusionListCount = exclusionList.exclusion_list_values_count;
  if (file) {
    const uploadResult = await uploadExclusionListFile(context, user, exclusionList.internal_id, file);
    fileSize = uploadResult.byteLength;
    exclusionListCount = uploadResult.linesNumber;
  }
  const fullInput = [...(input ?? []), { key: 'exclusion_list_file_size', value: [fileSize] }, { key: 'exclusion_list_values_count', value: [exclusionListCount] }];
  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_EXCLUSION_LIST, fullInput);

  if (file || fullInput.some((i) => i.key === 'enabled')) {
    await refreshExclusionListStatus();
  }

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input?.map((i) => i.key).join(', ')}\` for exclusion list \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_EXCLUSION_LIST, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_EXCLUSION_LIST].EDIT_TOPIC, element, user);
};

export const deleteExclusionList = async (context: AuthContext, user: AuthUser, exclusionListId: string) => {
  const exclusionList = await findById(context, user, exclusionListId);
  await deleteFile(context, user, exclusionList.file_id);
  const deletedExclusionList = deleteInternalObject(context, user, exclusionListId, ENTITY_TYPE_EXCLUSION_LIST);
  await refreshExclusionListStatus();
  return deletedExclusionList;
};
