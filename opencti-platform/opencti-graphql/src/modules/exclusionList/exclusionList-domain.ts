import { Readable } from 'stream';
import conf, { BUS_TOPICS } from '../../config/conf';
import { type FileUploadData, uploadToStorage } from '../../database/file-storage';
import { deleteFile, guessMimeType } from '../../database/file-storage';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST, type StoreEntityExclusionList } from './exclusionList-types';
import type { ExclusionListFileAddInput, MutationExclusionListFieldPatchArgs, QueryExclusionListsArgs } from '../../generated/graphql';
import { getClusterInstances, notify, redisGetExclusionListStatus, redisUpdateExclusionListStatus } from '../../database/redis';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { generateInternalId, normalizeName } from '../../schema/identifier';
import { FilterMode } from '../../generated/graphql';
import { exclusionListNameSchema, hasSameTypes } from './exclusionList-rules';

const filePath = 'exclusionLists';

export const MAX_FILE_SIZE = conf.get('app:exclusion_list:file_max_size') ?? 10000000;

// The name of the file of a list: the upload takes it from here, and the key of the list in the storage is built from it
const exclusionListFileName = (internalId: string) => `${internalId}.txt`;

// The key of the file of a list in the storage: the upload lowercases the name of the file, not the folder
export const exclusionListStorageKey = (internalId: string) => `${filePath}/${exclusionListFileName(internalId).toLowerCase()}`;

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityExclusionList>(context, user, id, ENTITY_TYPE_EXCLUSION_LIST);
};

// The lists that have this name, whatever its case. The filter on a name is an exact match on the index (lowercased), so only the candidates
// are read, not every list: the comparison is made again here, as the importer decides on it.
export const findExclusionListsByName = async (context: AuthContext, user: AuthUser, name: string) => {
  const candidates = await fullEntitiesList<BasicStoreEntityExclusionList>(context, user, [ENTITY_TYPE_EXCLUSION_LIST], {
    filters: { mode: FilterMode.And, filters: [{ key: ['name'], values: [name] }], filterGroups: [] },
  });
  return candidates.filter((list) => normalizeName(list.name) === normalizeName(name));
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
  const exclusionFile = { ...fullFile, filename: exclusionListFileName(exclusionListId) };
  const { upload } = await uploadToStorage(context, user, filePath, exclusionFile, {});
  return { upload, byteLength, linesNumber };
};

const storeAndCreateExclusionList = async (context: AuthContext, user: AuthUser, input: ExclusionListFileAddInput, file: FileUploadData, enabled: boolean) => {
  // One rule for every way to create a list: the creation form, the API and the import of a configuration preset
  const name = exclusionListNameSchema.safeParse(input.name);
  if (!name.success) {
    throw FunctionalError(name.error.issues[0].message, { name: input.name });
  }
  const exclusionListInternalId = generateInternalId();
  const { upload, byteLength, linesNumber } = await uploadExclusionListFile(context, user, exclusionListInternalId, file);
  const exclusionListToCreate = {
    name: input.name,
    description: input.description,
    enabled,
    exclusion_list_entity_types: input.exclusion_list_entity_types,
    file_id: upload.id,
    internal_id: exclusionListInternalId,
    exclusion_list_file_size: byteLength,
    exclusion_list_values_count: linesNumber,
  };
  // The list is indexed before the cache is asked to rebuild, or a rebuild between the two would miss it
  const createdExclusionList = await createInternalObject<StoreEntityExclusionList>(context, user, exclusionListToCreate, ENTITY_TYPE_EXCLUSION_LIST);
  await refreshExclusionListStatus();
  return createdExclusionList;
};

// A list is created with its final state: disabling it afterwards could leave the cache built from the enabled list
export const addExclusionListFile = async (context: AuthContext, user: AuthUser, input: ExclusionListFileAddInput, enabled = true) => {
  return storeAndCreateExclusionList(context, user, input, input.file, enabled);
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
  const { element } = await updateAttribute<StoreEntityExclusionList>(context, user, id, ENTITY_TYPE_EXCLUSION_LIST, fullInput);

  // The cache holds the types of each list next to its values: a change of types needs a rebuild as much as a change of values. The edit form
  // sends the types on every save: only types that differ from the ones of the list are a change.
  const typesChanged = (input ?? []).some((i) => i.key === 'exclusion_list_entity_types' && !hasSameTypes(exclusionList.exclusion_list_entity_types, i.value as string[]));
  if (file || typesChanged || fullInput.some((i) => i.key === 'enabled')) {
    await refreshExclusionListStatus();
  }

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${[...(input ?? []).map((i) => i.key), ...(file ? ['file'] : [])].join(', ')}\` for exclusion list \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_EXCLUSION_LIST, input },
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
