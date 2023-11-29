import * as R from 'ramda';
import { logApp } from '../config/conf';
import { deleteFile, fileListingForIndexing, loadFile, upload, uploadJobImport } from '../database/file-storage';
import { internalLoadById } from '../database/middleware-loader';
import { buildContextDataForFile, publishUserAction } from '../listener/UserActionListener';
import { stixCoreObjectImportDelete } from './stixCoreObject';
import { elDeleteAllFiles, elSearchFiles, getStats } from '../database/engine';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { READ_INDEX_FILES } from '../database/utils';
import {
  RELATION_CREATED_BY,
  RELATION_GRANTED_TO,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../schema/stixRefRelationship';
import {
  getManagerConfigurationFromCache,
  managerConfigurationEditField
} from '../modules/managerConfiguration/managerConfiguration-domain';
import { FunctionalError } from '../config/errors';

// region File indexing
export const filesMetrics = async (context, user, args) => {
  const { excludedPaths = [] } = args;
  const finalExcludedPaths = ['import/pending/', ...excludedPaths]; // always exclude pending
  const finalArgs = {
    ...args,
    excludedPaths: finalExcludedPaths,
  };
  const files = await fileListingForIndexing(context, user, 'import/', finalArgs);
  const metricsByMimeType = [];
  const filesWithMimeType = files.filter((f) => f.mimeType !== null);
  const filesByMimetype = R.groupBy((f) => f.mimeType, filesWithMimeType);
  const mimeTypesGroups = Object.keys(filesByMimetype);
  for (let index = 0; index < mimeTypesGroups.length; index += 1) {
    const mimeType = mimeTypesGroups[index];
    metricsByMimeType.push({
      mimeType,
      count: filesByMimetype[mimeType].length,
      size: R.sum(filesByMimetype[mimeType].map((file) => file.Size)),
    });
  }
  return {
    globalCount: files.length,
    globalSize: R.sum(files.map((file) => file.Size)),
    metricsByMimeType,
  };
};

export const indexedFilesMetrics = async () => {
  const metrics = await getStats([READ_INDEX_FILES]);
  return {
    globalCount: metrics.docs.count,
    globalSize: metrics.store.size_in_bytes,
  };
};

export const searchIndexedFiles = async (context, user, args) => {
  return elSearchFiles(context, context.user, args);
};

export const resetFileIndexing = async (context, user) => {
  const managerConfiguration = await getManagerConfigurationFromCache(context, user, 'FILE_INDEX_MANAGER');
  if (!managerConfiguration) {
    throw FunctionalError('No manager configuration found');
  }
  const managerConfigurationEditInput = [
    { key: 'manager_running', value: [false] },
    { key: 'last_run_start_date', value: [null] },
    { key: 'last_run_end_date', value: [null] },
  ];
  await managerConfigurationEditField(context, user, managerConfiguration.id, managerConfigurationEditInput);
  await elDeleteAllFiles();
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'Reset file indexing',
  });
  return true;
};

// endregion

// region import / upload
export const askJobImport = async (context, user, args) => {
  const { fileName, connectorId = null, configuration = null, bypassEntityId = null, bypassValidation = false } = args;
  logApp.debug(`[JOBS] ask import for file ${fileName} by ${user.user_email}`);
  const file = await loadFile(user, fileName);
  const entityId = bypassEntityId || file.metaData.entity_id;
  const opts = { manual: true, connectorId, configuration, bypassValidation };
  const entity = await internalLoadById(context, user, entityId);
  const connectors = await uploadJobImport(context, user, file.id, file.metaData.mimetype, entityId, opts);
  const entityName = entityId ? extractEntityRepresentativeName(entity) : 'global';
  const entityType = entityId ? entity.entity_type : 'global';
  const contextData = {
    id: entityId,
    file_id: file.id,
    file_name: file.name,
    file_mime: file.metaData.mimetype,
    connectors: connectors.map((c) => c.name),
    entity_name: entityName,
    entity_type: entityType
  };
  if (entity.creator_id) {
    contextData.creator_ids = Array.isArray(entity.creator_id) ? entity.creator_id : [entity.creator_id];
  }
  if (entity[RELATION_GRANTED_TO]) {
    contextData.granted_refs_ids = entity[RELATION_GRANTED_TO];
  }
  if (entity[RELATION_OBJECT_MARKING]) {
    contextData.object_marking_refs_ids = entity[RELATION_OBJECT_MARKING];
  }
  if (entity[RELATION_CREATED_BY]) {
    contextData.created_by_ref_id = entity[RELATION_CREATED_BY];
  }
  if (entity[RELATION_OBJECT_LABEL]) {
    contextData.labels_ids = entity[RELATION_OBJECT_LABEL];
  }
  await publishUserAction({
    user,
    event_access: 'extended',
    event_type: 'command',
    event_scope: 'import',
    context_data: contextData
  });
  return file;
};

export const uploadImport = async (context, user, file) => {
  const path = 'import/global';
  const up = await upload(context, user, path, file, {});
  const contextData = buildContextDataForFile(null, path, up.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
  return up;
};

export const uploadPending = async (context, user, file, entityId = null, labels = null, errorOnExisting = false) => {
  const meta = { labels_text: labels ? labels.join(';') : undefined };
  const entity = entityId ? await internalLoadById(context, user, entityId) : undefined;
  const up = await upload(context, user, 'import/pending', file, { meta, errorOnExisting, entity });
  const contextData = buildContextDataForFile(entity, 'import/pending', up.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
  return up;
};

export const deleteImport = async (context, user, fileName) => {
  // Imported file must be handled specifically
  // File deletion must publish a specific event
  // and update the updated_at field of the source entity
  if (fileName.startsWith('import') && !fileName.includes('global') && !fileName.includes('pending')) {
    await stixCoreObjectImportDelete(context, context.user, fileName);
    return fileName;
  }
  // If not, a simple deletion is enough
  const upDelete = await deleteFile(context, context.user, fileName);
  const contextData = buildContextDataForFile(null, fileName, upDelete.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'delete',
    context_data: contextData
  });
  return fileName;
};
