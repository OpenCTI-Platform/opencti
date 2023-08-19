import * as R from 'ramda';
import { logApp } from '../config/conf';
import { deleteFile, loadFile, upload, uploadJobImport } from '../database/file-storage';
import { internalLoadById } from '../database/middleware-loader';
import { buildContextDataForFile, publishUserAction } from '../listener/UserActionListener';
import { stixCoreObjectImportDelete } from './stixCoreObject';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { allFilesForPaths, allRemainingFilesCount } from '../modules/internal/document/document-domain';
import { getManagerConfigurationFromCache } from '../modules/managerConfiguration/managerConfiguration-domain';
import { supportedMimeTypes } from '../modules/managerConfiguration/managerConfiguration-utils';
import { SYSTEM_USER } from '../utils/access';
import { isEmptyField, isNotEmptyField, READ_INDEX_FILES } from '../database/utils';
import { getStats } from '../database/engine';

export const buildOptionsFromFileManager = async (context) => {
  let importPaths = ['import/'];
  const excludedPaths = ['import/pending/']; // always exclude pending
  const managerConfiguration = await getManagerConfigurationFromCache(context, SYSTEM_USER, 'FILE_INDEX_MANAGER');
  const configMimetypes = managerConfiguration.manager_setting?.accept_mime_types;
  if (isEmptyField(configMimetypes)) {
    return {
      globalCount: 0,
      globalSize: 0,
      metricsByMimeType: [],
    };
  }
  const includeGlobal = managerConfiguration.manager_setting?.include_global_files || false;
  const onlyForEntityTypes = managerConfiguration.manager_setting?.entity_types;
  if (isNotEmptyField(onlyForEntityTypes)) {
    importPaths = onlyForEntityTypes.map((entityType) => `import/${entityType}/`);
    if (includeGlobal) {
      importPaths.push('import/global/');
    }
  } else if (!includeGlobal) {
    excludedPaths.push('import/global/');
  }
  const maxFileSize = managerConfiguration.manager_setting?.max_file_size || 5242880;
  // const modifiedSince = await getIndexFromDate(context);
  return { paths: importPaths, opts: { prefixMimeTypes: configMimetypes, maxFileSize, excludedPaths } };
};

export const filesMetrics = async (context, user) => {
  const metrics = await getStats([READ_INDEX_FILES]);
  const indexedFilesCount = metrics.docs.count;
  const fileOptions = await buildOptionsFromFileManager(context);
  const potentialIndexingFiles = await allFilesForPaths(context, user, fileOptions.paths, fileOptions.opts);
  const remainingFilesCount = await allRemainingFilesCount(context, user, fileOptions.paths, fileOptions.opts);
  const metricsByMimeType = [];
  supportedMimeTypes.forEach((mimeType) => {
    const mimeTypeFiles = potentialIndexingFiles.filter((file) => file.metaData.mimetype?.startsWith(mimeType));
    if (mimeTypeFiles.length > 0) {
      metricsByMimeType.push({
        mimeType,
        count: mimeTypeFiles.length,
        size: R.sum(mimeTypeFiles.map((file) => file.size)),
      });
    }
  });
  return {
    globalCount: indexedFilesCount + remainingFilesCount,
    globalSize: R.sum(potentialIndexingFiles.map((file) => file.size)),
    metricsByMimeType,
  };
};

export const askJobImport = async (context, user, args) => {
  const { fileName, connectorId = null, configuration = null, bypassEntityId = null, bypassValidation = false } = args;
  logApp.debug(`[JOBS] ask import for file ${fileName} by ${user.user_email}`);
  const file = await loadFile(user, fileName);
  const entityId = bypassEntityId || file.metaData.entity_id;
  const opts = { manual: true, connectorId, configuration, bypassValidation };
  const entity = await internalLoadById(context, user, entityId);
  const connectors = await uploadJobImport(context, createEntity, user, file.id, file.metaData.mimetype, entityId, opts);
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
  if (entity) { // Entity can be null for global
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
