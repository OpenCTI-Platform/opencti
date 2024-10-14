import * as R from 'ramda';
import { Readable } from 'stream';
import { logApp } from '../config/conf';
import { deleteFile, loadFile, uploadJobImport } from '../database/file-storage';
import { internalLoadById, listAllEntities } from '../database/middleware-loader';
import { buildContextDataForFile, completeContextDataForEntity, publishUserAction } from '../listener/UserActionListener';
import { stixCoreObjectImportDelete } from './stixCoreObject';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { allFilesMimeTypeDistribution, allRemainingFilesCount } from '../modules/internal/document/document-domain';
import { getManagerConfigurationFromCache } from '../modules/managerConfiguration/managerConfiguration-domain';
import { supportedMimeTypes } from '../modules/managerConfiguration/managerConfiguration-utils';
import { SYSTEM_USER } from '../utils/access';
import { isEmptyField, isNotEmptyField, READ_INDEX_FILES, READ_INDEX_HISTORY } from '../database/utils';
import { getStats } from '../database/engine';
import { controlUserConfidenceAgainstElement } from '../utils/confidence-level';
import { uploadToStorage } from '../database/file-storage-helper';
import { extractContentFrom } from '../utils/fileToContent';
import { stixLoadById } from '../database/middleware';
import { getEntitiesMapFromCache } from '../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { FilterMode, OrderingMode } from '../generated/graphql';
import { telemetry } from '../config/tracing';
import { ENTITY_TYPE_WORK } from '../schema/internalObject';
import { TELEMETRY_DB_NAME, TELEMETRY_DB_OPERATION } from '../utils/telemetry-attributes';

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
  const filesMimeTypesDistribution = await allFilesMimeTypeDistribution(context, user, fileOptions.paths, fileOptions.opts);
  const remainingFilesCount = await allRemainingFilesCount(context, user, fileOptions.paths, fileOptions.opts);
  const metricsByMimeType = [];
  supportedMimeTypes.forEach((mimeType) => {
    const mimeTypeDistribution = filesMimeTypesDistribution.filter((dist) => dist.label.startsWith(mimeType));
    if (mimeTypeDistribution.length > 0) {
      metricsByMimeType.push({
        mimeType,
        count: R.sum(mimeTypeDistribution.map((dist) => dist.count)),
        size: R.sum(mimeTypeDistribution.map((dist) => dist.value)),
      });
    }
  });
  return {
    globalCount: indexedFilesCount + remainingFilesCount,
    globalSize: R.sum(filesMimeTypesDistribution.map((dist) => dist.value)),
    metricsByMimeType,
  };
};

export const askJobImport = async (context, user, args) => {
  const { fileName, connectorId = null, configuration = null, bypassEntityId = null, bypassValidation = false } = args;
  logApp.debug(`[JOBS] ask import for file ${fileName} by ${user.user_email}`);
  const file = await loadFile(context, user, fileName);
  const entityId = bypassEntityId || file.metaData.entity_id;
  const opts = { manual: true, connectorId, configuration, bypassValidation };
  const entity = await internalLoadById(context, user, entityId);
  // This is a manual request for import, we have to check confidence and throw on error
  if (entity) {
    controlUserConfidenceAgainstElement(user, entity);
  }
  const connectors = await uploadJobImport(context, user, file.id, file.metaData.mimetype, entityId, opts);
  const entityName = entityId ? extractEntityRepresentativeName(entity) : 'global';
  const entityType = entityId ? entity.entity_type : 'global';
  const baseData = {
    id: entityId,
    file_id: file.id,
    file_name: file.name,
    file_mime: file.metaData.mimetype,
    connectors: connectors.map((c) => c.name),
    entity_name: entityName,
    entity_type: entityType
  };
  const contextData = completeContextDataForEntity(baseData, entity);
  await publishUserAction({
    user,
    event_access: 'extended',
    event_type: 'command',
    event_scope: 'import',
    context_data: contextData
  });
  return file;
};

export const uploadImport = async (context, user, args) => {
  const { file, fileMarkings: file_markings } = args;
  const path = 'import/global';
  const { upload: up } = await uploadToStorage(context, user, path, file, { file_markings });
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

export const uploadPending = async (context, user, file, entityId = null, labels = null, errorOnExisting = false, refreshEntity = false) => {
  let finalFile = file;
  const meta = { labels_text: labels ? labels.join(';') : undefined };
  const entity = entityId ? await internalLoadById(context, user, entityId) : undefined;

  // In the case of a workbench of an entity, if we want to refresh the entity data contains in
  // the workbench before uploading the file then we fetch data from Elastic, replace old
  // workbench data and recreate a readable stream for upload.
  if (refreshEntity && !!entity) {
    let bundle = await extractContentFrom(file);
    if (bundle.objects && bundle.objects.length > 0) {
      const entityAsStix = await stixLoadById(context, user, entityId);
      if (entityAsStix) {
        bundle = {
          ...bundle,
          objects: bundle.objects.map((o) => (
            o.id === entity.standard_id
              ? { ...entityAsStix, object_refs: o.object_refs }
              : o
          ))
        };
      }
    }
    // Retransform the bundle into a readable stream for upload.
    const json = JSON.stringify(bundle);
    const fileData = await file;
    finalFile = {
      createReadStream: () => Readable.from(Buffer.from(json, 'utf-8')),
      filename: fileData.filename,
      mimetype: fileData.mimetype
    };
  }

  const { upload: up } = await uploadToStorage(context, user, 'import/pending', finalFile, { meta, errorOnExisting, entity });
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

export const batchFileMarkingDefinitions = async (context, user, files) => {
  const markingsFromCache = await getEntitiesMapFromCache(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  return files.map((s) => {
    const markings = (s.metaData.file_markings ?? []).map((id) => markingsFromCache.get(id));
    return R.sortWith([
      R.ascend(R.propOr('TLP', 'definition_type')),
      R.descend(R.propOr(0, 'x_opencti_order')),
    ])(markings);
  });
};

export const batchFileWorks = async (context, user, files) => {
  const getWorkForFileFn = async () => {
    const filters = {
      mode: FilterMode.And,
      filters: [{ key: ['event_source_id'], values: files }],
      filterGroups: [],
    };
    const items = await listAllEntities(context, user, [ENTITY_TYPE_WORK], {
      indices: [READ_INDEX_HISTORY],
      connectionFormat: false,
      orderBy: 'timestamp',
      orderMode: OrderingMode.Desc,
      filters,
    });
    return files.map((fileId) => items.filter(({ event_source_id }) => event_source_id === fileId));
  };
  return telemetry(context, user, 'BATCH works for file', {
    [TELEMETRY_DB_NAME]: 'file_domain',
    [TELEMETRY_DB_OPERATION]: 'read',
  }, getWorkForFileFn);
};
