import * as R from 'ramda';
import { Readable } from 'stream';
import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import { defaultValidationMode, deleteFile, uploadToStorage } from '../database/file-storage';
import { internalLoadById, fullEntitiesList } from '../database/middleware-loader';
import { buildContextDataForFile, publishUserAction } from '../listener/UserActionListener';
import { stixCoreObjectImportDelete } from './stixCoreObject';
import { allFilesMimeTypeDistribution, allRemainingFilesCount } from '../modules/internal/document/document-domain';
import { getManagerConfigurationFromCache } from '../modules/managerConfiguration/managerConfiguration-domain';
import { supportedMimeTypes } from '../modules/managerConfiguration/managerConfiguration-utils';
import { isUserHasCapabilities, SYSTEM_USER } from '../utils/access';
import { isEmptyField, isNotEmptyField, READ_INDEX_FILES, READ_INDEX_HISTORY } from '../database/utils';
import { getStats } from '../database/engine';
import { extractContentFrom } from '../utils/fileToContent';
import { stixLoadById } from '../database/middleware';
import { getEntitiesMapFromCache } from '../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { FilterMode, OrderingMode } from '../generated/graphql';
import { telemetry } from '../config/tracing';
import { ENTITY_TYPE_WORK } from '../schema/internalObject';
import { getDraftContext } from '../utils/draftContext';
import { UnsupportedError } from '../config/errors';
import { isDraftFile } from '../database/draft-utils';
import { askJobImport } from './connector';
import { addWorkbenchUploadCount } from '../manager/telemetryManager';

export const buildOptionsFromFileManager = async (context) => {
  let importPaths = ['import/'];
  const excludedPaths = ['import/pending/']; // always exclude pending
  const managerConfiguration = await getManagerConfigurationFromCache(context, SYSTEM_USER, 'FILE_INDEX_MANAGER');
  const configMimetypes = managerConfiguration.manager_setting?.accept_mime_types;
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
  if (isEmptyField(fileOptions.opts.prefixMimeTypes)) {
    return {
      globalCount: 0,
      globalSize: 0,
      metricsByMimeType: [],
    };
  }
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

export const uploadImport = async (context, user, args) => {
  const { file, fileMarkings: file_markings, noTriggerImport } = args;
  const path = 'import/global';
  const { upload: up } = await uploadToStorage(context, user, path, file, { file_markings, noTriggerImport });
  const contextData = buildContextDataForFile(null, path, up.name, file_markings);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
  return up;
};

export const uploadPending = async (context, user, args) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot create a workbench in draft');
  }
  const { file, entityId = null, labels = null, errorOnExisting = false, refreshEntity = false, file_markings = [] } = args;
  let finalFile = file;
  const meta = { labels, labels_text: labels ? labels.join(';') : undefined };
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

  const { upload: up } = await uploadToStorage(context, user, 'import/pending', finalFile, { meta, file_markings, errorOnExisting, entity });
  const contextData = buildContextDataForFile(entity, 'import/pending', up.name, up.metaData.file_markings);
  await addWorkbenchUploadCount();
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
  return up;
};

export const uploadAndAskJobImport = async (context, user, args = {}) => {
  const {
    file,
    fileMarkings,
    connectors,
    validationMode = defaultValidationMode,
    draftId,
    noTriggerImport,
  } = args;
  const contextInDraft = { ...context, draft_context: draftId };
  const uploadedFile = await uploadImport(contextInDraft, user, { file, fileMarkings, noTriggerImport });

  if (connectors && isUserHasCapabilities(user, ['KNOWLEDGE_KNASKIMPORT'])) {
    await Promise.all(connectors.map(async ({ connectorId, configuration }) => (
      askJobImport(contextInDraft, user, {
        fileName: uploadedFile.id,
        connectorId,
        configuration,
        validationMode,
        forceValidation: true
      })
    )));
  }

  return uploadedFile;
};

export const deleteImport = async (context, user, fileName) => {
  const draftContext = getDraftContext(context, user);
  if (draftContext && !isDraftFile(fileName, draftContext)) {
    throw UnsupportedError('Cannot delete non draft imports in draft', { fileName });
  }
  // Imported file must be handled specifically
  // File deletion must publish a specific event
  // and update the updated_at field of the source entity
  const isDraftFileImport = draftContext && isDraftFile(fileName, draftContext, 'import');
  const isImportFile = fileName.startsWith('import') || isDraftFileImport;
  if (isImportFile && !fileName.includes('global') && !fileName.includes('pending')) {
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
    const items = await fullEntitiesList(context, user, [ENTITY_TYPE_WORK], {
      indices: [READ_INDEX_HISTORY],
      orderBy: 'timestamp',
      orderMode: OrderingMode.Desc,
      filters,
    });
    return files.map((fileId) => items.filter(({ event_source_id }) => event_source_id === fileId));
  };
  return telemetry(context, user, 'BATCH works for file', {
    [SEMATTRS_DB_NAME]: 'file_domain',
    [SEMATTRS_DB_OPERATION]: 'read',
  }, getWorkForFileFn);
};
