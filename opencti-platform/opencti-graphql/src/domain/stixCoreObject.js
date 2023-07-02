import * as R from 'ramda';
import {
  batchListThroughGetFrom,
  batchListThroughGetTo,
  batchLoadThroughGetTo,
  createEntity,
  createRelationRaw,
  deleteElementById,
  distributionEntities,
  storeLoadByIdWithRefs,
  timeSeriesEntities,
} from '../database/middleware';
import { internalLoadById, listEntities, storeLoadById, storeLoadByIds } from '../database/middleware-loader';
import { findAll as relationFindAll } from './stixCoreRelationship';
import { delEditContext, lockResource, notify, setEditContext, storeUpdateEvent } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { isStixCoreObject, stixCoreObjectOptions } from '../schema/stixCoreObject';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  buildRefRelationKey,
  ENTITY_TYPE_IDENTITY,
  INPUT_EXTERNAL_REFS,
} from '../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixRefRelationship';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
} from '../schema/stixDomainObject';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { now } from '../utils/format';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { deleteFile, loadFile, storeFileConverter, upload } from '../database/file-storage';
import { elCount, elUpdateElement } from '../database/engine';
import { generateStandardId, getInstanceIds } from '../schema/identifier';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import {
  extractEntityRepresentative,
  isEmptyField,
  isNotEmptyField,
  READ_ENTITIES_INDICES,
  READ_INDEX_INFERRED_ENTITIES
} from '../database/utils';
import { RELATION_RELATED_TO } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import {
  stixObjectOrRelationshipAddRefRelation,
  stixObjectOrRelationshipAddRefRelations,
  stixObjectOrRelationshipDeleteRefRelation
} from './stixObjectOrStixRelationship';
import { buildContextDataForFile, publishUserAction } from '../listener/UserActionListener';

export const findAll = async (context, user, args) => {
  let types = [];
  if (isNotEmptyField(args.types)) {
    types = R.filter((type) => isStixCoreObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  if (isNotEmptyField(args.relationship_type) && isEmptyField(args.elementId)) {
    throw UnsupportedError('Cant find stixCoreObject only based on relationship type, elementId is required');
  }
  let filters = args.filters ?? [];
  if (isNotEmptyField(args.elementId)) {
    // In case of element id, we look for a specific entity used by relationships independent of the direction
    // To do that we need to lookup the element inside the rel_ fields that represent the relationships connections
    // that are denormalized at relation creation.
    // If relation types are also in the query, we filter on specific rel_[TYPE], if not, using a wilcard.
    if (isNotEmptyField(args.relationship_type)) {
      const relationshipFilterKeys = args.relationship_type.map((n) => buildRefRelationKey(n));
      filters = [...filters, { key: relationshipFilterKeys, values: [args.elementId] }];
    } else {
      filters = [...filters, { key: buildRefRelationKey('*'), values: [args.elementId] }];
    }
  }
  if (args.globalSearch) {
    await publishUserAction({
      user,
      event_type: 'command',
      event_scope: 'search',
      event_access: 'extended',
      context_data: { input: args }
    });
  }
  return listEntities(context, user, types, { ...R.omit(['elementId', 'relationship_type'], args), filters });
};

export const findById = async (context, user, stixCoreObjectId) => {
  return storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
};

export const findByIds = async (context, user, stixCoreObjectIds) => {
  return storeLoadByIds(context, user, stixCoreObjectIds, ABSTRACT_STIX_CORE_OBJECT);
};

export const batchCreatedBy = async (context, user, stixCoreObjectIds) => {
  return batchLoadThroughGetTo(context, user, stixCoreObjectIds, RELATION_CREATED_BY, ENTITY_TYPE_IDENTITY);
};

export const batchCases = async (context, user, stixCoreObjectIds, args = {}) => {
  return batchListThroughGetFrom(context, user, stixCoreObjectIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_CASE, args);
};

export const batchNotes = (context, user, stixCoreObjectIds, args = {}) => {
  return batchListThroughGetFrom(context, user, stixCoreObjectIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE, args);
};

export const batchOpinions = (context, user, stixCoreObjectIds, args = {}) => {
  return batchListThroughGetFrom(context, user, stixCoreObjectIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION, args);
};

export const batchObservedData = (context, user, stixCoreObjectIds, args = {}) => {
  return batchListThroughGetFrom(context, user, stixCoreObjectIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, args);
};

export const batchLabels = (context, user, stixCoreObjectIds) => {
  return batchListThroughGetTo(context, user, stixCoreObjectIds, RELATION_OBJECT_LABEL, ENTITY_TYPE_LABEL);
};

export const batchMarkingDefinitions = (context, user, stixCoreObjectIds) => {
  return batchListThroughGetTo(context, user, stixCoreObjectIds, RELATION_OBJECT_MARKING, ENTITY_TYPE_MARKING_DEFINITION);
};

export const batchExternalReferences = (context, user, stixDomainObjectIds) => {
  return batchListThroughGetTo(context, user, stixDomainObjectIds, RELATION_EXTERNAL_REFERENCE, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const batchKillChainPhases = (context, user, stixCoreObjectIds) => {
  return batchListThroughGetTo(context, user, stixCoreObjectIds, RELATION_KILL_CHAIN_PHASE, ENTITY_TYPE_KILL_CHAIN_PHASE);
};

export const stixCoreRelationships = (context, user, stixCoreObjectId, args) => {
  const finalArgs = R.assoc('elementId', stixCoreObjectId, args);
  return relationFindAll(context, user, finalArgs);
};

// region relation ref
export const stixCoreObjectAddRelation = async (context, user, stixCoreObjectId, input) => {
  return stixObjectOrRelationshipAddRefRelation(context, user, stixCoreObjectId, input, ABSTRACT_STIX_CORE_OBJECT);
};
export const stixCoreObjectAddRelations = async (context, user, stixCoreObjectId, input, opts = {}) => {
  return stixObjectOrRelationshipAddRefRelations(context, user, stixCoreObjectId, input, ABSTRACT_STIX_CORE_OBJECT, opts);
};
export const stixCoreObjectDeleteRelation = async (context, user, stixCoreObjectId, toId, relationshipType, opts = {}) => {
  return stixObjectOrRelationshipDeleteRefRelation(context, user, stixCoreObjectId, toId, relationshipType, ABSTRACT_STIX_CORE_OBJECT, opts);
};
// endregion

export const stixCoreObjectDelete = async (context, user, stixCoreObjectId) => {
  const stixCoreObject = await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the object, Stix-Core-Object cannot be found.');
  }
  await deleteElementById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  return stixCoreObjectId;
};

export const askElementEnrichmentForConnector = async (context, user, elementId, connectorId) => {
  const connector = await storeLoadById(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
  const element = await internalLoadById(context, user, elementId);
  if (!element) {
    throw FunctionalError('Cannot enrich the object, element cannot be found.');
  }
  const work = await createWork(context, user, connector, 'Manual enrichment', elementId);
  const message = {
    internal: {
      work_id: work.id, // Related action for history
      applicant_id: user.id, // User asking for the import
    },
    event: {
      entity_id: elementId,
    },
  };
  await pushToConnector(context, connector, message);
  await publishUserAction({
    user,
    event_access: 'extended',
    event_type: 'command',
    event_scope: 'enrich',
    context_data: {
      id: elementId,
      connector_id: connectorId,
      connector_name: connector.name,
      entity_name: extractEntityRepresentative(element),
      entity_type: element.entity_type
    }
  });
  return work;
};

// region stats
export const stixCoreObjectsTimeSeries = (context, user, args) => {
  const { types } = args;
  return timeSeriesEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], args);
};

export const stixCoreObjectsTimeSeriesByAuthor = (context, user, args) => {
  const { authorId, types } = args;
  const filters = [{
    key: [buildRefRelationKey(RELATION_CREATED_BY, '*')],
    values: [authorId]
  }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], { ...args, filters });
};

export const stixCoreObjectsMultiTimeSeries = (context, user, args) => {
  return Promise.all(args.timeSeriesParameters.map((timeSeriesParameter) => {
    const { types } = timeSeriesParameter;
    return { data: timeSeriesEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], { ...args, ...timeSeriesParameter }) };
  }));
};

export const stixCoreObjectsNumber = (context, user, args) => ({
  count: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_ENTITIES_INDICES, args),
  total: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_ENTITIES_INDICES, R.dissoc('endDate', args)),
});

export const stixCoreObjectsMultiNumber = (context, user, args) => {
  return Promise.all(args.numberParameters.map((numberParameter) => {
    return {
      count: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_ENTITIES_INDICES, { ...args, ...numberParameter }),
      total: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_ENTITIES_INDICES, R.dissoc('endDate', { ...args, ...numberParameter }))
    };
  }));
};

export const stixCoreObjectsDistribution = async (context, user, args) => {
  const { types } = args;
  return distributionEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], args);
};

export const stixCoreObjectsDistributionByEntity = async (context, user, args) => {
  const { relationship_type, objectId, types } = args;
  const filters = [{
    key: (relationship_type ?? [RELATION_RELATED_TO]).map((n) => buildRefRelationKey(n, '*')),
    values: Array.isArray(objectId) ? objectId : [objectId]
  }, ...(args.filters || [])];
  return distributionEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], { ...args, filters });
};

export const stixCoreObjectsMultiDistribution = (context, user, args) => {
  return Promise.all(args.distributionParameters.map((distributionParameter) => {
    const { types } = distributionParameter;
    return { data: distributionEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], { ...args, ...distributionParameter }) };
  }));
};
// endregion

// region export
export const stixCoreObjectsExportAsk = async (context, user, args) => {
  const { format, type, exportType, maxMarkingDefinition, selectedIds } = args;
  const { search, orderBy, orderMode, filters, filterMode, relationship_type, elementId } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode, relationship_type, elementId };
  const filtersOpts = stixCoreObjectOptions.StixCoreObjectsFilter;
  const ordersOpts = stixCoreObjectOptions.StixCoreObjectsOrdering;
  const listParams = exportTransformFilters(argsFilters, filtersOpts, ordersOpts);
  const works = await askListExport(context, user, format, type, selectedIds, listParams, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w));
};
export const stixCoreObjectExportAsk = async (context, user, stixCoreObjectId, args) => {
  const { format, exportType = null, maxMarkingDefinition = null } = args;
  const entity = await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  const works = await askEntityExport(context, user, format, entity, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w));
};

export const stixCoreObjectsExportPush = async (context, user, type, file, listFilters) => {
  const meta = { list_filters: listFilters };
  await upload(context, user, `export/${type}`, file, { meta });
  return true;
};

export const stixCoreObjectExportPush = async (context, user, entityId, file) => {
  const previous = await storeLoadByIdWithRefs(context, user, entityId);
  if (!previous) {
    throw UnsupportedError('Cant upload a file an none existing element', { entityId });
  }
  const path = `export/${previous.entity_type}/${entityId}`;
  const up = await upload(context, user, path, file, { entity: previous });
  const contextData = buildContextDataForFile(null, path, up.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
  return true;
};

export const stixCoreObjectImportPush = async (context, user, id, file, noTriggerImport = false) => {
  let lock;
  const previous = await storeLoadByIdWithRefs(context, user, id);
  if (!previous) {
    throw UnsupportedError('Cant upload a file an none existing element', { id });
  }
  const participantIds = getInstanceIds(previous);
  try {
    // Lock the participants that will be merged
    lock = await lockResource(participantIds);
    const { internal_id: internalId } = previous;
    const { filename } = await file;
    const entitySetting = await getEntitySettingFromCache(context, previous.entity_type);
    const isAutoExternal = !entitySetting ? false : entitySetting.platform_entity_files_ref;
    const filePath = `import/${previous.entity_type}/${internalId}`;
    // 01. Upload the file
    const meta = {};
    if (isAutoExternal) {
      const key = `${filePath}/${filename}`;
      meta.external_reference_id = generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, { url: `/storage/get/${key}` });
    }
    const up = await upload(context, user, filePath, file, { meta, noTriggerImport, entity: previous });
    // 02. Create and link external ref if needed.
    let addedExternalRef;
    if (isAutoExternal) {
      // Create external ref + link to current entity
      const createExternal = { source_name: filename, url: `/storage/get/${up.id}`, fileId: up.id };
      const externalRef = await createEntity(context, user, createExternal, ENTITY_TYPE_EXTERNAL_REFERENCE);
      const relInput = { fromId: id, toId: externalRef.id, relationship_type: RELATION_EXTERNAL_REFERENCE };
      const opts = { publishStreamEvent: false, locks: participantIds };
      await createRelationRaw(context, user, relInput, opts);
      addedExternalRef = externalRef;
    }
    // Patch the updated_at to force live stream evolution
    const eventFile = storeFileConverter(user, up);
    const files = [...(previous.x_opencti_files ?? []).filter((f) => f.id !== up.id), eventFile];
    await elUpdateElement({
      _index: previous._index,
      internal_id: internalId,
      updated_at: now(),
      x_opencti_files: files
    });
    // Stream event generation
    if (addedExternalRef) {
      const newExternalRefs = [...(previous[INPUT_EXTERNAL_REFS] ?? []), addedExternalRef];
      const instance = { ...previous, x_opencti_files: files, [INPUT_EXTERNAL_REFS]: newExternalRefs };
      const message = `adds \`${up.name}\` in \`files\` and \`external_references\``;
      await storeUpdateEvent(context, user, previous, instance, message);
    } else {
      const instance = { ...previous, x_opencti_files: files };
      await storeUpdateEvent(context, user, previous, instance, `adds \`${up.name}\` in \`files\``);
    }
    // Add in activity only for notifications
    const contextData = buildContextDataForFile(previous, filePath, up.name);
    await publishUserAction({
      user,
      event_type: 'file',
      event_access: 'extended',
      event_scope: 'create',
      prevent_indexing: true,
      context_data: contextData
    });
    return up;
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const stixCoreObjectImportDelete = async (context, user, fileId) => {
  if (!fileId.startsWith('import')) {
    throw UnsupportedError('Cant delete an exported file with this method');
  }
  // Get the context
  const up = await loadFile(context, user, fileId);
  const entityId = up.metaData.entity_id;
  const externalReferenceId = up.metaData.external_reference_id;
  const previous = await storeLoadByIdWithRefs(context, user, entityId);
  if (!previous) {
    throw UnsupportedError('Cant delete a file of none existing element', { entityId });
  }
  let lock;
  const participantIds = getInstanceIds(previous);
  try {
    // Lock the participants that will be merged
    lock = await lockResource(participantIds);
    // If external reference attached, delete first
    if (externalReferenceId) {
      try {
        await deleteElementById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
      } catch {
        // If external reference already deleted.
      }
    }
    // Delete the file
    await deleteFile(context, user, fileId);
    // Patch the updated_at to force live stream evolution
    const files = (previous.x_opencti_files ?? []).filter((f) => f.id !== fileId);
    await elUpdateElement({ _index: previous._index, internal_id: entityId, updated_at: now(), x_opencti_files: files });
    // Stream event generation
    const instance = { ...previous, x_opencti_files: files };
    await storeUpdateEvent(context, user, previous, instance, `removes \`${up.name}\` in \`files\``);
    // Add in activity only for notifications
    const contextData = buildContextDataForFile(previous, fileId, up.name);
    await publishUserAction({
      user,
      event_type: 'file',
      event_access: 'extended',
      event_scope: 'delete',
      prevent_indexing: true,
      context_data: contextData
    });
    return up;
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

// region context
export const stixCoreObjectCleanContext = async (context, user, stixCoreObjectId) => {
  await delEditContext(user, stixCoreObjectId);
  return storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((stixCoreObject) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixCoreObject, user);
  });
};

export const stixCoreObjectEditContext = async (context, user, stixCoreObjectId, input) => {
  await setEditContext(user, stixCoreObjectId, input);
  return storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((stixCoreObject) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixCoreObject, user);
  });
};
// endregion
