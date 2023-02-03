import * as R from 'ramda';
import {
  batchListThroughGetFrom,
  batchListThroughGetTo,
  batchLoadThroughGetTo,
  createEntity,
  createRelation,
  createRelationRaw,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  distributionEntities,
  storeLoadByIdWithRefs,
  timeSeriesEntities,
} from '../database/middleware';
import { internalLoadById, listEntities, storeLoadById } from '../database/middleware-loader';
import { findAll as relationFindAll } from './stixCoreRelationship';
import { delEditContext, lockResource, notify, setEditContext, storeUpdateEvent } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { isStixCoreObject, stixCoreObjectOptions } from '../schema/stixCoreObject';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_META_RELATIONSHIP,
  buildRefRelationKey,
  ENTITY_TYPE_IDENTITY,
  INPUT_EXTERNAL_REFS,
} from '../schema/general';
import {
  isStixMetaRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
} from '../schema/stixDomainObject';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { now } from '../utils/format';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { deleteFile, loadFile, storeFileConverter, upload } from '../database/file-storage';
import { elCount, elUpdateElement } from '../database/engine';
import { generateStandardId, getInstanceIds } from '../schema/identifier';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { isNotEmptyField, READ_ENTITIES_INDICES, READ_INDEX_INFERRED_ENTITIES } from '../database/utils';
import { RELATION_RELATED_TO } from '../schema/stixCoreRelationship';
import { getEntitiesFromCache } from '../database/cache';
import { SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';

export const findAll = async (context, user, args) => {
  let types = [];
  if (isNotEmptyField(args.types)) {
    types = R.filter((type) => isStixCoreObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  let filters = args.filters ?? [];
  if (isNotEmptyField(args.elementId) && isNotEmptyField(args.relationship_type)) {
    const relationshipFilterKeys = args.relationship_type.map((n) => buildRefRelationKey(n));
    filters = [
      ...filters,
      { key: relationshipFilterKeys, values: [args.elementId] },
    ];
  }
  return listEntities(context, user, types, { ...R.omit(['elementId', 'relationship_type'], args), filters });
};

export const findById = async (context, user, stixCoreObjectId) => {
  return storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
};

export const batchCreatedBy = async (context, user, stixCoreObjectIds) => {
  return batchLoadThroughGetTo(context, user, stixCoreObjectIds, RELATION_CREATED_BY, ENTITY_TYPE_IDENTITY);
};

export const batchReports = async (context, user, stixCoreObjectIds, args = {}) => {
  return batchListThroughGetFrom(context, user, stixCoreObjectIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT, args);
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

export const stixCoreObjectAddRelation = async (context, user, stixCoreObjectId, input) => {
  const data = await internalLoadById(context, user, stixCoreObjectId);
  if (!isStixCoreObject(data.entity_type) || !isStixRelationship(input.relationship_type)) {
    throw FunctionalError('Only stix-meta-relationship can be added through this method.', { stixCoreObjectId, input });
  }
  const finalInput = R.assoc('fromId', stixCoreObjectId, input);
  return createRelation(context, user, finalInput);
};

export const stixCoreObjectAddRelations = async (context, user, stixCoreObjectId, input) => {
  const stixCoreObject = await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot add the relation, Stix-Core-Object cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.map(
    (n) => ({ fromId: stixCoreObjectId, toId: n, relationship_type: input.relationship_type }),
    input.toIds
  );
  await createRelations(context, user, finalInput);
  return storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((entity) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, entity, user);
  });
};

export const stixCoreObjectDeleteRelation = async (context, user, stixCoreObjectId, toId, relationshipType) => {
  const stixCoreObject = await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the relation, Stix-Core-Object cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(context, user, stixCoreObjectId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixCoreObject, user);
};

export const stixCoreObjectDelete = async (context, user, stixCoreObjectId) => {
  const stixCoreObject = await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the object, Stix-Core-Object cannot be found.');
  }
  return deleteElementById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
};

export const askElementEnrichmentForConnector = async (context, user, elementId, connectorId) => {
  const connector = await storeLoadById(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
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
    values: [objectId]
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
export const stixCoreObjectExportAsk = async (context, user, args) => {
  const { format, stixCoreObjectId = null, exportType = null, maxMarkingDefinition = null } = args;
  const entity = stixCoreObjectId ? await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT) : null;
  const works = await askEntityExport(context, user, format, entity, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w));
};

export const stixCoreObjectsExportPush = async (context, user, type, file, listFilters) => {
  await upload(context, user, `export/${type}`, file, { list_filters: listFilters });
  return true;
};
export const stixCoreObjectExportPush = async (context, user, entityId, file) => {
  const entity = await internalLoadById(context, user, entityId);
  await upload(context, user, `export/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
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
    const entitySettings = await getEntitiesFromCache(context, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING);
    const entitySetting = entitySettings.find((es) => es.target_type === previous.entity_type);
    const isAutoExternal = !entitySetting ? false : entitySetting.platform_entity_files_ref;
    const filePath = `import/${previous.entity_type}/${internalId}`;
    // 01. Upload the file
    const meta = { entity_id: internalId };
    if (isAutoExternal) {
      const key = `${filePath}/${filename}`;
      meta.external_reference_id = generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, { url: `/storage/get/${key}` });
    }
    const up = await upload(context, user, filePath, file, meta, noTriggerImport);
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
    return true;
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
