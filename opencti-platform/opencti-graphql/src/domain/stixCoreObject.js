import * as R from 'ramda';
import mime from 'mime-types';
import { assoc, invertObj, map, pipe, propOr } from 'ramda';
import {
  batchListThroughGetTo,
  createRelation,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  internalLoadById,
  batchListThroughGetFrom,
  storeLoadById,
  mergeEntities,
  updateAttribute,
  batchLoadThroughGetTo, storeLoadByIdWithRefs, mergeInstanceWithInputs,
} from '../database/middleware';
import { listEntities } from '../database/repository';
import { findAll as relationFindAll } from './stixCoreRelationship';
import { lockResource, notify, storeUpdateEvent } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { isStixCoreObject, stixCoreObjectOptions } from '../schema/stixCoreObject';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_META_RELATIONSHIP, ENTITY_TYPE_IDENTITY } from '../schema/general';
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
import { connectorsForExport } from './connector';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { now, observableValue } from '../utils/format';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { deleteFile, loadFile, stixFileConverter, upload } from '../database/minio';
import { uploadJobImport } from './file';
import { elUpdateElement } from '../database/engine';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { getInstanceIds } from '../schema/identifier';

export const findAll = async (user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = R.filter((type) => isStixCoreObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  return listEntities(user, types, args);
};

export const findById = async (user, stixCoreObjectId) => storeLoadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);

export const batchCreatedBy = async (user, stixCoreObjectIds) => {
  return batchLoadThroughGetTo(user, stixCoreObjectIds, RELATION_CREATED_BY, ENTITY_TYPE_IDENTITY);
};

export const batchReports = async (user, stixCoreObjectIds, args = {}) => {
  return batchListThroughGetFrom(user, stixCoreObjectIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT, args);
};

export const batchNotes = (user, stixCoreObjectIds, args = {}) => {
  return batchListThroughGetFrom(user, stixCoreObjectIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE, args);
};

export const batchOpinions = (user, stixCoreObjectIds, args = {}) => {
  return batchListThroughGetFrom(user, stixCoreObjectIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION, args);
};

export const batchLabels = (user, stixCoreObjectIds) => {
  return batchListThroughGetTo(user, stixCoreObjectIds, RELATION_OBJECT_LABEL, ENTITY_TYPE_LABEL);
};

export const batchMarkingDefinitions = (user, stixCoreObjectIds) => {
  return batchListThroughGetTo(user, stixCoreObjectIds, RELATION_OBJECT_MARKING, ENTITY_TYPE_MARKING_DEFINITION);
};

export const batchExternalReferences = (user, stixDomainObjectIds) => {
  return batchListThroughGetTo(user, stixDomainObjectIds, RELATION_EXTERNAL_REFERENCE, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const batchKillChainPhases = (user, stixCoreObjectIds) => {
  return batchListThroughGetTo(user, stixCoreObjectIds, RELATION_KILL_CHAIN_PHASE, ENTITY_TYPE_KILL_CHAIN_PHASE);
};

export const stixCoreRelationships = (user, stixCoreObjectId, args) => {
  const finalArgs = R.assoc('elementId', stixCoreObjectId, args);
  return relationFindAll(user, finalArgs);
};

export const stixCoreObjectAddRelation = async (user, stixCoreObjectId, input) => {
  const data = await internalLoadById(user, stixCoreObjectId);
  if (!isStixCoreObject(data.entity_type) || !isStixRelationship(input.relationship_type)) {
    throw FunctionalError('Only stix-meta-relationship can be added through this method.', { stixCoreObjectId, input });
  }
  const finalInput = R.assoc('fromId', stixCoreObjectId, input);
  return createRelation(user, finalInput);
};

export const stixCoreObjectAddRelations = async (user, stixCoreObjectId, input) => {
  const stixCoreObject = await storeLoadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
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
  await createRelations(user, finalInput);
  return storeLoadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((entity) => notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, entity, user));
};

export const stixCoreObjectDeleteRelation = async (user, stixCoreObjectId, toId, relationshipType) => {
  const stixCoreObject = await storeLoadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the relation, Stix-Core-Object cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, stixCoreObjectId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixCoreObject, user);
};

export const stixCoreObjectEditField = async (user, stixCoreObjectId, input) => {
  const stixCoreObject = await storeLoadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot edit the field, Stix-Core-Object cannot be found.');
  }
  const { element } = await updateAttribute(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, element, user);
};

export const stixCoreObjectDelete = async (user, stixCoreObjectId) => {
  const stixCoreObject = await storeLoadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the object, Stix-Core-Object cannot be found.');
  }
  return deleteElementById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
};

export const stixCoreObjectsDelete = async (user, stixCoreObjectsIds) => {
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixCoreObjectsIds.length; i += 1) {
    await stixCoreObjectDelete(user, stixCoreObjectsIds[i]);
  }
  return stixCoreObjectsIds;
};

export const stixCoreObjectMerge = async (user, targetId, sourceIds) => {
  return mergeEntities(user, targetId, sourceIds);
};
// endregion

export const stixCoreObjectAskEnrichment = async (user, stixCoreObjectId, connectorId) => {
  const connector = await storeLoadById(user, connectorId, ENTITY_TYPE_CONNECTOR);
  const work = await createWork(user, connector, 'Manual enrichment', stixCoreObjectId);
  const message = {
    internal: {
      work_id: work.id, // Related action for history
      applicant_id: user.id, // User asking for the import
    },
    event: {
      entity_id: stixCoreObjectId,
    },
  };
  await pushToConnector(connector, message);
  return work;
};

export const askEntityExport = async (user, format, entity, type = 'simple', maxMarkingId = null) => {
  const connectors = await connectorsForExport(user, format, true);
  const markingLevel = maxMarkingId ? await findMarkingDefinitionById(user, maxMarkingId) : null;
  const toFileName = (connector) => {
    const fileNamePart = `${entity.entity_type}-${entity.name || observableValue(entity)}_${type}.${mime.extension(
      format
    )}`;
    return `${now()}_${markingLevel?.definition || 'TLP:ALL'}_(${connector.name})_${fileNamePart}`;
  };
  const buildExportMessage = (work, fileName) => {
    return {
      internal: {
        work_id: work.id, // Related action for history
        applicant_id: user.id, // User asking for the import
      },
      event: {
        export_scope: 'single', // Single or List
        export_type: type, // Simple or full
        file_name: fileName, // Export expected file name
        max_marking: maxMarkingId, // Max marking id
        entity_type: entity.entity_type, // Exported entity type
        // For single entity export
        entity_id: entity.id, // Exported element
      },
    };
  };
  // noinspection UnnecessaryLocalVariableJS
  const worksForExport = await Promise.all(
    map(async (connector) => {
      const fileIdentifier = toFileName(connector);
      const path = `export/${entity.entity_type}/${entity.id}/`;
      const work = await createWork(user, connector, fileIdentifier, path);
      const message = buildExportMessage(work, fileIdentifier);
      await pushToConnector(connector, message);
      return work;
    }, connectors)
  );
  return worksForExport;
};

export const exportTransformFilters = (listFilters, filterOptions, orderOptions) => {
  const stixDomainObjectsFiltersInversed = invertObj(filterOptions);
  const stixDomainObjectsOrderingInversed = invertObj(orderOptions);
  return pipe(
    assoc(
      'filters',
      map(
        (n) => ({
          key: n.key in stixDomainObjectsFiltersInversed ? stixDomainObjectsFiltersInversed[n.key] : n.key,
          values: n.values,
          operator: n.operator ? n.operator : 'eq',
        }),
        propOr([], 'filters', listFilters)
      )
    ),
    assoc(
      'orderBy',
      listFilters.orderBy in stixDomainObjectsOrderingInversed
        ? stixDomainObjectsOrderingInversed[listFilters.orderBy]
        : listFilters.orderBy
    )
  )(listFilters);
};
export const askListExport = async (user, format, entityType, listParams, type = 'simple', maxMarkingId = null) => {
  const connectors = await connectorsForExport(user, format, true);
  const markingLevel = maxMarkingId ? await findMarkingDefinitionById(user, maxMarkingId) : null;
  const toFileName = (connector) => {
    const fileNamePart = `${entityType}_${type}.${mime.extension(format)}`;
    return `${now()}_${markingLevel?.definition || 'TLP:ALL'}_(${connector.name})_${fileNamePart}`;
  };
  const buildExportMessage = (work, fileName) => {
    return {
      internal: {
        work_id: work.id, // Related action for history
        applicant_id: user.id, // User asking for the import
      },
      event: {
        export_scope: 'list', // Single or List
        export_type: type, // Simple or full
        file_name: fileName, // Export expected file name
        max_marking: maxMarkingId, // Max marking id
        entity_type: entityType, // Exported entity type
        // For list entity export
        list_params: listParams,
      },
    };
  };
  // noinspection UnnecessaryLocalVariableJS
  const worksForExport = await Promise.all(
    map(async (connector) => {
      const fileIdentifier = toFileName(connector);
      const path = `export/${entityType}/`;
      const work = await createWork(user, connector, fileIdentifier, path);
      const message = buildExportMessage(work, fileIdentifier);
      await pushToConnector(connector, message);
      return work;
    }, connectors)
  );
  return worksForExport;
};

export const stixCoreObjectsExportAsk = async (user, args) => {
  const { format, type, exportType, maxMarkingDefinition } = args;
  const { search, orderBy, orderMode, filters, filterMode } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode };
  const filtersOpts = stixCoreObjectOptions.StixCoreObjectsFilter;
  const ordersOpts = stixCoreObjectOptions.StixCoreObjectsOrdering;
  const listParams = exportTransformFilters(argsFilters, filtersOpts, ordersOpts);
  const works = await askListExport(user, format, type, listParams, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w), works);
};
export const stixCoreObjectExportAsk = async (user, args) => {
  const { format, stixCoreObjectId = null, exportType = null, maxMarkingDefinition = null } = args;
  const entity = stixCoreObjectId ? await storeLoadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT) : null;
  const works = await askEntityExport(user, format, entity, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w), works);
};
export const stixCoreObjectsExportPush = async (user, type, file, listFilters) => {
  await upload(user, `export/${type}`, file, { list_filters: listFilters });
  return true;
};
export const stixCoreObjectExportPush = async (user, entityId, file) => {
  const entity = await internalLoadById(user, entityId);
  if (!entity) {
    throw UnsupportedError('Cant upload a file an none existing element', { entityId });
  }
  await upload(user, `export/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
  return true;
};
// endregion

export const stixCoreObjectImportPush = async (user, entity, file) => {
  let lock;
  const participantIds = getInstanceIds(entity);
  try {
    // Lock the participants that will be merged
    lock = await lockResource(participantIds);
    const { internal_id: internalId } = entity;
    const up = await upload(user, `import/${entity.entity_type}/${internalId}`, file, { entity_id: internalId });
    await uploadJobImport(user, up.id, up.metaData.mimetype, up.metaData.entity_id);
    // Patch the updated_at to force live stream evolution
    await elUpdateElement({ _index: entity._index, internal_id: internalId, updated_at: now() });
    // Stream event generation
    // const eventFiles = [stixFileConverter(user, up)];
    const eventInputs = [{ key: 'x_opencti_files', value: [eventFiles], operation: UPDATE_OPERATION_ADD }];
    await storeUpdateEvent(user, entity, eventInputs);
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

export const stixCoreObjectIdImportPush = async (user, entityId, file) => {
  const entity = await storeLoadByIdWithRefs(user, entityId);
  if (!entity) {
    throw UnsupportedError('Cant upload a file an none existing element', { entityId });
  }
  return stixCoreObjectImportPush(user, entity, file);
};

export const stixCoreObjectImportDelete = async (user, fileId) => {
  if (!fileId.startsWith('import')) {
    throw UnsupportedError('Cant delete an exported file with this method');
  }
  // Get the context
  const up = await loadFile(user, fileId);
  const entityId = up.metaData.entity_id;
  const previous = await storeLoadByIdWithRefs(user, entityId);
  if (!previous) {
    throw UnsupportedError('Cant delete a file of none existing element', { entityId });
  }
  let lock;
  const participantIds = getInstanceIds(previous);
  try {
    // Lock the participants that will be merged
    lock = await lockResource(participantIds);
    // Delete the file
    await deleteFile(user, fileId);
    // Patch the updated_at to force live stream evolution
    await elUpdateElement({ _index: previous._index, internal_id: entityId, updated_at: now() });
    // Stream event generation
    // const eventFiles = [stixFileConverter(user, up)];
    const eventInputs = [{ key: 'x_opencti_files', value: [up.uri], operation: UPDATE_OPERATION_REMOVE }];
    const instance = mergeInstanceWithInputs(previous, eventInputs);
    await storeUpdateEvent(user, previous, instance, `${up.name} remove from files`);
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
