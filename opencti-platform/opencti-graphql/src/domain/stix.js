import mime from 'mime-types';
import { invertObj, map } from 'ramda';
import { deleteElementById, mergeEntities, updateAttribute } from '../database/middleware';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { connectorsForExport } from './connector';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { now, observableValue } from '../utils/format';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, isStixDomainObjectShareableContainer, STIX_ORGANIZATIONS_UNRESTRICTED } from '../schema/stixDomainObject';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  CONNECTOR_INTERNAL_EXPORT_FILE,
  INPUT_GRANTED_REFS
} from '../schema/general';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { createQueryTask } from './backgroundTask';
import { getParentTypes } from '../schema/schemaUtils';
import { internalLoadById, storeLoadById } from '../database/middleware-loader';
import { schemaTypesDefinition } from '../schema/schema-types';
import { completeContextDataForEntity, publishUserAction } from '../listener/UserActionListener';
import { checkAndConvertFilters } from '../utils/filtering/filtering-utils';
import { specialTypesExtensions } from '../database/file-storage';
import { getExportFilter } from '../utils/getExportFilter';
import { getEntitiesListFromCache } from '../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { checkUserCanShareMarkings } from './user';

export const stixDelete = async (context, user, id) => {
  const element = await internalLoadById(context, user, id);
  if (element) {
    if (isStixObject(element.entity_type) || isStixRelationship(element.entity_type)) {
      // To handle delete synchronization events, we force the forceDelete flag to true, because we don't want delete events to create trash entries on synchronized platforms
      // THIS IS NOT IDEAL: we ideally would need to add the forceDelete flag to all delete related methods on the API,
      // and let the worker call this method with the flag set to true in case of synchronization
      await deleteElementById(context, user, element.id, element.entity_type, { forceDelete: true });
      return element.id;
    }
    throw UnsupportedError('This method can only delete Stix element');
  }
  throw FunctionalError(`Cannot delete the stix element, ${id} cannot be found.`);
};

export const stixObjectMerge = async (context, user, targetId, sourceIds) => {
  return mergeEntities(context, user, targetId, sourceIds);
};

export const askListExport = async (context, user, exportContext, format, selectedIds, listParams, type, contentMaxMarkings, fileMarkings) => {
  if (!exportContext || !exportContext?.entity_type) throw new Error('entity_type is missing from askListExport');

  const connectors = await connectorsForExport(context, user, format, true);
  const markingLevels = await Promise.all(contentMaxMarkings.map(async (id) => {
    return await findMarkingDefinitionById(context, user, id);
  }));
  await checkUserCanShareMarkings(context, user, markingLevels);
  const fileNameMarkingLevels = markingLevels.map((markingLevel) => markingLevel?.definition).join('_');

  const entity = exportContext.entity_id ? await storeLoadById(context, user, exportContext.entity_id, ABSTRACT_STIX_CORE_OBJECT) : null;
  const { entity_type } = exportContext;

  const toFileName = (connector) => {
    const fileNamePart = `${entity_type}_${type}.${mime.extension(format) ? mime.extension(format) : specialTypesExtensions[format] ?? 'unknown'}`;
    return `${now()}_${fileNameMarkingLevels || 'TLP:ALL'}_(${connector.name})_${fileNamePart}`;
  };

  const markingList = await getEntitiesListFromCache(context, user, ENTITY_TYPE_MARKING_DEFINITION);

  const { markingFilter, mainFilter } = await getExportFilter(user, { markingList, contentMaxMarkings, objectIdsList: selectedIds });

  const baseEvent = {
    format, // extension mime type
    export_type: type, // Simple or full
    // Related to entity (if export concern, must be hosted on a specific entity)
    entity_id: entity?.id,
    entity_name: entity ? extractEntityRepresentativeName(entity) : 'global',
    entity_type, // Exported entity type
    // All the params needed to execute the export on python connector
    file_markings: fileMarkings,
    main_filter: mainFilter,
    access_filter: markingFilter
  };
  const buildExportMessage = (work, fileName) => {
    const internal = {
      work_id: work.id, // Related action for history
      applicant_id: user.id, // User asking for the import
    };
    if (selectedIds && selectedIds.length > 0) {
      return {
        internal,
        event: {
          event_type: CONNECTOR_INTERNAL_EXPORT_FILE,
          export_scope: 'selection', // query or selection or single
          file_name: fileName, // Export expected file name
          selected_ids: selectedIds, // ids that are both selected via checkboxes and respect the filtering
          ...baseEvent,
        },
      };
    }
    return {
      internal,
      event: {
        export_scope: 'query', // query or selection or single
        file_name: fileName, // Export expected file name
        list_params: listParams,
        ...baseEvent,
      },
    };
  };
  // noinspection UnnecessaryLocalVariableJS
  const worksForExport = await Promise.all(
    map(async (connector) => {
      const fileIdentifier = toFileName(connector);
      const path = `export/${entity_type}${entity ? `/${entity.id}` : ''}`;
      const work = await createWork(context, user, connector, fileIdentifier, path, { fileMarkings });
      const message = buildExportMessage(work, fileIdentifier);
      await pushToConnector(connector.internal_id, message);
      return work;
    }, connectors)
  );
  await publishUserAction({
    user,
    event_access: 'extended',
    event_type: 'command',
    event_scope: 'export',
    context_data: baseEvent
  });
  return worksForExport;
};

export const askEntityExport = async (context, user, format, entity, type, contentMaxMarkings, fileMarkings) => {
  const connectors = await connectorsForExport(context, user, format, true);
  const markingLevels = await Promise.all(contentMaxMarkings.map(async (id) => {
    return await findMarkingDefinitionById(context, user, id);
  }));
  await checkUserCanShareMarkings(context, user, markingLevels);
  const fileNameMarkingLevels = markingLevels.map((markingLevel) => markingLevel?.definition).join('_');
  const toFileName = (connector) => {
    const fileNamePart = `${entity.entity_type}-${entity.name || observableValue(entity)}_${type}.${mime.extension(format) ? mime.extension(format) : specialTypesExtensions[format] ?? 'unknown'}`;
    return `${now()}_${fileNameMarkingLevels || 'TLP:ALL'}_(${connector.name})_${fileNamePart}`;
  };

  const markingList = await getEntitiesListFromCache(context, user, ENTITY_TYPE_MARKING_DEFINITION);

  const { markingFilter, mainFilter } = await getExportFilter(user, { markingList, contentMaxMarkings, objectIdsList: [entity.id] });

  const baseEvent = {
    format,
    export_scope: 'single', // query or selection or single
    entity_id: entity.id, // Location of the file export = the exported element
    entity_name: extractEntityRepresentativeName(entity),
    entity_type: entity.entity_type, // Exported entity type
    export_type: type, // Simple or full
    file_markings: fileMarkings,
    main_filter: mainFilter,
    access_filter: markingFilter
  };
  const buildExportMessage = (work, fileName) => {
    return {
      internal: {
        work_id: work.id, // Related action for history
        applicant_id: user.id, // User asking for the import
      },
      event: {
        event_type: CONNECTOR_INTERNAL_EXPORT_FILE,
        file_name: fileName, // Export expected file name
        ...baseEvent
      },
    };
  };

  // noinspection UnnecessaryLocalVariableJS
  const worksForExport = await Promise.all(
    map(async (connector) => { // can be refactored to native map
      const fileIdentifier = toFileName(connector);
      const path = `export/${entity.entity_type}/${entity.id}`;
      const work = await createWork(context, user, connector, fileIdentifier, path, { fileMarkings });
      const message = buildExportMessage(work, fileIdentifier);
      await pushToConnector(connector.internal_id, message);
      return work;
    }, connectors)
  );
  const contextData = completeContextDataForEntity(baseEvent, entity);
  await publishUserAction({
    user,
    event_access: 'extended',
    event_type: 'command',
    event_scope: 'export',
    context_data: contextData
  });
  return worksForExport;
};

export const exportTransformFilters = (filteringArgs, orderOptions) => {
  const orderingInversed = invertObj(orderOptions);
  const { filters } = filteringArgs;
  return {
    ...filteringArgs,
    orderBy: filteringArgs.orderBy in orderingInversed
      ? orderingInversed[filteringArgs.orderBy]
      : filteringArgs.orderBy,
    filters: checkAndConvertFilters(filters),
  };
};

const createSharingTask = async (context, type, containerId, organizationId) => {
  const allowedDomainsShared = schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT)
    .filter((s) => {
      if (s === ENTITY_TYPE_CONTAINER_OPINION || s === ENTITY_TYPE_CONTAINER_NOTE) return false;
      return !STIX_ORGANIZATIONS_UNRESTRICTED.some((o) => getParentTypes(s).includes(o));
    });
  const SCAN_ENTITIES = [...allowedDomainsShared, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_RELATIONSHIP];
  const filters = {
    mode: 'and',
    filters: [
      {
        key: ['objects'],
        values: [containerId],
      },
      {
        key: ['entity_type'],
        values: SCAN_ENTITIES,
      }
    ],
    filterGroups: [],
  };
  const input = {
    filters: JSON.stringify(filters),
    actions: [{ type, context: { values: [organizationId] } }],
    scope: 'KNOWLEDGE',
  };
  await createQueryTask(context, context.user, input);
};

export const addOrganizationRestriction = async (context, user, fromId, organizationId) => {
  const from = await internalLoadById(context, user, fromId);
  const updates = [{ key: INPUT_GRANTED_REFS, value: [organizationId], operation: UPDATE_OPERATION_ADD }];
  // We skip references validation when updating organization sharing
  const data = await updateAttribute(context, user, fromId, from.entity_type, updates, { bypassValidation: true });
  if (isStixDomainObjectShareableContainer(from.entity_type)) {
    await createSharingTask(context, 'SHARE', fromId, organizationId);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_OBJECT].EDIT_TOPIC, data.element, user);
};

export const removeOrganizationRestriction = async (context, user, fromId, organizationId) => {
  const from = await internalLoadById(context, user, fromId);
  const updates = [{ key: INPUT_GRANTED_REFS, value: [organizationId], operation: UPDATE_OPERATION_REMOVE }];
  // We skip references validation when updating organization sharing
  const data = await updateAttribute(context, user, fromId, from.entity_type, updates, { bypassValidation: true });
  if (isStixDomainObjectShareableContainer(from.entity_type)) {
    await createSharingTask(context, 'UNSHARE', fromId, organizationId);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_OBJECT].EDIT_TOPIC, data.element, user);
};
