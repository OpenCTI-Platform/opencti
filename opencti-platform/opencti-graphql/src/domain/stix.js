import mime from 'mime-types';
import { invertObj, map } from 'ramda';
import { batchListThroughGetTo, deleteElementById, mergeEntities, updateAttribute } from '../database/middleware';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { connectorsForExport } from './connector';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { now, observableValue } from '../utils/format';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { RELATION_GRANTED_TO } from '../schema/stixMetaRelationship';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  isStixDomainObjectShareableContainer,
  STIX_DOMAIN_OBJECTS,
  STIX_ORGANIZATIONS_UNRESTRICTED,
} from '../schema/stixDomainObject';
import {
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  INPUT_GRANTED_REFS
} from '../schema/general';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { createQueryTask } from './task';
import { getParentTypes } from '../schema/schemaUtils';
import { internalLoadById } from '../database/middleware-loader';

export const stixDelete = async (context, user, id) => {
  const element = await internalLoadById(context, user, id);
  if (element) {
    if (isStixObject(element.entity_type) || isStixRelationship(element.entity_type)) {
      return deleteElementById(context, user, element.id, element.entity_type);
    }
    throw UnsupportedError('This method can only delete Stix element');
  }
  throw FunctionalError(`Cannot delete the stix element, ${id} cannot be found.`);
};

export const stixObjectMerge = async (context, user, targetId, sourceIds) => {
  return mergeEntities(context, user, targetId, sourceIds);
};

export const askListExport = async (context, user, format, entityType, selectedIds, listParams, type = 'simple', maxMarkingId = null) => {
  const connectors = await connectorsForExport(context, user, format, true);
  const markingLevel = maxMarkingId ? await findMarkingDefinitionById(context, user, maxMarkingId) : null;
  const toFileName = (connector) => {
    const fileNamePart = `${entityType}_${type}.${mime.extension(format)}`;
    return `${now()}_${markingLevel?.definition || 'TLP:ALL'}_(${connector.name})_${fileNamePart}`;
  };
  const buildExportMessage = (work, fileName) => {
    if (selectedIds && selectedIds.length > 0) {
      return {
        internal: {
          work_id: work.id, // Related action for history
          applicant_id: user.id, // User asking for the import
        },
        event: {
          export_scope: 'selection', // query or selection or single
          export_type: type, // Simple or full
          file_name: fileName, // Export expected file name
          max_marking: maxMarkingId, // Max marking id
          entity_type: entityType, // Exported entity type
          element_id: listParams.elementId,
          selected_ids: selectedIds, // ids that are both selected via checkboxes and respect the filtering
        },
      };
    }
    return {
      internal: {
        work_id: work.id, // Related action for history
        applicant_id: user.id, // User asking for the import
      },
      event: {
        export_scope: 'query', // query or selection or single
        export_type: type, // Simple or full
        file_name: fileName, // Export expected file name
        max_marking: maxMarkingId, // Max marking id
        entity_type: entityType, // Exported entity type
        element_id: listParams.elementId,
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
      const work = await createWork(context, user, connector, fileIdentifier, path);
      const message = buildExportMessage(work, fileIdentifier);
      await pushToConnector(context, connector, message);
      return work;
    }, connectors)
  );
  return worksForExport;
};

export const askEntityExport = async (context, user, format, entity, type = 'simple', maxMarkingId = null) => {
  const connectors = await connectorsForExport(context, user, format, true);
  const markingLevel = maxMarkingId ? await findMarkingDefinitionById(context, user, maxMarkingId) : null;
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
        export_scope: 'single', // query or selection or single
        export_type: type, // Simple or full
        file_name: fileName, // Export expected file name
        max_marking: maxMarkingId, // Max marking id
        entity_type: entity.entity_type, // Exported entity type
        // For single entity export
        entity_id: entity.id, // Location of the file export = the exported element
      },
    };
  };
  // noinspection UnnecessaryLocalVariableJS
  const worksForExport = await Promise.all(
    map(async (connector) => {
      const fileIdentifier = toFileName(connector);
      const path = `export/${entity.entity_type}/${entity.id}/`;
      const work = await createWork(context, user, connector, fileIdentifier, path);
      const message = buildExportMessage(work, fileIdentifier);
      await pushToConnector(context, connector, message);
      return work;
    }, connectors)
  );
  return worksForExport;
};

export const exportTransformFilters = (listFilters, filterOptions, orderOptions) => {
  const filtersInversed = invertObj(filterOptions);
  const orderingInversed = invertObj(orderOptions);
  return {
    ...listFilters,
    orderBy: listFilters.orderBy in orderingInversed
      ? orderingInversed[listFilters.orderBy]
      : listFilters.orderBy,
    filters: (listFilters.filters ?? []).map(
      (n) => ({
        key: n.key in filtersInversed ? filtersInversed[n.key] : n.key,
        values: n.values,
        operator: n.operator ?? 'eq',
      })
    ),
  };
};

export const batchObjectOrganizations = (context, user, stixCoreObjectIds) => {
  return batchListThroughGetTo(context, user, stixCoreObjectIds, RELATION_GRANTED_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};

const createSharingTask = async (context, type, containerId, organizationId) => {
  const allowedDomainsShared = STIX_DOMAIN_OBJECTS.filter((s) => {
    if (s === ENTITY_TYPE_CONTAINER_OPINION || s === ENTITY_TYPE_CONTAINER_NOTE) return false;
    return !STIX_ORGANIZATIONS_UNRESTRICTED.some((o) => getParentTypes(s).includes(o));
  });
  const SCAN_ENTITIES = [...allowedDomainsShared, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_RELATIONSHIP];
  const filters = {
    containedBy: [{ id: containerId, value: containerId }],
    entity_type: SCAN_ENTITIES.map((e) => ({ id: e, value: e })),
  };
  const input = {
    filters: JSON.stringify(filters),
    actions: [{ type, context: { values: [organizationId] } }]
  };
  await createQueryTask(context, context.user, input);
};

export const addOrganizationRestriction = async (context, user, fromId, organizationId) => {
  const from = await internalLoadById(context, user, fromId);
  const updates = [{ key: INPUT_GRANTED_REFS, value: [organizationId], operation: UPDATE_OPERATION_ADD }];
  const data = await updateAttribute(context, user, fromId, from.entity_type, updates);
  if (isStixDomainObjectShareableContainer(from.entity_type)) {
    await createSharingTask(context, 'SHARE', fromId, organizationId);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_OBJECT].EDIT_TOPIC, data.element, user);
};

export const removeOrganizationRestriction = async (context, user, fromId, organizationId) => {
  const from = await internalLoadById(context, user, fromId);
  const updates = [{ key: INPUT_GRANTED_REFS, value: [organizationId], operation: UPDATE_OPERATION_REMOVE }];
  const data = await updateAttribute(context, user, fromId, from.entity_type, updates);
  if (isStixDomainObjectShareableContainer(from.entity_type)) {
    await createSharingTask(context, 'UNSHARE', fromId, organizationId);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_OBJECT].EDIT_TOPIC, data.element, user);
};
