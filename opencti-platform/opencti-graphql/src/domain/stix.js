import mime from 'mime-types';
import { assoc, invertObj, map, pipe, propOr } from 'ramda';
import { deleteElementById, internalLoadById } from '../database/middleware';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { connectorsForExport } from './connector';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { now, observableValue } from '../utils/format';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';

export const stixDelete = async (user, id) => {
  const element = await internalLoadById(user, id);
  if (element) {
    if (isStixObject(element.entity_type) || isStixRelationship(element.entity_type)) {
      return deleteElementById(user, element.id, element.entity_type);
    }
    throw UnsupportedError('This method can only delete Stix element');
  }
  throw FunctionalError(`Cannot delete the stix element, ${id} cannot be found.`);
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
  const filtersInversed = invertObj(filterOptions);
  const orderingInversed = invertObj(orderOptions);
  return pipe(
    assoc(
      'filters',
      map(
        (n) => ({
          key: n.key in filtersInversed ? filtersInversed[n.key] : n.key,
          values: n.values,
          operator: n.operator ? n.operator : 'eq',
        }),
        propOr([], 'filters', listFilters)
      )
    ),
    assoc(
      'orderBy',
      listFilters.orderBy in orderingInversed
        ? orderingInversed[listFilters.orderBy]
        : listFilters.orderBy
    )
  )(listFilters);
};
