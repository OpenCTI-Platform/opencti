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
  listEntities,
  batchListThroughGetFrom,
  loadById,
  mergeEntities,
  updateAttribute,
  batchLoadThroughGetTo,
} from '../database/middleware';
import { findAll as relationFindAll } from './stixCoreRelationship';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { isStixCoreObject } from '../schema/stixCoreObject';
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
import { createWork } from './work';
import { pushToConnector } from '../database/amqp';
import { now } from '../utils/format';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';

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

export const findById = async (user, stixCoreObjectId) => loadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);

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
  const stixCoreObject = await loadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
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
  return loadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((entity) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, entity, user)
  );
};

export const stixCoreObjectDeleteRelation = async (user, stixCoreObjectId, toId, relationshipType) => {
  const stixCoreObject = await loadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
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
  const stixCoreObject = await loadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot edit the field, Stix-Core-Object cannot be found.');
  }
  const { element } = await updateAttribute(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, element, user);
};

export const stixCoreObjectDelete = async (user, stixCoreObjectId) => {
  const stixCoreObject = await loadById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
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
  const connector = await loadById(user, connectorId, ENTITY_TYPE_CONNECTOR);
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
    const fileNamePart = `${entity.entity_type}-${entity.name}_${type}.${mime.extension(format)}`;
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
