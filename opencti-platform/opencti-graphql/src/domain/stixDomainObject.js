import { assoc, dissoc, invertObj, map, pipe, propOr, filter } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationsByFromAndTo,
  distributionEntities,
  distributionEntitiesThroughRelations,
  escape,
  listEntities,
  loadById,
  timeSeriesEntities,
  updateAttribute,
} from '../database/grakn';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { elCount } from '../database/elasticSearch';
import { generateFileExportName, upload } from '../database/minio';
import { connectorsForExport } from './connector';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { FunctionalError } from '../config/errors';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixDomainObject, stixDomainObjectOptions } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_META_RELATIONSHIP } from '../schema/general';
import { isStixMetaRelationship, RELATION_OBJECT } from '../schema/stixMetaRelationship';

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixDomainObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_DOMAIN_OBJECT);
  }
  return listEntities(types, ['standard_id'], args);
};

// eslint-disable-next-line no-unused-vars
export const findAllDuplicates = (args) => {
  // TODO @Sam, implement findAllDuplicates
  // const noTypes = !args.types || args.types.length === 0;
  // const entityTypes = noTypes ? [ABSTRACT_STIX_DOMAIN_OBJECT] : args.types;
  return [];
};

export const findById = async (stixDomainObjectId) => loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);

// region time series
export const reportsTimeSeries = (stixDomainObjectId, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: stixDomainObjectId }];
  return timeSeriesEntities('Report', filters, args);
};
export const stixDomainObjectsTimeSeries = (args) => {
  return timeSeriesEntities(args.type ? escape(args.type) : ABSTRACT_STIX_DOMAIN_OBJECT, [], args);
};

export const stixDomainObjectsNumber = (args) => ({
  count: elCount(INDEX_STIX_DOMAIN_OBJECTS, args),
  total: elCount(INDEX_STIX_DOMAIN_OBJECTS, dissoc('endDate', args)),
});

export const stixDomainObjectsDistributionByEntity = async (args) => {
  const { objectId, field, relationship_type: relationshipType } = args;
  if (field.includes('.')) {
    const options = pipe(
      assoc('field', field.split('.')[1]),
      assoc('relationshipType', relationshipType),
      assoc('remoteRelationshipType', field.split('.')[0]),
      assoc('fromId', objectId)
    )(args);
    return distributionEntitiesThroughRelations(options);
  }
  const filters = [{ isRelation: true, type: relationshipType, value: objectId }];
  return distributionEntities(ABSTRACT_STIX_DOMAIN_OBJECT, filters, args);
};
// endregion

// region export
const askJobExports = async (
  format,
  entity = null,
  type = null,
  exportType = null,
  maxMarkingDef = null,
  context = null,
  listArgs = null
) => {
  const connectors = await connectorsForExport(format, true);
  // Create job for every connectors
  const haveMarking = maxMarkingDef && maxMarkingDef.length > 0;
  const maxMarking = haveMarking ? await findMarkingDefinitionById(maxMarkingDef) : null;
  const finalEntityType = entity ? entity.entity_type : type;
  const workList = await Promise.all(
    map((connector) => {
      const fileName = generateFileExportName(format, connector, entity, finalEntityType, exportType, maxMarking);
      const workJob = createWork(connector, finalEntityType, entity ? entity.id : null, context, fileName);
      return workJob.then(({ work, job }) => ({ connector, job, work }));
    }, connectors)
  );
  let finalListArgs = listArgs;
  if (listArgs !== null) {
    const stixDomainObjectsFiltersInversed = invertObj(stixDomainObjectOptions.StixDomainObjectsFilter);
    const stixDomainObjectsOrderingInversed = invertObj(stixDomainObjectOptions.StixDomainObjectsOrdering);
    finalListArgs = pipe(
      assoc(
        'filters',
        map(
          (n) => ({
            key: n.key in stixDomainObjectsFiltersInversed ? stixDomainObjectsFiltersInversed[n.key] : n.key,
            values: n.values,
          }),
          propOr([], 'filters', listArgs)
        )
      ),
      assoc(
        'orderBy',
        listArgs.orderBy in stixDomainObjectsOrderingInversed
          ? stixDomainObjectsOrderingInversed[listArgs.orderBy]
          : listArgs.orderBy
      )
    )(listArgs);
  }
  // Send message to all correct connectors queues
  await Promise.all(
    map((data) => {
      const { connector, job, work } = data;
      const message = {
        work_id: work.internal_id, // work(id)
        job_id: job.internal_id, // job(id)
        max_marking_definition: maxMarkingDef && maxMarkingDef.length > 0 ? maxMarkingDef : null, // markingDefinition(id)
        export_type: exportType, // for entity, simple or full / for list, withArgs / withoutArgs
        entity_type: entity ? entity.entity_type : type, // report, threat, ...
        entity_id: entity ? entity.id : null, // report(id), thread(id), ...
        list_args: finalListArgs,
        file_context: work.work_context,
        file_name: work.work_file, // Base path for the upload
      };
      return pushToConnector(connector, message);
    }, workList)
  );
  return workList;
};
// endregion

// region mutation
/**
 * Create export element waiting for completion
 * @param args
 * @returns {*}
 */
export const stixDomainObjectExportAsk = async (args) => {
  const {
    format,
    type = null,
    stixDomainObjectId = null,
    exportType = null,
    maxMarkingDefinition = null,
    context = null,
  } = args;
  const entity = stixDomainObjectId ? await loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT) : null;
  const workList = await askJobExports(format, entity, type, exportType, maxMarkingDefinition, context, args);
  // Return the work list to do
  return map((w) => workToExportFile(w.work), workList);
};

export const stixDomainObjectImportPush = (user, entityType = null, entityId = null, file) => {
  return upload(user, 'import', file, entityType, entityId);
};

export const stixDomainObjectExportPush = async (
  user,
  entityType = null,
  entityId = null,
  file,
  context = null,
  listArgs = null
) => {
  // Upload the document in minio
  await upload(user, 'export', file, entityType, entityId, context, listArgs);
  return true;
};

export const addStixDomainObject = async (user, stixDomainObject) => {
  const innerType = stixDomainObject.type;
  const created = await createEntity(user, dissoc('type', stixDomainObject), innerType);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const stixDomainObjectDelete = async (user, stixDomainObjectId) => {
  const stixDomainObject = await loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot delete the object, Stix-Domain-Object cannot be found.');
  }
  return deleteEntityById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
};

export const stixDomainObjectsDelete = async (user, stixDomainObjectsIds) => {
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixDomainObjectsIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await stixDomainObjectDelete(user, stixDomainObjectsIds[i]);
  }
  return stixDomainObjectsIds;
};

export const stixDomainObjectAddRelation = async (user, stixDomainObjectId, input) => {
  const stixDomainObject = await loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot add the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = assoc('fromId', stixDomainObjectId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixDomainObjectAddRelations = async (user, stixDomainObjectId, input) => {
  const stixDomainObject = await loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot add the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = map(
    (n) => ({ fromId: stixDomainObjectId, toId: n, relationship_type: input.relationship_type }),
    input.toIds
  );
  await createRelations(user, finalInput);
  return loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT).then((entity) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, entity, user)
  );
};

export const stixDomainObjectDeleteRelation = async (user, stixDomainObjectId, toId, relationshipType) => {
  const stixDomainObject = await loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot delete the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, stixDomainObjectId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, stixDomainObject, user);
};

export const stixDomainObjectEditField = async (user, stixDomainObjectId, input, options = {}) => {
  const stixDomainObject = await loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot edit the field, Stix-Domain-Object cannot be found.');
  }
  const updatedStixDomainObject = await updateAttribute(
    user,
    stixDomainObjectId,
    ABSTRACT_STIX_DOMAIN_OBJECT,
    input,
    options
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedStixDomainObject, user);
};

// region context
export const stixDomainObjectCleanContext = async (user, stixDomainObjectId) => {
  await delEditContext(user, stixDomainObjectId);
  return loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT).then((stixDomainObject) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, stixDomainObject, user)
  );
};

export const stixDomainObjectEditContext = async (user, stixDomainObjectId, input) => {
  await setEditContext(user, stixDomainObjectId, input);
  return loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT).then((stixDomainObject) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, stixDomainObject, user)
  );
};
// endregion
