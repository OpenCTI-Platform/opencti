import { assoc, dissoc, filter, map } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  distributionEntities,
  escape,
  internalLoadById,
  listEntities,
  loadById,
  timeSeriesEntities,
  updateAttribute,
} from '../database/middleware';
import { elCount } from '../database/elasticSearch';
import { upload } from '../database/minio';
import { workToExportFile } from './work';
import { FunctionalError } from '../config/errors';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixDomainObject, stixDomainObjectOptions } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_META_RELATIONSHIP } from '../schema/general';
import { isStixMetaRelationship, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { askEntityExport, askListExport, exportTransformFilters } from './stixCoreObject';
import { addAttribute, find as findAttribute } from './attribute';

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixDomainObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_DOMAIN_OBJECT);
  }
  return listEntities(types, args);
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
  const { objectId, relationship_type: relationshipType } = args;
  const filters = [{ isRelation: true, type: relationshipType, value: objectId }];
  return distributionEntities(ABSTRACT_STIX_DOMAIN_OBJECT, filters, args);
};
// endregion

// region export
export const stixDomainObjectsExportAsk = async (user, args) => {
  const { format, type, exportType, maxMarkingDefinition } = args;
  const { search, orderBy, orderMode, filters, filterMode } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode };
  const filtersOpts = stixDomainObjectOptions.StixDomainObjectsFilter;
  const ordersOpts = stixDomainObjectOptions.StixDomainObjectsOrdering;
  const listParams = exportTransformFilters(argsFilters, filtersOpts, ordersOpts);
  const works = await askListExport(user, format, type, listParams, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w), works);
};
export const stixDomainObjectExportAsk = async (user, args) => {
  const { format, stixDomainObjectId = null, exportType = null, maxMarkingDefinition = null } = args;
  const entity = stixDomainObjectId ? await loadById(stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT) : null;
  const works = await askEntityExport(user, format, entity, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w), works);
};
export const stixDomainObjectsExportPush = async (user, type, file, listFilters) => {
  await upload(user, `export/${type}`, file, { list_filters: listFilters });
  return true;
};
export const stixDomainObjectExportPush = async (user, entityId, file) => {
  const entity = await internalLoadById(entityId);
  await upload(user, `export/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
  return true;
};
// endregion

// region mutation
export const stixDomainObjectImportPush = async (user, entityId, file) => {
  const entity = await internalLoadById(entityId);
  return upload(user, `import/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
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
  return deleteElementById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
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
  if (input.key === 'report_types') {
    await Promise.all(
      input.value.map(async (reportType) => {
        const currentAttribute = await findAttribute('report_types', reportType);
        if (!currentAttribute) {
          await addAttribute(user, { key: 'report_types', value: reportType });
        }
        return true;
      })
    );
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
