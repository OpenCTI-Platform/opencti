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
  internalLoadById,
  listThroughGetTo,
  storeLoadById,
  timeSeriesEntities,
  updateAttribute,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { elCount } from '../database/engine';
import { upload } from '../database/file-storage';
import { workToExportFile } from './work';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { isEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import {
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INDICATOR,
  isStixDomainObject,
  isStixDomainObjectContainer,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  stixDomainObjectOptions,
} from '../schema/stixDomainObject';
import {
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_META_RELATIONSHIP,
} from '../schema/general';
import { isStixMetaRelationship, RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { escape } from '../utils/format';
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';

export const findAll = async (user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixDomainObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_DOMAIN_OBJECT);
  }
  return listEntities(user, types, args);
};

export const findById = async (user, stixDomainObjectId) => storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);

// region time series
export const reportsTimeSeries = (user, stixDomainObjectId, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: stixDomainObjectId }];
  return timeSeriesEntities(user, 'Report', filters, args);
};

export const stixDomainObjectsTimeSeries = (user, args) => {
  return timeSeriesEntities(user, args.type ? escape(args.type) : ABSTRACT_STIX_DOMAIN_OBJECT, [], args);
};

export const stixDomainObjectsTimeSeriesByAuthor = (user, args) => {
  const { authorId } = args;
  const filters = [{ isRelation: true, type: RELATION_CREATED_BY, value: authorId }];
  return timeSeriesEntities(user, args.type ? escape(args.type) : ABSTRACT_STIX_DOMAIN_OBJECT, filters, args);
};

export const stixDomainObjectsNumber = (user, args) => ({
  count: elCount(user, READ_INDEX_STIX_DOMAIN_OBJECTS, args),
  total: elCount(user, READ_INDEX_STIX_DOMAIN_OBJECTS, dissoc('endDate', args)),
});

export const stixDomainObjectsDistributionByEntity = async (user, args) => {
  const { objectId, relationship_type: relationshipType } = args;
  const filters = [{ isRelation: true, type: relationshipType, value: objectId }];
  return distributionEntities(user, ABSTRACT_STIX_DOMAIN_OBJECT, filters, args);
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
  const entity = stixDomainObjectId ? await storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT) : null;
  const works = await askEntityExport(user, format, entity, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w), works);
};
export const stixDomainObjectsExportPush = async (user, type, file, listFilters) => {
  await upload(user, `export/${type}`, file, { list_filters: listFilters });
  return true;
};
export const stixDomainObjectExportPush = async (user, entityId, file) => {
  const entity = await internalLoadById(user, entityId);
  await upload(user, `export/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
  return true;
};
// endregion

// region mutation
export const addStixDomainObject = async (user, stixDomainObject) => {
  const innerType = stixDomainObject.type;
  if (!isStixDomainObject(innerType)) {
    throw UnsupportedError('This method can only create Stix domain');
  }
  if (isStixDomainObjectContainer(innerType)) {
    throw UnsupportedError('This method cant create Stix domain container');
  }
  const data = stixDomainObject;
  if (isStixDomainObjectIdentity(innerType)) {
    data.identity_class = innerType === ENTITY_TYPE_IDENTITY_SECTOR ? 'class' : innerType.toLowerCase();
  }
  if (isStixDomainObjectLocation(innerType)) {
    data.x_opencti_location_type = innerType;
  }
  if (innerType === ENTITY_TYPE_INDICATOR) {
    if (isEmptyField(stixDomainObject.pattern) || isEmptyField(stixDomainObject.pattern_type)) {
      throw UnsupportedError('You need to specify a pattern/pattern_type to create an indicator');
    }
  }
  // Create the element
  const created = await createEntity(user, dissoc('type', data), innerType);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const stixDomainObjectDelete = async (user, stixDomainObjectId) => {
  const stixDomainObject = await storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot delete the object, Stix-Domain-Object cannot be found.');
  }
  return deleteElementById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
};

export const stixDomainObjectsDelete = async (user, stixDomainObjectsIds) => {
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixDomainObjectsIds.length; i += 1) {
    await stixDomainObjectDelete(user, stixDomainObjectsIds[i]);
  }
  return stixDomainObjectsIds;
};

export const stixDomainObjectAddRelation = async (user, stixDomainObjectId, input) => {
  const stixDomainObject = await storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
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
  const stixDomainObject = await storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
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
  return storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT).then((entity) => notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, entity, user));
};

export const stixDomainObjectDeleteRelation = async (user, stixDomainObjectId, toId, relationshipType) => {
  const stixDomainObject = await storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot delete the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, stixDomainObjectId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, stixDomainObject, user);
};

export const stixDomainObjectEditField = async (user, stixObjectId, input, opts = {}) => {
  const stixDomainObject = await storeLoadById(user, stixObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot edit the field, Stix-Domain-Object cannot be found.');
  }
  const { element: updatedElem } = await updateAttribute(user, stixObjectId, ABSTRACT_STIX_DOMAIN_OBJECT, input, opts);
  if (stixDomainObject.entity_type === ENTITY_TYPE_INDICATOR && input.key === 'x_opencti_score') {
    const observables = await listThroughGetTo(user, [stixObjectId], RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE);
    await Promise.all(
      observables.map((observable) => updateAttribute(user, observable.id, ABSTRACT_STIX_CYBER_OBSERVABLE, input, opts))
    );
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
};

// region context
export const stixDomainObjectCleanContext = async (user, stixDomainObjectId) => {
  await delEditContext(user, stixDomainObjectId);
  return storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT).then((stixDomainObject) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, stixDomainObject, user);
  });
};

export const stixDomainObjectEditContext = async (user, stixDomainObjectId, input) => {
  await setEditContext(user, stixDomainObjectId, input);
  return storeLoadById(user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT).then((stixDomainObject) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, stixDomainObject, user);
  });
};
// endregion
