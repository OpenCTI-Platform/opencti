import * as R from 'ramda';
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
import { elCount, elFindByIds } from '../database/engine';
import { upload } from '../database/file-storage';
import { workToExportFile } from './work';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { isEmptyField, READ_INDEX_INFERRED_ENTITIES, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import {
  ENTITY_TYPE_CONTAINER_REPORT,
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
  STIX_META_RELATIONSHIPS_INPUTS,
} from '../schema/general';
import { isStixMetaRelationship, RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';
import { STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS } from '../schema/stixCyberObservableRelationship';

export const findAll = async (context, user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = R.filter((type) => isStixDomainObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_DOMAIN_OBJECT);
  }
  return listEntities(context, user, types, args);
};

export const findById = async (context, user, stixDomainObjectId) => storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);

export const batchStixDomainObjects = async (context, user, objectsIds) => {
  const objects = await elFindByIds(context, user, objectsIds, { toMap: true });
  return objectsIds.map((id) => objects[id]);
};

// region time series
export const reportsTimeSeries = (context, user, stixDomainObjectId, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: stixDomainObjectId }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], { ...args, filters });
};

export const stixDomainObjectsTimeSeries = (context, user, args) => {
  const { types = [ABSTRACT_STIX_DOMAIN_OBJECT] } = args;
  return timeSeriesEntities(context, user, types, args);
};

export const stixDomainObjectsTimeSeriesByAuthor = (context, user, args) => {
  const { authorId, types = [ABSTRACT_STIX_DOMAIN_OBJECT] } = args;
  const filters = [{ isRelation: true, type: RELATION_CREATED_BY, value: authorId }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, types, { ...args, filters });
};

export const stixDomainObjectsNumber = (context, user, args) => ({
  count: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_INDEX_STIX_DOMAIN_OBJECTS, args),
  total: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_INDEX_STIX_DOMAIN_OBJECTS, R.dissoc('endDate', args)),
});

export const stixDomainObjectsDistributionByEntity = async (context, user, args) => {
  const { objectId, relationship_type: relationshipType } = args;
  const filters = [{ isRelation: true, type: relationshipType, value: objectId }, ...(args.filters || [])];
  return distributionEntities(context, user, [ABSTRACT_STIX_DOMAIN_OBJECT], { ...args, filters });
};
// endregion

// region export
export const stixDomainObjectsExportAsk = async (context, user, args) => {
  const { format, type, exportType, maxMarkingDefinition } = args;
  const { search, orderBy, orderMode, filters, filterMode } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode };
  const filtersOpts = stixDomainObjectOptions.StixDomainObjectsFilter;
  const ordersOpts = stixDomainObjectOptions.StixDomainObjectsOrdering;
  const listParams = exportTransformFilters(argsFilters, filtersOpts, ordersOpts);
  const works = await askListExport(context, user, format, type, listParams, exportType, maxMarkingDefinition);
  return R.map((w) => workToExportFile(w), works);
};
export const stixDomainObjectExportAsk = async (context, user, args) => {
  const { format, stixDomainObjectId = null, exportType = null, maxMarkingDefinition = null } = args;
  const entity = stixDomainObjectId ? await storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT) : null;
  const works = await askEntityExport(context, user, format, entity, exportType, maxMarkingDefinition);
  return R.map((w) => workToExportFile(w), works);
};
export const stixDomainObjectsExportPush = async (context, user, type, file, listFilters) => {
  await upload(context, user, `export/${type}`, file, { list_filters: listFilters });
  return true;
};
export const stixDomainObjectExportPush = async (context, user, entityId, file) => {
  const entity = await internalLoadById(context, user, entityId);
  await upload(context, user, `export/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
  return true;
};
// endregion

// region mutation
export const addStixDomainObject = async (context, user, stixDomainObject) => {
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
  const created = await createEntity(context, user, R.dissoc('type', data), innerType);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const stixDomainObjectDelete = async (context, user, stixDomainObjectId) => {
  const stixDomainObject = await storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot delete the object, Stix-Domain-Object cannot be found.');
  }
  await deleteElementById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, stixDomainObject, user);
  return stixDomainObjectId;
};

export const stixDomainObjectsDelete = async (context, user, stixDomainObjectsIds) => {
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixDomainObjectsIds.length; i += 1) {
    await stixDomainObjectDelete(user, stixDomainObjectsIds[i]);
  }
  return stixDomainObjectsIds;
};

export const stixDomainObjectAddRelation = async (context, user, stixDomainObjectId, input) => {
  const stixDomainObject = await storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot add the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.assoc('fromId', stixDomainObjectId, input);
  return createRelation(context, user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixDomainObjectAddRelations = async (context, user, stixDomainObjectId, input) => {
  const stixDomainObject = await storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot add the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.map(
    (n) => ({ fromId: stixDomainObjectId, toId: n, relationship_type: input.relationship_type }),
    input.toIds
  );
  await createRelations(context, user, finalInput);
  const entity = await storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, entity, user);
};

export const stixDomainObjectDeleteRelation = async (context, user, stixDomainObjectId, toId, relationshipType) => {
  const stixDomainObject = await storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot delete the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(context, user, stixDomainObjectId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, stixDomainObject, user);
};

export const stixDomainObjectEditField = async (context, user, stixObjectId, input, opts = {}) => {
  const stixDomainObject = await storeLoadById(context, user, stixObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot edit the field, Stix-Domain-Object cannot be found.');
  }
  const { element: updatedElem } = await updateAttribute(context, user, stixObjectId, ABSTRACT_STIX_DOMAIN_OBJECT, input, opts);
  if (stixDomainObject.entity_type === ENTITY_TYPE_INDICATOR && input.key === 'x_opencti_score') {
    const observables = await listThroughGetTo(context, user, [stixObjectId], RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE);
    await Promise.all(
      observables.map((observable) => updateAttribute(context, user, observable.id, ABSTRACT_STIX_CYBER_OBSERVABLE, input, opts))
    );
  }
  // Check is a real update was done
  const updateWithoutMeta = R.pipe(
    R.omit(STIX_META_RELATIONSHIPS_INPUTS),
    R.omit(STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS),
  )(updatedElem);
  const isUpdated = !R.equals(stixDomainObject, updateWithoutMeta);
  if (isUpdated) {
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
  }
  return updatedElem;
};

// region context
export const stixDomainObjectCleanContext = async (context, user, stixDomainObjectId) => {
  await delEditContext(user, stixDomainObjectId);
  return storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT).then((stixDomainObject) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].CONTEXT_TOPIC, stixDomainObject, user);
  });
};

export const stixDomainObjectEditContext = async (context, user, stixDomainObjectId, input) => {
  await setEditContext(user, stixDomainObjectId, input);
  return storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT).then((stixDomainObject) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].CONTEXT_TOPIC, stixDomainObject, user);
  });
};
// endregion
