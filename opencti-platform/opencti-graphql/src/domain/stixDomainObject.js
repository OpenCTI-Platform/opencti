import * as R from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  batchListThroughGetTo,
  createEntity,
  deleteElementById,
  distributionEntities,
  listThroughGetTo,
  timeSeriesEntities,
  updateAttribute,
} from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { elCount, elFindByIds } from '../database/engine';
import { workToExportFile } from './work';
import { FunctionalError, UnsupportedError } from '../config/errors';
import {
  isEmptyField,
  isNotEmptyField,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_STIX_DOMAIN_OBJECTS
} from '../database/utils';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INDICATOR,
  isStixDomainObject,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
} from '../schema/stixDomainObject';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey, } from '../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, } from '../schema/stixRefRelationship';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';
import { now, utcDate } from '../utils/format';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../modules/grouping/grouping-types';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { stixDomainObjectOptions } from '../schema/stixDomainObjectOptions';
import {
  stixObjectOrRelationshipAddRefRelation,
  stixObjectOrRelationshipDeleteRefRelation
} from './stixObjectOrStixRelationship';

export const findAll = async (context, user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = R.filter((type) => isStixDomainObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_DOMAIN_OBJECT);
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

export const findById = async (context, user, stixDomainObjectId) => storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);

export const batchStixDomainObjects = async (context, user, objectsIds) => {
  const objectsToFinds = R.uniq(objectsIds.filter((u) => isNotEmptyField(u)));
  const objects = await elFindByIds(context, user, objectsToFinds, { toMap: true });
  return objectsIds.map((id) => objects[id]);
};

export const batchAssignees = (context, user, stixDomainObjectIds) => {
  return batchListThroughGetTo(context, user, stixDomainObjectIds, RELATION_OBJECT_ASSIGNEE, ENTITY_TYPE_USER);
};

// region time series
export const stixDomainObjectsTimeSeries = (context, user, args) => {
  const { types = [ABSTRACT_STIX_DOMAIN_OBJECT] } = args;
  return timeSeriesEntities(context, user, types, args);
};

export const stixDomainObjectsTimeSeriesByAuthor = (context, user, args) => {
  const { authorId, types = [ABSTRACT_STIX_DOMAIN_OBJECT] } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_CREATED_BY, '*')], values: [authorId] }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, types, { ...args, filters });
};

export const stixDomainObjectsNumber = (context, user, args) => ({
  count: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_INDEX_STIX_DOMAIN_OBJECTS, args),
  total: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_INDEX_STIX_DOMAIN_OBJECTS, R.dissoc('endDate', args)),
});

export const stixDomainObjectsDistributionByEntity = async (context, user, args) => {
  const { relationship_type, objectId, types = [ABSTRACT_STIX_DOMAIN_OBJECT] } = args;
  const filters = [{ key: [relationship_type.map((n) => buildRefRelationKey(n, '*'))], values: [objectId] }, ...(args.filters || [])];
  return distributionEntities(context, user, types, { ...args, filters });
};
// endregion

// region export
export const stixDomainObjectsExportAsk = async (context, user, args) => {
  const { format, type, exportType, maxMarkingDefinition, selectedIds } = args;
  const { search, orderBy, orderMode, filters, filterMode, relationship_type, elementId } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode, relationship_type, elementId };
  const filtersOpts = stixDomainObjectOptions.StixDomainObjectsFilter;
  const ordersOpts = stixDomainObjectOptions.StixDomainObjectsOrdering;
  let newArgsFiltersFilters = argsFilters.filters;
  const initialParams = {};
  if (argsFilters.filters && argsFilters.filters.length > 0) {
    if (argsFilters.filters.filter((n) => n.key.includes('elementId')).length > 0) {
      initialParams.elementId = R.head(R.head(argsFilters.filters.filter((n) => n.key.includes('elementId'))).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('elementId'));
    }
    if (argsFilters.filters.filter((n) => n.key.includes('fromId')).length > 0) {
      initialParams.fromId = R.head(R.head(argsFilters.filters.filter((n) => n.key.includes('fromId'))).values);
      newArgsFiltersFilters = newArgsFiltersFilters.filter((n) => !n.key.includes('fromId'));
    }
  }
  const finalArgsFilter = {
    ...argsFilters,
    filters: newArgsFiltersFilters
  };
  const listParams = { ...initialParams, ...exportTransformFilters(finalArgsFilter, filtersOpts, ordersOpts) };
  const works = await askListExport(context, user, format, type, selectedIds, listParams, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w));
};
export const stixDomainObjectExportAsk = async (context, user, stixDomainObjectId, args) => {
  const { format, exportType = null, maxMarkingDefinition = null } = args;
  const entity = await storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  const works = await askEntityExport(context, user, format, entity, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w));
};
// endregion

// region mutation
export const addStixDomainObject = async (context, user, stixDomainObject) => {
  const innerType = stixDomainObject.type;
  if (!isStixDomainObject(innerType)) {
    throw UnsupportedError('This method can only create Stix domain');
  }
  const data = stixDomainObject;
  if (isStixDomainObjectIdentity(innerType)) {
    data.identity_class = innerType === ENTITY_TYPE_IDENTITY_SECTOR ? 'class' : innerType.toLowerCase();
  }
  if (isStixDomainObjectLocation(innerType)) {
    data.x_opencti_location_type = innerType;
  }
  if (innerType === ENTITY_TYPE_CONTAINER_REPORT) {
    data.published = utcDate();
  }
  if (innerType === ENTITY_TYPE_CONTAINER_GROUPING) {
    if (isEmptyField(stixDomainObject.context)) {
      throw UnsupportedError('You need to specify a context to create an grouping');
    }
  }
  if (innerType === ENTITY_TYPE_INDICATOR) {
    if (isEmptyField(stixDomainObject.pattern) || isEmptyField(stixDomainObject.pattern_type)) {
      throw UnsupportedError('You need to specify a pattern/pattern_type to create an indicator');
    }
  }
  if (innerType === ENTITY_TYPE_CONTAINER_NOTE) {
    data.created = data.created || now();
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

// region relation ref
export const stixDomainObjectAddRelation = async (context, user, stixDomainObjectId, input) => {
  return stixObjectOrRelationshipAddRefRelation(context, user, stixDomainObjectId, input, ABSTRACT_STIX_DOMAIN_OBJECT);
};
export const stixDomainObjectDeleteRelation = async (context, user, stixDomainObjectId, toId, relationshipType) => {
  return stixObjectOrRelationshipDeleteRefRelation(context, user, stixDomainObjectId, toId, relationshipType, ABSTRACT_STIX_DOMAIN_OBJECT);
};
// endregion

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
    R.omit(schemaRelationsRefDefinition.getInputNames(stixDomainObject.entity_type)),
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
