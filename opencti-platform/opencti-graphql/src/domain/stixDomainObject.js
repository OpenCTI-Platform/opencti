import * as R from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  deleteElementById,
  distributionEntities,
  storeLoadByIdWithRefs,
  timeSeriesEntities,
  updateAttribute,
  updateAttributeFromLoadedWithRefs,
  validateCreatedBy
} from '../database/middleware';
import { listAllToEntitiesThroughRelations, listEntities, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { elCount, elFindByIds } from '../database/engine';
import { workToExportFile } from './work';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { isEmptyField, isNotEmptyField, READ_INDEX_INFERRED_ENTITIES, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_SECTOR,
  isStixDomainObject,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  isStixDomainObjectThreatActor
} from '../schema/stixDomainObject';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, } from '../schema/stixRefRelationship';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';
import { now, utcDate } from '../utils/format';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../modules/grouping/grouping-types';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { stixDomainObjectOptions } from '../schema/stixDomainObjectOptions';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from './stixObjectOrStixRelationship';
import { entityLocationType, identityClass, xOpenctiType } from '../schema/attribute-definition';
import { usersSessionRefresh } from './user';
import { addFilter } from '../utils/filtering/filtering-utils';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';

export const findAll = async (context, user, args) => {
  let types = [];
  if (isNotEmptyField(args.types)) {
    types = R.filter((type) => isStixDomainObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_DOMAIN_OBJECT);
  }
  return listEntities(context, user, types, args);
};

export const findById = async (context, user, stixDomainObjectId) => storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);

export const batchStixDomainObjects = async (context, user, objectsIds) => {
  const objectsToFinds = R.uniq(objectsIds.filter((u) => isNotEmptyField(u)));
  const objects = await elFindByIds(context, user, objectsToFinds, { toMap: true });
  return objectsIds.map((id) => objects[id]);
};

export const assigneesPaginated = async (context, user, stixDomainObjectId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixDomainObjectId, RELATION_OBJECT_ASSIGNEE, ENTITY_TYPE_USER, false, args);
};

// region time series
export const stixDomainObjectsTimeSeries = (context, user, args) => {
  let types = [];
  if (isNotEmptyField(args.types)) {
    types = R.filter((type) => isStixDomainObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_DOMAIN_OBJECT);
  }
  return timeSeriesEntities(context, user, types, args);
};

export const stixDomainObjectsTimeSeriesByAuthor = (context, user, args) => {
  const { authorId, types = [ABSTRACT_STIX_DOMAIN_OBJECT] } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return timeSeriesEntities(context, user, types, { ...args, filters });
};

export const stixDomainObjectsNumber = (context, user, args) => ({
  count: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_INDEX_STIX_DOMAIN_OBJECTS, args),
  total: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_INDEX_STIX_DOMAIN_OBJECTS, R.dissoc('endDate', args)),
});

export const stixDomainObjectsDistributionByEntity = async (context, user, args) => {
  const { relationship_type, objectId, types = [ABSTRACT_STIX_DOMAIN_OBJECT] } = args;
  const filters = addFilter(args.filters, relationship_type.map((n) => buildRefRelationKey(n, '*')), objectId);
  return distributionEntities(context, user, types, { ...args, filters });
};

export const stixDomainObjectAvatar = (stixDomainObject) => {
  const files = stixDomainObject.x_opencti_files ?? [];
  return files.sort((a, b) => (a.order || 0) - (b.order || 0)).find((n) => n.mime_type.includes('image/') && !!n.inCarousel);
};
// endregion

// region export
export const stixDomainObjectsExportAsk = async (context, user, args) => {
  const { exportContext, format, exportType, contentMaxMarkings, selectedIds, fileMarkings } = args;
  const { search, orderBy, orderMode, filters } = args;
  const filteringArgs = { search, orderBy, orderMode, filters };
  const ordersOpts = stixDomainObjectOptions.StixDomainObjectsOrdering;
  const listParams = await exportTransformFilters(context, user, filteringArgs, ordersOpts);
  const works = await askListExport(context, user, exportContext, format, selectedIds, listParams, exportType, contentMaxMarkings, fileMarkings);
  return works.map((w) => workToExportFile(w));
};
export const stixDomainObjectExportAsk = async (context, user, stixDomainObjectId, input) => {
  const { format, exportType, contentMaxMarkings, fileMarkings } = input;
  const entity = await storeLoadById(context, user, stixDomainObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  const works = await askEntityExport(context, user, format, entity, exportType, contentMaxMarkings, fileMarkings);
  return works.map((w) => workToExportFile(w));
};

// endregion

export const handleInnerType = (data, innerType) => {
  if (isStixDomainObjectIdentity(innerType)) {
    return {
      ...data,
      [identityClass.name]: innerType === ENTITY_TYPE_IDENTITY_SECTOR ? 'class' : innerType.toLowerCase()
    };
  }
  if (isStixDomainObjectLocation(innerType)) {
    return {
      ...data,
      [entityLocationType.name]: innerType
    };
  }
  if (isStixDomainObjectThreatActor(innerType)) {
    return {
      ...data,
      [xOpenctiType.name]: innerType
    };
  }
  return data;
};

// region mutation
export const addStixDomainObject = async (context, user, stixDomainObject) => {
  const innerType = stixDomainObject.type;
  if (!isStixDomainObject(innerType)) {
    throw UnsupportedError('This method can only create Stix domain');
  }
  let data = stixDomainObject;
  data = handleInnerType(data, innerType);

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
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, stixDomainObject, user);
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
export const stixDomainObjectAddRelation = async (context, user, stixDomainObjectId, input, opts = {}) => {
  return stixObjectOrRelationshipAddRefRelation(context, user, stixDomainObjectId, input, ABSTRACT_STIX_DOMAIN_OBJECT, opts);
};
export const stixDomainObjectDeleteRelation = async (context, user, stixDomainObjectId, toId, relationshipType, opts = {}) => {
  return stixObjectOrRelationshipDeleteRefRelation(context, user, stixDomainObjectId, toId, relationshipType, ABSTRACT_STIX_DOMAIN_OBJECT, opts);
};
// endregion

export const stixDomainObjectEditField = async (context, user, stixObjectId, input, opts = {}) => {
  const stixDomainObject = await storeLoadById(context, user, stixObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixDomainObject) {
    throw FunctionalError('Cannot edit the field, Stix-Domain-Object cannot be found.');
  }

  const createdByKey = input.find((inputData) => inputData.key === 'createdBy');
  if (createdByKey && createdByKey.value?.length > 0) {
    await validateCreatedBy(context, user, createdByKey.value[0]);
  }

  const { element: updatedElem } = await updateAttribute(context, user, stixObjectId, ABSTRACT_STIX_DOMAIN_OBJECT, input, opts);
  // If indicator is score patched, we also patch the score of all observables attached to the indicator
  if (stixDomainObject.entity_type === ENTITY_TYPE_INDICATOR && input.key === 'x_opencti_score') {
    const observables = await listAllToEntitiesThroughRelations(context, user, stixObjectId, RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE);
    await Promise.all(
      observables.map((observable) => updateAttribute(context, user, observable.id, ABSTRACT_STIX_CYBER_OBSERVABLE, input, opts))
    );
  }
  // Check is a real update was done
  const updateWithoutMeta = R.pipe(R.omit(schemaRelationsRefDefinition.getInputNames(stixDomainObject.entity_type)),)(updatedElem);
  const isUpdated = !R.equals(stixDomainObject, updateWithoutMeta);
  if (isUpdated) {
    // Refresh user sessions for organization authorities
    if (isNotEmptyField(updatedElem.authorized_authorities)) {
      const grantedGroupsInput = input.find((i) => i.key === 'grantable_groups');
      if (grantedGroupsInput) {
        await usersSessionRefresh(updatedElem.authorized_authorities);
      }
    }
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
  }
  return updatedElem;
};

export const stixDomainObjectFileEdit = async (context, user, sdoId, { id, order, description, inCarousel }) => {
  const stixDomainObject = await storeLoadByIdWithRefs(context, user, sdoId);
  const files = stixDomainObject.x_opencti_files.map((file) => {
    if (file.id === id) {
      return { ...file, order, description, inCarousel };
    }
    return file;
  });

  const { element: updatedElement } = await updateAttributeFromLoadedWithRefs(context, user, stixDomainObject, { key: 'x_opencti_files', value: files });
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElement, user);
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
