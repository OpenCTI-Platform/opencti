import * as R from 'ramda';
import { createEntity, distributionEntities, timeSeriesEntities, } from '../database/middleware';
import { internalLoadById, listEntitiesPaginated, listRelations, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixRefRelationship';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';
import { isStixId } from '../schema/schemaUtils';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { addFilter } from '../utils/filtering/filtering-utils';

export const findById = (context, user, observedDataId) => {
  return storeLoadById(context, user, observedDataId, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
};

export const findAll = async (context, user, args) => {
  return listEntitiesPaginated(context, user, [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], args);
};

export const resolveName = async (context, user, observedData) => {
  const relationArgs = { first: 1, fromId: observedData.id, toTypes: [ABSTRACT_STIX_CORE_OBJECT], baseData: true };
  const observedDataRelations = await listRelations(context, user, RELATION_OBJECT, relationArgs);
  if (observedDataRelations.length === 1) {
    const firstElement = await internalLoadById(context, user, observedDataRelations[0].toId);
    return extractEntityRepresentativeName(firstElement);
  }
  return 'empty';
};

// All entities
export const observedDataContainsStixObjectOrStixRelationship = async (context, user, observedDataId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).id : thingId;
  const args = {
    filters: {
      mode: 'and',
      filters: [
        { key: 'internal_id', values: [observedDataId] },
        { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const observedDataFound = await findAll(context, user, args);
  return observedDataFound.edges.length > 0;
};

// region series
export const observedDatasTimeSeries = (context, user, args) => {
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], args);
};

export const observedDatasNumber = (context, user, args) => ({
  count: elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, R.assoc('types', [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], args)),
  total: elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(R.assoc('types', [ENTITY_TYPE_CONTAINER_OBSERVED_DATA]), R.dissoc('endDate')(args))
  ),
});

export const observedDatasTimeSeriesByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], { ...args, filters });
};

export const observedDatasTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], { ...args, filters });
};

export const observedDatasNumberByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA] },
    ),
  };
};

export const observedDatasDistributionByEntity = async (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], { ...args, filters });
};
// endregion

// region mutations
export const addObservedData = async (context, user, observedData) => {
  if (observedData.first_observed > observedData.last_observed) {
    throw DatabaseError('You cant create an observed data with last_observed less than first_observed', {
      input: observedData,
    });
  }
  const observedDataResult = await createEntity(context, user, observedData, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, observedDataResult, user);
};
// endregion
