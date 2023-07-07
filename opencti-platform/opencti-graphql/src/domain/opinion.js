import { assoc, dissoc, pipe } from 'ramda';
import * as R from 'ramda';
import {
  createEntity,
  distributionEntities,
  timeSeriesEntities,
} from '../database/middleware';
import { internalLoadById, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_OPINION } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixRefRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';
import { now } from '../utils/format';

export const findById = (context, user, opinionId) => {
  return storeLoadById(context, user, opinionId, ENTITY_TYPE_CONTAINER_OPINION);
};
export const findAll = async (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_CONTAINER_OPINION], args);
};
export const findMyOpinion = async (context, user, entityId) => {
  const keyObject = buildRefRelationKey(RELATION_OBJECT);
  const opinionsArgs = {
    filters: [
      { key: keyObject, values: [entityId] },
      { key: 'creator_id', values: [user.id] },
    ],
    connectionFormat: false,
  };
  const opinions = await findAll(context, user, opinionsArgs);
  return opinions.length > 0 ? R.head(opinions) : null;
};

// Entities tab

export const opinionContainsStixObjectOrStixRelationship = async (context, user, opinionId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [opinionId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const opinionFound = await findAll(context, user, args);
  return opinionFound.edges.length > 0;
};

// region series
export const opinionsTimeSeries = (context, user, args) => {
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_OPINION], args);
};

export const opinionsNumber = (context, user, args) => ({
  count: elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, assoc('types', [ENTITY_TYPE_CONTAINER_OPINION], args)),
  total: elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    pipe(assoc('types', [ENTITY_TYPE_CONTAINER_OPINION]), dissoc('endDate'))(args)
  ),
});

export const opinionsTimeSeriesByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_OPINION], { ...args, filters });
};

export const opinionsTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_CREATED_BY, '*')], values: [authorId] }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_OPINION], { ...args, filters });
};

export const opinionsNumberByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER_OPINION] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER_OPINION] },
    ),
  };
};

export const opinionsDistributionByEntity = async (context, user, args) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_OPINION], { ...args, filters });
};
// endregion

// region mutations
export const addOpinion = async (context, user, opinion) => {
  const opinionToCreate = opinion.created ? opinion : { ...opinion, created: now() };
  const created = await createEntity(context, user, opinionToCreate, ENTITY_TYPE_CONTAINER_OPINION);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
