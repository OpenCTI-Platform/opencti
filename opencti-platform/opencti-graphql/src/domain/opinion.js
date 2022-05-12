import { assoc, dissoc, pipe } from 'ramda';
import * as R from 'ramda';
import {
  createEntity,
  distributionEntities,
  internalLoadById,
  storeLoadById,
  timeSeriesEntities,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_OPINION } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';
import { addIndividual, findAll as findIndividuals } from './individual';

export const findById = (user, opinionId) => {
  return storeLoadById(user, opinionId, ENTITY_TYPE_CONTAINER_OPINION);
};
export const findAll = async (user, args) => {
  return listEntities(user, [ENTITY_TYPE_CONTAINER_OPINION], args);
};
export const findMyOpinion = async (user, entityId) => {
  // Resolve the individual
  const individualsArgs = {
    filters: [{ key: 'contact_information', values: [user.user_email] }],
    connectionFormat: false,
  };
  const individuals = await findIndividuals(user, individualsArgs);
  if (individuals.length === 0) {
    return null;
  }
  const keyObject = buildRefRelationKey(RELATION_OBJECT);
  const keyCreatedBy = buildRefRelationKey(RELATION_CREATED_BY);
  const opinionsArgs = {
    filters: [
      { key: keyObject, values: [entityId] },
      { key: keyCreatedBy, values: [R.head(individuals).id] },
    ],
    connectionFormat: false,
  };
  const opinions = await findAll(user, opinionsArgs);
  return opinions.length > 0 ? R.head(opinions) : null;
};

// Entities tab

export const opinionContainsStixObjectOrStixRelationship = async (user, opinionId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(user, thingId)).id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [opinionId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const opinionFound = await findAll(user, args);
  return opinionFound.edges.length > 0;
};

// region series
export const opinionsTimeSeries = (user, args) => {
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_OPINION, [], args);
};

export const opinionsNumber = (user, args) => ({
  count: elCount(user, READ_INDEX_STIX_DOMAIN_OBJECTS, assoc('types', [ENTITY_TYPE_CONTAINER_OPINION], args)),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    pipe(assoc('types', [ENTITY_TYPE_CONTAINER_OPINION]), dissoc('endDate'))(args)
  ),
});

export const opinionsTimeSeriesByEntity = (user, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};

export const opinionsTimeSeriesByAuthor = async (user, args) => {
  const { authorId } = args;
  const filters = [
    {
      isRelation: true,
      from: `${RELATION_CREATED_BY}_from`,
      to: `${RELATION_CREATED_BY}_to`,
      type: RELATION_CREATED_BY,
      value: authorId,
    },
  ];
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};

export const opinionsNumberByEntity = (user, args) => ({
  count: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    pipe(
      assoc('isMetaRelationship', true),
      assoc('types', [ENTITY_TYPE_CONTAINER_OPINION]),
      assoc('relationshipType', RELATION_OBJECT),
      assoc('fromId', args.objectId)
    )(args)
  ),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    pipe(
      assoc('isMetaRelationship', true),
      assoc('types', [ENTITY_TYPE_CONTAINER_OPINION]),
      assoc('relationshipType', RELATION_OBJECT),
      assoc('fromId', args.objectId),
      dissoc('endDate')
    )(args)
  ),
});

export const opinionsDistributionByEntity = async (user, args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(user, ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};
// endregion

// region mutations
export const addOpinion = async (user, opinion) => {
  const opinionToCreate = opinion;
  // For note, auto assign current user as author
  if (!opinion.createdBy) {
    const args = { filters: [{ key: 'contact_information', values: [user.user_email] }], connectionFormat: false };
    const individuals = await findIndividuals(user, args);
    if (individuals.length > 0) {
      opinionToCreate.createdBy = R.head(individuals).id;
    } else {
      const individual = await addIndividual(user, { name: user.name, contact_information: user.user_email });
      opinionToCreate.createdBy = individual.id;
    }
  }
  const created = await createEntity(user, opinionToCreate, ENTITY_TYPE_CONTAINER_OPINION);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
