import { assoc, dissoc, pipe } from 'ramda';
import { createEntity, distributionEntities, listEntities, loadById, timeSeriesEntities } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_OPINION } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT, REL_INDEX_PREFIX } from '../schema/general';
import { elCount } from '../database/elasticSearch';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';

export const findById = (opinionId) => {
  return loadById(opinionId, ENTITY_TYPE_CONTAINER_OPINION);
};
export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_OPINION], args);
};

// Entities tab

export const opinionContainsStixObjectOrStixRelationship = async (opinionId, thingId) => {
  const args = {
    filters: [
      { key: 'internal_id', values: [opinionId] },
      { key: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`, values: [thingId] },
    ],
  };
  const opinionFound = await findAll(args);
  return opinionFound.edges.length > 0;
};

// region series
export const opinionsTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OPINION, [], args);
};

export const opinionsNumber = (args) => ({
  count: elCount(INDEX_STIX_DOMAIN_OBJECTS, assoc('types', [ENTITY_TYPE_CONTAINER_OPINION], args)),
  total: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(assoc('types', [ENTITY_TYPE_CONTAINER_OPINION]), dissoc('endDate'))(args)
  ),
});

export const opinionsTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};

export const opinionsTimeSeriesByAuthor = async (args) => {
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
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};

export const opinionsNumberByEntity = (args) => ({
  count: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(
      assoc('isMetaRelationship', true),
      assoc('types', [ENTITY_TYPE_CONTAINER_OPINION]),
      assoc('relationshipType', RELATION_OBJECT),
      assoc('fromId', args.objectId)
    )(args)
  ),
  total: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(
      assoc('isMetaRelationship', true),
      assoc('types', [ENTITY_TYPE_CONTAINER_OPINION]),
      assoc('relationshipType', RELATION_OBJECT),
      assoc('fromId', args.objectId),
      dissoc('endDate')
    )(args)
  ),
});

export const opinionsDistributionByEntity = async (args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};
// endregion

// region mutations
export const addOpinion = async (user, opinion) => {
  const created = await createEntity(user, opinion, ENTITY_TYPE_CONTAINER_OPINION);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
