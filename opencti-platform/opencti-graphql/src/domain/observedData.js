import { assoc, dissoc, pipe } from 'ramda';
import { createEntity, distributionEntities, listEntities, loadById, timeSeriesEntities } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT, REL_INDEX_PREFIX } from '../schema/general';
import { elCount } from '../database/elasticSearch';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';

export const findById = (observedDataId) => {
  return loadById(observedDataId, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
};

export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_OBSERVED_DATA], args);
};

// All entities
export const observedDataContainsStixObjectOrStixRelationship = async (observedDataId, thingId) => {
  const args = {
    filters: [
      { key: 'internal_id', values: [observedDataId] },
      { key: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`, values: [thingId] },
    ],
  };
  const observedDataFound = await findAll(args);
  return observedDataFound.edges.length > 0;
};

// region series
export const observedDatasTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, [], args);
};

export const observedDatasNumber = (args) => ({
  count: elCount(INDEX_STIX_DOMAIN_OBJECTS, assoc('types', [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], args)),
  total: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(assoc('types', [ENTITY_TYPE_CONTAINER_OBSERVED_DATA]), dissoc('endDate')(args))
  ),
});

export const observedDatasTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, filters, args);
};

export const observedDatasTimeSeriesByAuthor = async (args) => {
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
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, filters, args);
};

export const observedDatasNumberByEntity = (args) => ({
  count: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(
      assoc('isMetaRelationship', true),
      assoc('types', [ENTITY_TYPE_CONTAINER_OBSERVED_DATA]),
      assoc('relationshipType', RELATION_OBJECT),
      assoc('fromId', args.objectId)
    )(args)
  ),
  total: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(
      assoc('isMetaRelationship', true),
      assoc('types', [ENTITY_TYPE_CONTAINER_OBSERVED_DATA]),
      assoc('relationshipType', RELATION_OBJECT),
      assoc('fromId', args.objectId),
      dissoc('endDate')
    )(args)
  ),
});

export const observedDatasDistributionByEntity = async (args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, filters, args);
};
// endregion

// region mutations
export const addObservedData = async (user, observedData) => {
  const created = await createEntity(user, observedData, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
