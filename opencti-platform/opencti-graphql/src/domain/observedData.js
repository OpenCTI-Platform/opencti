import { assoc, append, propOr, pipe } from 'ramda';
import {
  createEntity,
  distributionEntities,
  distributionEntitiesThroughRelations,
  escapeString,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  prepareDate,
  timeSeriesEntities,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { notify } from '../database/redis';
import { findAll as findAllStixDomainEntities } from './stixDomainObject';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (observedDataId) => {
  return loadEntityById(observedDataId, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
};

export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_OBSERVED_DATA], ['standard_id'], args);
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
  count: getSingleValueNumber(
    `match $x isa ObservedData; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } get; count;`
  ),
  total: getSingleValueNumber(`match $x isa ${ENTITY_TYPE_CONTAINER_OBSERVED_DATA}; get; count;`),
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
  count: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_OBSERVED_DATA};
    $rel(${RELATION_OBJECT}_from:$x, ${RELATION_OBJECT}_to:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}" ${
      args.endDate ? `; $x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    }
    get;
    count;`
  ),
  total: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_OBSERVED_DATA};
    $rel(${RELATION_OBJECT}_from:$x, ${RELATION_OBJECT}_to:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}";
    get;
    count;`
  ),
});

export const observedDatasDistributionByEntity = async (args) => {
  const { objectId, field } = args;
  if (field.includes('.')) {
    const options = pipe(
      assoc('relationshipType', RELATION_OBJECT),
      assoc('toType', ENTITY_TYPE_CONTAINER_OBSERVED_DATA),
      assoc('field', field.split('.')[1]),
      assoc('remoteRelationshipType', field.split('.')[0]),
      assoc('fromId', objectId)
    )(args);
    return distributionEntitiesThroughRelations(options);
  }
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
