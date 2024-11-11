import * as R from 'ramda';
import { assoc, dissoc, pipe } from 'ramda';
import { createEntity, distributionEntities, listAllThings, patchAttribute, timeSeriesEntities } from '../database/middleware';
import { internalLoadById, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_OPINION } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixRefRelationship';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { elCount, ES_MAX_PAGINATION } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';
import { now } from '../utils/format';
import { addFilter } from '../utils/filtering/filtering-utils';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';

export const findById = (context, user, opinionId) => {
  return storeLoadById(context, user, opinionId, ENTITY_TYPE_CONTAINER_OPINION);
};
export const findAll = async (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_CONTAINER_OPINION], args);
};
export const findMyOpinion = async (context, user, entityId) => {
  const keyObject = buildRefRelationKey(RELATION_OBJECT);
  const opinionsArgs = {
    filters: {
      mode: 'and',
      filters: [
        { key: keyObject, values: [entityId] },
        { key: 'creator_id', values: [user.id] },
      ],
      filterGroups: [],
    },
    connectionFormat: false,
  };
  const opinions = await findAll(context, user, opinionsArgs);
  return opinions.length > 0 ? R.head(opinions) : null;
};

// Entities tab

export const opinionContainsStixObjectOrStixRelationship = async (context, user, opinionId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).id : thingId;
  const args = {
    filters: {
      mode: 'and',
      filters: [
        { key: 'internal_id', values: [opinionId] },
        { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
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
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_OPINION], { ...args, filters });
};

export const opinionsTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_OPINION], { ...args, filters });
};

export const opinionsNumberByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
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
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
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

// region utils
export const updateOpinionsMetrics = async (context, user, opinionId) => {
  const filtersForVocabs = {
    mode: 'and',
    filters: [{ key: 'category', values: ['opinion_ov'] }],
    filterGroups: [],
  };
  const vocabs = await listAllThings(context, user, [ENTITY_TYPE_VOCABULARY], { filters: filtersForVocabs, maxSize: ES_MAX_PAGINATION });
  const indexedVocab = R.indexBy(R.prop('name'), vocabs);
  const filtersForObjects = {
    mode: 'and',
    filters: [{ key: buildRefRelationKey(RELATION_OBJECT), values: [opinionId] }],
    filterGroups: [],
  };
  const elements = await listAllThings(
    context,
    user,
    [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP],
    { filters: filtersForObjects, maxSize: ES_MAX_PAGINATION, baseData: true }
  );
  for (let i = 0; i < elements.length; i += 1) {
    const filtersForOpinions = {
      mode: 'and',
      filters: [{ key: buildRefRelationKey(RELATION_OBJECT), values: [elements[i].id] }],
      filterGroups: [],
    };
    const opinions = await listAllThings(context, user, [ENTITY_TYPE_CONTAINER_OPINION], { filters: filtersForOpinions, maxSize: ES_MAX_PAGINATION });
    const opinionsWithVocabs = opinions.map((n) => ({ ...n, vocab: indexedVocab[n.opinion] }));
    const opinionsNumbers = opinionsWithVocabs.map((n) => n.vocab.order);
    const opinionsMetrics = {
      mean: parseFloat(R.mean(opinionsNumbers).toFixed(2)),
      max: Math.max(...opinionsNumbers),
      min: Math.min(...opinionsNumbers),
      total: opinionsNumbers.length,
    };
    const patch = { opinions_metrics: opinionsMetrics };
    console.log(elements[i]);
    await patchAttribute(context, user, elements[i].id, elements[i].entity_type, patch);
  }
};
// endregion
