/* eslint-disable camelcase */
import * as R from 'ramda';
import { elIndex, elPaginate } from '../database/elasticSearch';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_OBJECTS, READ_STIX_INDICES } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_TAXII_COLLECTION } from '../schema/internalObject';
import { deleteElementById, listEntities, loadById, stixLoadById, updateAttribute } from '../database/middleware';
import { buildStixData } from '../database/stix';
import { FunctionalError, ResourceNotFoundError } from '../config/errors';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { GlobalFilters } from '../utils/filtering';

const STIX_MEDIA_TYPE = 'application/stix+json;version=2.1';

// Taxii graphQL handlers
export const createTaxiiCollection = async (user, input) => {
  const collectionId = generateInternalId();
  const data = {
    id: collectionId,
    internal_id: collectionId,
    standard_id: generateStandardId(ENTITY_TYPE_TAXII_COLLECTION, input),
    entity_type: ENTITY_TYPE_TAXII_COLLECTION,
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, data);
  return data;
};
export const findById = async (user, collectionId) => {
  return loadById(user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
};
export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_TAXII_COLLECTION], args);
};

export const taxiiCollectionEditField = async (user, collectionId, input) => {
  const collection = await updateAttribute(user, collectionId, ENTITY_TYPE_TAXII_COLLECTION, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_TAXII_COLLECTION].EDIT_TOPIC, collection, user);
};
export const taxiiCollectionDelete = async (user, collectionId) => {
  await deleteElementById(user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
  return collectionId;
};
export const taxiiCollectionCleanContext = async (user, collectionId) => {
  await delEditContext(user, collectionId);
  return loadById(user, collectionId, ENTITY_TYPE_TAXII_COLLECTION).then((collectionToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_TAXII_COLLECTION].EDIT_TOPIC, collectionToReturn, user)
  );
};
export const taxiiCollectionEditContext = async (user, collectionId, input) => {
  await setEditContext(user, collectionId, input);
  return loadById(user, collectionId, ENTITY_TYPE_TAXII_COLLECTION).then((collectionToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_TAXII_COLLECTION].EDIT_TOPIC, collectionToReturn, user)
  );
};

// Taxii rest API
const prepareStixElement = async (user, data) => {
  const element = await stixLoadById(user, data.internal_id);
  return buildStixData(element, { diffMode: false });
};
const prepareManifestElement = async (data) => {
  return {
    id: data.standard_id,
    date_added: data.created_at,
    version: data.updated_at,
    media_type: STIX_MEDIA_TYPE,
  };
};
export const collectionCount = async (taxiiCollection, user) => {
  const { filters } = taxiiCollection;
  const data = await elPaginate(user, READ_INDEX_INTERNAL_OBJECTS, {
    first: 1, // We only need to fetch 1 to get the global count
    types: [ENTITY_TYPE_TAXII_COLLECTION],
    filters,
  });
  return data.pageInfo.globalCount;
};
const collectionQuery = async (user, collectionId, args) => {
  const { added_after, limit, next, match = {} } = args;
  const { id, spec_version, type, version } = match;
  if (spec_version || version) {
    throw FunctionalError('Unsupported parameters provided', { spec_version, version });
  }
  const collection = await loadById(user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
  if (!collection) {
    throw ResourceNotFoundError({ id: collectionId });
  }
  const queryFilters = [];
  const filters = collection.filters ? JSON.parse(collection.filters) : undefined;
  const types = [];
  if (filters) {
    const filterEntries = Object.entries(filters);
    for (let index = 0; index < filterEntries.length; index += 1) {
      const [key, val] = filterEntries[index];
      if (key === 'entity_type') {
        types.push(...val.map((v) => v.id));
      } else {
        queryFilters.push({ key: GlobalFilters[key] || key, values: val.map((v) => v.id) });
      }
    }
  }
  if (added_after) {
    queryFilters.push({ key: 'updated_at', values: [added_after], operator: 'gte' });
  }
  let maxSize = 100;
  if (limit) {
    const paramLimit = parseInt(limit, 10);
    maxSize = paramLimit > 100 ? 100 : paramLimit;
  }
  const options = {
    types,
    first: maxSize,
    orderMode: 'asc',
    orderBy: 'updated_at',
    after: next,
    filters: queryFilters,
  };
  if (type) options.types = type.split(',');
  if (id) options.ids = id.split(',');
  return elPaginate(user, READ_STIX_INDICES, options);
};
export const restCollectionStix = async (user, id, args) => {
  const { edges, pageInfo } = await collectionQuery(user, id, args);
  const objects = await Promise.all(edges.map((e) => prepareStixElement(user, e.node)));
  return {
    more: pageInfo.hasNextPage,
    next: R.last(edges)?.cursor || '',
    objects,
  };
};
export const restCollectionManifest = async (user, id, args) => {
  const { edges, pageInfo } = await collectionQuery(user, id, args);
  const objects = await Promise.all(edges.map((e) => prepareManifestElement(e.node)));
  return {
    more: pageInfo.hasNextPage,
    next: R.last(edges)?.cursor || '',
    objects,
  };
};
const restBuildCollection = async (collection) => {
  return {
    id: collection.id,
    title: collection.name,
    description: collection.description,
    can_read: true,
    can_write: false,
    media_types: [STIX_MEDIA_TYPE],
  };
};
export const restLoadCollectionById = async (user, collectionId) => {
  const collection = await loadById(user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
  if (!collection) {
    throw ResourceNotFoundError({ id: collectionId });
  }
  return restBuildCollection(collection);
};
export const restAllCollections = async (user) => {
  const collections = await elPaginate(user, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_TAXII_COLLECTION],
    connectionFormat: false,
  });
  return Promise.all(collections.map(async (c) => restBuildCollection(c)));
};
