/* eslint-disable camelcase */
import * as R from 'ramda';
import { Promise } from 'bluebird';
import { elIndex, elPaginate } from '../database/engine';
import {
  INDEX_INTERNAL_OBJECTS,
  READ_INDEX_INTERNAL_OBJECTS,
  READ_STIX_INDICES
} from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_TAXII_COLLECTION } from '../schema/internalObject';
import { deleteElementById, updateAttribute, stixLoadByIds } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { FunctionalError, ResourceNotFoundError } from '../config/errors';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { convertFiltersToQueryOptions } from '../utils/filtering';

const STIX_MEDIA_TYPE = 'application/stix+json;version=2.1';

// Taxii graphQL handlers
export const createTaxiiCollection = async (context, user, input) => {
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
export const findById = async (context, user, collectionId) => {
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
};
export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_TAXII_COLLECTION], args);
};
export const taxiiCollectionEditField = async (context, user, collectionId, input) => {
  const { element } = await updateAttribute(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_TAXII_COLLECTION].EDIT_TOPIC, element, user);
};
export const taxiiCollectionDelete = async (context, user, collectionId) => {
  await deleteElementById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
  return collectionId;
};
export const taxiiCollectionCleanContext = async (context, user, collectionId) => {
  await delEditContext(user, collectionId);
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION).then((collectionToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_TAXII_COLLECTION].EDIT_TOPIC, collectionToReturn, user);
  });
};
export const taxiiCollectionEditContext = async (context, user, collectionId, input) => {
  await setEditContext(user, collectionId, input);
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION).then((collectionToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_TAXII_COLLECTION].EDIT_TOPIC, collectionToReturn, user);
  });
};

// Taxii rest API
const prepareManifestElement = async (data) => {
  return {
    id: data.standard_id,
    date_added: data.created_at,
    version: data.updated_at,
    media_type: STIX_MEDIA_TYPE,
  };
};
export const collectionCount = async (context, taxiiCollection, user) => {
  const { filters } = taxiiCollection;
  const data = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
    first: 1, // We only need to fetch 1 to get the global count
    types: [ENTITY_TYPE_TAXII_COLLECTION],
    filters,
  });
  return data.pageInfo.globalCount;
};

const collectionQuery = async (context, user, collectionId, args) => {
  const { added_after, limit, next, match = {} } = args;
  const { id, spec_version, type, version } = match;
  if (spec_version || version) {
    throw FunctionalError('Unsupported parameters provided', { spec_version, version });
  }
  const collection = await storeLoadById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
  if (!collection) {
    throw ResourceNotFoundError({ id: collectionId });
  }
  const filters = collection.filters ? JSON.parse(collection.filters) : undefined;
  const options = await convertFiltersToQueryOptions(context, filters, { after: added_after });
  options.after = next;
  let maxSize = 100;
  if (limit) {
    const paramLimit = parseInt(limit, 10);
    maxSize = paramLimit > 100 ? 100 : paramLimit;
  }
  options.first = maxSize;
  if (type) options.types = type.split(',');
  if (id) options.ids = id.split(',');
  return elPaginate(context, user, READ_STIX_INDICES, options);
};
export const restCollectionStix = async (context, user, id, args) => {
  const { edges, pageInfo } = await collectionQuery(context, user, id, args);
  const edgeIds = edges.map((e) => e.node.internal_id);
  const instances = await stixLoadByIds(context, user, edgeIds);
  return {
    more: pageInfo.hasNextPage,
    next: R.last(edges)?.cursor || '',
    objects: instances,
  };
};
export const restCollectionManifest = async (context, user, id, args) => {
  const { edges, pageInfo } = await collectionQuery(context, user, id, args);
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
export const restLoadCollectionById = async (context, user, collectionId) => {
  const collection = await storeLoadById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
  if (!collection) {
    throw ResourceNotFoundError({ id: collectionId });
  }
  return restBuildCollection(collection);
};
export const restAllCollections = async (context, user) => {
  const collections = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_TAXII_COLLECTION],
    connectionFormat: false,
  });
  return Promise.all(collections.map(async (c) => restBuildCollection(c)));
};
