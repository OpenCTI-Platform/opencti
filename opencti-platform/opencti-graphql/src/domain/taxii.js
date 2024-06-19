/* eslint-disable camelcase */
import * as R from 'ramda';
import { Promise } from 'bluebird';
import { elIndex, elPaginate } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_OBJECTS, READ_STIX_INDICES, READ_STIX_DATA_WITH_INFERRED } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_TAXII_COLLECTION } from '../schema/internalObject';
import { deleteElementById, stixLoadByIds, updateAttribute } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { ForbiddenAccess, FunctionalError } from '../config/errors';
import { delEditContext, notify, setEditContext } from '../database/redis';
import conf, { BUS_TOPICS } from '../config/conf';
import { addFilter } from '../utils/filtering/filtering-utils';
import { convertFiltersToQueryOptions } from '../utils/filtering/filtering-resolution';
import { publishUserAction } from '../listener/UserActionListener';
import { MEMBER_ACCESS_RIGHT_VIEW, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../utils/access';

const MAX_TAXII_PAGINATION = conf.get('app:data_sharing:taxii:max_pagination_result') || 500;
const STIX_MEDIA_TYPE = 'application/stix+json;version=2.1';

// Taxii graphQL handlers
export const createTaxiiCollection = async (context, user, input) => {
  const collectionId = generateInternalId();
  const data = {
    id: collectionId,
    internal_id: collectionId,
    standard_id: generateStandardId(ENTITY_TYPE_TAXII_COLLECTION, input),
    entity_type: ENTITY_TYPE_TAXII_COLLECTION,
    authorized_authorities: [TAXIIAPI_SETCOLLECTIONS],
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, data);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates Taxii collection \`${input.name}\``,
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_TAXII_COLLECTION, input }
  });
  return data;
};
export const findById = async (context, user, collectionId) => {
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
};
export const findAll = (context, user, args) => {
  if (user) {
    const options = { ...args, includeAuthorities: true };
    return listEntities(context, user, [ENTITY_TYPE_TAXII_COLLECTION], options);
  }
  // No user specify, listing only public taxii collections
  const filters = addFilter(args?.filters, 'taxii_public', 'true');
  const publicArgs = { ...(args ?? {}), filters };
  return listEntities(context, SYSTEM_USER, [ENTITY_TYPE_TAXII_COLLECTION], publicArgs);
};
export const taxiiCollectionEditField = async (context, user, collectionId, input) => {
  const finalInput = input.map(({ key, value }) => {
    const item = { key, value };
    if (key === 'authorized_members') {
      item.value = value.map((id) => ({ id, access_right: MEMBER_ACCESS_RIGHT_VIEW }));
    }
    return item;
  });

  const { element } = await updateAttribute(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION, finalInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for Taxii collection \`${element.name}\``,
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_TAXII_COLLECTION, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_TAXII_COLLECTION].EDIT_TOPIC, element, user);
};
export const taxiiCollectionDelete = async (context, user, collectionId) => {
  const deleted = await deleteElementById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes Taxii collection \`${deleted.name}\``,
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_TAXII_COLLECTION, input: deleted }
  });
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
    date_added: data.updated_at,
    version: data.updated_at,
    media_type: STIX_MEDIA_TYPE,
  };
};

export const collectionQuery = async (context, user, collection, args) => {
  const { added_after, limit, next, match = {} } = args;
  const { id, spec_version, type, version } = match;
  if (spec_version && spec_version !== '2.1') {
    throw FunctionalError('Invalid spec_version provided, only \'2.1\' supported', { spec_version });
  }
  if (version && version !== 'last') {
    throw FunctionalError('Invalid version provided, only \'last\' supported', { version });
  }
  const filters = collection.filters ? JSON.parse(collection.filters) : undefined;
  const options = await convertFiltersToQueryOptions(filters, { after: added_after });
  options.after = next;
  let maxSize = MAX_TAXII_PAGINATION;
  if (limit) {
    const paramLimit = parseInt(limit, 10);
    maxSize = paramLimit > MAX_TAXII_PAGINATION ? MAX_TAXII_PAGINATION : paramLimit;
  }
  options.first = maxSize;
  if (type) options.types = type.split(',');
  if (id) options.ids = id.split(',');
  const currentIndex = collection.include_inferences ? READ_STIX_DATA_WITH_INFERRED : READ_STIX_INDICES;
  return elPaginate(context, user, currentIndex, options);
};
export const restCollectionStix = async (context, user, collection, args) => {
  const { edges, pageInfo } = await collectionQuery(context, user, collection, args);
  const edgeIds = edges.map((e) => e.node.internal_id);
  const instances = await stixLoadByIds(context, user, edgeIds);
  return {
    more: pageInfo.hasNextPage,
    next: R.last(edges)?.cursor || '',
    objects: instances,
  };
};
export const restCollectionManifest = async (context, user, collection, args) => {
  const { edges, pageInfo } = await collectionQuery(context, user, collection, args);
  const objects = await Promise.all(edges.map((e) => prepareManifestElement(e.node)));
  return {
    more: pageInfo.hasNextPage,
    next: R.last(edges)?.cursor || '',
    objects,
  };
};
export const restBuildCollection = (collection) => {
  return {
    id: collection.id,
    title: collection.name,
    description: collection.description,
    can_read: true,
    can_write: false,
    media_types: [STIX_MEDIA_TYPE],
  };
};
export const getCollectionById = async (context, user, collectionId) => {
  const collection = await storeLoadById(context, user, collectionId, ENTITY_TYPE_TAXII_COLLECTION);
  if (!collection) {
    throw ForbiddenAccess();
  }
  return collection;
};
export const restAllCollections = async (context, user) => {
  const collections = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_TAXII_COLLECTION],
    connectionFormat: false,
  });
  return collections.map((c) => restBuildCollection(c));
};
