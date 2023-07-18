import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { RELATION_OBJECT } from '../schema/stixRefRelationship';
import { paginateAllThings, listThings, listAllThings } from '../database/middleware';
import {
  internalFindByIds,
  listEntities,
  storeLoadById
} from '../database/middleware-loader';
import {
  ABSTRACT_BASIC_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP,
  buildRefRelationKey,
  ENTITY_TYPE_CONTAINER,
  ID_INFERRED,
  ID_INTERNAL
} from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { buildPagination, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { now } from '../utils/format';
import { elCount } from '../database/engine';

const MANUAL_OBJECT = 'manual';
const INFERRED_OBJECT = 'inferred';

export const findById = async (context, user, containerId) => {
  return storeLoadById(context, user, containerId, ENTITY_TYPE_CONTAINER);
};

export const findAll = async (context, user, args) => {
  const hasTypesArgs = args.types && args.types.length > 0;
  const types = hasTypesArgs ? args.types.filter((type) => isStixDomainObjectContainer(type)) : [ENTITY_TYPE_CONTAINER];
  return listEntities(context, user, types, args);
};

export const numberOfContainersForObject = (context, user, args) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...R.dissoc('endDate', args), filters, types: [ENTITY_TYPE_CONTAINER] },
    ),
  };
};

export const objects = async (context, user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT, '*');
  const types = args.types ? args.types : ['Stix-Core-Object', 'stix-relationship'];
  const filters = [{ key, values: [containerId], operator: 'wildcard' }, ...(args.filters || [])];
  const data = args.all ? await paginateAllThings(context, user, types, R.assoc('filters', filters, args))
    : await listThings(context, user, types, R.assoc('filters', filters, args));
  // Container objects can be manual and/or inferred
  // This type must be specified to inform the UI what's need to be done.
  for (let index = 0; index < data.edges.length; index += 1) {
    const edge = data.edges[index];
    const relIdObjects = edge.node[buildRefRelationKey(RELATION_OBJECT, ID_INTERNAL)] ?? [];
    const relInferredObjects = edge.node[buildRefRelationKey(RELATION_OBJECT, ID_INFERRED)] ?? [];
    const refTypes = [];
    if (relIdObjects.includes(containerId)) {
      refTypes.push(MANUAL_OBJECT);
    }
    if (relInferredObjects.includes(containerId)) {
      refTypes.push(INFERRED_OBJECT);
    }
    edge.types = refTypes;
  }
  return data;
};

export const relatedContainers = async (context, user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT);
  const types = args.viaTypes ? args.viaTypes : ['Stix-Core-Object', 'stix-core-relationship'];
  const filters = [{ key, values: [containerId] }];
  const elements = await listAllThings(context, user, types, { filters });
  if (elements.length === 0) {
    return buildPagination(0, null, [], 0);
  }
  const elementsIds = elements.map((element) => element.id).slice(0, 800);
  const queryFilters = [...(args.filters || []), { key: buildRefRelationKey(RELATION_OBJECT), values: elementsIds }];
  const queryArgs = { ...args, filters: queryFilters };
  return findAll(context, user, queryArgs);
};

export const containersObjectsOfObject = async (context, user, { id, types, filters = [], search = null }) => {
  const queryFilters = [...filters, { key: buildRefRelationKey(RELATION_OBJECT), values: [id] }];
  const containers = await findAll(context, user, { types: [ENTITY_TYPE_CONTAINER], first: 1000, search, filters: queryFilters, connectionFormat: false });
  const objectIds = R.uniq(containers.map((n) => n[buildRefRelationKey(RELATION_OBJECT)]).flat());
  const resolvedObjectsMap = await internalFindByIds(context, user, objectIds, { type: types, toMap: true });
  const resolvedObjects = Object.values(resolvedObjectsMap);
  resolvedObjects.push(
    ...containers,
    ...(containers.map((c) => c[buildRefRelationKey(RELATION_OBJECT)].filter((toId) => resolvedObjectsMap[toId]).map((toId) => (
      {
        id: uuidv4(),
        created_at: now(),
        updated_at: now(),
        parent_types: [ABSTRACT_BASIC_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP],
        entity_type: RELATION_OBJECT,
        relationship_type: RELATION_OBJECT,
        from: {
          id: c.id,
          entity_type: c.entity_type,
          parent_types: c.parent_types,
          relationship_type: c.parent_types.includes(ABSTRACT_BASIC_RELATIONSHIP) ? c.entity_type : null
        },
        to: {
          id: toId,
          entity_type: resolvedObjectsMap[toId].entity_type,
          parent_types: resolvedObjectsMap[toId].parent_types,
          relationship_type: resolvedObjectsMap[toId].parent_types.includes(ABSTRACT_BASIC_RELATIONSHIP) ? resolvedObjectsMap[toId].entity_type : null
        }
      }
    ))).flat())
  );
  return buildPagination(0, null, resolvedObjects.map((r) => ({ node: r })), resolvedObjects.length);
};
