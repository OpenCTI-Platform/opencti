import { assoc, dissoc, map, pipe } from 'ramda';
import {
  createRelation,
  deleteRelationById,
  escapeString,
  findWithConnectedRelations,
  internalLoadEntityById,
  listEntities,
  loadWithConnectedRelations,
} from '../database/grakn';
import { findAll as relationFindAll } from './stixCoreRelationship';
import { buildPagination } from '../database/utils';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import {
  isStixCoreObject,
  isStixRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
  ENTITY_TYPE_LABEL,
  ABSTRACT_STIX_META_OBJECT,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_MARKING_DEFINITION,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ABSTRACT_STIX_CORE_OBJECT,
} from '../utils/idGenerator';

export const findAll = async (args) => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? [ABSTRACT_STIX_CORE_OBJECT] : args.types;
  const finalArgs = assoc('parentType', ABSTRACT_STIX_CORE_OBJECT, args);
  let data = await listEntities(entityTypes, ['name', 'aliases'], finalArgs);
  data = assoc(
    'edges',
    map(
      (n) => ({
        cursor: n.cursor,
        node: pipe(dissoc('user_email'), dissoc('password'))(n.node),
        relation: n.relation,
      }),
      data.edges
    ),
    data
  );
  return data;
};

export const findById = async (stixCoreObjectId) => {
  let data = await internalLoadEntityById(stixCoreObjectId);
  if (!data) return data;
  if (!isStixCoreObject(data.type)) throw ForbiddenAccess();
  data = pipe(dissoc('user_email'), dissoc('password'))(data);
  return data;
};

export const createdBy = (stixCoreObjectId) => {
  return loadWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_IDENTITY}; 
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to: $to) isa ${RELATION_CREATED_BY};
    $from has internal_id "${escapeString(stixCoreObjectId)}"; 
    get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  );
};

export const reports = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_CONTAINER_REPORT};
    $rel(${RELATION_OBJECT}_from:$from ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT};
    $to has internal_id "${escapeString(stixCoreObjectId)}";
    get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const notes = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_CONTAINER_NOTE}; 
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT};
    $to has internal_id "${escapeString(stixCoreObjectId)}";
    get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const opinions = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_CONTAINER_OPINION};
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT};
    $to has internal_id "${escapeString(stixCoreObjectId)}";
    get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const labels = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_LABEL}; 
    $rel(${RELATION_OBJECT_LABEL}_from:$from, ${RELATION_OBJECT_LABEL}_to:$to) isa ${RELATION_OBJECT_LABEL};
    $from has internal_id "${escapeString(stixCoreObjectId)}";
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const markingDefinitions = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_MARKING_DEFINITION};
    $rel(${RELATION_OBJECT_MARKING}_from:$from, ${RELATION_OBJECT_MARKING}_to:$to) isa ${RELATION_OBJECT_MARKING};
    $from has internal_id "${escapeString(stixCoreObjectId)}"; 
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const killChainPhases = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_KILL_CHAIN_PHASE}; 
    $rel(${RELATION_KILL_CHAIN_PHASE}_from:$from, ${RELATION_KILL_CHAIN_PHASE}_to:$to) isa ${RELATION_KILL_CHAIN_PHASE};
    $from has internal_id "${escapeString(stixDomainObjectId)}";
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const externalReferences = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_EXTERNAL_REFERENCE};
    $rel(${RELATION_EXTERNAL_REFERENCE}_from:$from, ${RELATION_EXTERNAL_REFERENCE}_to:$to) isa ${RELATION_EXTERNAL_REFERENCE};
    $from has internal_id "${escapeString(stixDomainObjectId)}";
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const stixCoreRelationships = (stixCoreObjectId, args) => {
  const finalArgs = assoc('fromId', stixCoreObjectId, args);
  return relationFindAll(finalArgs);
};

export const stixCoreObjectAddRelation = async (user, stixCoreObjectId, input) => {
  const data = await internalLoadEntityById(stixCoreObjectId);
  if (!isStixCoreObject(data.type) || !isStixRelationship(input.relationship_type)) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixCoreObjectId, input);
  return createRelation(user, finalInput);
};

export const stixCoreObjectDeleteRelation = async (user, stixCoreObjectId, relationId) => {
  const stixDomainObject = await internalLoadEntityById(stixCoreObjectId);
  // Check if entity is a real stix domain
  if (!isStixCoreObject(stixDomainObject.entity_type)) {
    throw ForbiddenAccess();
  }
  await deleteRelationById(user, relationId, ABSTRACT_STIX_META_OBJECT);
  return notify(BUS_TOPICS.stixCoreObject.EDIT_TOPIC, stixDomainObject, user);
};
