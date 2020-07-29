import { assoc, dissoc, map, pipe } from 'ramda';
import {
  createRelation,
  deleteRelationById,
  escapeString,
  findWithConnectedRelations,
  internalLoadEntityById,
  listEntities,
  loadEntityById,
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
  return listEntities(entityTypes, ['name', 'aliases'], finalArgs);
};

export const findById = async (stixCoreObjectId) => loadEntityById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);

export const createdBy = (stixCoreObjectId) => {
  return loadWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_IDENTITY}, has internal_id $to_id;
    $rel(${RELATION_CREATED_BY}_from:$from, ${RELATION_CREATED_BY}_to: $to) isa ${RELATION_CREATED_BY}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $from has internal_id "${escapeString(stixCoreObjectId)}"; 
    get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => (data ? data.node : null));
};

export const reports = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_CONTAINER_REPORT}, has internal_id $from_id;
    $rel(${RELATION_OBJECT}_from:$from ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $to has internal_id "${escapeString(stixCoreObjectId)}";
    get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const notes = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_CONTAINER_NOTE}, has internal_id $from_id; 
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $to has internal_id "${escapeString(stixCoreObjectId)}";
    get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const opinions = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_CONTAINER_OPINION}, has internal_id $from_id;
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $to has internal_id "${escapeString(stixCoreObjectId)}";
    get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const labels = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_LABEL}, has internal_id $to_id; 
    $rel(${RELATION_OBJECT_LABEL}_from:$from, ${RELATION_OBJECT_LABEL}_to:$to) isa ${RELATION_OBJECT_LABEL}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $from has internal_id "${escapeString(stixCoreObjectId)}";
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const markingDefinitions = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_MARKING_DEFINITION}, has internal_id $to_id;
    $rel(${RELATION_OBJECT_MARKING}_from:$from, ${RELATION_OBJECT_MARKING}_to:$to) isa ${RELATION_OBJECT_MARKING}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $from has internal_id "${escapeString(stixCoreObjectId)}"; 
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const killChainPhases = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_KILL_CHAIN_PHASE}, has internal_id $to_id;
    $rel(${RELATION_KILL_CHAIN_PHASE}_from:$from, ${RELATION_KILL_CHAIN_PHASE}_to:$to) isa ${RELATION_KILL_CHAIN_PHASE}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $from has internal_id "${escapeString(stixDomainObjectId)}";
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const externalReferences = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_EXTERNAL_REFERENCE}, has internal_id $to_id;
    $rel(${RELATION_EXTERNAL_REFERENCE}_from:$from, ${RELATION_EXTERNAL_REFERENCE}_to:$to) isa ${RELATION_EXTERNAL_REFERENCE}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
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
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixDomainObject, user);
};
