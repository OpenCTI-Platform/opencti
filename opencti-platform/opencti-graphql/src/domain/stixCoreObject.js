import { assoc, dissoc, pipe } from 'ramda';
import {
  createRelation,
  deleteRelationById,
  escapeString,
  findWithConnectedRelations,
  internalLoadEntityById,
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
} from '../utils/idGenerator';

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
    $from has internal_id "${escapeString(stixCoreObjectId)}"; get; offset 0; limit 1;`,
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
    `match $to isa Opinion; 
    $rel(knowledge_aggregation:$to, so:$from) isa ${RELATION_OBJECT};
    $from has internal_id "${escapeString(stixCoreObjectId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const labels = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_LABEL}; $rel(tagging:$to, so:$from) isa ${RELATION_OBJECT_LABEL};
   $from has internal_id "${escapeString(stixCoreObjectId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const markingDefinitions = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa Marking-Definition; $rel(marking:$to, so:$from) isa ${RELATION_OBJECT_MARKING};
   $from has internal_id "${escapeString(stixCoreObjectId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const killChainPhases = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa Kill-Chain-Phase; $rel(kill_chain_phase:$to, phase_belonging:$from) isa ${RELATION_KILL_CHAIN_PHASE};
    $from has internal_id "${escapeString(stixDomainObjectId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const externalReferences = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa External-Reference; $rel(external_reference:$to, so:$from) isa ${RELATION_EXTERNAL_REFERENCE};
    $from has internal_id "${escapeString(stixDomainObjectId)}"; get;`,
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
