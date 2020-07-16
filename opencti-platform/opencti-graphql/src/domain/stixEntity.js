import { assoc, dissoc, isNil, pipe } from 'ramda';
import {
  createRelation,
  deleteRelationById,
  escapeString,
  findWithConnectedRelations,
  internalLoadEntityById,
  loadWithConnectedRelations,
} from '../database/grakn';
import { findAll as relationFindAll } from './stixRelation';
import { buildPagination } from '../database/utils';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import {
  ENTITY_TYPE_USER,
  isStixCoreObject,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
  ENTITY_TYPE_LABEL,
} from '../utils/idGenerator';

export const findById = async (stixEntityId) => {
  let data = await internalLoadEntityById(stixEntityId);
  if (!data) return data;
  if (!isStixCoreObject(data.type)) throw ForbiddenAccess();
  data = pipe(dissoc('user_email'), dissoc('password'))(data);
  return data;
};

export const createdBy = (stixEntityId) => {
  return loadWithConnectedRelations(
    `match $to isa Identity; $rel(creator:$to, so:$from) isa ${RELATION_CREATED_BY};
   $from has internal_id "${escapeString(stixEntityId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  );
};
export const reports = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Report; $rel(knowledge_aggregation:$to, so:$from) isa ${RELATION_OBJECT};
   $from has internal_id "${escapeString(stixEntityId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const notes = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Note; $rel(knowledge_aggregation:$to, so:$from) isa ${RELATION_OBJECT};
   $from has internal_id "${escapeString(stixEntityId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const opinions = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Opinion; $rel(knowledge_aggregation:$to, so:$from) isa ${RELATION_OBJECT};
   $from has internal_id "${escapeString(stixEntityId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const labels = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_LABEL}; $rel(tagging:$to, so:$from) isa ${RELATION_OBJECT_LABEL};
   $from has internal_id "${escapeString(stixEntityId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const markingDefinitions = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Marking-Definition; $rel(marking:$to, so:$from) isa ${RELATION_OBJECT_MARKING};
   $from has internal_id "${escapeString(stixEntityId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const killChainPhases = (stixDomainEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Kill-Chain-Phase; $rel(kill_chain_phase:$to, phase_belonging:$from) isa ${RELATION_KILL_CHAIN_PHASE};
    $from has internal_id "${escapeString(stixDomainEntityId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const externalReferences = (stixDomainEntityId) => {
  return findWithConnectedRelations(
    `match $to isa External-Reference; $rel(external_reference:$to, so:$from) isa ${RELATION_EXTERNAL_REFERENCE};
    $from has internal_id "${escapeString(stixDomainEntityId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const stixRelations = (stixEntityId, args) => {
  const finalArgs = assoc('fromId', stixEntityId, args);
  return relationFindAll(finalArgs);
};

export const stixEntityAddRelation = async (user, stixEntityId, input) => {
  const data = await internalLoadEntityById(stixEntityId);
  const isUser = data.entity_type === 'user';
  const stixElement = isStixCoreObject(data.type);
  // TODO @JRI NEED EXPLANATION
  if (
    (isUser &&
      !isNil(data.external) &&
      ![RELATION_OBJECT_LABEL, RELATION_CREATED_BY, RELATION_OBJECT_MARKING].includes(input.through)) ||
    !stixElement ||
    !input.through
  ) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixEntityId, input);
  return createRelation(user, finalInput);
};

export const stixEntityDeleteRelation = async (user, stixEntityId, relationId) => {
  const stixDomainEntity = await internalLoadEntityById(stixEntityId);
  const entityType = stixDomainEntity.entity_type;
  // Check if entity is a real stix domain
  if (!isStixCoreObject(entityType)) {
    throw ForbiddenAccess();
  }
  const data = await internalLoadEntityById(relationId);
  // TODO JRI @SAM CHECK
  if (
    (data.entity_type !== 'stix_relation' && data.entity_type !== 'relation_embedded') ||
    (stixDomainEntity.entity_type === ENTITY_TYPE_USER &&
      !isNil(stixDomainEntity.external) &&
      ![RELATION_OBJECT_LABEL, RELATION_CREATED_BY, RELATION_OBJECT_MARKING].includes(data.entity_type))
  ) {
    throw ForbiddenAccess();
  }
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  return notify(BUS_TOPICS.StixEntity.EDIT_TOPIC, stixDomainEntity, user);
};
