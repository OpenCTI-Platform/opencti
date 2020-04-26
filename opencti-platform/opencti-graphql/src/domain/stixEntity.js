import { assoc, dissoc, isNil, pipe } from 'ramda';
import {
  createRelation,
  deleteRelationById,
  escapeString,
  findWithConnectedRelations,
  internalLoadEntityById,
  internalLoadEntityByStixId,
  loadWithConnectedRelations,
} from '../database/grakn';
import { findAll as relationFindAll } from './stixRelation';
import { buildPagination } from '../database/utils';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';

export const findById = async (stixEntityId) => {
  let data;
  if (stixEntityId.match(/[a-z-]+--[\w-]{36}/g)) {
    data = await internalLoadEntityByStixId(stixEntityId);
  } else {
    data = await internalLoadEntityById(stixEntityId);
  }
  if (!data) {
    return data;
  }
  if (
    !data.parent_types.includes('Stix-Domain-Entity') &&
    !data.parent_types.includes('Stix-Observable') &&
    !data.parent_types.includes('stix_relation')
  ) {
    throw new ForbiddenAccess();
  }
  data = pipe(dissoc('user_email'), dissoc('password'))(data);
  return data;
};

export const createdByRef = (stixEntityId) => {
  return loadWithConnectedRelations(
    `match $to isa Identity; $rel(creator:$to, so:$from) isa created_by_ref;
   $from has internal_id_key "${escapeString(stixEntityId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  );
};
export const reports = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Report; $rel(knowledge_aggregation:$to, so:$from) isa object_refs;
   $from has internal_id_key "${escapeString(stixEntityId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const notes = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Note; $rel(knowledge_aggregation:$to, so:$from) isa object_refs;
   $from has internal_id_key "${escapeString(stixEntityId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const opinions = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Opinion; $rel(knowledge_aggregation:$to, so:$from) isa object_refs;
   $from has internal_id_key "${escapeString(stixEntityId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const tags = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Tag; $rel(tagging:$to, so:$from) isa tagged;
   $from has internal_id_key "${escapeString(stixEntityId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const markingDefinitions = (stixEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Marking-Definition; $rel(marking:$to, so:$from) isa object_marking_refs;
   $from has internal_id_key "${escapeString(stixEntityId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const killChainPhases = (stixDomainEntityId) => {
  return findWithConnectedRelations(
    `match $to isa Kill-Chain-Phase; $rel(kill_chain_phase:$to, phase_belonging:$from) isa kill_chain_phases;
    $from has internal_id_key "${escapeString(stixDomainEntityId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const externalReferences = (stixDomainEntityId) => {
  return findWithConnectedRelations(
    `match $to isa External-Reference; $rel(external_reference:$to, so:$from) isa external_references;
    $from has internal_id_key "${escapeString(stixDomainEntityId)}"; get;`,
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
  if (
    (data.entity_type === 'user' &&
      !isNil(data.external) &&
      !['tagged', 'created_by_ref', 'object_marking_refs'].includes(input.through)) ||
    (!data.parent_types.includes('Stix-Domain-Entity') &&
      !data.parent_types.includes('Stix-Observable') &&
      !data.parent_types.includes('stix_relation')) ||
    !input.through
  ) {
    throw new ForbiddenAccess();
  }
  return createRelation(user, stixEntityId, input);
};

export const stixEntityDeleteRelation = async (user, stixEntityId, relationId) => {
  const stixDomainEntity = await internalLoadEntityById(stixEntityId);
  const parentTypes = stixDomainEntity.parent_types;
  // Check if entity is a real stix domain
  if (!parentTypes.includes('Stix-Domain-Entity') && !parentTypes.includes('stix_relation')) {
    throw new ForbiddenAccess();
  }
  const data = await internalLoadEntityById(relationId);
  if (
    (data.entity_type !== 'stix_relation' && data.entity_type !== 'relation_embedded') ||
    (stixDomainEntity.entity_type === 'user' &&
      !isNil(stixDomainEntity.external) &&
      !['tagged', 'created_by_ref', 'object_marking_refs'].includes(data.relationship_type))
  ) {
    throw new ForbiddenAccess();
  }
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  return notify(BUS_TOPICS.StixEntity.EDIT_TOPIC, stixDomainEntity, user);
};