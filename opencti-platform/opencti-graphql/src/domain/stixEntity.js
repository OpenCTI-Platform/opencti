import { assoc } from 'ramda';
import {
  createRelation,
  deleteRelationById,
  escapeString,
  findWithConnectedRelations,
  loadEntityById,
  loadEntityByStixId,
  loadWithConnectedRelations
} from '../database/grakn';
import { findAll as relationFindAll } from './stixRelation';
import { buildPagination } from '../database/utils';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';

export const findById = stixEntityId => {
  if (stixEntityId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(stixEntityId);
  }
  return loadEntityById(stixEntityId);
};

export const createdByRef = async stixEntityId => {
  return loadWithConnectedRelations(
    `match $to isa Identity; $rel(creator:$to, so:$from) isa created_by_ref;
   $from has internal_id_key "${escapeString(stixEntityId)}"; get; offset 0; limit 1;`,
    'to',
    'rel'
  );
};
export const reports = stixEntityId => {
  return findWithConnectedRelations(
    `match $to isa Report; $rel(knowledge_aggregation:$to, so:$from) isa object_refs;
   $from has internal_id_key "${escapeString(stixEntityId)}";
   get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
export const tags = async stixEntityId => {
  return findWithConnectedRelations(
    `match $to isa Tag; $rel(tagging:$to, so:$from) isa tagged;
   $from has internal_id_key "${escapeString(stixEntityId)}";
   get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
export const markingDefinitions = async stixEntityId => {
  return findWithConnectedRelations(
    `match $to isa Marking-Definition; $rel(marking:$to, so:$from) isa object_marking_refs;
   $from has internal_id_key "${escapeString(stixEntityId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
export const killChainPhases = async stixDomainEntityId => {
  return findWithConnectedRelations(
    `match $to isa Kill-Chain-Phase; $rel(kill_chain_phase:$to, phase_belonging:$from) isa kill_chain_phases;
    $from has internal_id_key "${escapeString(stixDomainEntityId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
export const externalReferences = async stixDomainEntityId => {
  return findWithConnectedRelations(
    `match $to isa External-Reference; $rel(external_reference:$to, so:$from) isa external_references;
    $from has internal_id_key "${escapeString(stixDomainEntityId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};

export const stixRelations = (stixEntityId, args) => {
  const finalArgs = assoc('fromId', stixEntityId, args);
  return relationFindAll(finalArgs);
};

export const stixEntityAddRelation = async (user, stixEntityId, input) => {
  return createRelation(stixEntityId, input);
};

export const stixEntityDeleteRelation = async (user, stixEntityId, relationId) => {
  await deleteRelationById(relationId);
  const data = await loadEntityById(stixEntityId);
  return notify(BUS_TOPICS.StixEntity.EDIT_TOPIC, data, user);
};
