import { assoc, isEmpty, map } from 'ramda';
import uuid from 'uuid/v4';
import { createRelation, escapeString, loadWithConnectedRelations, paginate } from '../database/grakn';
import { findAll as relationFindAll, search as relationSearch } from './stixRelation';
import {
  elFindRelationAndTarget,
  elLoadById,
  elLoadByStixId,
  elLoadRelationAndTarget
} from '../database/elasticSearch';

// region elastic fetch
export const findById = (id, isStixId) => {
  return isStixId ? elLoadByStixId(id) : elLoadById(id);
};
export const tags = async (stixEntityId, args) => {
  const test = await elFindRelationAndTarget(stixEntityId, 'tagged');
  // test = await findTags(stixEntityId, args);
  return test;
};
export const createdByRef = async stixEntityId => {
  const test = await elLoadRelationAndTarget(stixEntityId, 'created_by_ref');
  // test = await loadCreatedByRef(stixEntityId);
  return test;
};
export const markingDefinitions = async (stixEntityId, args) => {
  // eslint-disable-next-line prettier/prettier
  const test = await elFindRelationAndTarget(stixEntityId, 'object_marking_refs');
  // test = await findMarkingDefinitions(stixEntityId, args);
  return test;
};
// endregion

// region grakn fetch
export const findMarkingDefinitions = (stixEntityId, args) => {
  return paginate(
    `match $to isa Marking-Definition; $rel(marking:$to, so:$from) isa object_marking_refs;
    $from has internal_id_key "${escapeString(stixEntityId)}"`,
    args,
    false,
    null,
    false,
    false
  );
};
export const findTags = (stixEntityId, args) => {
  return paginate(
    `match $to isa Tag; $rel(tagging:$to, so:$from) isa tagged;
    $from has internal_id_key "${escapeString(stixEntityId)}"`,
    args,
    false,
    null,
    false,
    false
  );
};
export const loadCreatedByRef = stixEntityId => {
  return loadWithConnectedRelations(
    `match $to isa Identity; $rel(creator:$to, so:$from) isa created_by_ref;
   $from has internal_id_key "${escapeString(stixEntityId)}";
   get; offset 0; limit 1;`,
    'to',
    'rel'
  );
};
export const reports = (stixEntityId, args) => {
  return paginate(
    `match $r isa Report; 
    $rel(knowledge_aggregation:$r, so:$x) isa object_refs; 
    $x has internal_id_key "${escapeString(stixEntityId)}"`,
    args
  );
};
// endregion

// TODO REMOVE THIS
export const linkCreatedByRef = async (wTx, fromId, createdByRefId) => {
  if (createdByRefId) {
    await wTx.tx.query(
      `match $from id ${fromId};
      $to has internal_id_key "${escapeString(createdByRefId)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id_key "${uuid()}";`
    );
  }
};
export const linkMarkingDef = async (wTx, fromId, markingDefs) => {
  if (markingDefs) {
    const create = markingDefinition => {
      return wTx.tx.query(
        `match $from id ${fromId}; 
        $to has internal_id_key "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id_key "${uuid()}";`
      );
    };
    await Promise.all(map(create, markingDefs));
  }
};
export const linkKillChains = async (wTx, fromId, killChains) => {
  if (killChains) {
    const createKillChainPhase = killChainPhase =>
      wTx.tx.query(
        `match $from id ${fromId}; 
        $to has internal_id_key "${escapeString(killChainPhase)}";
        insert (phase_belonging: $from, kill_chain_phase: $to) isa kill_chain_phases, has internal_id_key "${uuid()}";`
      );
    await Promise.all(map(createKillChainPhase, killChains));
  }
};

// region mutations
export const addOwner = async (fromInternalId, ownerId) => {
  if (!ownerId) return undefined;
  const input = { fromRole: 'to', toId: ownerId, toRole: 'owner', through: 'owned_by' };
  const created = await createRelation(fromInternalId, input);
  return created.relation;
};
export const addCreatedByRef = async (fromInternalId, createdByRefId) => {
  if (!createdByRefId) return undefined;
  const input = { fromRole: 'so', toId: createdByRefId, toRole: 'creator', through: 'created_by_ref' };
  const created = await createRelation(fromInternalId, input);
  return created.relation;
};
export const addMarkingDef = async (fromInternalId, markingDefId) => {
  if (!markingDefId) return undefined;
  const input = { fromRole: 'so', toId: markingDefId, toRole: 'marking', through: 'object_marking_refs' };
  const created = await createRelation(fromInternalId, input);
  return created.relation;
};
export const addMarkingDefs = async (internalId, markingDefIds) => {
  if (isEmpty(markingDefIds)) return undefined;
  const markings = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < markingDefIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const marking = await addMarkingDef(internalId, markingDefIds[i]);
    markings.push(marking);
  }
  return markings;
};
export const addKillChain = async (fromInternalId, killChainId) => {
  if (!killChainId) return undefined;
  const input = {
    fromRole: 'phase_belonging',
    toId: killChainId,
    toRole: 'kill_chain_phase',
    through: 'kill_chain_phases'
  };
  const created = await createRelation(fromInternalId, input);
  return created.relation;
};
export const addKillChains = async (internalId, killChainIds) => {
  if (isEmpty(killChainIds)) return undefined;
  const killChains = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < killChainIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const killChain = await addKillChain(internalId, killChainIds[i]);
    killChains.push(killChain);
  }
  return killChains;
};
// endregion

export const stixRelations = (stixEntityId, args) => {
  const finalArgs = assoc('fromId', stixEntityId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};
