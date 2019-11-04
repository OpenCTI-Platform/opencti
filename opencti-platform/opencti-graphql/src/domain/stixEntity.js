import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  escapeString,
  getById,
  getObject,
  load,
  paginate
} from '../database/grakn';
import {
  findAll as relationFindAll,
  search as relationSearch
} from './stixRelation';

const findByStixId = stixId => {
  const query = `match $x isa entity;
   { $x isa Stix-Domain; } or { $x isa Stix-Observable; } or { $x isa stix_relation; };
   $x has stix_id_key "${escapeString(stixId)}"; get;`;
  return load(query, ['x']).then(data => {
    return data && data.x;
  });
};

export const findById = (id, isStixId) => {
  return isStixId ? findByStixId(id) : getById(id);
};

export const markingDefinitions = (stixEntityId, args) => {
  return paginate(
    `match $m isa Marking-Definition; 
    $rel(marking:$m, so:$x) isa object_marking_refs; 
    $x has internal_id_key "${escapeString(stixEntityId)}"`,
    args,
    false,
    null,
    false,
    false
  );
};

export const tags = (stixEntityId, args) => {
  return paginate(
    `match $t isa Tag; 
    $rel(tagging:$t, so:$x) isa tagged; 
    $x has internal_id_key "${escapeString(stixEntityId)}"`,
    args,
    false,
    null,
    false,
    false
  );
};

export const createdByRef = stixEntityId => {
  return getObject(
    `match $i isa Identity;
    $rel(creator:$i, so:$x) isa created_by_ref; 
    $x has internal_id_key "${escapeString(stixEntityId)}"; 
    get; 
    offset 0; 
    limit 1;`,
    'i',
    'rel'
  );
};

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

export const linkTags = async (wTx, fromId, tagsList) => {
  if (tagsList) {
    const createTagLink = tag => {
      return wTx.tx.query(
        `match $from id ${fromId};
        $to has internal_id_key "${escapeString(tag)}";
        insert (so: $from, tagging: $to) isa tagged, has internal_id_key "${uuid()}";`
      );
    };
    await Promise.all(map(createTagLink, tagsList));
  }
};

export const reports = (stixEntityId, args) => {
  return paginate(
    `match $r isa Report; 
    $rel(knowledge_aggregation:$r, so:$x) isa object_refs; 
    $x has internal_id_key "${escapeString(stixEntityId)}"`,
    args
  );
};

export const stixRelations = (stixEntityId, args) => {
  const finalArgs = assoc('fromId', stixEntityId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};
