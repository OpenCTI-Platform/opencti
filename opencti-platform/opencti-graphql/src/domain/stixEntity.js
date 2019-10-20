import { assoc } from 'ramda';
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
