import { assoc } from 'ramda';
import { escapeString, loadEntityById, loadEntityByStixId, loadWithConnectedRelations, paginate } from '../database/grakn';
import { findAll as relationFindAll, search as relationSearch } from './stixRelation';
import { elFindRelationAndTarget, elLoadRelationAndTarget } from '../database/elasticSearch';

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

// region elastic fetch
export const findById = (id, isStixId) => {
  return isStixId ? loadEntityByStixId(id) : loadEntityById(id);
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

export const stixRelations = (stixEntityId, args) => {
  const finalArgs = assoc('fromId', stixEntityId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};
