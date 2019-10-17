import { assoc } from 'ramda';
import { escapeString, getById, paginate } from '../database/grakn';
import {
  findAll as relationFindAll,
  search as relationSearch
} from './stixRelation';

export const findById = stixEntityId => getById(stixEntityId);

export const markingDefinitions = (stixEntityId, args) =>
  paginate(
    `match $m isa Marking-Definition; 
    $rel(marking:$m, so:$x) isa object_marking_refs; 
    $x has internal_id "${escapeString(stixEntityId)}"`,
    args,
    false,
    null,
    false,
    false
  );

export const stixRelations = (stixEntityId, args) => {
  const finalArgs = assoc('fromId', stixEntityId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};
