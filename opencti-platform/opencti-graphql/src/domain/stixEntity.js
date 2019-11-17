import { assoc, concat, head } from 'ramda';
import { loadEntityById, loadEntityByStixId } from '../database/grakn';
import { findAll as relationFindAll, search as relationSearch } from './stixRelation';
import { findAll as findAllMarkings } from './markingDefinition';
import { findAll as findAllTags } from './tag';
import { findAll as findAllReports } from './report';
import { findAll as findAllIdentity } from './identity';

export const findById = (id, isStixId) => {
  return isStixId ? loadEntityByStixId(id) : loadEntityById(id);
};
export const reports = (stixEntityId, args) => {
  const filter = { key: 'object_refs.internal_id_key', values: [stixEntityId] };
  const filters = concat([filter], args.filters || []);
  const filterArgs = assoc('filters', filters, args);
  return findAllReports(filterArgs);
};
export const tags = async (stixEntityId, args) => {
  const filter = { key: 'tagged.internal_id_key', values: [stixEntityId] };
  const filters = concat([filter], args.filters || []);
  const filterArgs = assoc('filters', filters, args);
  return findAllTags(filterArgs);
};
export const createdByRef = async stixEntityId => {
  const filter = { key: 'created_by_ref.internal_id_key', values: [stixEntityId] };
  const filterArgs = assoc('filters', [filter], []);
  return findAllIdentity(filterArgs).then(data => head(data.edges));
};
export const markingDefinitions = async (stixEntityId, args) => {
  const filter = { key: 'object_marking_refs.internal_id_key', values: [stixEntityId] };
  const filters = concat([filter], args.filters || []);
  const filterArgs = assoc('filters', filters, args);
  return findAllMarkings(filterArgs);
};
export const stixRelations = (stixEntityId, args) => {
  const finalArgs = assoc('fromId', stixEntityId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};
