import { assoc, append, propOr, pipe } from 'ramda';
import {
  createEntity,
  distributionEntities,
  distributionEntitiesThroughRelations,
  escapeString,
  getSingleValueNumber,
  listEntities,
  listRelations,
  loadEntityById,
  loadEntityByStixId,
  prepareDate,
  timeSeriesEntities,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { notify } from '../database/redis';
import { findAll as findAllStixObservables } from './stixObservable';
import { findAll as findAllStixDomainEntities } from './stixDomainEntity';

export const findById = (noteId) => {
  if (noteId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(noteId, 'Note');
  }
  return loadEntityById(noteId, 'Note');
};
export const findAll = async (args) => {
  return listEntities(['Note'], ['name', 'content'], args);
};

// Entities tab
export const objectRefs = (noteId, args) => {
  const key = `${REL_INDEX_PREFIX}object_refs.internal_id_key`;
  const finalArgs = assoc('filters', append({ key, values: [noteId] }, propOr([], 'filters', args)), args);
  return findAllStixDomainEntities(finalArgs);
};
export const noteContainsStixDomainEntity = async (noteId, objectId) => {
  const args = {
    filters: [
      { key: `${REL_INDEX_PREFIX}object_refs.internal_id_key`, values: [noteId] },
      { key: 'id', values: [objectId] },
    ],
  };
  const stixDomainEntities = await findAllStixDomainEntities(args);
  return stixDomainEntities.edges.length > 0;
};
// Relation refs
export const relationRefs = (noteId, args) => {
  const relationFilter = { relation: 'object_refs', fromRole: 'so', toRole: 'knowledge_aggregation', id: noteId };
  const finalArgs = assoc('relationFilter', relationFilter, args);
  return listRelations(args.relationType, finalArgs);
};
export const noteContainsStixRelation = async (noteId, objectId) => {
  const relationFilter = {
    relation: 'object_refs',
    fromRole: 'so',
    toRole: 'knowledge_aggregation',
    id: noteId,
    relationId: objectId,
  };
  const stixRelations = await listRelations(null, { relationFilter });
  return stixRelations.edges.length > 0;
};
// Observable refs
export const observableRefs = (noteId, args) => {
  const key = `${REL_INDEX_PREFIX}observable_refs.internal_id_key`;
  const finalArgs = assoc('filters', append({ key, values: [noteId] }, propOr([], 'filters', args)), args);
  return findAllStixObservables(finalArgs);
};
export const noteContainsStixObservable = async (noteId, objectId) => {
  const args = {
    filters: [
      { key: `${REL_INDEX_PREFIX}observable_refs.internal_id_key`, values: [noteId] },
      { key: 'id', values: [objectId] },
    ],
  };
  const stixObservables = await findAllStixObservables(args);
  return stixObservables.edges.length > 0;
};
// region series
export const notesTimeSeries = (args) => {
  return timeSeriesEntities('Note', [], args);
};
export const notesNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x isa Note; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } get; count;`
  ),
  total: getSingleValueNumber(`match $x isa Note; get; count;`),
});
export const notesTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: 'object_refs', value: args.objectId }];
  return timeSeriesEntities('Note', filters, args);
};
export const notesTimeSeriesByAuthor = async (args) => {
  const { authorId } = args;
  const filters = [{ isRelation: true, from: 'so', to: 'creator', type: 'created_by_ref', value: authorId }];
  return timeSeriesEntities('Note', filters, args);
};
export const notesNumberByEntity = (args) => ({
  count: getSingleValueNumber(
    `match $x isa Note;
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
    $so has internal_id_key "${escapeString(args.objectId)}" ${
      args.endDate ? `; $x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    }
    get;
    count;`
  ),
  total: getSingleValueNumber(
    `match $x isa Note;
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
    $so has internal_id_key "${escapeString(args.objectId)}";
    get;
    count;`
  ),
});
export const notesDistributionByEntity = async (args) => {
  const { objectId, field } = args;
  if (field.includes('.')) {
    const options = pipe(
      assoc('relationType', 'object_refs'),
      assoc('toType', 'Note'),
      assoc('field', field.split('.')[1]),
      assoc('remoteRelationType', field.split('.')[0]),
      assoc('fromId', objectId)
    )(args);
    return distributionEntitiesThroughRelations(options);
  }
  const filters = [{ isRelation: true, type: 'object_refs', value: objectId }];
  return distributionEntities('Note', filters, args);
};
// endregion

// region mutations
export const addNote = async (user, note) => {
  const created = await createEntity(user, note, 'Note');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
// endregion
