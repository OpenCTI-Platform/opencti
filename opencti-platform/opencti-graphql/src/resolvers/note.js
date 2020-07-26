import {
  addNote,
  findAll,
  findById,
  objects,
  notesDistributionByEntity,
  notesNumber,
  notesNumberByEntity,
  notesTimeSeries,
  notesTimeSeriesByAuthor,
  notesTimeSeriesByEntity,
  noteContainsStixCoreObjectOrStixRelationship,
} from '../domain/note';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
} from '../utils/idGenerator';

const noteResolvers = {
  Query: {
    note: (_, { id }) => findById(id),
    notes: (_, args) => findAll(args),
    notesTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesTimeSeriesByEntity(args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return notesTimeSeriesByAuthor(args);
      }
      return notesTimeSeries(args);
    },
    notesNumber: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesNumberByEntity(args);
      }
      return notesNumber(args);
    },
    notesDistribution: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesDistributionByEntity(args);
      }
      return [];
    },
    noteObjectContains: (_, args) => {
      return noteContainsStixCoreObjectOrStixRelationship(args.id, args.objectId);
    },
  },
  NotesOrdering: {
    objectMarking: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    objectLabel: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.name`,
  },
  NotesFilter: {
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    objectContains: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
  },
  Note: {
    objects: (note, args) => objects(note.id, args),
  },
  Mutation: {
    noteEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ relationId, toId, relationship_type }) =>
        stixDomainObjectDeleteRelation(user, id, relationId, toId, relationship_type),
    }),
    noteAdd: (_, { input }, { user }) => addNote(user, input),
  },
};

export default noteResolvers;
