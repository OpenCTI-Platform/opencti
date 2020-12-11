import {
  addNote,
  findAll,
  findById,
  noteContainsStixObjectOrStixRelationship,
  notesDistributionByEntity,
  notesNumber,
  notesNumberByEntity,
  notesTimeSeries,
  notesTimeSeriesByAuthor,
  notesTimeSeriesByEntity,
} from '../domain/note';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';

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
    noteContainsStixObjectOrStixRelationship: (_, args) => {
      return noteContainsStixObjectOrStixRelationship(args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  NotesOrdering: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.name`,
  },
  NotesFilter: {
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    objectContains: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
  },
  Mutation: {
    noteEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    noteAdd: (_, { input }, { user }) => addNote(user, input),
  },
};

export default noteResolvers;
