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
import { buildRefRelationKey } from '../schema/general';

const noteResolvers = {
  Query: {
    note: (_, { id }, context) => findById(context, context.user, id),
    notes: (_, args, context) => findAll(context, context.user, args),
    notesTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesTimeSeriesByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return notesTimeSeriesByAuthor(context, context.user, args);
      }
      return notesTimeSeries(context, context.user, args);
    },
    notesNumber: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesNumberByEntity(context, context.user, args);
      }
      return notesNumber(context, context.user, args);
    },
    notesDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesDistributionByEntity(context, context.user, args);
      }
      return [];
    },
    noteContainsStixObjectOrStixRelationship: (_, args, context) => {
      return noteContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  NotesFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT),
  },
  Mutation: {
    noteEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    noteAdd: (_, { input }, context) => addNote(context, context.user, input),
  },
};

export default noteResolvers;
