import {
  addOpinion,
  findAll,
  findById,
  findMyOpinion,
  opinionsDistributionByEntity,
  opinionsNumber,
  opinionsNumberByEntity,
  opinionsTimeSeries,
  opinionsTimeSeriesByAuthor,
  opinionsTimeSeriesByEntity,
  opinionContainsStixObjectOrStixRelationship,
} from '../domain/opinion';
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

const opinionResolvers = {
  Query: {
    opinion: (_, { id }, context) => findById(context, context.user, id),
    opinions: (_, args, context) => findAll(context, context.user, args),
    myOpinion: (_, { id }, context) => findMyOpinion(context, context.user, id),
    opinionsTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsTimeSeriesByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return opinionsTimeSeriesByAuthor(context, context.user, args);
      }
      return opinionsTimeSeries(context, context.user, args);
    },
    opinionsNumber: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsNumberByEntity(context, context.user, args);
      }
      return opinionsNumber(context, context.user, args);
    },
    opinionsDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsDistributionByEntity(context, context.user, args);
      }
      return [];
    },
    opinionContainsStixObjectOrStixRelationship: (_, args, context) => {
      return opinionContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  OpinionsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT, '*'),
    creator: 'creator_id',
  },
  Mutation: {
    opinionEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    opinionAdd: (_, { input }, context) => addOpinion(context, context.user, input),
  },
};

export default opinionResolvers;
