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
    opinion: (_, { id }, { user }) => findById(user, id),
    opinions: (_, args, { user }) => findAll(user, args),
    myOpinion: (_, { id }, { user }) => findMyOpinion(user, id),
    opinionsTimeSeries: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsTimeSeriesByEntity(user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return opinionsTimeSeriesByAuthor(user, args);
      }
      return opinionsTimeSeries(user, args);
    },
    opinionsNumber: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsNumberByEntity(user, args);
      }
      return opinionsNumber(user, args);
    },
    opinionsDistribution: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsDistributionByEntity(user, args);
      }
      return [];
    },
    opinionContainsStixObjectOrStixRelationship: (_, args, { user }) => {
      return opinionContainsStixObjectOrStixRelationship(user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  OpinionsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT),
  },
  Mutation: {
    opinionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    opinionAdd: (_, { input }, { user }) => addOpinion(user, input),
  },
};

export default opinionResolvers;
