import {
  addOpinion,
  findAll,
  findById,
  objects,
  opinionsDistributionByEntity,
  opinionsNumber,
  opinionsNumberByEntity,
  opinionsTimeSeries,
  opinionsTimeSeriesByAuthor,
  opinionsTimeSeriesByEntity,
  opinionContainsStixCoreObjectOrStixRelationship,
} from '../domain/opinion';
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

const opinionResolvers = {
  Query: {
    opinion: (_, { id }) => findById(id),
    opinions: (_, args) => findAll(args),
    opinionsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsTimeSeriesByEntity(args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return opinionsTimeSeriesByAuthor(args);
      }
      return opinionsTimeSeries(args);
    },
    opinionsNumber: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsNumberByEntity(args);
      }
      return opinionsNumber(args);
    },
    opinionsDistribution: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return opinionsDistributionByEntity(args);
      }
      return [];
    },
    opinionObjectContains: (_, args) => {
      return opinionContainsStixCoreObjectOrStixRelationship(args.id, args.objectId);
    },
  },
  OpinionsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.name`,
  },
  OpinionsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    objectContains: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
  },
  Opinion: {
    objects: (opinion, args) => objects(opinion.id, args),
  },
  Mutation: {
    opinionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ relationId, toId, relationType }) =>
        stixDomainObjectDeleteRelation(user, id, relationId, toId, relationType),
    }),
    opinionAdd: (_, { input }, { user }) => addOpinion(user, input),
  },
};

export default opinionResolvers;
