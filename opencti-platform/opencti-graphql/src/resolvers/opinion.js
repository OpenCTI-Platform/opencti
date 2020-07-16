import {
  addOpinion,
  findAll,
  findById,
  objectRefs,
  observableRefs,
  relationRefs,
  opinionsDistributionByEntity,
  opinionsNumber,
  opinionsNumberByEntity,
  opinionsTimeSeries,
  opinionsTimeSeriesByAuthor,
  opinionsTimeSeriesByEntity,
  opinionContainsStixDomainObject,
  opinionContainsStixRelation,
  opinionContainsStixObservable,
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
    opinionContainsStixDomainObject: (_, args) => {
      return opinionContainsStixDomainObject(args.id, args.objectId);
    },
    opinionContainsStixRelation: (_, args) => {
      return opinionContainsStixRelation(args.id, args.objectId);
    },
    opinionContainsStixObservable: (_, args) => {
      return opinionContainsStixObservable(args.id, args.objectId);
    },
  },
  OpinionsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.name`,
  },
  OpinionsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    knowledgeContains: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
    observablesContains: `${REL_INDEX_PREFIX}observable_refs.internal_id`,
  },
  Opinion: {
    objectRefs: (opinion, args) => objectRefs(opinion.id, args),
    observableRefs: (opinion, args) => observableRefs(opinion.id, args),
    relationRefs: (opinion, args) => relationRefs(opinion.id, args),
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
