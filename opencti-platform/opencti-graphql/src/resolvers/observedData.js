import {
  addObservedData,
  findAll,
  findById,
  observedDataContainsStixObjectOrStixRelationship,
  observedDatasDistributionByEntity,
  observedDatasNumber,
  observedDatasNumberByEntity,
  observedDatasTimeSeries,
  observedDatasTimeSeriesByAuthor,
  observedDatasTimeSeriesByEntity,
} from '../domain/observedData';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';

const observedDataResolvers = {
  Query: {
    observedData: (_, { id }) => findById(id),
    observedDatas: (_, args) => findAll(args),
    observedDatasTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasTimeSeriesByEntity(args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return observedDatasTimeSeriesByAuthor(args);
      }
      return observedDatasTimeSeries(args);
    },
    observedDatasNumber: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasNumberByEntity(args);
      }
      return observedDatasNumber(args);
    },
    observedDatasDistribution: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasDistributionByEntity(args);
      }
      return [];
    },
    observedDataContainsStixObjectOrStixRelationship: (_, args) => {
      return observedDataContainsStixObjectOrStixRelationship(args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  ObservedDatasFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Mutation: {
    observedDataEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    observedDataAdd: (_, { input }, { user }) => addObservedData(user, input),
  },
};

export default observedDataResolvers;
