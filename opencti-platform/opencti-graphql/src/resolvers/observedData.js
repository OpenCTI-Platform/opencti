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
  resolveName,
} from '../domain/observedData';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const observedDataResolvers = {
  Query: {
    observedData: (_, { id }, context) => findById(context, context.user, id),
    observedDatas: (_, args, context) => findAll(context, context.user, args),
    observedDatasTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasTimeSeriesByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return observedDatasTimeSeriesByAuthor(context, context.user, args);
      }
      return observedDatasTimeSeries(context, context.user, args);
    },
    observedDatasNumber: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasNumberByEntity(context, context.user, args);
      }
      return observedDatasNumber(context, context.user, args);
    },
    observedDatasDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasDistributionByEntity(context, context.user, args);
      }
      return [];
    },
    observedDataContainsStixObjectOrStixRelationship: (_, args, context) => {
      return observedDataContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  ObservedData: {
    name: (observedData, _, context) => resolveName(context, context.user, observedData),
  },
  Mutation: {
    observedDataEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    observedDataAdd: (_, { input }, context) => addObservedData(context, context.user, input),
  },
};

export default observedDataResolvers;
