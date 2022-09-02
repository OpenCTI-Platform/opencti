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
import { RELATION_CREATED_BY, RELATION_OBJECT, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { buildRefRelationKey } from '../schema/general';

const observedDataResolvers = {
  Query: {
    observedData: (_, { id }, { user }) => findById(user, id),
    observedDatas: (_, args, { user }) => findAll(user, args),
    observedDatasTimeSeries: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasTimeSeriesByEntity(user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return observedDatasTimeSeriesByAuthor(user, args);
      }
      return observedDatasTimeSeries(user, args);
    },
    observedDatasNumber: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasNumberByEntity(user, args);
      }
      return observedDatasNumber(user, args);
    },
    observedDatasDistribution: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return observedDatasDistributionByEntity(user, args);
      }
      return [];
    },
    observedDataContainsStixObjectOrStixRelationship: (_, args, { user }) => {
      return observedDataContainsStixObjectOrStixRelationship(user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  ObservedData: {
    name: (observedData, _, { user }) => resolveName(user, observedData),
  },
  ObservedDatasFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT),
  },
  Mutation: {
    observedDataEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    observedDataAdd: (_, { input }, { user }) => addObservedData(user, input),
  },
};

export default observedDataResolvers;
