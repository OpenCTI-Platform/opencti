import {
  addReport,
  findAll,
  findById,
  reportsDistributionByEntity,
  reportsNumber,
  reportsNumberByEntity,
  reportsNumberByAuthor,
  reportsTimeSeries,
  reportsTimeSeriesByAuthor,
  reportsTimeSeriesByEntity,
  reportContainsStixObjectOrStixRelationship,
} from '../domain/report';
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
import { distributionEntities } from '../database/middleware';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';

const reportResolvers = {
  Query: {
    report: (_, { id }, { user }) => findById(user, id),
    reports: (_, args, { user }) => findAll(user, args),
    reportsTimeSeries: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsTimeSeriesByEntity(user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return reportsTimeSeriesByAuthor(user, args);
      }
      return reportsTimeSeries(user, args);
    },
    reportsNumber: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsNumberByEntity(user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return reportsNumberByAuthor(user, args);
      }
      return reportsNumber(user, args);
    },
    reportsDistribution: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsDistributionByEntity(user, args);
      }
      return distributionEntities(user, ENTITY_TYPE_CONTAINER_REPORT, [], args);
    },
    reportContainsStixObjectOrStixRelationship: (_, args, { user }) => {
      return reportContainsStixObjectOrStixRelationship(user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  ReportsOrdering: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.name`,
  },
  ReportsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    objectContains: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
  },
  Mutation: {
    reportEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    reportAdd: (_, { input }, { user }) => addReport(user, input),
  },
};

export default reportResolvers;
