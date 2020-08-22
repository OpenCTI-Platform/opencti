import {
  addReport,
  findAll,
  findById,
  objects,
  reportsDistributionByEntity,
  reportsNumber,
  reportsNumberByEntity,
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
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';

const reportResolvers = {
  Query: {
    report: (_, { id }) => findById(id),
    reports: (_, args) => findAll(args),
    reportsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsTimeSeriesByEntity(args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return reportsTimeSeriesByAuthor(args);
      }
      return reportsTimeSeries(args);
    },
    reportsNumber: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsNumberByEntity(args);
      }
      return reportsNumber(args);
    },
    reportsDistribution: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsDistributionByEntity(args);
      }
      return [];
    },
    reportContainsStixObjectOrStixRelationship: (_, args) => {
      return reportContainsStixObjectOrStixRelationship(args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  ReportsOrdering: {
    objectMarking: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    objectLabel: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.name`,
  },
  ReportsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    objectContains: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
  },
  Report: {
    objects: (report, args) => objects(report.id, args),
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
