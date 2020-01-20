import {
  addReport,
  findAll,
  findById,
  objectRefs,
  observableRefs,
  relationRefs,
  reportsDistributionByEntity,
  reportsNumber,
  reportsNumberByEntity,
  reportsTimeSeries,
  reportsTimeSeriesByAuthor,
  reportsTimeSeriesByEntity
} from '../domain/report';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField
} from '../domain/stixDomainEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

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
    }
  },
  ReportsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`
  },
  ReportsFilter: {
    createdBy: `${REL_INDEX_PREFIX}created_by_ref.internal_id_key`,
    knowledgeContains: `${REL_INDEX_PREFIX}object_refs.internal_id_key`,
    observablesContains: `${REL_INDEX_PREFIX}observable_refs.internal_id_key`
  },
  Report: {
    objectRefs: (report, args) => objectRefs(report.id, args),
    observableRefs: report => observableRefs(report.id),
    relationRefs: (report, args) => relationRefs(report.id, args)
  },
  Mutation: {
    reportEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    reportAdd: (_, { input }, { user }) => addReport(user, input)
  }
};

export default reportResolvers;
