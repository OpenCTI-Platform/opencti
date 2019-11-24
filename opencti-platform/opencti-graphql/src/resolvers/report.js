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
  externalReferences,
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField
} from '../domain/stixDomainEntity';

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
    createdByRef: 'created_by_ref.name',
    markingDefinitions: 'object_marking_refs.definition',
    tags: 'tagged.value'
  },
  ReportsFilter: {
    createdBy: 'created_by_ref.internal_id_key',
    knowledgeContains: 'object_refs.internal_id_key'
  },
  Report: {
    externalReferences: (report, args) => externalReferences(report.id, args),
    objectRefs: (report, args) => objectRefs(report.id, args),
    observableRefs: (report, args) => observableRefs(report.id, args),
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
