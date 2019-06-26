import {
  addReport,
  findAll,
  findByEntity,
  findByAuthor,
  reportsTimeSeries,
  reportsTimeSeriesByEntity,
  reportsTimeSeriesByAuthor,
  reportsNumber,
  reportsNumberByEntity,
  reportsDistributionByEntity,
  findById,
  objectRefs,
  observableRefs,
  relationRefs
} from '../domain/report';
import {
  createdByRef,
  markingDefinitions,
  externalReferences,
  exports,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const reportResolvers = {
  Query: {
    report: (_, { id }) => findById(id),
    reports: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return findByEntity(args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return findByAuthor(args);
      }
      return findAll(args);
    },
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
      return reportsDistribution(args);
    }
  },
  Report: {
    createdByRef: (report, args) => createdByRef(report.id, args),
    markingDefinitions: (report, args) => markingDefinitions(report.id, args),
    externalReferences: (report, args) => externalReferences(report.id, args),
    objectRefs: (report, args) => objectRefs(report.id, args),
    exports: (report, args) => exports(report.id, args),
    observableRefs: (report, args) => observableRefs(report.id, args),
    relationRefs: (report, args) => relationRefs(report.id, args),
    editContext: report => fetchEditContext(report.id)
  },
  Mutation: {
    reportEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    reportAdd: (_, { input }, { user }) => addReport(user, input)
  }
};

export default reportResolvers;
