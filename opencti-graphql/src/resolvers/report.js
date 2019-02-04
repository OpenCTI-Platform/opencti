import {
  addReport,
  reportDelete,
  findAll,
  findByEntity,
  reportsTimeSeries,
  reportsTimeSeriesByEntity,
  findById,
  objectRefs,
  relationRefs
} from '../domain/report';
import {
  createdByRef,
  markingDefinitions,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const reportResolvers = {
  Query: {
    report: auth((_, { id }) => findById(id)),
    reports: auth((_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return findByEntity(args);
      }
      return findAll(args);
    }),
    reportsTimeSeries: auth((_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsTimeSeriesByEntity(args);
      }
      return reportsTimeSeries(args);
    })
  },
  Report: {
    createdByRef: (report, args) => createdByRef(report.id, args),
    markingDefinitions: (report, args) => markingDefinitions(report.id, args),
    objectRefs: (report, args) => objectRefs(report.id, args),
    relationRefs: (report, args) => relationRefs(report.id, args),
    editContext: auth(report => fetchEditContext(report.id))
  },
  Mutation: {
    reportEdit: auth((_, { id }, { user }) => ({
      delete: () => reportDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    reportAdd: auth((_, { input }, { user }) => addReport(user, input))
  }
};

export default reportResolvers;
