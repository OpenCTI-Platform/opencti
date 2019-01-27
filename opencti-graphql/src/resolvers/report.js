import {
  addReport,
  reportDelete,
  findAll,
  findAllByClass,
  findAllBySo,
  findAllBySoAndClass,
  findById,
  createdByRef,
  markingDefinitions,
  objectRefs,
  relationRefs,
  reportEditContext,
  reportEditField,
  reportAddRelation,
  reportDeleteRelation,
} from '../domain/report';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const reportResolvers = {
  Query: {
    report: auth((_, { id }) => findById(id)),
    reports: auth((_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        if (args.reportClass && args.reportClass.length > 0) {
          return findAllBySoAndClass(args);
        }
        return findAllBySo(args);
      }
      if (args.reportClass && args.reportClass.length > 0) {
        return findAllByClass(args);
      }
      return findAll(args);
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
      fieldPatch: ({ input }) => reportEditField(user, id, input),
      contextPatch: ({ input }) => reportEditContext(user, id, input),
      relationAdd: ({ input }) => reportAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        reportDeleteRelation(user, id, relationId)
    })),
    reportAdd: auth((_, { input }, { user }) => addReport(user, input))
  }
};

export default reportResolvers;
