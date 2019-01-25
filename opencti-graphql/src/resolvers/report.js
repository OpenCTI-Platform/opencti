import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
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
  reportCleanContext
} from '../domain/report';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

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
  },
  Subscription: {
    report: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        reportEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Report.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          reportCleanContext(user, id);
        });
      })
    }
  }
};

export default reportResolvers;
