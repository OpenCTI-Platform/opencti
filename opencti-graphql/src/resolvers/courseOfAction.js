import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addCourseOfAction,
  courseOfActionDelete,
  findAll,
  findById,
  createdByRef,
  markingDefinitions,
  killChainPhases,
  reports,
  courseOfActionEditContext,
  courseOfActionEditField,
  courseOfActionAddRelation,
  courseOfActionDeleteRelation,
  courseOfActionCleanContext
} from '../domain/courseOfAction';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const courseOfActionResolvers = {
  Query: {
    courseOfAction: auth((_, { id }) => findById(id)),
    courseOfActions: auth((_, args) => findAll(args))
  },
  CourseOfAction: {
    createdByRef: (courseOfAction, args) => createdByRef(courseOfAction.id, args),
    markingDefinitions: (courseOfAction, args) => markingDefinitions(courseOfAction.id, args),
    reports: (courseOfAction, args) => reports(courseOfAction.id, args),
    editContext: auth(courseOfAction => fetchEditContext(courseOfAction.id))
  },
  Mutation: {
    courseOfActionEdit: auth((_, { id }, { user }) => ({
      delete: () => courseOfActionDelete(id),
      fieldPatch: ({ input }) => courseOfActionEditField(user, id, input),
      contextPatch: ({ input }) => courseOfActionEditContext(user, id, input),
      relationAdd: ({ input }) => courseOfActionAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        courseOfActionDeleteRelation(user, id, relationId)
    })),
    courseOfActionAdd: auth((_, { input }, { user }) => addCourseOfAction(user, input))
  },
  Subscription: {
    courseOfAction: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        courseOfActionEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.CourseOfAction.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          courseOfActionCleanContext(user, id);
        });
      })
    }
  }
};

export default courseOfActionResolvers;
