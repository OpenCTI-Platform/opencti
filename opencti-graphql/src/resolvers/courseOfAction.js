import {
  addCourseOfAction,
  courseOfActionDelete,
  findAll,
  findById,
  createdByRef,
  markingDefinitions,
  reports,
  courseOfActionEditContext,
  courseOfActionEditField,
  courseOfActionAddRelation,
  courseOfActionDeleteRelation
} from '../domain/courseOfAction';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const courseOfActionResolvers = {
  Query: {
    courseOfAction: auth((_, { id }) => findById(id)),
    courseOfActions: auth((_, args) => findAll(args))
  },
  CourseOfAction: {
    createdByRef: (courseOfAction, args) => createdByRef(courseOfAction.id, args),
    markingDefinitions: (courseOfAction, args) => markingDefinitions(courseOfAction.id, args),
    reports: (courseOfAction, args) => reports(courseOfAction.id, args),
    stixRelations: (courseOfAction, args) => stixRelations(courseOfAction.id, args),
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
  }
};

export default courseOfActionResolvers;
