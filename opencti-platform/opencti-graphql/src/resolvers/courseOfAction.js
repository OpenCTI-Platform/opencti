import {
  addCourseOfAction,
  findAll,
  findByEntity,
  findById
} from '../domain/courseOfAction';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const courseOfActionResolvers = {
  Query: {
    courseOfAction: (_, { id }) => findById(id),
    coursesOfAction: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return findByEntity(args);
      }
      return findAll(args);
    }
  },
  CourseOfAction: {
    createdByRef: courseOfAction => createdByRef(courseOfAction.id),
    markingDefinitions: (courseOfAction, args) =>
      markingDefinitions(courseOfAction.id, args),
    reports: (courseOfAction, args) => reports(courseOfAction.id, args),
    stixRelations: (courseOfAction, args) =>
      stixRelations(courseOfAction.id, args),
    editContext: courseOfAction => fetchEditContext(courseOfAction.id)
  },
  Mutation: {
    courseOfActionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    courseOfActionAdd: (_, { input }, { user }) =>
      addCourseOfAction(user, input)
  }
};

export default courseOfActionResolvers;
