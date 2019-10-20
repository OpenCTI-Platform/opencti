import {
  addCourseOfAction,
  findAll,
  findByEntity,
  findById
} from '../domain/courseOfAction';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';

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
