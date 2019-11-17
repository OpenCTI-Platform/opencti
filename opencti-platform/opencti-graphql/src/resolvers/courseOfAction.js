import { addCourseOfAction, findAll, findById } from '../domain/courseOfAction';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField
} from '../domain/stixDomainEntity';

const courseOfActionResolvers = {
  Query: {
    courseOfAction: (_, { id }) => findById(id),
    coursesOfAction: (_, args) => findAll(args)
  },
  CoursesOfActionOrdering: {
    tags: 'tagged.value',
    markingDefinitions: 'object_marking_refs.definition'
  },
  CoursesOfActionFilter: {
    tags: 'tagged.internal_id_key',
    mitigateBy: 'mitigates.internal_id_key'
  },
  Mutation: {
    courseOfActionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    courseOfActionAdd: (_, { input }, { user }) => addCourseOfAction(user, input)
  }
};

export default courseOfActionResolvers;
