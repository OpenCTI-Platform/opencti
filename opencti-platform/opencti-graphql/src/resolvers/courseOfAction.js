import { addCourseOfAction, batchAttackPatterns, findAll, findById } from '../domain/courseOfAction';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { batchLoader } from '../database/middleware';

const attackPatternsLoader = batchLoader(batchAttackPatterns);

const courseOfActionResolvers = {
  Query: {
    courseOfAction: (_, { id }, context) => findById(context, context.user, id),
    coursesOfAction: (_, args, context) => findAll(context, context.user, args),
  },
  CourseOfAction: {
    attackPatterns: (courseOfAction, _, context) => attackPatternsLoader.load(courseOfAction.id, context, context.user),
  },
  Mutation: {
    courseOfActionEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    courseOfActionAdd: (_, { input }, context) => addCourseOfAction(context, context.user, input),
  },
};

export default courseOfActionResolvers;
