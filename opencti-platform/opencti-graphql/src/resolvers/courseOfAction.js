import { addCourseOfAction, findAll, findById, batchAttackPatterns } from '../domain/courseOfAction';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader } from '../database/middleware';
import { RELATION_MITIGATES } from '../schema/stixCoreRelationship';

const attackPatternsLoader = batchLoader(batchAttackPatterns);

const courseOfActionResolvers = {
  Query: {
    courseOfAction: (_, { id }, context) => findById(context, context.user, id),
    coursesOfAction: (_, args, context) => findAll(context, context.user, args),
  },
  CourseOfAction: {
    attackPatterns: (courseOfAction, _, context) => attackPatternsLoader.load(courseOfAction.id, context, context.user),
  },
  CoursesOfActionFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    mitigatedBy: buildRefRelationKey(RELATION_MITIGATES),
    creator: 'creator_id',
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
