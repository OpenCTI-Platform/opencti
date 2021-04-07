import { addCourseOfAction, findAll, findById, batchAttackPatterns } from '../domain/courseOfAction';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';
import { batchLoader } from '../database/middleware';

const attackPatternsLoader = batchLoader(batchAttackPatterns);

const courseOfActionResolvers = {
  Query: {
    courseOfAction: (_, { id }, { user }) => findById(user, id),
    coursesOfAction: (_, args, { user }) => findAll(user, args),
  },
  CourseOfAction: {
    attackPatterns: (courseOfAction, _, { user }) => attackPatternsLoader.load(courseOfAction.id, user),
  },
  CoursesOfActionFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    mitigatedBy: `${REL_INDEX_PREFIX}mitigates.internal_id`,
  },
  Mutation: {
    courseOfActionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    courseOfActionAdd: (_, { input }, { user }) => addCourseOfAction(user, input),
  },
};

export default courseOfActionResolvers;
