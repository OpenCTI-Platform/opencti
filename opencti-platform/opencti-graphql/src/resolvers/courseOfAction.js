import { addCourseOfAction, findAll, findById, attackPatterns } from '../domain/courseOfAction';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
} from '../domain/stixDomainEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const courseOfActionResolvers = {
  Query: {
    courseOfAction: (_, { id }) => findById(id),
    coursesOfAction: (_, args) => findAll(args),
  },
  CourseOfAction: {
    attackPatterns: (courseOfAction) => attackPatterns(courseOfAction.id),
  },
  CoursesOfActionOrdering: {
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
  },
  CoursesOfActionFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id_key`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id_key`,
    mitigateBy: `${REL_INDEX_PREFIX}mitigates.internal_id_key`,
  },
  Mutation: {
    courseOfActionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    courseOfActionAdd: (_, { input }, { user }) => addCourseOfAction(user, input),
  },
};

export default courseOfActionResolvers;
