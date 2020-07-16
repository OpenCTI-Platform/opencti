import { addCourseOfAction, findAll, findById, attackPatterns } from '../domain/courseOfAction';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
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
      relationDelete: ({ relationId }) => stixDomainObjectDeleteRelation(user, id, relationId),
    }),
    courseOfActionAdd: (_, { input }, { user }) => addCourseOfAction(user, input),
  },
};

export default courseOfActionResolvers;
