import { addAttackPattern, findAll, findById, coursesOfAction } from '../domain/attackPattern';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
} from '../domain/stixDomainEntity';
import { killChainPhases } from '../domain/stixEntity';

import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import {
  RELATION_CREATED_BY,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../utils/idGenerator';

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }) => findById(id),
    attackPatterns: (_, args) => findAll(args),
  },
  AttackPattern: {
    killChainPhases: (attackPattern) => killChainPhases(attackPattern.id),
    coursesOfAction: (attackPattern) => coursesOfAction(attackPattern.id),
  },
  AttackPatternsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    killChainPhases: `${REL_INDEX_PREFIX}${RELATION_KILL_CHAIN_PHASE}.phase_name`,
  },
  AttackPatternsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    mitigateBy: `${REL_INDEX_PREFIX}mitigates.internal_id`,
  },
  Mutation: {
    attackPatternEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    attackPatternAdd: (_, { input }, { user }) => addAttackPattern(user, input),
  },
};

export default attackPatternResolvers;
