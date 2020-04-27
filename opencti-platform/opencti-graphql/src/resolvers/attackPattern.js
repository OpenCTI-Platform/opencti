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
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`,
    killChainPhases: `${REL_INDEX_PREFIX}kill_chain_phases.phase_name`,
  },
  AttackPatternsFilter: {
    createdBy: `${REL_INDEX_PREFIX}created_by_ref.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.internal_id_key`,
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
    mitigateBy: `${REL_INDEX_PREFIX}mitigates.internal_id_key`,
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
