import { addAttackPattern, findAll, findById } from '../domain/attackPattern';
import {
  externalReferences,
  killChainPhases,
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField
} from '../domain/stixDomainEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }) => findById(id),
    attackPatterns: (_, args) => findAll(args)
  },
  AttackPattern: {
    externalReferences: (attPatt, args) => externalReferences(attPatt.id, args),
    killChainPhases: (attPatt, args) => killChainPhases(attPatt.id, args)
  },
  AttackPatternsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`,
    killChainPhases: `${REL_INDEX_PREFIX}kill_chain_phases.phase_name`
  },
  AttackPatternsFilter: {
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
    mitigateBy: `${REL_INDEX_PREFIX}mitigates.internal_id_key`
  },
  Mutation: {
    attackPatternEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    attackPatternAdd: (_, { input }, { user }) => addAttackPattern(user, input)
  }
};

export default attackPatternResolvers;
