import {
  addAttackPattern,
  attackPatternDelete,
  findAll,
  findById,
  createdByRef,
  markingDefinitions,
  killChainPhases,
  reports,
} from '../domain/attackPattern';
import {
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const attackPatternResolvers = {
  Query: {
    attackPattern: auth((_, { id }) => findById(id)),
    attackPatterns: auth((_, args) => findAll(args))
  },
  AttackPattern: {
    createdByRef: (attackPattern, args) => createdByRef(attackPattern.id, args),
    markingDefinitions: (attackPattern, args) =>
      markingDefinitions(attackPattern.id, args),
    killChainPhases: (attackPattern, args) =>
      killChainPhases(attackPattern.id, args),
    reports: (attackPattern, args) => reports(attackPattern.id, args),
    stixRelations: (attackPattern, args) =>
      stixRelations(attackPattern.id, args),
    editContext: auth(attackPattern => fetchEditContext(attackPattern.id))
  },
  Mutation: {
    attackPatternEdit: auth((_, { id }, { user }) => ({
      delete: () => attackPatternDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    attackPatternAdd: auth((_, { input }, { user }) =>
      addAttackPattern(user, input)
    )
  }
};

export default attackPatternResolvers;
