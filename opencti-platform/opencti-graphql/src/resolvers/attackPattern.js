import { addAttackPattern, findAll, findById } from '../domain/attackPattern';
import {
  createdByRef,
  killChainPhases,
  markingDefinitions,
  tags,
  externalReferences,
  reports,
  exports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }) => findById(id),
    attackPatterns: (_, args) => findAll(args)
  },
  AttackPattern: {
    createdByRef: attackPattern => createdByRef(attackPattern.id),
    markingDefinitions: (attackPattern, args) =>
      markingDefinitions(attackPattern.id, args),
    tags: (attackPattern, args) => tags(attackPattern.id, args),
    externalReferences: (attackPattern, args) =>
      externalReferences(attackPattern.id, args),
    killChainPhases: (attackPattern, args) =>
      killChainPhases(attackPattern.id, args),
    reports: (attackPattern, args) => reports(attackPattern.id, args),
    exports: (attackPattern, args) => exports(attackPattern.id, args),
    stixRelations: (attackPattern, args) =>
      stixRelations(attackPattern.id, args),
    editContext: attackPattern => fetchEditContext(attackPattern.id)
  },
  Mutation: {
    attackPatternEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    attackPatternAdd: (_, { input }, { user }) => addAttackPattern(user, input)
  }
};

export default attackPatternResolvers;
