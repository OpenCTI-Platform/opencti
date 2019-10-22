import {
  addAttackPattern,
  findAll,
  findById,
  findByCourseOfAction
} from '../domain/attackPattern';
import {
  killChainPhases,
  externalReferences,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }) => findById(id),
    attackPatterns: (_, args) => {
      if (args.courseOfActionId && args.courseOfActionId.length > 0) {
        return findByCourseOfAction(args);
      }
      return findAll(args);
    }
  },
  AttackPattern: {
    externalReferences: (attPatt, args) => externalReferences(attPatt.id, args),
    killChainPhases: (attPatt, args) => killChainPhases(attPatt.id, args)
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
