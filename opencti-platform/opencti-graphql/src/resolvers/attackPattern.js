import {
  addAttackPattern,
  batchCoursesOfAction,
  batchDataComponents,
  batchIsSubAttackPattern,
  batchParentAttackPatterns,
  batchSubAttackPatterns,
  findAll,
  findById,
} from '../domain/attackPattern';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { batchKillChainPhases } from '../domain/stixCoreObject';
import { batchLoader } from '../database/middleware';

const killChainPhasesLoader = batchLoader(batchKillChainPhases);
const coursesOfActionLoader = batchLoader(batchCoursesOfAction);
const parentAttackPatternsLoader = batchLoader(batchParentAttackPatterns);
const subAttackPatternsLoader = batchLoader(batchSubAttackPatterns);
const isSubAttackPatternLoader = batchLoader(batchIsSubAttackPattern);
const dataComponentsLoader = batchLoader(batchDataComponents);

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }, context) => findById(context, context.user, id),
    attackPatterns: (_, args, context) => findAll(context, context.user, args),
  },
  AttackPattern: {
    killChainPhases: (attackPattern, _, context) => killChainPhasesLoader.load(attackPattern.id, context, context.user),
    coursesOfAction: (attackPattern, _, context) => coursesOfActionLoader.load(attackPattern.id, context, context.user),
    parentAttackPatterns: (attackPattern, _, context) => parentAttackPatternsLoader.load(attackPattern.id, context, context.user),
    subAttackPatterns: (attackPattern, _, context) => subAttackPatternsLoader.load(attackPattern.id, context, context.user),
    isSubAttackPattern: (attackPattern, _, context) => isSubAttackPatternLoader.load(attackPattern.id, context, context.user),
    dataComponents: (attackPattern, _, context) => dataComponentsLoader.load(attackPattern.id, context, context.user),
  },
  Mutation: {
    attackPatternEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    attackPatternAdd: (_, { input }, context) => addAttackPattern(context, context.user, input),
  },
};

export default attackPatternResolvers;
