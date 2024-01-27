import {
  addAttackPattern,
  childAttackPatternsPaginated,
  coursesOfActionPaginated,
  dataComponentsPaginated,
  findAll,
  findById,
  isSubAttackPattern,
  parentAttackPatternsPaginated
} from '../domain/attackPattern';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { batchLoader } from '../database/middleware';
import { batchInternalRels } from '../domain/stixCoreObject';
import { loadThroughDenormalized } from './stix';
import { INPUT_KILLCHAIN } from '../schema/general';

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }, context) => findById(context, context.user, id),
    attackPatterns: (_, args, context) => findAll(context, context.user, args),
  },
  AttackPattern: {
    killChainPhases: (attackPattern, _, context) => loadThroughDenormalized(context, context.user, attackPattern, INPUT_KILLCHAIN),
    coursesOfAction: (attackPattern, args, context) => coursesOfActionPaginated(context, context.user, attackPattern.id, args),
    parentAttackPatterns: (attackPattern, args, context) => parentAttackPatternsPaginated(context, context.user, attackPattern.id, args),
    subAttackPatterns: (attackPattern, args, context) => childAttackPatternsPaginated(context, context.user, attackPattern.id, args),
    dataComponents: (attackPattern, args, context) => dataComponentsPaginated(context, context.user, attackPattern.id, args),
    isSubAttackPattern: (attackPattern, _, context) => isSubAttackPattern(context, context.user, attackPattern.id),
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
