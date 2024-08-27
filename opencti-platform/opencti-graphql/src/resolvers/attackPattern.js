import {
  addAttackPattern,
  batchChildAttackPatternsPaginated,
  batchIsSubAttackPattern,
  batchParentAttackPatternsPaginated,
  coursesOfActionPaginated,
  dataComponentsPaginated,
  findAll,
  findById,
  getAttackPatternsMatrix,
} from '../domain/attackPattern';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { loadThroughDenormalized } from './stix';
import { INPUT_KILLCHAIN } from '../schema/general';
import { batchLoader } from '../database/middleware';

const batchLoadSubAttackPatterns = batchLoader(batchChildAttackPatternsPaginated);
const batchLoadParentAttackPatterns = batchLoader(batchParentAttackPatternsPaginated);
const batchLoadIsSubAttackPattern = batchLoader(batchIsSubAttackPattern);

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }, context) => findById(context, context.user, id),
    attackPatterns: (_, args, context) => findAll(context, context.user, args),
    attackPatternsMatrix: (_, __, context) => getAttackPatternsMatrix(context, context.user),
  },
  AttackPattern: {
    killChainPhases: (attackPattern, _, context) => loadThroughDenormalized(context, context.user, attackPattern, INPUT_KILLCHAIN, { sortBy: 'phase_name' }),
    coursesOfAction: (attackPattern, args, context) => coursesOfActionPaginated(context, context.user, attackPattern.id, args),
    parentAttackPatterns: (attackPattern, args, context) => batchLoadParentAttackPatterns.load(attackPattern.id, context, context.user, args),
    subAttackPatterns: (attackPattern, args, context) => batchLoadSubAttackPatterns.load(attackPattern.id, context, context.user, args),
    dataComponents: (attackPattern, args, context) => dataComponentsPaginated(context, context.user, attackPattern.id, args),
    isSubAttackPattern: (attackPattern, _, context) => batchLoadIsSubAttackPattern.load(attackPattern.id, context, context.user),
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
