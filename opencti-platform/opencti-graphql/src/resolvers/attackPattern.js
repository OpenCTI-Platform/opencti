import {
  addAttackPattern,
  findAll,
  findById,
  batchCoursesOfAction,
  batchParentAttackPatterns,
  batchSubAttackPatterns,
  batchIsSubAttackPattern,
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
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader } from '../database/middleware';
import { RELATION_MITIGATES } from '../schema/stixCoreRelationship';

const killChainPhasesLoader = batchLoader(batchKillChainPhases);
const coursesOfActionLoader = batchLoader(batchCoursesOfAction);
const parentAttackPatternsLoader = batchLoader(batchParentAttackPatterns);
const subAttackPatternsLoader = batchLoader(batchSubAttackPatterns);
const isSubAttackPatternLoader = batchLoader(batchIsSubAttackPattern);

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }, { user }) => findById(user, id),
    attackPatterns: (_, args, { user }) => findAll(user, args),
  },
  AttackPattern: {
    killChainPhases: (attackPattern, _, { user }) => killChainPhasesLoader.load(attackPattern.id, user),
    coursesOfAction: (attackPattern, _, { user }) => coursesOfActionLoader.load(attackPattern.id, user),
    parentAttackPatterns: (attackPattern, _, { user }) => parentAttackPatternsLoader.load(attackPattern.id, user),
    subAttackPatterns: (attackPattern, _, { user }) => subAttackPatternsLoader.load(attackPattern.id, user),
    isSubAttackPattern: (attackPattern, _, { user }) => isSubAttackPatternLoader.load(attackPattern.id, user),
  },
  AttackPatternsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    mitigatedBy: buildRefRelationKey(RELATION_MITIGATES),
  },
  Mutation: {
    attackPatternEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    attackPatternAdd: (_, { input }, { user }) => addAttackPattern(user, input),
  },
};

export default attackPatternResolvers;
