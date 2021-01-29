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
import { REL_INDEX_PREFIX } from '../schema/general';
import { initBatchLoader } from '../database/middleware';

const killChainPhasesLoader = (user) => initBatchLoader(user, batchKillChainPhases);
const coursesOfActionLoader = (user) => initBatchLoader(user, batchCoursesOfAction);
const parentAttackPatternsLoader = (user) => initBatchLoader(user, batchParentAttackPatterns);
const subAttackPatternsLoader = (user) => initBatchLoader(user, batchSubAttackPatterns);
const isSubAttackPatternLoader = (user) => initBatchLoader(user, batchIsSubAttackPattern);

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }, { user }) => findById(user, id),
    attackPatterns: (_, args, { user }) => findAll(user, args),
  },
  AttackPattern: {
    killChainPhases: (attackPattern, _, { user }) => killChainPhasesLoader(user).load(attackPattern.id),
    coursesOfAction: (attackPattern, _, { user }) => coursesOfActionLoader(user).load(attackPattern.id),
    parentAttackPatterns: (attackPattern, _, { user }) => parentAttackPatternsLoader(user).load(attackPattern.id),
    subAttackPatterns: (attackPattern, _, { user }) => subAttackPatternsLoader(user).load(attackPattern.id),
    isSubAttackPattern: (attackPattern, _, { user }) => isSubAttackPatternLoader(user).load(attackPattern.id),
  },
  AttackPatternsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    mitigatedBy: `${REL_INDEX_PREFIX}mitigates.internal_id`,
  },
  Mutation: {
    attackPatternEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    attackPatternAdd: (_, { input }, { user }) => addAttackPattern(user, input),
  },
};

export default attackPatternResolvers;
