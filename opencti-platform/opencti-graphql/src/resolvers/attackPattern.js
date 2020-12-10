import {
  addAttackPattern,
  findAll,
  findById,
  batchCoursesOfAction,
  parentAttackPatterns,
  subAttackPatterns,
  isSubAttackPattern,
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
import {
  RELATION_CREATED_BY,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';
import { initBatchLoader } from '../database/grakn';

const killChainPhaseLoader = initBatchLoader(batchKillChainPhases);

const attackPatternResolvers = {
  Query: {
    attackPattern: (_, { id }) => findById(id),
    attackPatterns: (_, args) => findAll(args),
  },
  AttackPattern: {
    killChainPhases: (attackPattern) => killChainPhaseLoader.load(attackPattern.id),
    coursesOfAction: (attackPattern) => batchCoursesOfAction(attackPattern.id),
    parentAttackPatterns: (attackPattern) => parentAttackPatterns(attackPattern.id),
    subAttackPatterns: (attackPattern) => subAttackPatterns(attackPattern.id),
    isSubAttackPattern: (sector) => isSubAttackPattern(sector.id),
  },
  AttackPatternsOrdering: {
    objectMarking: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    objectLabel: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    killChainPhase: `${REL_INDEX_PREFIX}${RELATION_KILL_CHAIN_PHASE}.phase_name`,
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
