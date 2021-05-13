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
import { batchLoader } from '../database/middleware';
import { UPDATE_OPERATION_REPLACE } from '../database/utils';

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
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    mitigatedBy: `${REL_INDEX_PREFIX}mitigates.internal_id`,
  },
  Mutation: {
    attackPatternEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, operation = UPDATE_OPERATION_REPLACE }) =>
        stixDomainObjectEditField(user, id, input, { operation }),
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
