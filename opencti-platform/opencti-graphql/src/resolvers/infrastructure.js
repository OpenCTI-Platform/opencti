import { addInfrastructure, findAll, findById } from '../domain/infrastructure';
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

const killChainPhaseLoader = initBatchLoader(batchKillChainPhases);

const infrastructureResolvers = {
  Query: {
    infrastructure: (_, { id }) => findById(id),
    infrastructures: (_, args) => findAll(args),
  },
  InfrastructuresFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Infrastructure: {
    killChainPhases: (infrastructure) => killChainPhaseLoader.load(infrastructure.id),
  },
  Mutation: {
    infrastructureEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    infrastructureAdd: (_, { input }, { user }) => addInfrastructure(user, input),
  },
};

export default infrastructureResolvers;
