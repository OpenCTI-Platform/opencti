import { addThreatActor, findAll, findById } from '../domain/threatActor';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
} from '../domain/stixDomainEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const threatActorResolvers = {
  Query: {
    threatActor: (_, { id }) => findById(id),
    threatActors: (_, args) => findAll(args),
  },
  ThreatActorsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
  },
  ThreatActorsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id_key`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id_key`,
  },
  Mutation: {
    threatActorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    threatActorAdd: (_, { input }, { user }) => addThreatActor(user, input),
  },
};

export default threatActorResolvers;
