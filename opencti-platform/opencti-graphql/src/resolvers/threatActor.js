import { addThreatActor, findAll, findById, batchLocations } from '../domain/threatActor';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';
import { batchLoader } from '../database/middleware';
import { UPDATE_OPERATION_REPLACE } from '../database/utils';

const locationsLoader = batchLoader(batchLocations);

const threatActorResolvers = {
  Query: {
    threatActor: (_, { id }, { user }) => findById(user, id),
    threatActors: (_, args, { user }) => findAll(user, args),
  },
  ThreatActor: {
    locations: (threatActor, _, { user }) => locationsLoader.load(threatActor.id, user),
  },
  ThreatActorsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Mutation: {
    threatActorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, operation = UPDATE_OPERATION_REPLACE }) =>
        stixDomainObjectEditField(user, id, input, { operation }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    threatActorAdd: (_, { input }, { user }) => addThreatActor(user, input),
  },
};

export default threatActorResolvers;
