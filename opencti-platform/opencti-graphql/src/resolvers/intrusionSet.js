import { addIntrusionSet, findAll, findById, batchLocations } from '../domain/intrusionSet';
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
import { initBatchLoader } from '../database/middleware';

const locationsLoader = (user) => initBatchLoader(user, batchLocations);

const intrusionSetResolvers = {
  Query: {
    intrusionSet: (_, { id }, { user }) => findById(user, id),
    intrusionSets: (_, args, { user }) => findAll(user, args),
  },
  IntrusionSet: {
    locations: (intrusionSet, _, { user }) => locationsLoader(user).load(intrusionSet.id),
  },
  IntrusionSetsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Mutation: {
    intrusionSetEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    intrusionSetAdd: (_, { input }, { user }) => addIntrusionSet(user, input),
  },
};

export default intrusionSetResolvers;
