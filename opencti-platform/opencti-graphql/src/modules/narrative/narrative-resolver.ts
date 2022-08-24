import type { Resolvers } from '../../generated/graphql';
import { addNarrative, findById, findAll } from './narrative-domain';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';

const narrativeResolvers: Resolvers = {
  Query: {
    narrative: (_, { id }, { user }) => findById(user, id),
    narratives: (_, args, { user }) => findAll(user, args),
  },
  NarrativesFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    narrativeAdd: (_, { input }, { user }) => addNarrative(user, input),
  },
};

export default narrativeResolvers;
