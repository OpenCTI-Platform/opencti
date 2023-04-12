import { addPosition, findAll, findById, batchCity } from '../domain/position';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader } from '../database/middleware';

const batchCityLoader = batchLoader(batchCity);

const positionResolvers = {
  Query: {
    position: (_, { id }, context) => findById(context, context.user, id),
    positions: (_, args, context) => findAll(context, context.user, args),
  },
  Position: {
    city: (position, _, context) => batchCityLoader.load(position.id, context, context.user),
  },
  PositionsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    positionEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    positionAdd: (_, { input }, context) => addPosition(context, context.user, input),
  },
};

export default positionResolvers;
