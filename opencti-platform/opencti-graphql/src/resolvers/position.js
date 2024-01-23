import { addPosition, findAll, findById, locatedAtCity } from '../domain/position';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const positionResolvers = {
  Query: {
    position: (_, { id }, context) => findById(context, context.user, id),
    positions: (_, args, context) => findAll(context, context.user, args),
  },
  Position: {
    city: (position, _, context) => locatedAtCity(context, context.user, position.id),
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
