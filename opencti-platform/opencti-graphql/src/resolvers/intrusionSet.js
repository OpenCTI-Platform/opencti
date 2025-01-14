import { addIntrusionSet, findAll, findById, locationsPaginated } from '../domain/intrusionSet';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const intrusionSetResolvers = {
  Query: {
    intrusionSet: (_, { id }, context) => findById(context, context.user, id),
    intrusionSets: (_, args, context) => findAll(context, context.user, args),
  },
  IntrusionSet: {
    locations: (intrusionSet, args, context) => locationsPaginated(context, context.user, intrusionSet.id, args),
  },
  Mutation: {
    intrusionSetEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    intrusionSetAdd: (_, { input }, context) => addIntrusionSet(context, context.user, input),
  },
};

export default intrusionSetResolvers;
