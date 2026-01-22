import { addIndividual, findIndividualPaginated, findById, isUser, partOfOrganizationsPaginated } from '../domain/individual';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../schema/stixDomainObject';

const individualResolvers = {
  Query: {
    individual: (_, { id }, context) => findById(context, context.user, id),
    individuals: (_, args, context) => findIndividualPaginated(context, context.user, args),
  },
  Individual: {
    organizations: (individual, args, context) => partOfOrganizationsPaginated(context, context.user, individual.id, args),
    isUser: (individual, _, context) => isUser(context, individual),
  },
  Mutation: {
    individualEdit: (_, { id }, context) => ({
      delete: async () => {
        // Use the type-checking version that validates the entity type
        return stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
      },
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    individualAdd: (_, { input }, context) => addIndividual(context, context.user, input),
  },
};

export default individualResolvers;
