import { addIndividual, batchOrganizations, findAll, findById, isUser } from '../domain/individual';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { batchLoader } from '../database/middleware';

const organizationsLoader = batchLoader(batchOrganizations);

const individualResolvers = {
  Query: {
    individual: (_, { id }, context) => findById(context, context.user, id),
    individuals: (_, args, context) => findAll(context, context.user, args),
  },
  Individual: {
    organizations: (individual, _, context) => organizationsLoader.load(individual.id, context, context.user),
    isUser: (individual, _, context) => isUser(context, context.user, individual.contact_information),
  },
  Mutation: {
    individualEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
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
