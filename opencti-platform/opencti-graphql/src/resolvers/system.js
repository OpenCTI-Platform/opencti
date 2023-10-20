import { addSystem, batchOrganizations, findAll, findById } from '../domain/system';
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

const systemResolvers = {
  Query: {
    system: (_, { id }, context) => findById(context, context.user, id),
    systems: (_, args, context) => findAll(context, context.user, args),
  },
  System: {
    organizations: (system, _, context) => organizationsLoader.load(system.id, context, context.user),
  },
  Mutation: {
    systemEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    systemAdd: (_, { input }, context) => addSystem(context, context.user, input),
  },
};

export default systemResolvers;
